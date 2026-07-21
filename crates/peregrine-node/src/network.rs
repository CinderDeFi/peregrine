//! In-process network: reliable, ordered broadcast + targeted unicast over
//! tokio mpsc channels. This deliberately models an *idealized* transport so
//! consensus-logic bugs are never masked by transport flakiness; loss,
//! delay, and partitions are injected in tests, not here.
//!
//! Two message classes ride the same wire:
//! * **vertices** — normal DAG dissemination (broadcast);
//! * **sync** — ancestor fetch: a validator that receives a vertex whose
//!   parents it hasn't seen asks a peer for them (unicast request/response).
//!
//! ## Reconnection
//! Each peer slot is an `Arc<Mutex<Sender>>` shared by every [`Broadcaster`]
//! clone and by the owning [`Network`]. That indirection lets a node be
//! *killed and restarted* against a still-running network: [`Network::reconnect`]
//! swaps a fresh sender into the slot, and because all broadcasters hold the
//! same `Arc`, they immediately deliver to the restarted node — the mechanism
//! the restart-recovery test relies on. The lock is uncontended and never held
//! across an await, so it does not change the idealized-transport story.

use peregrine_consensus::Vertex;
use peregrine_core::{Hash, ValidatorId};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

/// A swappable delivery endpoint for one validator.
type Slot = Arc<Mutex<mpsc::UnboundedSender<NetMessage>>>;

/// Message on the wire. Serializable so it can be framed and shipped over
/// QUIC (see [`crate::quic`]) as well as handed across in-process channels.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetMessage {
    /// Normal DAG block dissemination.
    Vertex(Vertex),
    /// "I'm missing these vertices — please send any you have."
    SyncRequest { from: ValidatorId, want: Vec<Hash> },
    /// Response carrying the requested vertices we hold.
    SyncResponse { vertices: Vec<Vertex> },
}

/// Cloneable handle for broadcast and targeted send. `peers[i]` is the
/// (swappable) inbox of `ValidatorId(i)`.
#[derive(Clone)]
pub struct Broadcaster {
    peers: Vec<Slot>,
}

impl Broadcaster {
    /// Build a broadcaster from one outbound sender per validator (indexed by
    /// id). Transports that reconnect internally rather than by hot-swapping a
    /// slot — e.g. the QUIC layer, whose per-peer writer tasks redial on their
    /// own — construct their broadcaster this way. Each sender's far end is the
    /// peer's inbox (in-process) or that peer's outbound writer queue (QUIC).
    pub fn from_senders(senders: Vec<mpsc::UnboundedSender<NetMessage>>) -> Self {
        Self {
            peers: senders
                .into_iter()
                .map(|s| Arc::new(Mutex::new(s)))
                .collect(),
        }
    }

    /// Send to every node (including the sender — a node learns its own
    /// vertex through the same path as everyone else, keeping the loop
    /// uniform).
    pub async fn broadcast(&self, msg: NetMessage) {
        // Non-blocking send over an unbounded queue: an idealized reliable
        // transport never applies backpressure to the consensus loop. A
        // fully-connected mesh where every node both sends and receives can
        // otherwise deadlock — each node blocked awaiting a bounded `send`
        // to a peer that is itself blocked sending back — so delivery must
        // never make the sender wait. A closed peer (crashed) is a no-op.
        for peer in &self.peers {
            let _ = peer.lock().expect("peer slot poisoned").send(msg.clone());
        }
    }

    /// Send to a single validator (used for sync request/response). A closed
    /// or out-of-range peer is a no-op — that node has shut down.
    pub async fn send_to(&self, to: ValidatorId, msg: NetMessage) {
        if let Some(peer) = self.peers.get(to.0 as usize) {
            let _ = peer.lock().expect("peer slot poisoned").send(msg);
        }
    }
}

/// One node's receive side.
pub struct Inbox {
    pub id: ValidatorId,
    pub rx: mpsc::UnboundedReceiver<NetMessage>,
}

/// Owns the peer slots so nodes can be reconnected after a restart. Hand out
/// [`broadcaster`](Self::broadcaster) clones to every validator; keep the
/// `Network` itself to call [`reconnect`](Self::reconnect).
pub struct Network {
    peers: Vec<Slot>,
}

impl Network {
    /// A broadcaster wired to the current set of peer slots. Cheap to clone.
    pub fn broadcaster(&self) -> Broadcaster {
        Broadcaster {
            peers: self.peers.clone(),
        }
    }

    /// Install a fresh inbox for `id`, replacing whatever sender the slot held
    /// (typically a dead one from the killed instance). Returns the new
    /// [`Inbox`] for the restarted task. All existing broadcasters see the
    /// swap because they share the slot's `Arc`.
    pub fn reconnect(&self, id: ValidatorId) -> Inbox {
        let (tx, rx) = mpsc::unbounded_channel();
        *self.peers[id.0 as usize]
            .lock()
            .expect("peer slot poisoned") = tx;
        Inbox { id, rx }
    }
}

/// Build a fully-connected local network for `n` nodes, returning the
/// [`Network`] owner (for reconnects) alongside each node's [`Inbox`].
pub fn build_network(n: u16) -> (Network, Vec<Inbox>) {
    let mut inboxes = Vec::with_capacity(n as usize);
    let mut slots = Vec::with_capacity(n as usize);
    for i in 0..n {
        let (tx, rx) = mpsc::unbounded_channel();
        slots.push(Arc::new(Mutex::new(tx)));
        inboxes.push(Inbox {
            id: ValidatorId(i),
            rx,
        });
    }
    (Network { peers: slots }, inboxes)
}

/// Convenience for callers that never reconnect (the sim and the plain
/// crash-liveness test): build a network and discard the [`Network`] handle.
pub fn local_network(n: u16) -> (Vec<Inbox>, Broadcaster) {
    let (net, inboxes) = build_network(n);
    let broadcaster = net.broadcaster();
    (inboxes, broadcaster)
}
