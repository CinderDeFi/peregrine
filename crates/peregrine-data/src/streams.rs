//! Streams: protocol-level pub/sub (design doc §4.5a).
//!
//! Lifecycle:
//! 1. A publisher registers a stream (bonded in production; open in dev)
//!    and signs [`StreamRecord`]s at high frequency.
//! 2. Records are encoded as [`StreamShred`]s and placed **directly into
//!    consensus vertex payloads** — data rides DAG dissemination; there is
//!    no "oracle transaction".
//! 3. On commit, the node's data pipeline calls
//!    [`StreamRegistry::apply_committed`], which validates the publisher
//!    signature + sequencing and fans out to subscribers.
//!
//! The registry is deliberately sync-and-pure except for the tokio
//! broadcast used for subscriber fan-out, keeping it embeddable in both
//! the simulated node and the future tile pipeline.

use peregrine_core::{crypto, Hash, Keypair, PublicKey, Signature, StreamSeq};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::broadcast;

pub const STREAM_DOMAIN: &[u8] = b"peregrine.slipstream.record.v1";

/// Stream identity = hash of (name, publisher key). Stable, collision-free.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct StreamId(pub Hash);

impl StreamId {
    pub fn derive(name: &str, publisher: &PublicKey) -> Self {
        let mut bytes = Vec::with_capacity(name.len() + 32);
        bytes.extend_from_slice(name.as_bytes());
        bytes.extend_from_slice(&publisher.0);
        StreamId(Hash::digest(&bytes))
    }
}

impl std::fmt::Debug for StreamId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "strm:{}", self.0.short())
    }
}

/// One data point. `payload` is schema-opaque here; typed columnar schemas
/// arrive with the Tables integration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StreamRecord {
    pub stream: StreamId,
    /// Publisher-assigned sequence number (monotonic per stream).
    pub seq: StreamSeq,
    /// Advisory publish timestamp (ns). Authoritative time = commit order.
    pub timestamp_ns: u64,
    pub payload: Vec<u8>,
}

impl StreamRecord {
    fn signing_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("record serialize")
    }
}

/// A signed record as it travels inside a consensus vertex payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StreamShred {
    pub record: StreamRecord,
    pub signature: Signature,
}

impl StreamShred {
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("shred serialize")
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, StreamError> {
        bincode::deserialize(bytes).map_err(|e| StreamError::Codec(e.to_string()))
    }
}

/// Publisher handle: owns the signing key and the sequence counter.
pub struct Publisher {
    keypair: Keypair,
    stream: StreamId,
    next_seq: StreamSeq,
}

impl Publisher {
    pub fn new(name: &str, keypair: Keypair) -> Self {
        let stream = StreamId::derive(name, &keypair.public());
        Self {
            keypair,
            stream,
            next_seq: 0,
        }
    }

    pub fn stream_id(&self) -> StreamId {
        self.stream
    }

    pub fn public_key(&self) -> PublicKey {
        self.keypair.public()
    }

    /// Sign the next record. This is the entire hot path of an oracle /
    /// sensor gateway: build, sign, hand to the node's ingest queue.
    pub fn emit(&mut self, payload: Vec<u8>) -> StreamShred {
        let record = StreamRecord {
            stream: self.stream,
            seq: self.next_seq,
            timestamp_ns: now_ns(),
            payload,
        };
        self.next_seq += 1;
        let signature = self.keypair.sign(STREAM_DOMAIN, &record.signing_bytes());
        StreamShred { record, signature }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StreamError {
    #[error("unknown stream {0:?}")]
    UnknownStream(StreamId),
    #[error("bad publisher signature on {0:?} seq {1}")]
    BadSignature(StreamId, StreamSeq),
    #[error("stale or duplicate seq {got} (expected >= {expected}) on {stream:?}")]
    StaleSeq {
        stream: StreamId,
        got: StreamSeq,
        expected: StreamSeq,
    },
    #[error("codec error: {0}")]
    Codec(String),
}

/// Per-stream committed state.
struct StreamState {
    publisher_key: PublicKey,
    name: String,
    /// Next expected sequence number.
    next_seq: StreamSeq,
    /// Total committed records (metrics / fee accounting).
    committed_records: u64,
    committed_bytes: u64,
    /// Fan-out channel to subscribers. Lossy by design under lag —
    /// subscribers needing history read Tables/blobs instead.
    tx: broadcast::Sender<StreamRecord>,
}

/// Subscription handle returned to consumers.
pub struct SubscriberHandle {
    pub rx: broadcast::Receiver<StreamRecord>,
}

/// The node-side stream registry: registration, committed-record
/// validation, and subscriber fan-out.
pub struct StreamRegistry {
    streams: HashMap<StreamId, StreamState>,
}

impl StreamRegistry {
    pub fn new() -> Self {
        Self {
            streams: HashMap::new(),
        }
    }

    /// Register a stream (dev-mode: permissionless; production: bonded
    /// publisher slots with data-quality slashing).
    pub fn register(&mut self, name: &str, publisher_key: PublicKey) -> StreamId {
        let id = StreamId::derive(name, &publisher_key);
        self.streams.entry(id).or_insert_with(|| StreamState {
            publisher_key,
            name: name.to_string(),
            next_seq: 0,
            committed_records: 0,
            committed_bytes: 0,
            tx: broadcast::channel(4096).0,
        });
        id
    }

    pub fn subscribe(&self, id: &StreamId) -> Result<SubscriberHandle, StreamError> {
        let st = self
            .streams
            .get(id)
            .ok_or(StreamError::UnknownStream(*id))?;
        Ok(SubscriberHandle {
            rx: st.tx.subscribe(),
        })
    }

    /// Apply a shred that consensus has committed. Validates signature and
    /// per-stream monotonic sequencing, updates metrics, fans out.
    ///
    /// Returns the record's byte size for data-meter accounting.
    pub fn apply_committed(&mut self, shred: &StreamShred) -> Result<u64, StreamError> {
        // Verify inline. The signature is a pure predicate over the shred, so
        // this is exactly `apply_committed_with` given a locally-computed
        // verdict — see there for why the split exists.
        let ok = match self.streams.get(&shred.record.stream) {
            Some(st) => crypto::verify(
                &st.publisher_key,
                STREAM_DOMAIN,
                &shred.record.signing_bytes(),
                &shred.signature,
            )
            .is_ok(),
            None => false,
        };
        self.apply_committed_with(shred, ok)
    }

    /// The public key a shred's signature must verify against, if its stream is
    /// known. Lets a caller batch the (expensive, pure) signature checks across
    /// tiles before entering the serial apply loop.
    pub fn publisher_key_for(&self, shred: &StreamShred) -> Option<PublicKey> {
        self.streams
            .get(&shred.record.stream)
            .map(|s| s.publisher_key)
    }

    /// The exact bytes a shred's signature covers.
    pub fn signing_bytes_of(shred: &StreamShred) -> Vec<u8> {
        shred.record.signing_bytes()
    }

    /// Apply a committed shred, trusting a **precomputed** signature verdict.
    ///
    /// # Why this exists
    ///
    /// Signature verification is ~25 µs and is a pure function of the shred;
    /// everything else here mutates registry state and must stay serial and
    /// ordered. Splitting them lets the verification run across tiles while
    /// this stage keeps its single owner.
    ///
    /// # Determinism
    ///
    /// `sig_verified` must be the result of checking this shred's signature
    /// against the key `publisher_key_for` returns — nothing else. Given that,
    /// the outcome is identical to `apply_committed`, because the predicate is
    /// the same one, merely computed earlier and elsewhere. **Passing an
    /// unchecked `true` would let unsigned data into committed state**, so this
    /// takes a verdict rather than a "skip verification" flag: there is no way
    /// to call it that reads as "don't bother".
    pub fn apply_committed_with(
        &mut self,
        shred: &StreamShred,
        sig_verified: bool,
    ) -> Result<u64, StreamError> {
        let id = shred.record.stream;
        let st = self
            .streams
            .get_mut(&id)
            .ok_or(StreamError::UnknownStream(id))?;

        if !sig_verified {
            return Err(StreamError::BadSignature(id, shred.record.seq));
        }

        if shred.record.seq < st.next_seq {
            return Err(StreamError::StaleSeq {
                stream: id,
                got: shred.record.seq,
                expected: st.next_seq,
            });
        }
        st.next_seq = shred.record.seq + 1;
        st.committed_records += 1;
        let bytes = shred.record.payload.len() as u64;
        st.committed_bytes += bytes;

        // Fan out; a full channel only means slow subscribers lag (lossy).
        let _ = st.tx.send(shred.record.clone());
        Ok(bytes)
    }

    pub fn stats(&self, id: &StreamId) -> Option<(String, u64, u64)> {
        self.streams
            .get(id)
            .map(|s| (s.name.clone(), s.committed_records, s.committed_bytes))
    }
}

impl Default for StreamRegistry {
    fn default() -> Self {
        Self::new()
    }
}

fn now_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}
