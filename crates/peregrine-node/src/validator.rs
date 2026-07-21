//! The per-validator event loop for the local simulation.
//!
//! ```text
//!   inbox ─▶ buffer/insert into DAG ─▶ (fetch missing ancestors) ─▶ commit
//!         └▶ maybe propose next round ─────────────────────────────┘
//! ```
//!
//! Proposal is message-driven: once the DAG holds a stake quorum at round
//! `r`, propose our vertex for `r+1` referencing all known round-`r`
//! vertices. Rounds advance as fast as the network delivers — finality is a
//! function of RTT, not block time (the Stoop property).
//!
//! ## Ancestor fetch (sync)
//! Delivery may be out of order or lossy. When we receive a vertex whose
//! parents we don't yet hold, we (a) park it for reassembly and (b) send a
//! targeted [`NetMessage::SyncRequest`] to its author for the missing
//! hashes. Peers answer from their DAG with [`NetMessage::SyncResponse`];
//! delivered ancestors may unblock parked vertices and, if they in turn
//! have gaps, trigger a deeper fetch — each hash is requested at most once.

use crate::network::{Broadcaster, Inbox, NetMessage};
use crate::payload::WirePayload;
use crate::pipeline::ExecutionPipeline;
use crate::store::{DagSnapshot, StateSnapshot, Store};
use peregrine_consensus::{CommitObserver, Committer, Dag, DagError, Payload, PayloadItem, Vertex};
use peregrine_core::{Committee, Hash, Keypair, Round, ValidatorId};
use peregrine_data::tables::{ProvenRead, TableId};
use std::collections::{HashSet, VecDeque};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::Instant;

/// Max vertices returned in a single sync response (bounds fan-in).
const MAX_SYNC_BATCH: usize = 1024;

/// Bounded leader-wait: before advancing a round, wait at most this long for
/// the round's designated anchor to arrive. Short enough to be invisible on
/// a healthy network, long enough to absorb ordinary delivery jitter — so
/// honest anchors are almost never needlessly skipped. A crashed anchor
/// costs only this much extra latency before its round is skipped, which is
/// what keeps the protocol live. This is the steady-state half of the
/// skip/undecided cascade: the cascade guarantees liveness, the leader-wait
/// keeps the common case efficient.
const LEADER_WAIT: Duration = Duration::from_millis(4);

/// Persist at most once every this many commits (plus a guaranteed final flush
/// on shutdown). Each flush rewrites the whole snapshot, so flushing on *every*
/// commit is O(n²) over a run; batching keeps steady-state throughput high
/// while bounding how much a restart must re-sync from peers to a small commit
/// suffix. This is the "flush every N commits" durability/throughput knob.
const FLUSH_EVERY_N_COMMITS: u64 = 16;

/// What a validator task hands back when the simulation stops.
pub struct NodeReport {
    pub id: ValidatorId,
    pub pipeline: ExecutionPipeline,
    pub highest_round_proposed: Round,
    pub dag_size: usize,
    pub commits: u64,
    pub skips: u64,
    pub sync_requests_sent: u64,
}

/// Everything a validator task needs at spawn time.
pub struct ValidatorConfig {
    pub id: ValidatorId,
    pub keypair: Keypair,
    pub committee: Committee,
    pub inbox: Inbox,
    pub net: Broadcaster,
    pub ingest_rx: mpsc::Receiver<WirePayload>,
    pub shutdown: watch::Receiver<bool>,
    pub pipeline: ExecutionPipeline,
    pub max_items_per_vertex: usize,
    /// Optional persistence. `Some` → the node loads any prior snapshot on
    /// boot and flushes on commits; `None` → pure in-memory (the sim default).
    pub store: Option<Store>,
    /// Optional read-query channel, served from inside the loop so the pipeline
    /// keeps a single owner (no locks around committed state). `Some` when a
    /// client-facing [`crate::rpc`] server is attached; `None` otherwise.
    pub query_rx: Option<mpsc::Receiver<Query>>,
}

/// A read request served against this validator's committed state.
///
/// Answered *inside* the validator loop: the pipeline is owned exclusively by
/// the task, so queries are messages rather than shared-memory reads. Each
/// carries its own reply channel.
#[derive(Debug)]
pub enum Query {
    /// Value + inclusion proof for `key` in `table` (`None` if absent).
    ProveRead {
        table: TableId,
        key: Vec<u8>,
        reply: oneshot::Sender<Option<ProvenRead>>,
    },
    /// The current 32-byte store root.
    StoreRoot { reply: oneshot::Sender<Hash> },
}

/// Serve one query from the pipeline. A dropped receiver (client gone) is fine.
fn handle_query(q: Query, pipeline: &mut ExecutionPipeline) {
    match q {
        Query::ProveRead { table, key, reply } => {
            let _ = reply.send(pipeline.prove_read(table, &key));
        }
        Query::StoreRoot { reply } => {
            let _ = reply.send(pipeline.store_root());
        }
    }
}

/// Receive from an optional query channel; parks forever when unattached so it
/// can sit in `select!` as an inert arm (same idiom as `wait_until`).
async fn recv_query(rx: &mut Option<mpsc::Receiver<Query>>) -> Option<Query> {
    match rx {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

/// Run the validator until shutdown; returns the final report.
pub async fn run_validator(mut cfg: ValidatorConfig) -> NodeReport {
    let mut committer = Committer::new();
    let mut pipeline = cfg.pipeline;

    // Reassembly buffer for vertices whose parents haven't arrived.
    let mut pending: VecDeque<Vertex> = VecDeque::new();
    // Hashes already requested via sync (dedup; each fetched at most once).
    let mut requested: HashSet<Hash> = HashSet::new();
    // Client payload waiting for the next proposal slot.
    let mut ingest_buf: VecDeque<WirePayload> = VecDeque::new();
    let mut sync_requests_sent = 0u64;
    // Commit count at the last durable flush, for the every-N-commits policy.
    let mut commits_at_last_flush = 0u64;
    // When Some((r, deadline)), we hold proposal until `deadline` waiting for
    // the anchor of round `r` to arrive (bounded leader-wait). Keying it to the
    // round keeps a "still gathering quorum" pause from being confused with —
    // or clobbering — an active anchor-wait for a different round. None = not
    // waiting.
    let mut leader_wait: Option<(Round, Instant)> = None;

    // ── Load-or-init ────────────────────────────────────────────────────
    // If a snapshot exists on disk, rebuild the DAG and materialized state
    // from it and resume; otherwise start from a fresh genesis.
    let restored = match &cfg.store {
        Some(s) => s.restore().unwrap_or_else(|e| {
            tracing::error!(id = ?cfg.id, "restore failed, starting fresh: {e}");
            None
        }),
        None => None,
    };

    let mut dag: Dag;
    let mut next_round_to_propose: Round;

    match restored {
        Some((dag_snap, state_snap)) => {
            // Materialized state: rebuild from rows (SMT + roots recomputed).
            pipeline.tables = state_snap.into_store();

            // Resume proposing just past our own highest previously-proposed
            // round. A clean shutdown always flushes last (see end of loop), so
            // a gracefully-stopped node's restored DAG contains its latest
            // proposal and it never re-issues a round peers already saw. After
            // an *ungraceful* crash the resume point may trail the last few
            // broadcasts by up to N commits; those rounds are re-synced from
            // peers, and self-equivocation on them is the one bootstrap gap a
            // production node closes with a cheap per-proposal round watermark.
            let my_max = dag_snap
                .vertices
                .iter()
                .filter(|v| v.header.author == cfg.id)
                .map(|v| v.header.round)
                .max();

            dag = rebuild_dag(cfg.committee.clone(), dag_snap.vertices);

            // Re-derive the commit cursor by replaying the (deterministic)
            // commit rule over the restored DAG with a no-op observer. This
            // reconstructs the exact `(next_anchor_round, committed)` that
            // produced the persisted tables *without* re-applying any payload
            // — the atomic snapshot guarantees tables already reflect it.
            committer.try_commit(&dag, &mut NullObserver);

            match my_max {
                Some(r) => {
                    next_round_to_propose = r + 1;
                    tracing::info!(
                        id = ?cfg.id,
                        resume_round = next_round_to_propose,
                        dag = dag.len(),
                        commits = committer.commits,
                        "restored from disk"
                    );
                }
                // Snapshot held no vertex of ours (degenerate) — propose genesis.
                None => {
                    let genesis =
                        Vertex::new_signed(&cfg.keypair, cfg.id, 0, vec![], Payload::default());
                    buffer_insert(&mut dag, &mut pending, genesis.clone());
                    flush(&cfg.store, &dag, &pipeline); // durable before broadcast
                    cfg.net.broadcast(NetMessage::Vertex(genesis)).await;
                    next_round_to_propose = 1;
                }
            }
        }
        None => {
            // Fresh boot. Round 0: parentless genesis, self-inserted and made
            // durable *before* broadcast, so a crash right after boot can never
            // resurrect as a second, different genesis (self-equivocation).
            dag = Dag::new(cfg.committee.clone(), vec![]);
            let genesis = Vertex::new_signed(&cfg.keypair, cfg.id, 0, vec![], Payload::default());
            buffer_insert(&mut dag, &mut pending, genesis.clone());
            flush(&cfg.store, &dag, &pipeline);
            cfg.net.broadcast(NetMessage::Vertex(genesis)).await;
            next_round_to_propose = 1;
        }
    }

    // Reused scratch buffer for messages drained each wake.
    let mut msg_buf: Vec<NetMessage> = Vec::new();

    // Liveness backstop. Round advancement is normally driven by inbound
    // vertices and by the tight leader-wait deadline below; this slow tick is
    // a safety net so the loop can re-drive commit/propose even in the rare
    // case where neither fires (e.g. every survivor is idle at exact quorum
    // waiting on the others). Deliberately coarse so it never busy-spins — the
    // fast paths, not this, set steady-state latency.
    let mut pacemaker = tokio::time::interval(Duration::from_millis(100));
    pacemaker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            biased;

            _ = cfg.shutdown.changed() => {
                if *cfg.shutdown.borrow() { break; }
            }

            // Leader-wait expiry: wake exactly at the active anchor-wait
            // deadline to re-evaluate proposal, so a crashed anchor is skipped
            // after only LEADER_WAIT rather than a full pacemaker period.
            // Inert (never fires) when we are not waiting.
            _ = wait_until(leader_wait) => {}

            // Coarse liveness backstop (see above).
            _ = pacemaker.tick() => {}

            maybe = cfg.inbox.rx.recv() => {
                match maybe {
                    Some(m) => msg_buf.push(m),
                    None => break, // all senders gone
                }
            }

            maybe = cfg.ingest_rx.recv() => {
                if let Some(item) = maybe { ingest_buf.push_back(item); }
            }

            // Client reads (proven reads / store root), served against the
            // pipeline we exclusively own. Inert when no RPC server is attached.
            maybe = recv_query(&mut cfg.query_rx) => {
                if let Some(q) = maybe { handle_query(q, &mut pipeline); }
            }
        }

        // Drain any other queued queries so a burst of client reads is served
        // in this wake rather than one per loop iteration.
        if let Some(rx) = cfg.query_rx.as_mut() {
            while let Ok(q) = rx.try_recv() {
                handle_query(q, &mut pipeline);
            }
        }

        // Drain everything queued so no message sits unprocessed while we
        // block on the next await. Processing one message per wake starves
        // the DAG under bursty delivery and, at exact quorum, can wedge the
        // round frontier — every queued vertex must be applied before we
        // decide whether we can propose.
        while let Ok(m) = cfg.inbox.rx.try_recv() {
            msg_buf.push(m);
        }
        while let Ok(more) = cfg.ingest_rx.try_recv() {
            ingest_buf.push_back(more);
        }

        // Apply all drained network messages, then commit once.
        let mut got_vertices = false;
        for m in msg_buf.drain(..) {
            match m {
                NetMessage::Vertex(v) => {
                    if let Some((author, missing)) = buffer_insert(&mut dag, &mut pending, v) {
                        sync_requests_sent +=
                            request_missing(&cfg.net, cfg.id, author, missing, &mut requested)
                                .await;
                    }
                    got_vertices = true;
                }
                NetMessage::SyncRequest { from, want } => {
                    // Answer from our DAG with whatever ancestors we hold.
                    let vertices: Vec<Vertex> = want
                        .iter()
                        .filter_map(|h| dag.get(h).cloned())
                        .take(MAX_SYNC_BATCH)
                        .collect();
                    if !vertices.is_empty() {
                        cfg.net
                            .send_to(from, NetMessage::SyncResponse { vertices })
                            .await;
                    }
                }
                NetMessage::SyncResponse { vertices } => {
                    for v in vertices {
                        if let Some((author, missing)) = buffer_insert(&mut dag, &mut pending, v) {
                            sync_requests_sent +=
                                request_missing(&cfg.net, cfg.id, author, missing, &mut requested)
                                    .await;
                        }
                    }
                    got_vertices = true;
                }
            }
        }
        if got_vertices {
            committer.try_commit(&dag, &mut pipeline);
        }

        // Propose while the previous round has quorum stake — but prefer to
        // include the previous round's anchor so we don't needlessly skip an
        // honest leader (see LEADER_WAIT).
        loop {
            let prev = next_round_to_propose - 1;
            if dag.round_stake(prev) < dag.committee().quorum_threshold() {
                // Not enough of round `prev` to build on yet — this is a
                // quorum wait, not a leader wait, so leave any active
                // anchor-wait (for this or a later round) untouched.
                break;
            }

            // Do we already hold the anchor of the round we'd build on?
            let anchor = Committer::anchor_for_round(&dag, prev);
            let anchor_present = prev == 0
                || dag
                    .round_vertices(prev)
                    .map(|m| m.contains_key(&anchor))
                    .unwrap_or(false);

            if !anchor_present {
                match leader_wait {
                    // Already waiting for THIS round's anchor.
                    Some((r, deadline)) if r == prev => {
                        if Instant::now() < deadline {
                            break; // keep waiting
                        }
                        // deadline passed — proceed without the anchor
                    }
                    // Not yet waiting for this round (None, or a stale wait
                    // that referred to a different round) — arm it.
                    _ => {
                        leader_wait = Some((prev, Instant::now() + LEADER_WAIT));
                        break;
                    }
                }
            }
            leader_wait = None;

            let parents: Vec<Hash> = dag
                .round_vertices(prev)
                .map(|m| m.values().copied().collect())
                .unwrap_or_default();

            let take = ingest_buf.len().min(cfg.max_items_per_vertex);
            let items: Vec<PayloadItem> = ingest_buf
                .drain(..take)
                .map(|p| PayloadItem(p.encode()))
                .collect();

            let vertex = Vertex::new_signed(
                &cfg.keypair,
                cfg.id,
                next_round_to_propose,
                parents,
                Payload { items },
            );
            next_round_to_propose += 1;

            // SELF-PARENT INVARIANT: insert our own vertex synchronously
            // before broadcasting, so the next round we build always links
            // our previous vertex (an uncertified DAG never links back to an
            // unreferenced vertex, which would orphan its payload forever).
            buffer_insert(&mut dag, &mut pending, vertex.clone());
            committer.try_commit(&dag, &mut pipeline);
            cfg.net.broadcast(NetMessage::Vertex(vertex)).await;
        }

        // Periodic durability: persist once the commit cursor has advanced by
        // N since the last flush. The snapshot is taken at a commit-consistent
        // point (after `try_commit` ran to a fixpoint above), so the persisted
        // DAG and tables always agree on "committed through anchor K".
        if committer.commits.saturating_sub(commits_at_last_flush) >= FLUSH_EVERY_N_COMMITS {
            flush(&cfg.store, &dag, &pipeline);
            commits_at_last_flush = committer.commits;
        }
    }

    // Final flush so the last committed state — and our latest self-proposal —
    // is durable on a clean shutdown. This is what lets a gracefully-stopped
    // node resume at exactly `highest_own_round + 1` with no re-proposal.
    flush(&cfg.store, &dag, &pipeline);

    NodeReport {
        id: cfg.id,
        pipeline,
        highest_round_proposed: next_round_to_propose.saturating_sub(1),
        dag_size: dag.len(),
        commits: committer.commits,
        skips: committer.skips,
        sync_requests_sent,
    }
}

/// Atomically persist the current DAG + materialized state, if this node has
/// a store. A no-op for in-memory nodes. Errors are logged, never fatal —
/// losing a flush costs at most a re-sync, never correctness.
fn flush(store: &Option<Store>, dag: &Dag, pipeline: &ExecutionPipeline) {
    let Some(store) = store else { return };
    let dag_snap = DagSnapshot {
        vertices: dag.all_vertices(),
    };
    let state_snap = StateSnapshot::from_store(&pipeline.tables);
    // The redb commit fsyncs — a blocking syscall. `block_in_place` hands our
    // other-task work to sibling workers for the duration, so a flush never
    // stalls message delivery or a peer's catch-up sync on the shared runtime.
    let res = tokio::task::block_in_place(|| store.snapshot(&dag_snap, &state_snap));
    if let Err(e) = res {
        tracing::error!("snapshot flush failed: {e}");
    }
}

/// Rebuild a DAG from persisted vertices by re-inserting them in round order,
/// so every vertex's parents already exist when it is validated. Insertion
/// re-runs full validation, so a tampered vertex cannot enter on reload.
fn rebuild_dag(committee: Committee, mut vertices: Vec<Vertex>) -> Dag {
    vertices.sort_by_key(|v| v.header.round);
    let mut dag = Dag::new(committee, vec![]);
    for v in vertices {
        if let Err(e) = dag.insert(v) {
            // A persisted vertex that fails re-validation should be impossible
            // (it passed on first insert); skip it rather than abort recovery.
            tracing::warn!("skipping vertex during DAG rebuild: {e}");
        }
    }
    dag
}

/// Discards every commit callback. Used only to fast-forward a fresh
/// `Committer` over a restored DAG so its cursor matches the already-persisted
/// table state, without re-applying (and thus double-counting) any payload.
struct NullObserver;

impl CommitObserver for NullObserver {
    fn on_commit(&mut self, _round: Round, _anchor: Hash, _ordered: &[Hash], _dag: &Dag) {}
}

/// Insert a vertex, retrying parked vertices to a fixpoint. If the vertex
/// can't be inserted because parents are missing, park it and return its
/// `(author, missing_parent_hashes)` so the caller can fetch them.
fn buffer_insert(
    dag: &mut Dag,
    pending: &mut VecDeque<Vertex>,
    v: Vertex,
) -> Option<(ValidatorId, Vec<Hash>)> {
    match dag.insert(v.clone()) {
        Ok(_) => {
            // Progress may unblock parked vertices; retry until fixpoint.
            let mut made_progress = true;
            while made_progress {
                made_progress = false;
                let n = pending.len();
                for _ in 0..n {
                    let Some(p) = pending.pop_front() else { break };
                    match dag.insert(p.clone()) {
                        Ok(_) => made_progress = true,
                        Err(DagError::MissingParent(..)) => pending.push_back(p),
                        Err(e) => tracing::warn!("dropping parked vertex: {e}"),
                    }
                }
            }
            None
        }
        Err(DagError::MissingParent(..)) => {
            let missing = dag.missing_parents(&v);
            let author = v.header.author;
            pending.push_back(v);
            Some((author, missing))
        }
        Err(e) => {
            tracing::warn!("rejecting vertex: {e}");
            None
        }
    }
}

/// A future that resolves at the leader-wait deadline, or never if `None`.
/// Lets the select arm stay inert while we are not in a leader-wait.
async fn wait_until(deadline: Option<(Round, Instant)>) {
    match deadline {
        Some((_, d)) => tokio::time::sleep_until(d).await,
        None => std::future::pending::<()>().await,
    }
}

/// Send a sync request for parent hashes we haven't requested before.
/// Returns 1 if a request was sent, 0 otherwise (for metrics).
async fn request_missing(
    net: &Broadcaster,
    me: ValidatorId,
    author: ValidatorId,
    missing: Vec<Hash>,
    requested: &mut HashSet<Hash>,
) -> u64 {
    let want: Vec<Hash> = missing
        .into_iter()
        .filter(|h| requested.insert(*h))
        .collect();
    if want.is_empty() {
        return 0;
    }
    net.send_to(author, NetMessage::SyncRequest { from: me, want })
        .await;
    1
}
