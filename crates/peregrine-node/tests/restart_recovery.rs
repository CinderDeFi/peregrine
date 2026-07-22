//! End-to-end restart recovery.
//!
//! Spins up a 4-validator network with on-disk persistence, lets it commit a
//! batch of stream ticks, then **kills one validator** (graceful shutdown → it
//! flushes its final snapshot). The remaining three keep committing more ticks
//! while it is down. The killed validator is then **restarted from disk**: it
//! reloads its DAG and materialized table state, re-derives its commit cursor,
//! reconnects to the still-running network, re-syncs the vertices it missed,
//! and rejoins.
//!
//! After the network quiesces we assert:
//!   1. every validator — including the restarted one — converges to the exact
//!      same non-empty store root (no fork, full recovery of pre-crash state);
//!   2. the restarted node committed *after* it came back (it actively rejoined
//!      rather than sitting frozen on its restored prefix);
//!   3. a Talon VM write made before the crash survives and still verifies.
//!
//! # Why this test waits on conditions, not clocks
//!
//! An earlier version drove every phase with a fixed `sleep` and asserted
//! afterwards. It passed alone and failed roughly one run in six under full
//! CPU load, reporting `v2 diverged after restart` — which reads like a
//! consensus fork but was really the restarted node still catching up when the
//! test pulled the plug. A sleep encodes a guess about how fast the machine is,
//! and a loaded CI box is not the machine the guess was made on.
//!
//! So every phase now polls each validator's committed state over its
//! [`Query`] channel — the same interface the RPC server uses — and proceeds
//! the moment the real condition holds. Timeouts stay generous because they are
//! only reached when something is genuinely wrong, and on timeout the failure
//! prints every node's root so *lag* and a genuine *fork* are distinguishable
//! at a glance rather than by rerunning.

use peregrine_core::{Committee, Hash, Keypair, PublicKey, ValidatorId, ValidatorInfo};
use peregrine_data::streams::Publisher;
use peregrine_data::tables::TableId;
use peregrine_node::network::{build_network, Broadcaster, Inbox};
use peregrine_node::payload::WirePayload;
use peregrine_node::pipeline::ExecutionPipeline;
use peregrine_node::store::Store;
use peregrine_node::validator::{run_validator, NodeReport, Query, ValidatorConfig};
use peregrine_vm::Instr;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;

const N: u16 = 4;
const RESTART: u16 = 2; // validator we kill and bring back

/// How long any single condition may take before the test fails.
///
/// Deliberately far longer than the operation needs on an idle machine. This is
/// not a performance assertion — it is the point at which we stop believing the
/// system is merely slow. Overshooting costs nothing on a healthy run because
/// the polls exit as soon as the condition holds.
const CONDITION_TIMEOUT: Duration = Duration::from_secs(90);
/// Gap between polls. Short enough to keep a healthy run brisk, long enough not
/// to add meaningful load to the thing being measured.
const POLL_INTERVAL: Duration = Duration::from_millis(25);

/// One validator's handles, so a phase can talk to it while it runs.
struct Node {
    shutdown: watch::Sender<bool>,
    query: mpsc::Sender<Query>,
    handle: Option<JoinHandle<NodeReport>>,
}

/// Build a validator task with persistence and a query channel.
#[allow(clippy::too_many_arguments)]
fn spawn(
    id: u16,
    keypair: Keypair,
    committee: Committee,
    inbox: Inbox,
    net: Broadcaster,
    ingest_rx: mpsc::Receiver<WirePayload>,
    shutdown: watch::Receiver<bool>,
    publisher_pk: PublicKey,
    store: Store,
    query_rx: mpsc::Receiver<Query>,
) -> JoinHandle<NodeReport> {
    let mut pipeline = ExecutionPipeline::new();
    pipeline.streams.register("test/feed", publisher_pk);
    tokio::spawn(run_validator(ValidatorConfig {
        id: ValidatorId(id),
        keypair,
        committee,
        inbox,
        net,
        ingest_rx,
        shutdown,
        pipeline,
        max_items_per_vertex: 64,
        store: Some(store),
        query_rx: Some(query_rx),
    }))
}

/// Ask a running validator for its current store root.
///
/// `None` means the validator did not answer — it is shutting down, or its
/// loop is wedged. Callers treat that as "condition not yet met" rather than
/// as an error, so a node that is briefly busy does not fail the test.
async fn store_root(q: &mpsc::Sender<Query>) -> Option<Hash> {
    let (tx, rx) = oneshot::channel();
    q.send(Query::StoreRoot { reply: tx }).await.ok()?;
    tokio::time::timeout(Duration::from_secs(5), rx)
        .await
        .ok()?
        .ok()
}

/// Ask a running validator whether `key` is present in `table`.
async fn has_key(q: &mpsc::Sender<Query>, table: TableId, key: &[u8]) -> bool {
    let (tx, rx) = oneshot::channel();
    if q.send(Query::ProveRead {
        table,
        key: key.to_vec(),
        reply: tx,
    })
    .await
    .is_err()
    {
        return false;
    }
    matches!(
        tokio::time::timeout(Duration::from_secs(5), rx).await,
        Ok(Ok(Some(_)))
    )
}

/// Poll `cond` until it returns true, or fail with `what` after the timeout.
async fn wait_for<F, Fut>(what: &str, mut cond: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = Instant::now() + CONDITION_TIMEOUT;
    while Instant::now() < deadline {
        if cond().await {
            return;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    panic!("timed out after {CONDITION_TIMEOUT:?} waiting for: {what}");
}

/// Collect every live validator's root, for convergence checks and diagnostics.
async fn roots(nodes: &[Node]) -> Vec<(ValidatorId, Option<Hash>)> {
    let mut out = Vec::with_capacity(nodes.len());
    for (i, n) in nodes.iter().enumerate() {
        out.push((ValidatorId(i as u16), store_root(&n.query).await));
    }
    out
}

/// A one-line summary of where every node is, for failure messages.
fn describe(rs: &[(ValidatorId, Option<Hash>)]) -> String {
    rs.iter()
        .map(|(id, r)| match r {
            Some(h) => format!("{id:?}={}", h.short()),
            None => format!("{id:?}=<no answer>"),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn crashed_validator_recovers_from_disk() {
    let mut rng = rand::rngs::OsRng;

    // Keep each validator's secret seed so the restarted node can reload the
    // *same* identity from "disk".
    let secrets: Vec<[u8; 32]> = (0..N)
        .map(|_| Keypair::generate(&mut rng).to_bytes())
        .collect();
    let committee = Committee::new(
        secrets
            .iter()
            .enumerate()
            .map(|(i, s)| ValidatorInfo {
                id: ValidatorId(i as u16),
                public_key: Keypair::from_bytes(s).public(),
                stake: 100,
            })
            .collect(),
    );

    // Per-validator store files in a unique scratch dir.
    let base = std::env::temp_dir().join(format!("peregrine-restart-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&base);
    let store_path = |id: u16| -> PathBuf { base.join(format!("v{id}.redb")) };
    for id in 0..N {
        let _ = std::fs::remove_file(store_path(id));
    }

    let (net, inboxes) = build_network(N);
    let bcast = net.broadcaster();

    let mut publisher = Publisher::new("test/feed", Keypair::generate(&mut rng));
    let publisher_pk = publisher.public_key();

    let mut nodes: Vec<Node> = Vec::new();
    let mut ingest_txs: Vec<mpsc::Sender<WirePayload>> = Vec::new();

    for inbox in inboxes.into_iter() {
        let id = inbox.id.0;
        let (stx, srx) = watch::channel(false);
        let (itx, irx) = mpsc::channel(4096);
        let (qtx, qrx) = mpsc::channel::<Query>(256);
        let store = Store::open(store_path(id)).expect("open store");
        let keypair = Keypair::from_bytes(&secrets[id as usize]);
        nodes.push(Node {
            shutdown: stx,
            query: qtx,
            handle: Some(spawn(
                id,
                keypair,
                committee.clone(),
                inbox,
                bcast.clone(),
                irx,
                srx,
                publisher_pk,
                store,
                qrx,
            )),
        });
        ingest_txs.push(itx);
    }

    // ── Phase 1: commit a batch, including a Talon VM write ─────────────────
    for _ in 0..200 {
        let shred = publisher.emit(1111u64.to_le_bytes().to_vec());
        ingest_txs[0].send(WirePayload::Shred(shred)).await.unwrap();
    }
    // 20 + 22 = 42, written *before* the crash, so recovery must reconstruct it
    // from persisted state rather than by re-running the program.
    let vm_table = TableId::named("recovery.vm");
    ingest_txs[0]
        .send(WirePayload::TalonTx {
            program: vec![
                Instr::Push(20),
                Instr::Push(22),
                Instr::Add,
                Instr::StoreTable {
                    table: vm_table,
                    key: b"answer".to_vec(),
                },
                Instr::Halt,
            ],
        })
        .await
        .unwrap();

    // Wait for the node we are about to kill to have actually committed the VM
    // write. This is the precise precondition the rest of the test depends on;
    // a sleep here could kill it a millisecond too early and turn a passing run
    // into "the write vanished".
    wait_for(
        "the doomed validator to commit the pre-crash VM write",
        || has_key(&nodes[RESTART as usize].query, vm_table, b"answer"),
    )
    .await;

    let pre_crash_root = store_root(&nodes[RESTART as usize].query)
        .await
        .expect("doomed validator answers before shutdown");

    // ── Phase 2: kill RESTART. Graceful shutdown → final flush, store dropped.
    nodes[RESTART as usize].shutdown.send(true).unwrap();
    let pre_restart = nodes[RESTART as usize]
        .handle
        .take()
        .unwrap()
        .await
        .unwrap();
    assert!(
        pre_restart.commits > 0,
        "validator committed before the crash"
    );

    // ── Phase 3: the survivors make progress while RESTART is down ──────────
    for _ in 0..150 {
        let shred = publisher.emit(2222u64.to_le_bytes().to_vec());
        ingest_txs[0].send(WirePayload::Shred(shred)).await.unwrap();
    }
    // There must be a real gap for the restarted node to re-sync, otherwise the
    // test would pass without ever exercising catch-up. Waiting for a survivor
    // to move *past* the pre-crash root proves the gap exists.
    wait_for(
        "the survivors to advance past the pre-crash root",
        || async { matches!(store_root(&nodes[0].query).await, Some(r) if r != pre_crash_root) },
    )
    .await;

    // ── Phase 4: restart RESTART from disk, reconnect to the live network ────
    let inbox2 = net.reconnect(ValidatorId(RESTART));
    let (stx2, srx2) = watch::channel(false);
    let (_itx2, irx2) = mpsc::channel(4096);
    let (qtx2, qrx2) = mpsc::channel::<Query>(256);
    let store2 = Store::open(store_path(RESTART)).expect("reopen store");
    let keypair2 = Keypair::from_bytes(&secrets[RESTART as usize]);
    nodes[RESTART as usize] = Node {
        shutdown: stx2,
        query: qtx2,
        handle: Some(spawn(
            RESTART,
            keypair2,
            committee.clone(),
            inbox2,
            bcast.clone(),
            irx2,
            srx2,
            publisher_pk,
            store2,
            qrx2,
        )),
    };

    // ── Phase 5: more input, then wait for genuine convergence ──────────────
    for _ in 0..150 {
        let shred = publisher.emit(3333u64.to_le_bytes().to_vec());
        ingest_txs[0].send(WirePayload::Shred(shred)).await.unwrap();
    }
    // Stop feeding: with no new input the frontier stabilises. Empty rounds keep
    // being proposed, which keeps driving the restarted node's catch-up sync.
    drop(ingest_txs);

    // **The fix.** Poll until all four nodes report the same non-zero root,
    // rather than sleeping and hoping. A node that is merely behind converges
    // and the test proceeds immediately; a node that has genuinely forked never
    // converges and the timeout prints every root.
    wait_for(
        "all four validators to converge on one store root",
        || async {
            let rs = roots(&nodes).await;
            let Some(Some(first)) = rs.first().map(|(_, r)| *r) else {
                return false;
            };
            first != Hash::ZERO && rs.iter().all(|(_, r)| *r == Some(first))
        },
    )
    .await;

    // Snapshot the agreed root while everyone is still alive, so the assertions
    // below are checked against a state we *observed* converged rather than one
    // we hope survived shutdown.
    let converged = roots(&nodes).await;
    let agreed = converged[0].1.expect("converged root");

    // ── Shut down and collect final reports ─────────────────────────────────
    for n in &nodes {
        let _ = n.shutdown.send(true);
    }
    let mut reports: Vec<NodeReport> = Vec::new();
    for n in nodes.iter_mut() {
        if let Some(h) = n.handle.take() {
            reports.push(h.await.unwrap());
        }
    }
    assert_eq!(reports.len(), N as usize, "all four validators reported");

    // (1) The convergence we observed is the state each node shut down with.
    //     Re-checking post-shutdown catches a node that regressed on its way
    //     out — e.g. a final flush that lost committed work.
    let final_roots: Vec<(ValidatorId, Hash)> = reports
        .iter_mut()
        .map(|r| (r.id, r.pipeline.store_root()))
        .collect();
    assert_ne!(agreed, Hash::ZERO, "committed state is non-empty");
    for (id, root) in &final_roots {
        assert_eq!(
            *root,
            agreed,
            "{id:?} does not match the converged root {} (final: {:?}, observed: {})",
            agreed.short(),
            final_roots
                .iter()
                .map(|(i, r)| format!("{i:?}={}", r.short()))
                .collect::<Vec<_>>()
                .join(" "),
            describe(&converged)
        );
    }

    // (2) The restarted node actually rejoined and did new work. Its pipeline is
    //     fresh on restart (metrics start at 0) and is only touched by *real*
    //     commits — the no-op fast-forward that rebuilds the commit cursor uses
    //     a null observer — so post-restart committed records prove it re-synced
    //     the gap it missed and applied it to the reloaded state.
    let restarted = reports
        .iter()
        .find(|r| r.id == ValidatorId(RESTART))
        .unwrap();
    assert!(
        restarted.pipeline.metrics.committed_records > 0,
        "restarted validator applied no records after recovery — it did not rejoin"
    );

    // (3) The Talon VM write made before the crash survived recovery on the
    //     restarted node, and still verifies against its store root.
    let restarted = reports
        .iter_mut()
        .find(|r| r.id == ValidatorId(RESTART))
        .unwrap();
    let root = restarted.pipeline.store_root();
    let proof = restarted
        .pipeline
        .prove_read(vm_table, b"answer")
        .expect("VM write present after recovery");
    assert_eq!(
        u64::from_le_bytes(proof.value[..8].try_into().unwrap()),
        42,
        "recovered VM table value wrong"
    );
    assert!(
        proof.verify(&root),
        "recovered VM write does not verify against the store root"
    );

    // Cleanup.
    for id in 0..N {
        let _ = std::fs::remove_file(store_path(id));
    }
    let _ = std::fs::remove_dir(&base);
}
