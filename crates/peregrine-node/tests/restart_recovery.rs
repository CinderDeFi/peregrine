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
//! the moment the real condition holds. On timeout the failure prints every
//! node's root so *lag* and a genuine *fork* are distinguishable at a glance
//! rather than by rerunning.
//!
//! # Why every wait here is bounded (the CI-hang fix)
//!
//! Condition polling alone is not enough: a wait that can *block* rather than
//! return `false` still hangs forever. This test previously did that in three
//! places, and on a heavily-loaded GitHub runner it would stall for the job's
//! whole 20-minute budget instead of failing:
//!
//!  * joining a validator task after shutdown (`handle.await`) had no cap, so a
//!    task that never observed shutdown blocked the test indefinitely;
//!  * a `Query` send (`q.send(..).await`) was unbounded — only the *reply* was
//!    timed out — so a wedged validator whose 256-slot query channel had filled
//!    blocked the poll loop before it could re-check its own deadline.
//!
//! Now **every** cross-task wait has a hard wall-clock cap: [`ask`] bounds the
//! whole send+reply exchange, [`join_report`] bounds shutdown joins, and the
//! poll deadline is [`CONDITION_TIMEOUT`]. A genuinely stuck system fails with a
//! diagnostic in seconds, never a 20-minute hang.

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
/// This is not a performance assertion — it is the point at which we stop
/// believing the system is merely slow and call it stuck. A healthy run exits
/// each poll the instant its condition holds (locally ~13s end to end), so the
/// cap is only ever reached on a genuine failure, where reaching it *fast* is
/// the point: the earlier this fails, the sooner CI reports a diagnostic
/// instead of burning the runner.
///
/// History: this was 90s, then 180s, chasing a "flake" that looked like slow
/// convergence but was really unbounded blocking — a wedged validator's query
/// never returned, so the poll never re-checked its deadline and the job hung
/// until the runner killed it. With every wait now individually bounded (see
/// the module docs), the deadline no longer has to absorb that, and 45s is
/// ample headroom over the observed ~13s while still failing fast.
const CONDITION_TIMEOUT: Duration = Duration::from_secs(45);
/// Gap between polls. Long enough not to add meaningful query load to the
/// (possibly CPU-starved) validators being measured — hammering them every few
/// ms is itself part of what starved their loops on a shared runner — short
/// enough that convergence is still detected promptly.
const POLL_INTERVAL: Duration = Duration::from_millis(100);
/// Hard cap on a single `Query` round-trip (send *and* reply). Bounds the whole
/// exchange so a wedged validator can never block a poll past its deadline; on
/// expiry the probe reports "no answer", i.e. "condition not yet met".
///
/// Generous on purpose: the goal is to bound a *wedged* node, not to punish a
/// *busy* one. A validator mid-catch-up (the restarted node re-applying its gap)
/// can be a second or two late to service its query channel under load; too
/// tight a cap would report it dead when it is merely working, so the poll would
/// churn without ever seeing it. Since probes run concurrently (see [`roots`]),
/// one slow node does not stretch a poll — this cap only sets how long we wait
/// on it before trying again.
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);
/// Hard cap on joining a validator task after its shutdown signal. A graceful
/// stop only has to flush a final snapshot; overrunning this means the task is
/// wedged, not slow, and the test says so rather than hanging.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

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

/// Send one `Query` and await its reply, bounding the **whole** exchange —
/// send included — by [`QUERY_TIMEOUT`].
///
/// This is the load-bearing part of the hang fix. Wrapping only the reply (as
/// before) leaves `q.send(..).await` unbounded, and that send blocks once a
/// wedged validator's query channel fills, freezing the caller's poll loop
/// before it can re-check its deadline. Bounding the send too means a stuck
/// node always resolves to `None` ("no answer" → condition not yet met) within
/// `QUERY_TIMEOUT`, so the loop keeps its own wall-clock guarantee.
async fn ask<T>(
    q: &mpsc::Sender<Query>,
    make: impl FnOnce(oneshot::Sender<T>) -> Query,
) -> Option<T> {
    let (tx, rx) = oneshot::channel();
    tokio::time::timeout(QUERY_TIMEOUT, async move {
        q.send(make(tx)).await.ok()?;
        rx.await.ok()
    })
    .await
    .ok()
    .flatten()
}

/// Ask a running validator for its current store root. `None` means it did not
/// answer within [`QUERY_TIMEOUT`] — shutting down, wedged, or briefly starved;
/// callers treat that as "condition not yet met", not an error.
async fn store_root(q: &mpsc::Sender<Query>) -> Option<Hash> {
    ask(q, |reply| Query::StoreRoot { reply }).await
}

/// Ask a running validator whether `key` is present in `table`.
async fn has_key(q: &mpsc::Sender<Query>, table: TableId, key: &[u8]) -> bool {
    let key = key.to_vec();
    matches!(
        ask(q, |reply| Query::ProveRead { table, key, reply }).await,
        Some(Some(_))
    )
}

/// Ask a running validator for its committed progress: `(commit_rounds,
/// committed_records)`. `None` means it did not answer (shutting down or wedged).
/// These counters reset on restart, so for the restarted node they report
/// post-recovery progress — a zero here at timeout means it never rejoined,
/// which is precisely what a diagnostic must distinguish from mere lag.
async fn committed_progress(q: &mpsc::Sender<Query>) -> Option<(u64, u64)> {
    ask(q, |reply| Query::CommittedProgress { reply }).await
}

/// Join a validator task after shutdown, bounded by [`SHUTDOWN_TIMEOUT`], so a
/// task that never observes its shutdown signal fails the test fast with a
/// clear message instead of hanging the runner. `what` names the phase.
async fn join_report(what: &str, handle: JoinHandle<NodeReport>) -> NodeReport {
    match tokio::time::timeout(SHUTDOWN_TIMEOUT, handle).await {
        Ok(Ok(report)) => report,
        Ok(Err(e)) => panic!("{what}: validator task panicked: {e}"),
        Err(_) => panic!(
            "{what}: validator task did not exit within {SHUTDOWN_TIMEOUT:?} of shutdown — \
             wedged, not slow"
        ),
    }
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

/// Like [`wait_for`], but on timeout runs `diag` and appends its snapshot to the
/// panic message. Used for convergence, where knowing *where every node was*
/// (root + committed height) is what tells a load-induced lag apart from a real
/// fork — the whole reason this test polls a condition instead of sleeping.
async fn wait_for_or_dump<F, Fut, D, DFut>(what: &str, mut cond: F, diag: D)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
    D: Fn() -> DFut,
    DFut: std::future::Future<Output = String>,
{
    let deadline = Instant::now() + CONDITION_TIMEOUT;
    while Instant::now() < deadline {
        if cond().await {
            return;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
    let snapshot = diag().await;
    panic!("timed out after {CONDITION_TIMEOUT:?} waiting for: {what}\nfinal state:\n{snapshot}");
}

/// A per-node snapshot — store root and committed height — printed when
/// convergence times out. A set of differing-but-advancing roots reads as lag;
/// a stuck root (or a restarted node still at height 0) reads as a real problem.
/// Probes run concurrently so an unresponsive node costs one [`QUERY_TIMEOUT`],
/// not one per node.
async fn diagnose(nodes: &[Node]) -> String {
    let mut set = tokio::task::JoinSet::new();
    for (i, n) in nodes.iter().enumerate() {
        let q = n.query.clone();
        set.spawn(async move {
            let root = match store_root(&q).await {
                Some(h) => h.short(),
                None => "<no answer>".to_string(),
            };
            let height = match committed_progress(&q).await {
                Some((rounds, records)) => format!("height={rounds} records={records}"),
                None => "height=<no answer>".to_string(),
            };
            (
                i,
                format!("  {:?}: root={root} {height}", ValidatorId(i as u16)),
            )
        });
    }
    let mut lines: Vec<(usize, String)> = Vec::with_capacity(nodes.len());
    while let Some(res) = set.join_next().await {
        if let Ok(line) = res {
            lines.push(line);
        }
    }
    lines.sort_by_key(|(i, _)| *i);
    lines
        .into_iter()
        .map(|(_, l)| l)
        .collect::<Vec<_>>()
        .join("\n")
}

/// Collect every live validator's root, for convergence checks and diagnostics.
///
/// Probes run **concurrently**: with sequential polling, one node timing out at
/// [`QUERY_TIMEOUT`] would stretch every poll by that much and starve the loop
/// of attempts (the exact effect that made a slow restarted node look like a
/// hang). Concurrently, a poll costs at most one `QUERY_TIMEOUT` regardless of
/// how many nodes are slow, so the loop keeps its ~[`POLL_INTERVAL`] cadence.
async fn roots(nodes: &[Node]) -> Vec<(ValidatorId, Option<Hash>)> {
    let mut set = tokio::task::JoinSet::new();
    for (i, n) in nodes.iter().enumerate() {
        let q = n.query.clone();
        set.spawn(async move { (i, store_root(&q).await) });
    }
    let mut out: Vec<(ValidatorId, Option<Hash>)> = (0..nodes.len())
        .map(|i| (ValidatorId(i as u16), None))
        .collect();
    while let Some(res) = set.join_next().await {
        if let Ok((i, root)) = res {
            out[i] = (ValidatorId(i as u16), root);
        }
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

// Keep the multi-threaded runtime with several workers: each validator's
// periodic flush parks its worker in `block_in_place` while it fsyncs, and
// `block_in_place` relocates the *other* tasks off that worker rather than
// spawning a replacement — so the pool must be wide enough that four validators
// flushing never leaves the runtime with no worker to make progress on. Eight
// gives that headroom; the recovery-under-load story is carried by the bounded,
// concurrent waits below, not by starving the scheduler of threads.
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
    let handle = nodes[RESTART as usize].handle.take().unwrap();
    let pre_restart = join_report("killing the doomed validator", handle).await;
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
    // converges and the timeout dumps every node's root and committed height so
    // lag (roots differ but heights climb) and a true fork (a stuck root) are
    // told apart from the failure message alone.
    wait_for_or_dump(
        "all four validators to converge on one store root",
        || async {
            let rs = roots(&nodes).await;
            let Some(Some(first)) = rs.first().map(|(_, r)| *r) else {
                return false;
            };
            first != Hash::ZERO && rs.iter().all(|(_, r)| *r == Some(first))
        },
        || diagnose(&nodes),
    )
    .await;

    // Snapshot the agreed root while everyone is still alive, so the assertions
    // below are checked against a state we *observed* converged rather than one
    // we hope survived shutdown.
    let converged = roots(&nodes).await;
    let agreed = converged[0].1.expect("converged root");

    // ── Shut down and collect final reports ─────────────────────────────────
    // Bounded joins: without a cap, a single validator that failed to observe
    // shutdown would hang this loop — and the whole CI job — indefinitely. This
    // was the actual source of the multi-minute GHA stalls.
    for n in &nodes {
        let _ = n.shutdown.send(true);
    }
    let mut reports: Vec<NodeReport> = Vec::new();
    for (i, n) in nodes.iter_mut().enumerate() {
        if let Some(h) = n.handle.take() {
            reports.push(join_report(&format!("final shutdown of v{i}"), h).await);
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
