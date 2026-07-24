//! # bench — throughput & latency harness
//!
//! Spins up a configurable QUIC (or in-process) validator mesh, drives one
//! stream publisher per validator (so ingest load is spread across proposers —
//! the whole point of a multi-proposer DAG — without cross-proposer stream
//! re-sequencing), and reports sustained committed throughput and publish→commit
//! latency percentiles.
//!
//! Configured via [`BenchOptions`] — see `peregrine bench --help`, or the
//! `[bench]` table in `peregrine.toml`.
//!
//! Run: `peregrine bench --duration 10 --validators 4`

use crate::network::{local_network, Broadcaster, Inbox};
use crate::payload::WirePayload;
use crate::pipeline::ExecutionPipeline;
use crate::quic::{quic_cluster, QuicCluster};
use crate::tiles::TilePool;
use crate::validator::{run_validator, NodeReport, ValidatorConfig};
use anyhow::Result;
use peregrine_core::{Committee, Keypair, ValidatorId, ValidatorInfo};
use peregrine_data::streams::Publisher;
use peregrine_sdk::{Client, Instr, SdkError, TableId};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch, Semaphore};

/// Which transport the harness drives the mesh over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    /// Real QUIC sockets on loopback (the honest number).
    Quic,
    /// In-process channels — isolates consensus cost from the network.
    InProcess,
}

impl Transport {
    pub fn as_str(&self) -> &'static str {
        match self {
            Transport::Quic => "quic",
            Transport::InProcess => "inproc",
        }
    }
}

/// Knobs for a benchmark run.
#[derive(Clone, Copy, Debug)]
pub struct BenchOptions {
    /// Validators in the mesh.
    pub validators: u16,
    /// How long to sustain load.
    pub duration: Duration,
    /// Total records/sec across all publishers; `0` = flood as fast as possible.
    pub rate: u64,
    /// Payload items batched into each proposal.
    pub items_per_vertex: usize,
    pub transport: Transport,
}

impl Default for BenchOptions {
    fn default() -> Self {
        Self {
            validators: 4,
            duration: Duration::from_secs(5),
            rate: 0,
            items_per_vertex: 512,
            transport: Transport::Quic,
        }
    }
}

/// Run the harness and print the report.
pub async fn run(opts: BenchOptions) -> Result<()> {
    let validators = opts.validators.max(1);
    let duration = opts.duration.max(Duration::from_secs(1));
    let rate = opts.rate;
    let items_per_vtx = opts.items_per_vertex.max(1);
    let transport = opts.transport.as_str().to_string();

    let mut rng = rand::rngs::OsRng;
    let keypairs: Vec<Keypair> = (0..validators)
        .map(|_| Keypair::generate(&mut rng))
        .collect();
    let committee = Committee::new(
        keypairs
            .iter()
            .enumerate()
            .map(|(i, kp)| ValidatorInfo {
                id: ValidatorId(i as u16),
                public_key: kp.public(),
                stake: 100,
            })
            .collect(),
    );

    // One publisher (stream) per validator; every validator registers them all.
    let publishers: Vec<Publisher> = (0..validators)
        .map(|i| Publisher::new(&format!("bench/feed-{i}"), Keypair::generate(&mut rng)))
        .collect();

    // Build the transport: per-validator (Inbox, Broadcaster). Keep the QUIC
    // cluster alive for the whole run.
    let mut quic_guard: Option<QuicCluster> = None;
    let mut endpoints: Vec<(Inbox, Broadcaster)> = Vec::with_capacity(validators as usize);
    match transport.as_str() {
        "inproc" => {
            let (inboxes, shared) = local_network(validators);
            for inbox in inboxes {
                endpoints.push((inbox, shared.clone()));
            }
        }
        _ => {
            let mut cluster = quic_cluster(validators).await?;
            for node in cluster.nodes.iter_mut() {
                endpoints.push((node.take_inbox(), node.broadcaster()));
            }
            quic_guard = Some(cluster);
        }
    }

    // One tile pool shared by every validator in this process.
    //
    // Sharing is right for a benchmark: N in-process validators on one machine
    // are simulating N machines, so giving each its own pool would oversubscribe
    // the cores and measure scheduler thrash rather than the pipeline. A real
    // deployment runs one validator per host and gets the whole pool to itself.
    let tiles = Arc::new(TilePool::sized_for_machine());

    // Spawn validators.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut ingest_txs = Vec::with_capacity(validators as usize);
    let mut handles = Vec::with_capacity(validators as usize);
    for (kp, (inbox, net)) in keypairs.into_iter().zip(endpoints) {
        let id = inbox.id;
        let mut pipeline = ExecutionPipeline::new().with_tiles(Arc::clone(&tiles));
        // `PEREGRINE_MERKLE_V2=1` schedules the upgrade at round 0, so the run
        // exercises the real activation path rather than a special-cased
        // constructor. Same binary, both formats — which is the only way to
        // compare them without confounding the tree change with a rebuild.
        if std::env::var("PEREGRINE_MERKLE_V2").as_deref() == Ok("1") {
            pipeline = pipeline.with_merkle_v2_at(0);
        }
        for (i, p) in publishers.iter().enumerate() {
            pipeline
                .streams
                .register(&format!("bench/feed-{i}"), p.public_key());
        }
        let (ingest_tx, ingest_rx) = mpsc::channel(16_384);
        ingest_txs.push(ingest_tx);
        handles.push(tokio::spawn(run_validator(ValidatorConfig {
            id,
            keypair: kp,
            committee: committee.clone(),
            inbox,
            net,
            ingest_rx,
            shutdown: shutdown_rx.clone(),
            pipeline,
            max_items_per_vertex: items_per_vtx,
            store: None,
            query_rx: None,
        })));
    }

    // Spawn one feeder per validator: publisher i → validator i's ingest.
    let per_feeder_rate = if rate == 0 {
        0
    } else {
        (rate / validators as u64).max(1)
    };
    let mut feeders = Vec::with_capacity(validators as usize);
    for (mut publisher, ingest_tx) in publishers.into_iter().zip(ingest_txs.iter().cloned()) {
        let mut stop = shutdown_rx.clone();
        feeders.push(tokio::spawn(async move {
            let mut sent = 0u64;
            if per_feeder_rate == 0 {
                // Flood: push as fast as the bounded ingest accepts, yielding on
                // backpressure so the shutdown signal stays responsive.
                loop {
                    if *stop.borrow() {
                        break;
                    }
                    let shred = publisher.emit(sent.to_le_bytes().to_vec());
                    tokio::select! {
                        _ = stop.changed() => break,
                        res = ingest_tx.send(WirePayload::Shred(shred)) => {
                            if res.is_err() { break; }
                            sent += 1;
                        }
                    }
                }
            } else {
                // Paced: emit `batch` records every 5 ms to approximate the rate.
                let batch = (per_feeder_rate / 200).max(1);
                let mut tick = tokio::time::interval(Duration::from_millis(5));
                loop {
                    tokio::select! {
                        _ = stop.changed() => break,
                        _ = tick.tick() => {
                            for _ in 0..batch {
                                let shred = publisher.emit(sent.to_le_bytes().to_vec());
                                if ingest_tx.send(WirePayload::Shred(shred)).await.is_err() {
                                    return sent;
                                }
                                sent += 1;
                            }
                        }
                    }
                }
            }
            sent
        }));
    }

    let started = Instant::now();
    println!(
        "running: transport={transport} validators={validators} duration={}s rate={}",
        duration.as_secs(),
        if rate == 0 {
            "max".into()
        } else {
            rate.to_string()
        }
    );
    tokio::time::sleep(duration).await;
    let elapsed = started.elapsed();
    shutdown_tx.send(true).ok();
    drop(ingest_txs);

    let mut total_published = 0u64;
    for f in feeders {
        total_published += f.await.unwrap_or(0);
    }
    let mut reports: Vec<NodeReport> = Vec::with_capacity(handles.len());
    for h in handles {
        reports.push(h.await.unwrap());
    }
    drop(quic_guard); // mesh no longer needed

    report(
        &transport,
        validators,
        &tiles,
        elapsed,
        total_published,
        &mut reports,
    );
    Ok(())
}

fn report(
    transport: &str,
    validators: u16,
    tiles: &TilePool,
    elapsed: Duration,
    published: u64,
    reports: &mut [NodeReport],
) {
    // Every validator commits the same total order, so any node's committed
    // count is the whole network's throughput; use validator 0.
    reports.sort_by_key(|r| r.id.0);
    let v0 = &reports[0];
    let committed = v0.pipeline.metrics.committed_records;
    let secs = elapsed.as_secs_f64();

    println!("\n════════════════════ peregrine-bench ════════════════════");
    println!("transport            : {transport}");
    println!("validators           : {validators}");
    println!(
        "sigverify tiles      : {} ({} jobs, {} batches, {} inline)",
        tiles.tiles(),
        tiles
            .metrics
            .jobs
            .load(std::sync::atomic::Ordering::Relaxed),
        tiles
            .metrics
            .batches
            .load(std::sync::atomic::Ordering::Relaxed),
        tiles
            .metrics
            .inline_batches
            .load(std::sync::atomic::Ordering::Relaxed),
    );
    println!("window               : {secs:.2}s");
    println!("records published    : {published}");
    println!("records committed    : {committed}");
    println!(
        "throughput           : {:.0} records/s (committed, sustained)",
        committed as f64 / secs
    );
    println!(
        "publish→commit       : p50 {:.2} ms | p99 {:.2} ms | avg {:.2} ms",
        v0.pipeline.metrics.p50_ms(),
        v0.pipeline.metrics.p99_ms(),
        v0.pipeline.metrics.avg_record_latency_ms(),
    );
    println!("── per-validator ─────────────────────────────────────────");
    for r in reports.iter() {
        println!(
            "  {:?}: round {:>5} | dag {:>6} | {:>5} commits | {:>4} skips | {:>7} records | {:>4} sync-req",
            r.id,
            r.highest_round_proposed,
            r.dag_size,
            r.commits,
            r.skips,
            r.pipeline.metrics.committed_records,
            r.sync_requests_sent,
        );
    }
    println!("══════════════════════════════════════════════════════════\n");
}

// ─────────────────────────── client-mode harness ────────────────────────────
//
// The local harness above spins up its *own* committee, so its latency numbers
// are loopback with no WAN round-trip. The client harness below drives an
// *already-running* committee (e.g. a real multi-host testnet) exactly the way
// an application would — over the SDK's QUIC RPC — so the numbers include real
// network RTT and the node's live load. It never starts a validator.
//
// ## Load path
// It submits Talon table-writes (`submit_tx`), not stream records. Streams need
// a publisher key registered in genesis (which a client cannot do against an
// arbitrary committee); a table write is permissionless — `sys.balances` is
// credit-only, so no payer is debited and no balance or fee is required. It is
// also the CLI's normal write path, so this measures what apps actually do.
//
// ## What "confirmed" means (precisely)
// Every write goes to a distinct key `run_id ‖ worker ‖ seq` (the `run_id` keeps
// keys from colliding with a previous run's already-committed keys, which would
// make `prove_read` return instantly and fake ~0 latency). A record is
// *confirmed* when a `prove_read` of its key first returns a value. So the
// reported latency is **submit-call-start → the client observes the commit via a
// proven read** — an honest, end-to-end, app-observable number that is an *upper
// bound* on the in-consensus publish→commit time (it also carries the confirming
// read's round-trip and the poll granularity). This is deliberately a different,
// stricter definition than the loopback harness's in-consensus histogram; the
// two are not directly comparable, and the client number is the one an app feels.

/// Confirm polling backs off from this…
const CONFIRM_POLL_START: Duration = Duration::from_millis(1);
/// …up to this cap. Starting fine gives sub-ms→ms latency resolution; the cap
/// keeps a slow commit from hammering the node with reads. Worst-case latency
/// over-report is one capped interval.
const CONFIRM_POLL_MAX: Duration = Duration::from_millis(20);
/// A write not observed within this long is counted `unconfirmed` (a real stall,
/// not slowness) rather than waited on forever.
const CONFIRM_TIMEOUT: Duration = Duration::from_secs(20);
/// The global rate pacer grants tokens on this cadence.
const PACER_TICK: Duration = Duration::from_millis(2);

/// The machine-readable summary of a client-mode run (the printed table plus a
/// few derived fields), returned so callers and tests can assert on it.
#[derive(Clone, Copy, Debug, Default)]
pub struct ClientReport {
    /// `submit_tx` calls made (≈ the offered rate × window when paced).
    pub attempted: u64,
    /// Calls the node accepted into its ingest queue.
    pub accepted: u64,
    /// Calls the node refused (over the per-connection RPC budget, or policy).
    pub rejected: u64,
    /// Calls that failed on the transport (connection dropped).
    pub disconnected: u64,
    /// Accepted writes later observed committed via a proven read.
    pub confirmed: u64,
    /// Accepted writes never observed within [`CONFIRM_TIMEOUT`].
    pub unconfirmed: u64,
    /// Accepted / window.
    pub accept_rate: f64,
    pub p50_ms: f64,
    pub p99_ms: f64,
    pub max_ms: f64,
}

/// How to drive load against an already-running committee.
#[derive(Clone, Debug)]
pub struct ClientBenchOptions {
    /// One or more node RPC addresses (QUIC) of the running committee. Load is
    /// spread round-robin across `concurrency` submit connections.
    pub addrs: Vec<SocketAddr>,
    /// How long to sustain load.
    pub duration: Duration,
    /// Target table-writes/sec across all workers; `0` = as fast as each
    /// connection's request/ack round-trip allows (ack-bound).
    pub rate: u64,
    /// Number of concurrent submitter connections.
    pub concurrency: usize,
}

#[derive(Default)]
struct ClientStats {
    attempted: AtomicU64,    // submit_tx calls made
    accepted: AtomicU64,     // returned Ok (into ingest)
    rejected: AtomicU64,     // node refused (e.g. per-connection rate limit)
    disconnected: AtomicU64, // transport/connect fault on submit
    confirmed: AtomicU64,    // accepted, observed provable within the timeout
    unconfirmed: AtomicU64,  // accepted, never observed within the timeout
    pending: AtomicU64,      // confirmations still in flight (for the drain)
}

fn bench_key(run_id: u64, worker: u16, seq: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(18);
    k.extend_from_slice(&run_id.to_be_bytes());
    k.extend_from_slice(&worker.to_be_bytes());
    k.extend_from_slice(&seq.to_be_bytes());
    k
}

/// Exact `q`-quantile (0.0–1.0) of an ascending-sorted slice of microsecond
/// samples, in milliseconds. Exact percentiles from raw samples (not power-of-two
/// buckets) so p50/p99/max vary meaningfully run to run and resolve sub-ms.
fn pct_ms(sorted_us: &[u64], q: f64) -> f64 {
    if sorted_us.is_empty() {
        return 0.0;
    }
    let rank = (q * (sorted_us.len() as f64 - 1.0)).round() as usize;
    sorted_us[rank.min(sorted_us.len() - 1)] as f64 / 1000.0
}

/// Wait until `key` becomes provable (or the timeout), recording the
/// publish→confirm latency in microseconds. Reads run on a **dedicated** read
/// connection so they never spend the submit connection's rate budget. A read
/// that errors or returns `None` is simply retried with backoff — a transient
/// rate-limit or a not-yet-committed key must not be mistaken for a lost write.
async fn confirm_write(
    read: &Client,
    table: TableId,
    key: &[u8],
    t0: Instant,
    stats: &ClientStats,
    samples: &Mutex<Vec<u64>>,
) {
    let deadline = t0 + CONFIRM_TIMEOUT;
    let mut backoff = CONFIRM_POLL_START;
    loop {
        if let Ok(Some(_)) = read.prove_read(table, key).await {
            let us = t0.elapsed().as_micros().min(u64::MAX as u128) as u64;
            samples.lock().expect("samples poisoned").push(us);
            stats.confirmed.fetch_add(1, Ordering::Relaxed);
            break;
        }
        if Instant::now() >= deadline {
            stats.unconfirmed.fetch_add(1, Ordering::Relaxed);
            break;
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(CONFIRM_POLL_MAX);
    }
    stats.pending.fetch_sub(1, Ordering::Relaxed);
}

/// Drive load against a running committee over the SDK and print an honest table.
pub async fn run_client(opts: ClientBenchOptions) -> Result<ClientReport> {
    anyhow::ensure!(
        !opts.addrs.is_empty(),
        "client mode needs at least one node address: --against <host:port>"
    );
    let concurrency = opts.concurrency.max(1);
    let duration = opts.duration.max(Duration::from_secs(1));
    let addrs = opts.addrs.clone();
    let table = TableId::named("bench.client");
    // Unique per run, so keys never alias an earlier run's committed keys (which
    // would make prove_read return instantly and fake ~0 latency).
    let run_id: u64 = rand::random();

    // Two connection pools: submits and confirmation reads are kept on **separate
    // connections** because the RPC limiter budgets per connection — mixing reads
    // into the submit bucket is what starved submits and inflated latency. Fail
    // *clearly* the instant a node is unreachable.
    let connect_all = |n: usize| {
        let addrs = addrs.clone();
        async move {
            let mut v: Vec<Arc<Client>> = Vec::with_capacity(n);
            for i in 0..n {
                let addr = addrs[i % addrs.len()];
                let c = Client::connect(addr)
                    .await
                    .map_err(|e| anyhow::anyhow!("cannot reach node at {addr}: {e}"))?;
                v.push(Arc::new(c));
            }
            Ok::<_, anyhow::Error>(v)
        }
    };
    let submit_conns = connect_all(concurrency).await?;
    let read_conns = connect_all(concurrency).await?;

    let stats = Arc::new(ClientStats::default());
    let samples = Arc::new(Mutex::new(Vec::<u64>::new()));
    let stop = Arc::new(AtomicBool::new(false));

    // Global rate pacing. A single pacer grants submit permits at `rate`/s into a
    // shared semaphore (small burst cap); every worker takes one permit per
    // submit. This bounds *aggregate attempted* submits to ≈ `rate` regardless of
    // worker count — the fix for the old per-worker loop that over-issued ~100×
    // and drowned the node in rejects. `rate == 0` means no pacing (ack-bound).
    let permits = Arc::new(Semaphore::new(0));
    let mut pacer: Option<tokio::task::JoinHandle<()>> = None;
    if opts.rate > 0 {
        let (permits, stop) = (permits.clone(), stop.clone());
        let rate = opts.rate;
        let burst = ((rate as usize) / 5).max(concurrency).min(1024);
        pacer = Some(tokio::spawn(async move {
            // Grant against **wall-clock** owed (`rate × elapsed`), not per-tick
            // accumulation: a per-tick counter under-delivers whenever the timer
            // runs slow under load (a 2 ms interval firing at 6 ms grants a third
            // of the rate). Wall-clock keeps achieved ≈ offered when the node can
            // keep up; a `granted` deficit the node/workers can't absorb is capped
            // to a small burst per tick, so catch-up never becomes an overshoot.
            let start = Instant::now();
            let mut granted: u64 = 0;
            let mut tick = tokio::time::interval(PACER_TICK);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            while !stop.load(Ordering::Relaxed) {
                tick.tick().await;
                let owed = (rate as f64 * start.elapsed().as_secs_f64()) as u64;
                let want = owed.saturating_sub(granted) as usize;
                if want > 0 {
                    let grant = want.min(burst.saturating_sub(permits.available_permits()));
                    if grant > 0 {
                        permits.add_permits(grant);
                        granted += grant as u64;
                    }
                }
            }
            // Wake any worker blocked on a permit so it can observe `stop`.
            permits.add_permits(concurrency * 4);
        }));
    }

    println!(
        "running: client-mode vs {} node(s) {:?} | concurrency={concurrency} \
         duration={}s rate={} | client is EXTERNAL to the committee",
        addrs.len(),
        addrs,
        duration.as_secs(),
        if opts.rate == 0 {
            "max (ack-bound)".into()
        } else {
            format!("{} writes/s (paced)", opts.rate)
        }
    );

    let started = Instant::now();
    let mut workers = Vec::with_capacity(concurrency);
    for wid in 0..concurrency {
        let mut submit = submit_conns[wid].clone();
        let read = read_conns[wid].clone();
        let addr = addrs[wid % addrs.len()];
        let paced = opts.rate > 0;
        let (stats, samples, permits, stop) = (
            stats.clone(),
            samples.clone(),
            permits.clone(),
            stop.clone(),
        );
        workers.push(tokio::spawn(async move {
            let mut seq: u64 = 0;
            while !stop.load(Ordering::Relaxed) {
                // Pace: take a global permit before each submit (skipped in
                // ack-bound mode). `forget` consumes it; the pacer replenishes.
                if paced {
                    match permits.clone().acquire_owned().await {
                        Ok(p) => p.forget(),
                        Err(_) => break,
                    }
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                }

                seq += 1;
                let key = bench_key(run_id, wid as u16, seq);
                let program = vec![
                    Instr::Push(seq),
                    Instr::StoreTable {
                        table,
                        key: key.clone(),
                    },
                    Instr::Halt,
                ];
                let t0 = Instant::now();
                stats.attempted.fetch_add(1, Ordering::Relaxed);
                match submit.submit_tx(program).await {
                    Ok(()) => {
                        stats.accepted.fetch_add(1, Ordering::Relaxed);
                        // Confirm every accepted write (100% confirm when healthy);
                        // reads go on the dedicated read connection.
                        stats.pending.fetch_add(1, Ordering::Relaxed);
                        let (r2, s2, sm2) = (read.clone(), stats.clone(), samples.clone());
                        tokio::spawn(async move {
                            confirm_write(&r2, table, &key, t0, &s2, &sm2).await;
                        });
                    }
                    // A rejected submit is counted, not retried — retrying in a
                    // tight loop is exactly what inflated the old reject numbers.
                    Err(SdkError::Node(_)) => {
                        stats.rejected.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => {
                        stats.disconnected.fetch_add(1, Ordering::Relaxed);
                        match Client::connect(addr).await {
                            Ok(c) => submit = Arc::new(c),
                            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
                        }
                    }
                }
            }
        }));
    }

    tokio::time::sleep(duration).await;
    stop.store(true, Ordering::Relaxed);
    if let Some(p) = pacer {
        let _ = p.await;
    }
    for w in workers {
        let _ = w.await;
    }
    let elapsed = started.elapsed();

    // Let in-flight confirmations finish (bounded) so their latency is counted.
    let drain_deadline = Instant::now() + CONFIRM_TIMEOUT + Duration::from_secs(2);
    while stats.pending.load(Ordering::Relaxed) > 0 && Instant::now() < drain_deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let secs = elapsed.as_secs_f64().max(1e-9);
    let mut sorted = samples.lock().expect("samples poisoned").clone();
    sorted.sort_unstable();
    let report = ClientReport {
        attempted: stats.attempted.load(Ordering::Relaxed),
        accepted: stats.accepted.load(Ordering::Relaxed),
        rejected: stats.rejected.load(Ordering::Relaxed),
        disconnected: stats.disconnected.load(Ordering::Relaxed),
        confirmed: stats.confirmed.load(Ordering::Relaxed),
        unconfirmed: stats.unconfirmed.load(Ordering::Relaxed),
        accept_rate: stats.accepted.load(Ordering::Relaxed) as f64 / secs,
        p50_ms: pct_ms(&sorted, 0.50),
        p99_ms: pct_ms(&sorted, 0.99),
        max_ms: pct_ms(&sorted, 1.0),
    };
    report_client(&addrs, concurrency, opts.rate, secs, &report);
    Ok(report)
}

fn report_client(
    addrs: &[SocketAddr],
    concurrency: usize,
    offered: u64,
    secs: f64,
    r: &ClientReport,
) {
    let attempt_rate = r.attempted as f64 / secs;
    let confirmed_frac = if r.accepted == 0 {
        0.0
    } else {
        r.confirmed as f64 / r.accepted as f64
    };

    println!("\n═════════════════ peregrine-bench (client mode) ═════════════════");
    println!("target node(s)       : {addrs:?}");
    println!("client host role     : external to the committee (real client RTT)");
    println!("transport / path     : QUIC SDK · table writes (submit_tx), proven-read confirm");
    println!("connections          : {concurrency} submit + {concurrency} read");
    println!("window               : {secs:.2}s");
    println!(
        "offered rate         : {}",
        if offered == 0 {
            "max (ack-bound)".into()
        } else {
            format!("{offered} writes/s")
        }
    );
    println!(
        "attempted            : {}   →  {attempt_rate:.0} writes/s",
        r.attempted
    );
    println!(
        "accepted             : {}   →  {:.0} writes/s achieved",
        r.accepted, r.accept_rate
    );
    println!(
        "confirmed committed  : {} / {} accepted  ({:.1}% provable)",
        r.confirmed,
        r.accepted,
        confirmed_frac * 100.0
    );
    println!(
        "publish→confirm      : p50 {:.1} ms | p99 {:.1} ms | max {:.1} ms   (client-observed, {} samples)",
        r.p50_ms,
        r.p99_ms,
        r.max_ms,
        r.confirmed,
    );
    println!(
        "errors               : {} rejected · {} disconnect · {} confirm-timeout",
        r.rejected, r.disconnected, r.unconfirmed
    );
    println!("──────────────────────────────────────────────────────────────────");
    println!("attempted = submit calls made · accepted = node took them into ingest ·");
    println!("rejected = over the per-connection RPC budget (raise --concurrency, or the");
    println!("operator can raise RPC limits). Latency is submit → the client first proves");
    println!("the write committed (client-observed upper bound on publish→commit).");
    println!("Public, unaudited testnet — no real value. Report validators, client host,");
    println!("transport, and offered-vs-achieved rate with any p50/p99; never a bare TPS.");
    println!("══════════════════════════════════════════════════════════════════\n");
}
