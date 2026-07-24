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
use crate::pipeline::{ExecutionPipeline, LatencyHistogram};
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

/// Poll interval while waiting for a write to become provable. Fine enough that
/// it is negligible against WAN RTT (the case this harness exists for); on
/// loopback it sets the latency floor, which the report notes.
const CONFIRM_POLL: Duration = Duration::from_millis(5);
/// A write not observed within this long is counted `unconfirmed` (a real stall,
/// not slowness) rather than waited on forever.
const CONFIRM_TIMEOUT: Duration = Duration::from_secs(20);

/// The machine-readable summary of a client-mode run (the printed table plus a
/// few derived fields), returned so callers and tests can assert on it.
#[derive(Clone, Copy, Debug, Default)]
pub struct ClientReport {
    pub submitted: u64,
    pub tracked: u64,
    pub confirmed: u64,
    pub unconfirmed: u64,
    pub rejected: u64,
    pub disconnected: u64,
    pub submit_rate: f64,
    pub p50_ms: f64,
    pub p99_ms: f64,
}

/// How to drive load against an already-running committee.
#[derive(Clone, Debug)]
pub struct ClientBenchOptions {
    /// One or more node RPC addresses (QUIC) of the running committee. Load is
    /// spread round-robin; each worker keeps its own connection so the
    /// per-connection RPC rate limiter does not throttle the aggregate.
    pub addrs: Vec<SocketAddr>,
    /// How long to sustain load.
    pub duration: Duration,
    /// Target table-writes/sec across all workers; `0` = as fast as each
    /// connection's request/ack round-trip allows.
    pub rate: u64,
    /// Number of concurrent submitter connections.
    pub concurrency: usize,
}

#[derive(Default)]
struct ClientStats {
    submitted: AtomicU64,    // submit_tx returned Ok (accepted into ingest)
    rejected: AtomicU64,     // node refused (e.g. rate limit / policy)
    disconnected: AtomicU64, // transport/connect fault on submit
    tracked: AtomicU64,      // submissions we attempted to confirm
    confirmed: AtomicU64,    // tracked, observed provable within the timeout
    unconfirmed: AtomicU64,  // tracked, never observed within the timeout
}

fn bench_key(run_id: u64, worker: u16, seq: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(18);
    k.extend_from_slice(&run_id.to_be_bytes());
    k.extend_from_slice(&worker.to_be_bytes());
    k.extend_from_slice(&seq.to_be_bytes());
    k
}

/// Wait until `key` becomes provable (or the timeout), recording the
/// publish→confirm latency. Read errors are retried — a transient stream error
/// or a briefly-busy node should not be mistaken for a lost write.
async fn confirm_write(
    client: &Client,
    table: TableId,
    key: &[u8],
    t0: Instant,
    stats: &ClientStats,
    hist: &Mutex<LatencyHistogram>,
) {
    let deadline = t0 + CONFIRM_TIMEOUT;
    loop {
        if let Ok(Some(_)) = client.prove_read(table, key).await {
            let ns = t0.elapsed().as_nanos().min(u64::MAX as u128) as u64;
            hist.lock().expect("hist poisoned").record(ns);
            stats.confirmed.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if Instant::now() >= deadline {
            stats.unconfirmed.fetch_add(1, Ordering::Relaxed);
            return;
        }
        tokio::time::sleep(CONFIRM_POLL).await;
    }
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
    // Unique per run, so keys never alias an earlier run's committed keys.
    let run_id: u64 = rand::random();

    // One connection per worker. Fail *clearly* the moment a node is unreachable
    // rather than reporting a run full of disconnect errors.
    let mut clients: Vec<Arc<Client>> = Vec::with_capacity(concurrency);
    for i in 0..concurrency {
        let addr = addrs[i % addrs.len()];
        let c = Client::connect(addr)
            .await
            .map_err(|e| anyhow::anyhow!("cannot reach node at {addr}: {e}"))?;
        clients.push(Arc::new(c));
    }

    let stats = Arc::new(ClientStats::default());
    let hist = Arc::new(Mutex::new(LatencyHistogram::default()));
    // Bound concurrent confirmation reads: under a high submit rate we *sample*
    // confirmations rather than doubling read traffic. At low (WAN) rates every
    // write gets a slot, so confirmed == tracked == submitted.
    let confirm_capacity = concurrency * 8;
    let confirm_slots = Arc::new(Semaphore::new(confirm_capacity));
    let stop = Arc::new(AtomicBool::new(false));
    let per_worker_rate = if opts.rate == 0 {
        0
    } else {
        (opts.rate / concurrency as u64).max(1)
    };

    println!(
        "running: client-mode vs {} node(s) {:?} | concurrency={concurrency} \
         duration={}s rate={} | client is EXTERNAL to the committee",
        addrs.len(),
        addrs,
        duration.as_secs(),
        if opts.rate == 0 {
            "max (ack-bound)".into()
        } else {
            opts.rate.to_string()
        }
    );

    let started = Instant::now();
    let mut workers = Vec::with_capacity(concurrency);
    for wid in 0..concurrency {
        let mut client = clients[wid].clone();
        let addr = addrs[wid % addrs.len()];
        let (stats, hist, slots, stop) = (
            stats.clone(),
            hist.clone(),
            confirm_slots.clone(),
            stop.clone(),
        );
        workers.push(tokio::spawn(async move {
            let mut seq: u64 = 0;
            // Paced: emit `batch` writes every 5 ms to approximate the rate.
            // `Delay` on a missed tick avoids a catch-up burst when the node is
            // slow — we want to fall behind honestly, not spike.
            let batch = if per_worker_rate == 0 {
                0
            } else {
                (per_worker_rate / 200).max(1)
            };
            let mut tick = tokio::time::interval(Duration::from_millis(5));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

            while !stop.load(Ordering::Relaxed) {
                let n = if batch == 0 {
                    1
                } else {
                    tick.tick().await;
                    batch
                };
                for _ in 0..n {
                    if stop.load(Ordering::Relaxed) {
                        break;
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
                    match client.submit_tx(program).await {
                        Ok(()) => {
                            stats.submitted.fetch_add(1, Ordering::Relaxed);
                            // Confirm this write iff a read slot is free.
                            if let Ok(permit) = slots.clone().try_acquire_owned() {
                                stats.tracked.fetch_add(1, Ordering::Relaxed);
                                let (c2, s2, h2) = (client.clone(), stats.clone(), hist.clone());
                                tokio::spawn(async move {
                                    let _permit = permit;
                                    confirm_write(&c2, table, &key, t0, &s2, &h2).await;
                                });
                            }
                        }
                        Err(SdkError::Node(_)) => {
                            stats.rejected.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(_) => {
                            stats.disconnected.fetch_add(1, Ordering::Relaxed);
                            // Reconnect for subsequent submits; back off on failure
                            // so a downed node does not become a tight retry spin.
                            match Client::connect(addr).await {
                                Ok(c) => client = Arc::new(c),
                                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
                            }
                        }
                    }
                }
            }
        }));
    }

    tokio::time::sleep(duration).await;
    stop.store(true, Ordering::Relaxed);
    for w in workers {
        let _ = w.await;
    }
    let elapsed = started.elapsed();

    // Let in-flight confirmations drain (bounded) so their latency is counted.
    let drain_deadline = Instant::now() + CONFIRM_TIMEOUT + Duration::from_secs(2);
    while confirm_slots.available_permits() < confirm_capacity && Instant::now() < drain_deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let secs = elapsed.as_secs_f64().max(1e-9);
    let hist_guard = hist.lock().expect("hist poisoned");
    let report = ClientReport {
        submitted: stats.submitted.load(Ordering::Relaxed),
        tracked: stats.tracked.load(Ordering::Relaxed),
        confirmed: stats.confirmed.load(Ordering::Relaxed),
        unconfirmed: stats.unconfirmed.load(Ordering::Relaxed),
        rejected: stats.rejected.load(Ordering::Relaxed),
        disconnected: stats.disconnected.load(Ordering::Relaxed),
        submit_rate: stats.submitted.load(Ordering::Relaxed) as f64 / secs,
        p50_ms: hist_guard.percentile_ms(0.50),
        p99_ms: hist_guard.percentile_ms(0.99),
    };
    report_client(&addrs, concurrency, opts.rate, secs, &report, &hist_guard);
    Ok(report)
}

fn report_client(
    addrs: &[SocketAddr],
    concurrency: usize,
    offered: u64,
    secs: f64,
    r: &ClientReport,
    hist: &LatencyHistogram,
) {
    let (submitted, tracked, confirmed) = (r.submitted, r.tracked, r.confirmed);
    let (unconfirmed, rejected, disconnected) = (r.unconfirmed, r.rejected, r.disconnected);
    let submit_rate = r.submit_rate;
    // Confirmed fraction of the *sampled* writes; used to estimate committed
    // rate without confirming every single write under a firehose.
    let confirmed_frac = if tracked == 0 {
        0.0
    } else {
        confirmed as f64 / tracked as f64
    };

    println!("\n═════════════════ peregrine-bench (client mode) ═════════════════");
    println!("target node(s)       : {addrs:?}");
    println!("client host role     : external to the committee (real client RTT)");
    println!("transport / path     : QUIC SDK · table writes (submit_tx), proven-read confirm");
    println!("concurrency          : {concurrency} connection(s)");
    println!("window               : {secs:.2}s");
    println!(
        "offered rate         : {}",
        if offered == 0 {
            "max (ack-bound)".into()
        } else {
            format!("{offered} writes/s")
        }
    );
    println!("submitted (accepted) : {submitted}   →  {submit_rate:.0} writes/s achieved");
    println!(
        "confirmed            : {confirmed} / {tracked} sampled  ({:.1}% of sampled provable)",
        confirmed_frac * 100.0
    );
    println!(
        "est. committed rate  : {:.0} writes/s   (achieved submit × confirmed fraction — estimate)",
        submit_rate * confirmed_frac
    );
    println!(
        "publish→confirm      : p50 {:.1} ms | p99 {:.1} ms | max {:.0} ms   (client-observed, {} samples)",
        hist.percentile_ms(0.50),
        hist.percentile_ms(0.99),
        hist.percentile_ms(1.0),
        hist.count(),
    );
    println!("errors               : {rejected} rejected · {disconnected} disconnect · {unconfirmed} confirm-timeout");
    println!("──────────────────────────────────────────────────────────────────");
    println!("note: latency is submit → the client first proves the write committed,");
    println!("      so it includes the confirming read's round-trip; it is an upper");
    println!("      bound on in-consensus publish→commit, and the number an app feels.");
    println!("      Public, unaudited testnet — no real value. Numbers are for");
    println!("      engineering, not marketing; report validators, host, and rate with them.");
    println!("══════════════════════════════════════════════════════════════════\n");
}
