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
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};

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
