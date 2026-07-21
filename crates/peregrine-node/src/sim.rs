//! # sim — local multi-validator demonstration
//!
//! Driven by `peregrine sim`. What this proves, end to end, on your laptop:
//!
//! 1. **Stoop DAG consensus** among 4 simulated validators: parentless
//!    genesis round, quorum-gated round advancement, implicit voting, and
//!    deterministic total-order commits.
//! 2. **Slipstream**: a publisher signs high-frequency price ticks; shreds
//!    ride *inside consensus vertices*; every validator validates,
//!    sequences, and fans them out to a live subscriber.
//! 3. **Materialized, verifiable state**: committed ticks land in the
//!    `sys.stream_ticks` table; all validators converge to the *same
//!    32-byte store root*; a light client verifies a point read against
//!    that root alone — and a tampered read fails.
//! 4. **Dual-meter fees**: data bytes priced 1000× under compute, settled
//!    50/30/20 into burn / validators / Data Endowment.
//!
//! Run: `peregrine sim` (see `peregrine sim --help` for knobs).

use crate::payload::WirePayload;
use crate::pipeline::{ticks_table, ExecutionPipeline};
use crate::quic::quic_cluster;
use crate::validator::{run_validator, NodeReport, ValidatorConfig};
use anyhow::{bail, Context, Result};
use peregrine_core::{Committee, Keypair, ValidatorId, ValidatorInfo};
use peregrine_data::fees::fmt_wing;
use peregrine_data::streams::Publisher;
use peregrine_data::tables::TableId;
use peregrine_vm::Instr;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};

/// Knobs for the demo run.
#[derive(Clone, Copy, Debug)]
pub struct SimOptions {
    /// Validators in the simulated committee.
    pub validators: u16,
    /// Signed stream records to publish.
    pub ticks: u64,
    /// Payload items batched into each proposal.
    pub max_items_per_vertex: usize,
}

impl Default for SimOptions {
    fn default() -> Self {
        Self {
            validators: 4,
            ticks: 5_000,
            max_items_per_vertex: 512,
        }
    }
}

/// Run the demonstration to completion, printing a report.
pub async fn run(opts: SimOptions) -> Result<()> {
    banner();

    // ── 1. Genesis: keys, committee, network ────────────────────────────
    let mut rng = rand::rngs::OsRng;
    let keypairs: Vec<Keypair> = (0..opts.validators)
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
    // Real QUIC mesh on loopback: each validator owns a UDP endpoint and dials
    // every peer. `cluster` must outlive the validators — it owns the endpoints
    // and the accept/writer tasks that keep the mesh up.
    let mut cluster = quic_cluster(opts.validators)
        .await
        .context("build QUIC cluster")?;
    println!(
        "• QUIC mesh up: {}",
        cluster
            .addrs
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );

    // ── 2. Register the publisher on every validator (genesis config) ───
    let mut publisher = Publisher::new("pyth.style/BTC-USD", Keypair::generate(&mut rng));
    let stream_id = publisher.stream_id();
    println!(
        "• stream registered: {:?} (publisher {:?})\n",
        stream_id,
        publisher.public_key()
    );

    // ── 3. Spawn validators ─────────────────────────────────────────────
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut ingest_txs = Vec::new();
    let mut handles = Vec::new();
    let mut subscriber = None;

    for (kp, node) in keypairs.into_iter().zip(cluster.nodes.iter_mut()) {
        let id = node.id;
        let inbox = node.take_inbox();
        let net = node.broadcaster();
        let mut pipeline = ExecutionPipeline::new();
        pipeline
            .streams
            .register("pyth.style/BTC-USD", publisher.public_key());
        // One live subscriber, attached to validator 0's fan-out.
        if id == ValidatorId(0) {
            subscriber = pipeline.subscribe(&stream_id);
        }
        let (ingest_tx, ingest_rx) = mpsc::channel(65_536);
        ingest_txs.push(ingest_tx);
        let cfg = ValidatorConfig {
            id,
            keypair: kp,
            committee: committee.clone(),
            inbox,
            net,
            ingest_rx,
            shutdown: shutdown_rx.clone(),
            pipeline,
            max_items_per_vertex: opts.max_items_per_vertex,
            // Pure in-memory demo: persistence is exercised by the node tests.
            store: None,
            query_rx: None,
        };
        handles.push(tokio::spawn(run_validator(cfg)));
    }
    let mut subscriber = subscriber.context("subscriber attached")?;

    // Count live fan-out deliveries concurrently with publishing.
    // Shared atomics let main watch progress without joining the task
    // (the broadcast sender lives inside the validator's pipeline, so the
    // channel never "closes" while reports are held).
    let fanout_count = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let fanout_last = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let (fc, fl) = (fanout_count.clone(), fanout_last.clone());
    let sub_task = tokio::spawn(async move {
        use std::sync::atomic::Ordering;
        use tokio::sync::broadcast::error::RecvError;
        loop {
            match subscriber.rx.recv().await {
                Ok(rec) => {
                    fc.fetch_add(1, Ordering::Relaxed);
                    if rec.payload.len() >= 8 {
                        let p = u64::from_le_bytes(rec.payload[..8].try_into().unwrap());
                        fl.store(p, Ordering::Relaxed);
                    }
                }
                // Lagged = we missed some fan-out messages (lossy by
                // design); keep counting what we do get.
                Err(RecvError::Lagged(_)) => continue,
                Err(RecvError::Closed) => break,
            }
        }
    });

    // ── 4. Publish high-frequency ticks + one Talon transaction ─────────
    println!(
        "publishing {} signed price ticks into validator 0's ingest…",
        opts.ticks
    );
    let t0 = Instant::now();
    let mut price: u64 = 6_150_000; // BTC-USD at $61,500.00, in cents
    for i in 0..opts.ticks {
        // Simple deterministic random walk.
        price = price.wrapping_add(i * 37 % 19).saturating_sub(i * 11 % 17);
        let shred = publisher.emit(price.to_le_bytes().to_vec());
        ingest_txs[0]
            .send(WirePayload::Shred(shred))
            .await
            .context("ingest send")?;
    }
    // A Talon transaction through the same pipeline, exercising real control
    // flow and a data-native proven read: a bounded loop sums 1..=10 into a
    // contract table cell (= 55), then reads it back *with an inclusion proof*
    // (metered for its proof bytes). Every validator runs this identically, so
    // the resulting table root stays byte-identical across the network.
    let answers = TableId::named("contract.answers");
    let sum = b"sum".to_vec();
    ingest_txs[1]
        .send(WirePayload::TalonTx {
            program: vec![
                Instr::Push(0), // 0
                Instr::StoreTable {
                    table: answers,
                    key: sum.clone(),
                }, // 1  sum = 0
                Instr::Push(10), // 2  i = 10
                Instr::Dup,     // 3  test: [i, i]
                Instr::JumpIf(6), // 4  i != 0 -> body
                Instr::Jump(13), // 5  else -> read-back
                Instr::Dup,     // 6  body: [i, i]
                Instr::LoadTable {
                    table: answers,
                    key: sum.clone(),
                }, // 7  [i, i, sum]
                Instr::Add,     // 8  [i, i+sum]
                Instr::StoreTable {
                    table: answers,
                    key: sum.clone(),
                }, // 9  sum += i
                Instr::Push(1), // 10
                Instr::Sub,     // 11 i -= 1
                Instr::Jump(3), // 12 loop
                Instr::LoadTableProven {
                    table: answers,
                    key: sum.clone(),
                }, // 13 proven read
                Instr::Halt,    // 14
            ],
        })
        .await
        .context("tx send")?;
    let publish_elapsed = t0.elapsed();

    // Adaptive drain: wait until the live subscriber has seen every tick,
    // or progress stalls (max ~10s), then stop the validators.
    {
        use std::sync::atomic::Ordering;
        let deadline = Instant::now() + Duration::from_secs(20);
        let min_run = Instant::now() + Duration::from_secs(3);
        let mut last_seen = 0u64;
        let mut stalls = 0u32; // consecutive ticks with no new fan-out
        loop {
            tokio::time::sleep(Duration::from_millis(150)).await;
            let seen = fanout_count.load(Ordering::Relaxed);
            if seen >= opts.ticks || Instant::now() > deadline {
                break;
            }
            stalls = if seen == last_seen { stalls + 1 } else { 0 };
            last_seen = seen;
            // Fan-out is bursty (commits land in batches as rounds decide),
            // so only give up after a sustained silence past a min runtime.
            if Instant::now() > min_run && stalls >= 20 {
                break;
            }
        }
    }
    shutdown_tx.send(true)?;
    drop(ingest_txs); // closes ingest channels

    let mut reports: Vec<NodeReport> = Vec::new();
    for h in handles {
        reports.push(h.await?);
    }
    sub_task.abort();
    let fanout_received = fanout_count.load(std::sync::atomic::Ordering::Relaxed);
    let fanout_last_price = fanout_last.load(std::sync::atomic::Ordering::Relaxed);

    // ── 5. Report: consensus + streams + fees ───────────────────────────
    let total_elapsed = t0.elapsed();
    println!("\n── consensus ─────────────────────────────────────────────");
    for r in &reports {
        println!(
            "  {:?}: round {:>4} | dag {:>5} | {:>4} commits | {:>3} skips | {:>6} records | {} txs | {} sync-req",
            r.id,
            r.highest_round_proposed,
            r.dag_size,
            r.commits,
            r.skips,
            r.pipeline.metrics.committed_records,
            r.pipeline.metrics.committed_txs,
            r.sync_requests_sent,
        );
    }

    let v0 = &reports[0];
    let committed = v0.pipeline.metrics.committed_records;
    println!("\n── slipstream ────────────────────────────────────────────");
    println!(
        "  ticks published        : {} in {publish_elapsed:.2?}",
        opts.ticks
    );
    println!("  ticks committed (v0)   : {committed}");
    println!(
        "  committed throughput   : {:.0} records/s (wall-clock, incl. drain)",
        committed as f64 / total_elapsed.as_secs_f64()
    );
    println!(
        "  avg publish→commit lat : {:.1} ms",
        v0.pipeline.metrics.avg_record_latency_ms()
    );
    println!(
        "  live fan-out delivered : {fanout_received} records (last price: {fanout_last_price})"
    );

    println!("\n── dual-meter fees (v0) ──────────────────────────────────");
    let split = v0.pipeline.fee_split;
    println!(
        "  burned (50%)           : {}",
        fmt_wing(split.burned_grains)
    );
    println!(
        "  validators (30%)       : {}",
        fmt_wing(split.validator_grains)
    );
    println!(
        "  data endowment (20%)   : {}",
        fmt_wing(split.endowment_grains)
    );

    // ── 6. Verifiable read: the wedge demo ──────────────────────────────
    println!("\n── verifiable state ──────────────────────────────────────");
    let mut reports = reports;
    let roots: Vec<_> = reports
        .iter_mut()
        .map(|r| (r.id, r.pipeline.store_root()))
        .collect();
    for (id, root) in &roots {
        println!("  {:?} store root: {root}", id);
    }
    let first_root = roots[0].1;
    if !roots.iter().all(|(_, r)| *r == first_root) {
        bail!("STATE DIVERGENCE — validators disagree on the store root");
    }
    println!(
        "  ✓ all {} validators converged to the same root",
        roots.len()
    );

    // Light-client flow: hold ONLY the 32-byte root; verify a proven read.
    let v0 = &mut reports[0];
    let mut key = Vec::with_capacity(40);
    key.extend_from_slice(&stream_id.0 .0);
    key.extend_from_slice(&0u64.to_be_bytes()); // tick #0
    let read = v0
        .pipeline
        .prove_read(ticks_table(), &key)
        .context("prove tick #0")?;
    let tick0_price = u64::from_le_bytes(read.value[..8].try_into().unwrap());
    println!(
        "\n  proven read: sys.stream_ticks[{stream_id:?}, seq 0] = {tick0_price} (price in cents)"
    );
    println!(
        "  light-client verify against root … {}",
        ok(read.verify(&first_root))
    );

    let mut tampered = read.clone();
    tampered.value = 999_999u64.to_le_bytes().to_vec();
    println!(
        "  tampered value rejected            … {}",
        ok(!tampered.verify(&first_root))
    );

    let answer = v0
        .pipeline
        .prove_read(answers, b"sum")
        .context("prove tx write")?;
    let sum_val = u64::from_le_bytes(answer.value[..8].try_into().unwrap());
    println!(
        "  proven read: contract.answers[\"sum\"] = {} (loop 1..=10) — verified {}",
        sum_val,
        ok(sum_val == 55 && answer.verify(&first_root)),
    );
    if sum_val != 55 {
        bail!("TalonVM control flow wrong: expected sum 55, got {sum_val}");
    }

    println!("\nStreams + verifiable state + metered VM: proven. Next: swap in the real pieces.\n");
    Ok(())
}

fn ok(b: bool) -> &'static str {
    if b {
        "✓ PASS"
    } else {
        "✗ FAIL"
    }
}

fn banner() {
    println!(
        r#"
    ┌──────────────────────────────────────────────────────────┐
    │  PEREGRINE  ·  local sim  ·  stoop dag + slipstream v0   │
    │  "fly fast. prove everything."                           │
    └──────────────────────────────────────────────────────────┘
"#
    );
}
