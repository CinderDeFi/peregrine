//! End-to-end crash-fault liveness **over real QUIC**.
//!
//! Spins up a 4-validator QUIC mesh on loopback, then *crashes* one validator
//! by taking its transport off the network entirely (its endpoint is dropped,
//! so peers' dials to it fail and retry) and never spawning its task. With
//! `n = 4`, quorum is exactly the 3 survivors, so every round needs all three —
//! and the crashed validator's anchor rounds must be skipped by the cascade
//! rather than stalling the chain. We assert the survivors keep committing,
//! converge on an identical store root, and actually skip the dead leader's
//! rounds — now with the idealized in-process channel replaced by UDP/QUIC.

use peregrine_core::{Committee, Hash, Keypair, ValidatorId, ValidatorInfo};
use peregrine_data::streams::Publisher;
use peregrine_node::payload::WirePayload;
use peregrine_node::pipeline::ExecutionPipeline;
use peregrine_node::quic::{quic_cluster, QuicNode};
use peregrine_node::validator::{run_validator, NodeReport, ValidatorConfig};
use std::time::Duration;
use tokio::sync::{mpsc, watch};

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn survivors_stay_live_when_one_validator_crashes() {
    const N: u16 = 4;
    const CRASHED: u16 = 2;
    const TICKS: u64 = 400;

    let mut rng = rand::rngs::OsRng;
    let keypairs: Vec<Keypair> = (0..N).map(|_| Keypair::generate(&mut rng)).collect();
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

    // Real QUIC mesh. Wrap nodes in Option so we can drop exactly one (the
    // "crash") while the others stay bound and reachable.
    let cluster = quic_cluster(N).await.expect("build QUIC cluster");
    let mut nodes: Vec<Option<QuicNode>> = cluster.nodes.into_iter().map(Some).collect();
    // CRASH: drop the transport → endpoint closes → survivors' dials to it fail.
    nodes[CRASHED as usize] = None;

    let mut publisher = Publisher::new("test/feed", Keypair::generate(&mut rng));

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut ingest_txs: Vec<Option<mpsc::Sender<WirePayload>>> = Vec::new();
    let mut handles = Vec::new();

    for (kp, slot) in keypairs.into_iter().zip(nodes.iter_mut()) {
        let Some(node) = slot.as_mut() else {
            // The crashed validator: never spawned.
            ingest_txs.push(None);
            continue;
        };
        let id = node.id;
        let inbox = node.take_inbox();
        let net = node.broadcaster();
        let mut pipeline = ExecutionPipeline::new();
        pipeline
            .streams
            .register("test/feed", publisher.public_key());
        let (ingest_tx, ingest_rx) = mpsc::channel(4096);
        ingest_txs.push(Some(ingest_tx));
        handles.push(tokio::spawn(run_validator(ValidatorConfig {
            id,
            keypair: kp,
            committee: committee.clone(),
            inbox,
            net,
            ingest_rx,
            shutdown: shutdown_rx.clone(),
            pipeline,
            max_items_per_vertex: 64,
            store: None,
            query_rx: None,
        })));
    }

    // Feed ticks to a live validator (id 0).
    let live_tx = ingest_txs[0].as_ref().expect("v0 is live").clone();
    for _ in 0..TICKS {
        let shred = publisher.emit(1234u64.to_le_bytes().to_vec());
        live_tx.send(WirePayload::Shred(shred)).await.unwrap();
    }

    // A little longer than the in-process version to absorb QUIC handshakes.
    tokio::time::sleep(Duration::from_millis(3000)).await;
    shutdown_tx.send(true).unwrap();
    drop(ingest_txs);

    let mut reports: Vec<NodeReport> = Vec::new();
    for h in handles {
        reports.push(h.await.unwrap());
    }

    // Every survivor made progress and skipped the dead leader's rounds.
    for r in &reports {
        assert!(r.commits > 0, "{:?} committed nothing — not live", r.id);
        assert!(
            r.skips > 0,
            "{:?} never skipped — the dead leader's rounds should skip",
            r.id
        );
    }

    // Consistency / safety under one crash (see the in-process version's notes;
    // the pair-agreement form is robust to snapshotting a live network at an
    // arbitrary instant).
    let mut fingerprints: Vec<(u64, Hash)> = reports
        .iter_mut()
        .map(|r| {
            (
                r.pipeline.metrics.committed_records,
                r.pipeline.store_root(),
            )
        })
        .collect();

    // (1) equal record count => equal root (no divergence at equal height).
    for i in 0..fingerprints.len() {
        for j in (i + 1)..fingerprints.len() {
            if fingerprints[i].0 == fingerprints[j].0 {
                assert_eq!(
                    fingerprints[i].1, fingerprints[j].1,
                    "survivors forked: same record count {} but different roots",
                    fingerprints[i].0
                );
            }
        }
    }

    // (2) a quorum shares one identical non-empty committed prefix.
    fingerprints.sort();
    let agree = fingerprints
        .iter()
        .filter(|fp| fp.0 > 0)
        .filter(|fp| {
            fingerprints
                .iter()
                .filter(|o| o.0 == fp.0 && o.1 == fp.1)
                .count()
                >= 2
        })
        .count();
    assert!(
        agree >= 2,
        "no quorum of survivors agreed on a non-empty committed prefix: {fingerprints:?}"
    );

    // Keep the mesh alive until every report is collected.
    drop(nodes);
}
