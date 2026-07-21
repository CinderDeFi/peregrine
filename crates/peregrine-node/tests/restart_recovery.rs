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
//! After the network quiesces (input stops, everyone drains), we assert:
//!   1. every validator — including the restarted one — converges to the exact
//!      same non-empty store root (no fork, full recovery of pre-crash state);
//!   2. the restarted node committed *after* it came back (it actively rejoined
//!      rather than sitting frozen on its restored prefix).

use peregrine_core::{Committee, Keypair, PublicKey, ValidatorId, ValidatorInfo};
use peregrine_data::streams::Publisher;
use peregrine_data::tables::TableId;
use peregrine_node::network::{build_network, Broadcaster, Inbox};
use peregrine_node::payload::WirePayload;
use peregrine_node::pipeline::ExecutionPipeline;
use peregrine_node::store::Store;
use peregrine_node::validator::{run_validator, NodeReport, ValidatorConfig};
use peregrine_vm::Instr;
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

const N: u16 = 4;
const RESTART: u16 = 2; // validator we kill and bring back

/// Build a validator task with persistence enabled. A fresh pipeline is used
/// every spawn; `run_validator` restores table state from the store on boot.
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
        query_rx: None,
    }))
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

    let mut shutdown_txs: Vec<watch::Sender<bool>> = Vec::new();
    let mut ingest_txs: Vec<mpsc::Sender<WirePayload>> = Vec::new();
    let mut handles: Vec<Option<JoinHandle<NodeReport>>> = Vec::new();

    for inbox in inboxes.into_iter() {
        let id = inbox.id.0;
        let (stx, srx) = watch::channel(false);
        let (itx, irx) = mpsc::channel(4096);
        let store = Store::open(store_path(id)).expect("open store");
        let keypair = Keypair::from_bytes(&secrets[id as usize]);
        handles.push(Some(spawn(
            id,
            keypair,
            committee.clone(),
            inbox,
            bcast.clone(),
            irx,
            srx,
            publisher_pk,
            store,
        )));
        shutdown_txs.push(stx);
        ingest_txs.push(itx);
    }

    // Phase 1: feed ticks to validator 0 and let the network commit them.
    for _ in 0..200 {
        let shred = publisher.emit(1111u64.to_le_bytes().to_vec());
        ingest_txs[0].send(WirePayload::Shred(shred)).await.unwrap();
    }
    // Also commit a Talon VM tx (20 + 22 = 42) *before* the crash, so recovery
    // must reconstruct its table write from persisted state, not just re-run it.
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
    tokio::time::sleep(Duration::from_millis(1200)).await;

    // Phase 2: kill validator RESTART. Graceful shutdown → final flush to disk,
    // then its task returns and drops its Store (releasing the file lock).
    shutdown_txs[RESTART as usize].send(true).unwrap();
    let pre_restart = handles[RESTART as usize].take().unwrap().await.unwrap();
    assert!(
        pre_restart.commits > 0,
        "validator committed before the crash"
    );

    // Phase 3: network keeps making progress while RESTART is down (kept short
    // so the gap it must re-sync on return stays modest).
    for _ in 0..150 {
        let shred = publisher.emit(2222u64.to_le_bytes().to_vec());
        ingest_txs[0].send(WirePayload::Shred(shred)).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(600)).await;

    // Phase 4: restart RESTART from disk and reconnect it to the live network.
    let inbox2 = net.reconnect(ValidatorId(RESTART));
    let (stx2, srx2) = watch::channel(false);
    let (_itx2, irx2) = mpsc::channel(4096);
    let store2 = Store::open(store_path(RESTART)).expect("reopen store");
    let keypair2 = Keypair::from_bytes(&secrets[RESTART as usize]);
    handles[RESTART as usize] = Some(spawn(
        RESTART,
        keypair2,
        committee.clone(),
        inbox2,
        bcast.clone(),
        irx2,
        srx2,
        publisher_pk,
        store2,
    ));
    shutdown_txs[RESTART as usize] = stx2;

    // Phase 5: a little more input, then let everyone catch up and quiesce.
    for _ in 0..150 {
        let shred = publisher.emit(3333u64.to_le_bytes().to_vec());
        ingest_txs[0].send(WirePayload::Shred(shred)).await.unwrap();
    }
    // Stop feeding, then drain: with no new input the frontier stabilizes and
    // every live node commits up to the identical point. Empty rounds keep
    // being proposed and broadcast, which keeps driving the restarted node's
    // catch-up sync until it fully converges; the window is generous so this
    // completes well before the deadline.
    drop(ingest_txs);
    tokio::time::sleep(Duration::from_millis(6000)).await;

    // Stop everyone and collect final reports.
    for stx in &shutdown_txs {
        let _ = stx.send(true);
    }
    let mut reports: Vec<NodeReport> = Vec::new();
    for h in handles.into_iter().flatten() {
        reports.push(h.await.unwrap());
    }
    assert_eq!(reports.len(), N as usize, "all four validators reported");

    // (1) After quiescence, every validator — including the restarted one —
    //     agrees on one identical, non-empty store root.
    let roots: Vec<(ValidatorId, peregrine_core::Hash)> = reports
        .iter_mut()
        .map(|r| (r.id, r.pipeline.store_root()))
        .collect();
    let first = roots[0].1;
    assert_ne!(
        first,
        peregrine_core::Hash::ZERO,
        "committed state is non-empty"
    );
    for (id, root) in &roots {
        assert_eq!(
            *root, first,
            "{id:?} diverged after restart: {root} != {first} (roots: {roots:?})"
        );
    }

    // (2) The restarted node actually rejoined and did new work. Its pipeline
    //     is fresh on restart (metrics start at 0) and is only touched by *real*
    //     commits — the no-op fast-forward that rebuilds the commit cursor uses
    //     a null observer — so post-restart committed records prove it re-synced
    //     the gap it missed while down and applied it to the reloaded state.
    let restarted = reports
        .iter()
        .find(|r| r.id == ValidatorId(RESTART))
        .unwrap();
    assert!(
        restarted.pipeline.metrics.committed_records > 0,
        "restarted validator applied no records after recovery — it did not rejoin"
    );

    // (3) The Talon VM write committed before the crash survived recovery on
    //     the restarted node, and still verifies against its store root.
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
