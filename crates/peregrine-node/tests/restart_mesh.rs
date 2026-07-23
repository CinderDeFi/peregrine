//! Restarting a **whole committee** from disk, with a peer that comes up late.
//!
//! `restart_recovery` covers the easy half of restart: one of four validators
//! dies while a quorum stays up, so the survivors keep proposing and the
//! returning node has a live network to sync against. This test covers the half
//! that a two-server testnet actually hits — *every* node is stopped, then every
//! node is restarted from its own storage.
//!
//! # The bug this pins
//!
//! Proposal is message-driven: a validator proposes round `r+1` when its DAG
//! holds a stake quorum at round `r`. A graceful stop therefore freezes each
//! node at precisely the point where it is *waiting for a peer's next vertex* —
//! that is what "idle" means here. On restart, both nodes reload exactly that
//! state and neither re-sends anything, so neither ever receives the vertex it
//! is blocked on. Both processes are healthy, the QUIC mesh is up, RPC answers,
//! CPU is idle, and consensus never advances again. The only recovery was
//! wiping storage and restarting from genesis, which is not a recovery.
//!
//! With a 2-validator committee the quorum threshold is the whole committee, so
//! the deadlock is deterministic rather than a race — which makes it the right
//! shape for a regression test.
//!
//! The test also restarts the two nodes *sequentially*, with a gap: node 0 comes
//! back while node 1 is still down and must sit there without a peer, then node
//! 1 arrives. That is the real operational sequence (`systemctl start` on one
//! host, then the other), and it exercises the redial path as well as the
//! stall-announce path.

use peregrine_core::{Hash, Keypair, ValidatorId};
use peregrine_node::devnet::{run_single_validator, SingleValidatorOptions, Validator};
use peregrine_node::genesis::Genesis;
use peregrine_sdk::{Client, Instr, TableId};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const N: usize = 2;

/// How long any one condition may take before we stop believing the network is
/// merely slow. Generous on purpose: a healthy run exits each poll as soon as
/// the condition holds, so overshooting is free. The bug this pins never
/// recovers, so the timeout is only ever reached when something is wrong.
const CONDITION_TIMEOUT: Duration = Duration::from_secs(60);
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Grab `n` distinct free UDP ports (bind all at once so they can't collide,
/// then release them for the QUIC endpoints to rebind). The mesh addresses must
/// stay identical across the restart — that is what the peers redial.
fn free_addrs(n: usize) -> Vec<SocketAddr> {
    let socks: Vec<std::net::UdpSocket> = (0..n)
        .map(|_| std::net::UdpSocket::bind("127.0.0.1:0").expect("bind"))
        .collect();
    socks
        .iter()
        .map(|s| s.local_addr().expect("addr"))
        .collect()
}

/// `table[key] = value`, the smallest program that changes committed state.
fn write_program(table: TableId, key: &[u8], value: u64) -> Vec<Instr> {
    vec![
        Instr::Push(value),
        Instr::StoreTable {
            table,
            key: key.to_vec(),
        },
        Instr::Halt,
    ]
}

/// Start one validator identity against a fixed mesh address list and its own
/// on-disk storage directory. Called once per node per launch, so the second
/// call for an id is a genuine restart-from-disk.
///
/// Rebinding the *same* UDP port races the OS releasing it from the previous
/// instance — a real process restart never sees this, but an in-process one
/// does — so binding is retried rather than slept on. The deadline is only
/// reached if the port is never released, which is a genuine failure.
async fn launch(
    i: usize,
    secrets: &[[u8; 32]],
    genesis: &Genesis,
    mesh: &[SocketAddr],
    dir: &Path,
) -> Validator {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut last = String::new();
    while Instant::now() < deadline {
        match run_single_validator(SingleValidatorOptions {
            identity: ValidatorId(i as u16),
            keypair: Keypair::from_bytes(&secrets[i]),
            committee: genesis.committee().expect("committee"),
            addrs: mesh.to_vec(),
            rpc_addr: "127.0.0.1:0".parse().expect("rpc addr"),
            max_items_per_vertex: 64,
            storage: Some(dir.to_path_buf()),
            chain_id: genesis.chain_id,
            faucet: None,
            allocations: vec![],
        })
        .await
        {
            Ok(v) => return v,
            Err(e) => {
                last = format!("{e:#}");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
    panic!("start validator {i}: {last}");
}

/// Poll `cond` until it holds, or fail with `what` after [`CONDITION_TIMEOUT`].
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

/// True when every node proves `table[key] == value` against its *own* store
/// root and all the roots agree — i.e. the write is committed everywhere and
/// the committee has not forked.
async fn all_agree_on(clients: &[Client], table: TableId, key: &[u8], value: u64) -> bool {
    let mut roots: Vec<Hash> = Vec::with_capacity(clients.len());
    for c in clients {
        let Ok(root) = c.store_root().await else {
            return false;
        };
        match c.prove_read(table, key).await {
            Ok(Some(read))
                if read.verify(&root)
                    && read.value.len() >= 8
                    && u64::from_le_bytes(read.value[..8].try_into().expect("8 bytes"))
                        == value => {}
            _ => return false,
        }
        roots.push(root);
    }
    roots[0] != Hash::ZERO && roots.windows(2).all(|w| w[0] == w[1])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_restored_committee_rejoins_and_commits_without_a_wipe() {
    let (genesis, keys, _) = Genesis::generate(N as u16, 4242, "restart-mesh", false);
    let secrets: Vec<[u8; 32]> = keys.iter().map(|k| k.to_bytes()).collect();
    let mesh = free_addrs(N);

    let base = std::env::temp_dir().join(format!("peregrine-restart-mesh-{}", std::process::id()));
    let dirs: Vec<PathBuf> = (0..N).map(|i| base.join(format!("data-{i}"))).collect();
    for d in &dirs {
        let _ = std::fs::remove_dir_all(d);
        std::fs::create_dir_all(d).expect("create storage dir");
    }

    let table = TableId::named("restart.mesh");

    // ── Phase 1: a clean run that commits ───────────────────────────────────
    let mut nodes: Vec<Validator> = Vec::new();
    for (i, dir) in dirs.iter().enumerate() {
        nodes.push(launch(i, &secrets, &genesis, &mesh, dir).await);
    }

    let mut clients = Vec::new();
    for v in &nodes {
        clients.push(Client::connect(v.rpc_addr).await.expect("connect"));
    }
    clients[0]
        .submit_tx(write_program(table, b"before", 111))
        .await
        .expect("submit pre-restart tx");
    wait_for(
        "the fresh committee to commit the pre-restart write",
        || all_agree_on(&clients, table, b"before", 111),
    )
    .await;

    // ── Phase 2: stop everything, gracefully (each node flushes on the way
    //     out, which is exactly what leaves it parked waiting on its peer).
    drop(clients);
    for v in nodes.drain(..) {
        v.shutdown().await.expect("graceful shutdown");
    }

    // ── Phase 3: bring node 0 back alone. Its peer is down, so it cannot and
    //     must not commit anything — but it must stay responsive and keep
    //     redialing rather than wedging or dying.
    let node0 = launch(0, &secrets, &genesis, &mesh, &dirs[0]).await;
    let client0 = Client::connect(node0.rpc_addr).await.expect("reconnect v0");
    tokio::time::sleep(Duration::from_secs(2)).await;
    let solo_root = client0
        .store_root()
        .await
        .expect("restored node answers RPC with no peer");
    assert_ne!(
        solo_root,
        Hash::ZERO,
        "the restored node lost its committed state"
    );
    assert!(
        matches!(client0.prove_read(table, b"before").await, Ok(Some(_))),
        "the pre-restart write did not survive the restart"
    );

    // ── Phase 4: the peer arrives late. Both nodes are now restored from disk,
    //     parked on the round each was waiting for when it stopped.
    let node1 = launch(1, &secrets, &genesis, &mesh, &dirs[1]).await;
    let client1 = Client::connect(node1.rpc_addr).await.expect("reconnect v1");
    let clients = vec![client0, client1];

    // ── Phase 5: a *new* transaction must commit on both. This is the whole
    //     point: before the fix the mesh came up, RPC answered, and this write
    //     never committed on either node.
    clients[1]
        .submit_tx(write_program(table, b"after", 222))
        .await
        .expect("submit post-restart tx");
    wait_for(
        "the restored committee to resume committing (new write on both nodes)",
        || all_agree_on(&clients, table, b"after", 222),
    )
    .await;

    // The pre-restart write is still there and still verifies — recovery did
    // not silently rebuild state from scratch.
    assert!(
        all_agree_on(&clients, table, b"before", 111).await,
        "the pre-restart write must survive alongside the post-restart one"
    );

    drop(clients);
    for v in [node0, node1] {
        v.shutdown().await.expect("final shutdown");
    }
    for d in &dirs {
        let _ = std::fs::remove_dir_all(d);
    }
    let _ = std::fs::remove_dir(&base);
}
