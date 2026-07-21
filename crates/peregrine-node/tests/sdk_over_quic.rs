//! End-to-end SDK ↔ node integration over real QUIC.
//!
//! Starts a local devnet (real consensus + pipeline + client-facing RPC
//! endpoint), then drives it exclusively through the public `peregrine-sdk`
//! client — no in-process shortcuts. This is the path an application takes:
//!
//!   1. connect + ping over QUIC;
//!   2. **publish** signed stream records → they ride consensus and
//!      materialize into `sys.stream_ticks`;
//!   3. **submit a Talon tx** (a bounded loop summing 1..=10) → executed on
//!      commit against the table store;
//!   4. **proven read** the results and **verify** them against the store root
//!      — the light-client trust path, where only 32 bytes are trusted;
//!   5. a tampered value must fail verification, and an absent key must read
//!      back as `None`.

use peregrine_node::devnet::{Devnet, DEMO_STREAM};
use peregrine_node::pipeline::ticks_table;
use peregrine_sdk::{Client, Hash, Instr, ProvenRead, TableId};
use std::time::Duration;

/// Poll a proven read until it appears or we give up (commit is asynchronous).
async fn await_read(client: &Client, table: TableId, key: &[u8]) -> Option<ProvenRead> {
    for _ in 0..100 {
        match client.prove_read(table, key).await {
            Ok(Some(read)) => return Some(read),
            _ => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    None
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sdk_drives_a_node_over_quic() {
    let mut devnet = Devnet::start().await.expect("start devnet");
    let client = Client::connect(devnet.rpc_addr)
        .await
        .expect("connect over QUIC");

    // (1) liveness
    client.ping().await.expect("ping");

    // (2) publish signed stream records through the SDK
    let stream_id = devnet.publisher.stream_id();
    for i in 0..16u64 {
        let shred = devnet.publisher.emit((1_000 + i).to_le_bytes().to_vec());
        client.publish(shred).await.expect("publish");
    }

    // (3) submit a Talon tx: bounded loop summing 1..=10 into a contract table
    let answers = TableId::named("sdk.contract");
    let sum = b"sum".to_vec();
    client
        .submit_tx(vec![
            Instr::Push(0), // 0
            Instr::StoreTable {
                table: answers,
                key: sum.clone(),
            }, // 1  sum = 0
            Instr::Push(10), // 2  i = 10
            Instr::Dup,     // 3  test
            Instr::JumpIf(6), // 4
            Instr::Jump(13), // 5  -> end
            Instr::Dup,     // 6  body
            Instr::LoadTable {
                table: answers,
                key: sum.clone(),
            }, // 7
            Instr::Add,     // 8
            Instr::StoreTable {
                table: answers,
                key: sum.clone(),
            }, // 9  sum += i
            Instr::Push(1), // 10
            Instr::Sub,     // 11 i -= 1
            Instr::Jump(3), // 12 loop
            Instr::Halt,    // 13
        ])
        .await
        .expect("submit tx");

    // (4) proven read of the VM result + light-client verification
    let read = await_read(&client, answers, b"sum")
        .await
        .expect("tx result committed");
    assert_eq!(
        u64::from_le_bytes(read.value[..8].try_into().unwrap()),
        55,
        "on-chain loop should sum 1..=10"
    );
    let root = client.store_root().await.expect("store root");
    assert_ne!(root, Hash::ZERO, "committed state is non-empty");
    assert!(
        read.verify(&root),
        "proof must verify against the store root"
    );

    // The published stream tick materialized and is provable too.
    let mut tick_key = Vec::with_capacity(40);
    tick_key.extend_from_slice(&stream_id.0 .0);
    tick_key.extend_from_slice(&0u64.to_be_bytes()); // seq 0
    let tick = await_read(&client, ticks_table(), &tick_key)
        .await
        .expect("tick committed");
    assert_eq!(
        u64::from_le_bytes(tick.value[..8].try_into().unwrap()),
        1_000
    );
    let root = client.store_root().await.expect("store root");
    assert!(tick.verify(&root), "stream tick proof must verify");

    // (5) a tampered value must not verify against the same root.
    let mut forged = tick.clone();
    forged.value = 9_999u64.to_le_bytes().to_vec();
    assert!(!forged.verify(&root), "tampered value must be rejected");

    // An absent key reads back as None rather than erroring.
    let missing = client
        .prove_read(answers, b"nope")
        .await
        .expect("absent read ok");
    assert!(missing.is_none(), "absent key should be None");

    let reports = devnet.shutdown().await.expect("shutdown");
    let v0 = &reports[0]; // the validator the SDK was talking to
    assert!(v0.commits > 0, "devnet committed");
    assert!(
        v0.pipeline.metrics.committed_records >= 16,
        "all published records committed"
    );
    assert!(
        v0.pipeline.metrics.committed_txs >= 1,
        "the Talon tx executed"
    );
    let _ = DEMO_STREAM; // the devnet's pre-registered stream
}
