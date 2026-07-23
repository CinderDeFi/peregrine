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

// ── claim submission over RPC ───────────────────────────────────────────────

/// Claims can now reach a node over the network, not just via in-process
/// ingest. Acceptance into the queue is **not** acceptance of the claim: the
/// proof is checked during commit by every validator, and this devnet runs the
/// fail-closed default policy, so the claim must be dropped there.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_claim_can_be_submitted_over_rpc_but_still_must_verify() {
    use peregrine_interop::zk::{Claim, Journal, NativeProver, Prover};

    let devnet = Devnet::start().await.expect("devnet");
    let client = Client::connect(devnet.rpc_addr).await.expect("connect");

    let claim = NativeProver
        .prove(Journal {
            chain_id: 1,
            block_number: 25_580_735,
            block_hash: [0x11; 32],
            state_root: [0x22; 32],
            claim: Claim::Storage {
                address: [0xc0; 20],
                slot: [0x02; 32],
                value: [0x12; 32],
            },
        })
        .unwrap();

    // The RPC accepts it into the ingest queue…
    client
        .submit_claim(claim)
        .await
        .expect("claim enters the ingest queue");

    // …and now we need a *happens-after* signal that consensus has actually run
    // commit over the round carrying the claim — otherwise the reject metric is
    // read before the claim was ever evaluated, which is the race that flaked
    // this test after the validator-loop timing changed. A fixed sleep only
    // guesses at that; instead submit a marker tx on the SAME connection right
    // after the claim. The RPC enqueues each submission before it answers, and
    // the ingest queue is FIFO, so the marker sits strictly behind the claim;
    // consensus commits in causal order, so once the marker's result is
    // committed and provable, the claim (in an earlier-or-equal vertex) has been
    // committed and evaluated by the commit rule. No verification is weakened:
    // this only synchronises the assertion with the commit it is asserting about.
    let marker = TableId::named("sdk.claim_marker");
    client
        .submit_tx(vec![
            Instr::Push(1),
            Instr::StoreTable {
                table: marker,
                key: b"done".to_vec(),
            },
            Instr::Halt,
        ])
        .await
        .expect("submit marker tx");
    assert!(
        await_read(&client, marker, b"done").await.is_some(),
        "marker tx must commit — its round carries the claim, so the claim was evaluated"
    );

    // Consensus refused the claim (no verifier, no anchors): nothing lands in
    // sys.eth_state. Checked live, and again against the final metrics below.
    let key = peregrine_node::pipeline::eth_state_key(1, &[0xc0; 20], &[0x02; 32]);
    let stored = client
        .prove_read(peregrine_node::pipeline::eth_state_table(), &key)
        .await
        .expect("query ok");
    assert!(stored.is_none(), "an unproven claim must not become state");

    let reports = devnet.shutdown().await.expect("shutdown");
    assert!(
        reports[0].pipeline.metrics.foreign_claims_rejected >= 1,
        "the claim should have been seen and rejected during commit (marker committed, so its \
         round — carrying the claim — was evaluated; rejected={}, applied={})",
        reports[0].pipeline.metrics.foreign_claims_rejected,
        reports[0].pipeline.metrics.foreign_claims_applied,
    );
    assert_eq!(
        reports[0].pipeline.metrics.foreign_claims_applied, 0,
        "and nothing should have been applied"
    );
}

/// Rate limiting must actually bite: a flood of claims on one connection gets
/// refused rather than filling the ingest queue.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn claim_submission_is_rate_limited() {
    use peregrine_interop::zk::{Claim, Journal, NativeProver, Prover};

    let devnet = Devnet::start().await.expect("devnet");
    let client = Client::connect(devnet.rpc_addr).await.expect("connect");

    let make = |i: u8| {
        let mut value = [0u8; 32];
        value[31] = i;
        NativeProver
            .prove(Journal {
                chain_id: 1,
                block_number: 1,
                block_hash: [0x11; 32],
                state_root: [0x22; 32],
                claim: Claim::Storage {
                    address: [0xc0; 20],
                    slot: [0x02; 32],
                    value,
                },
            })
            .unwrap()
    };

    let mut accepted = 0;
    let mut refused = 0;
    for i in 0..24u8 {
        match client.submit_claim(make(i)).await {
            Ok(()) => accepted += 1,
            Err(_) => refused += 1,
        }
    }
    assert!(
        accepted > 0,
        "some claims should get through the burst allowance"
    );
    assert!(
        refused > 0,
        "a burst of {} claims must hit the limiter (accepted {accepted})",
        24
    );

    // Cheap requests still work: the limiter throttles, it does not wedge the
    // connection.
    client
        .ping()
        .await
        .expect("ping is cheap enough to still succeed");

    devnet.shutdown().await.expect("shutdown");
}
