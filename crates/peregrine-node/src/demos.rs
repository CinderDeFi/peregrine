//! Runnable SDK walkthroughs.
//!
//! Each demo boots a real local [`Devnet`](crate::devnet::Devnet) — QUIC mesh,
//! consensus, pipeline, RPC listener — and then drives it **only through the
//! public `peregrine-sdk` client**, with no in-process shortcuts. What you read
//! here is what an application would write.
//!
//! They live in the library (rather than only in `examples/`) so both
//! `cargo run --example publish_stream` and `peregrine sdk example
//! publish-stream` execute the same code.

use crate::devnet::Devnet;
use crate::pipeline::ticks_table;
use anyhow::{bail, Result};
use peregrine_sdk::{Client, Hash, Instr, ProvenRead, TableId};
use std::time::Duration;

/// Poll a proven read until it appears (commit is asynchronous).
async fn await_read(client: &Client, table: TableId, key: &[u8]) -> Result<ProvenRead> {
    for _ in 0..100 {
        if let Some(read) = client.prove_read(table, key).await? {
            return Ok(read);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    bail!("nothing committed within the timeout")
}

/// Publish signed stream records, then read one back with a proof.
///
/// This is the oracle/DePIN path: sign a record, push it over QUIC, and it
/// rides *inside consensus vertices* into the `sys.stream_ticks` table.
pub async fn publish_stream() -> Result<()> {
    let mut devnet = Devnet::start().await?;
    println!("devnet rpc listening on {}\n", devnet.rpc_addr);

    let client = Client::connect(devnet.rpc_addr).await?;
    client.ping().await?;

    let stream_id = devnet.publisher.stream_id();
    let mut price: u64 = 6_150_000; // $61,500.00 in cents
    for i in 0..50u64 {
        price = price.wrapping_add(i * 7 % 23).saturating_sub(i * 3 % 19);
        client
            .publish(devnet.publisher.emit(price.to_le_bytes().to_vec()))
            .await?;
    }
    println!("published 50 signed ticks to stream {stream_id:?}");

    let mut key = Vec::with_capacity(40);
    key.extend_from_slice(&stream_id.0 .0);
    key.extend_from_slice(&0u64.to_be_bytes()); // seq 0

    let read = await_read(&client, ticks_table(), &key).await?;
    let root = client.store_root().await?;
    println!(
        "\ncommitted tick seq 0 = {} cents",
        u64::from_le_bytes(read.value[..8].try_into()?)
    );
    println!("store root           = {root}");
    println!("proof verifies       = {}", read.verify(&root));

    devnet.shutdown().await?;
    Ok(())
}

/// Submit a Talon transaction and read back its result.
///
/// The program is a bounded loop that sums 1..=10 entirely on-chain, using a
/// table cell as its accumulator — control flow, arithmetic, and data-native
/// host calls, all metered.
pub async fn submit_tx() -> Result<()> {
    let devnet = Devnet::start().await?;
    println!("devnet rpc listening on {}\n", devnet.rpc_addr);

    let client = Client::connect(devnet.rpc_addr).await?;
    let table = TableId::named("example.contract");
    let sum = b"sum".to_vec();

    client
        .submit_tx(vec![
            Instr::Push(0), // 0
            Instr::StoreTable {
                table,
                key: sum.clone(),
            }, // 1  sum = 0
            Instr::Push(10), // 2  i = 10
            Instr::Dup,     // 3  test
            Instr::JumpIf(6), // 4  i != 0 -> body
            Instr::Jump(13), // 5  else -> end
            Instr::Dup,     // 6  body
            Instr::LoadTable {
                table,
                key: sum.clone(),
            }, // 7
            Instr::Add,     // 8
            Instr::StoreTable {
                table,
                key: sum.clone(),
            }, // 9  sum += i
            Instr::Push(1), // 10
            Instr::Sub,     // 11 i -= 1
            Instr::Jump(3), // 12 loop
            Instr::Halt,    // 13
        ])
        .await?;
    println!("submitted Talon tx (on-chain loop summing 1..=10)");

    let read = await_read(&client, table, b"sum").await?;
    let root = client.store_root().await?;
    let value = u64::from_le_bytes(read.value[..8].try_into()?);
    println!("\nexample.contract[\"sum\"] = {value}   (expected 55)");
    println!(
        "proof verifies against root {root} = {}",
        read.verify(&root)
    );

    devnet.shutdown().await?;
    Ok(())
}

/// The light-client trust story: verify a read, then try to forge it.
///
/// A light client trusts **32 bytes** — the store root — and nothing else. It
/// does not trust the node that served the value: the inclusion proof either
/// reconstructs the root or it doesn't.
pub async fn light_client() -> Result<()> {
    let mut devnet = Devnet::start().await?;
    let client = Client::connect(devnet.rpc_addr).await?;

    let stream_id = devnet.publisher.stream_id();
    for i in 0..8u64 {
        client
            .publish(devnet.publisher.emit((7_000 + i).to_le_bytes().to_vec()))
            .await?;
    }

    let mut key = Vec::with_capacity(40);
    key.extend_from_slice(&stream_id.0 .0);
    key.extend_from_slice(&0u64.to_be_bytes());
    let read = await_read(&client, ticks_table(), &key).await?;

    // The only thing a light client must obtain honestly (from consensus or a
    // checkpoint) is this 32-byte root.
    let root = client.store_root().await?;
    println!("trusted store root : {root}");
    println!(
        "value              : {}",
        u64::from_le_bytes(read.value[..8].try_into()?)
    );
    println!("\nverification:");
    println!("  genuine proof            … {}", ok(read.verify(&root)));

    // 1. Tamper with the value.
    let mut forged = read.clone();
    forged.value = 999_999u64.to_le_bytes().to_vec();
    println!("  tampered value           … {}", ok(!forged.verify(&root)));

    // 2. Verify against the wrong root.
    println!(
        "  genuine proof, bad root  … {}",
        ok(!read.verify(&Hash::ZERO))
    );

    // 3. Tamper with the proof path itself.
    let mut bent = read.clone();
    if let Some(first) = bent.row_proof.siblings.first_mut() {
        *first = Hash::ZERO;
    }
    println!("  corrupted proof path     … {}", ok(!bent.verify(&root)));

    println!("\nA light client needs the 32-byte root and nothing else.");
    devnet.shutdown().await?;
    Ok(())
}

fn ok(b: bool) -> &'static str {
    if b {
        "✓ as expected"
    } else {
        "✗ UNEXPECTED"
    }
}

// ── the full tour ───────────────────────────────────────────────────────────

/// Everything, end to end, in one command (`peregrine demo`).
///
/// Four acts, each building on the last:
///
/// 1. **Streams** — sign price ticks, watch them ride consensus into a table.
/// 2. **TalonVM** — run a metered on-chain program over that state.
/// 3. **Light client** — verify a value against the 32-byte root, then fail to
///    forge it.
/// 4. **Interop** — read *Ethereum* state from a Peregrine contract, and see
///    the guardrail that stops unverified state from being read at all.
///
/// Act 4 is the one worth watching: the default path **refuses**, because
/// nothing has been proven. The demo then shows the success path explicitly
/// labelled as insecure, so the difference is impossible to miss.
pub async fn full_demo() -> Result<()> {
    println!("\n\x1b[1m── act 1 · Streams ─────────────────────────────────────\x1b[0m");
    let mut devnet = Devnet::start().await?;
    let client = Client::connect(devnet.rpc_addr).await?;
    client.ping().await?;
    println!(
        "4-validator devnet up on {} (real QUIC mesh)",
        devnet.rpc_addr
    );

    let stream_id = devnet.publisher.stream_id();
    let mut price: u64 = 6_150_000; // BTC-USD at $61,500.00, in cents
    for i in 0..25u64 {
        price = price.wrapping_add(i * 7 % 23).saturating_sub(i * 3 % 19);
        client
            .publish(devnet.publisher.emit(price.to_le_bytes().to_vec()))
            .await?;
    }
    println!("published 25 signed price ticks to {stream_id:?}");

    let mut key = Vec::with_capacity(40);
    key.extend_from_slice(&stream_id.0 .0);
    key.extend_from_slice(&0u64.to_be_bytes());
    let tick = await_read(&client, ticks_table(), &key).await?;
    println!(
        "  → committed and materialized: tick #0 = {} cents",
        u64::from_le_bytes(tick.value[..8].try_into()?)
    );

    println!("\n\x1b[1m── act 2 · TalonVM ─────────────────────────────────────\x1b[0m");
    let table = TableId::named("demo.contract");
    let sum = b"sum".to_vec();
    client
        .submit_tx(vec![
            Instr::Push(0),
            Instr::StoreTable {
                table,
                key: sum.clone(),
            },
            Instr::Push(10),
            Instr::Dup,
            Instr::JumpIf(6),
            Instr::Jump(13),
            Instr::Dup,
            Instr::LoadTable {
                table,
                key: sum.clone(),
            },
            Instr::Add,
            Instr::StoreTable {
                table,
                key: sum.clone(),
            },
            Instr::Push(1),
            Instr::Sub,
            Instr::Jump(3),
            Instr::Halt,
        ])
        .await?;
    let result = await_read(&client, table, b"sum").await?;
    println!(
        "on-chain loop summed 1..=10 → {} (metered: compute + data)",
        u64::from_le_bytes(result.value[..8].try_into()?)
    );

    println!("\n\x1b[1m── act 3 · Light client ────────────────────────────────\x1b[0m");
    let root = client.store_root().await?;
    println!("trusted store root : {root}");
    println!("  genuine proof           … {}", ok(result.verify(&root)));
    let mut forged = result.clone();
    forged.value = 999u64.to_le_bytes().to_vec();
    println!("  tampered value          … {}", ok(!forged.verify(&root)));
    println!(
        "  proof vs. wrong root    … {}",
        ok(!result.verify(&Hash::ZERO))
    );

    devnet.shutdown().await?;
    eth_interop_act()?;
    println!("\nEverything above ran against real consensus, real QUIC, and real proofs.");
    println!("See the README for what is *not* yet real — the list is deliberately long.\n");
    Ok(())
}

/// Act 4: reading Ethereum state from a Peregrine contract.
///
/// Runs the pipeline directly rather than over the network, because submitting
/// a proof-carrying claim over RPC is not wired up yet (a documented gap).
fn eth_interop_act() -> Result<()> {
    use crate::payload::WirePayload;
    use crate::pipeline::{eth_state_key, eth_state_table, ClaimPolicy, ExecutionPipeline};
    use peregrine_interop::beacon::Anchor;
    use peregrine_interop::zk::{
        Claim, Journal, NativeProver, NativeVerifier, Prover, StrictVerifier,
    };

    println!("\n\x1b[1m── act 4 · Ethereum interop ────────────────────────────\x1b[0m");

    // WETH, slot 2 = decimals = 18 (the value we proved from real mainnet data
    // in `cargo test -p peregrine-interop`).
    const WETH: [u8; 20] = [
        0xc0, 0x2a, 0xaa, 0x39, 0xb2, 0x23, 0xfe, 0x8d, 0x0a, 0x0e, 0x5c, 0x4f, 0x27, 0xea, 0xd9,
        0x08, 0x3c, 0x75, 0x6c, 0xc2,
    ];
    let mut slot = [0u8; 32];
    slot[31] = 2;
    let mut value = [0u8; 32];
    value[31] = 18;
    let block_hash = [0x11u8; 32];

    let reader = vec![
        Instr::LoadEthState {
            chain_id: 1,
            address: WETH,
            slot,
        },
        Instr::StoreTable {
            table: TableId::named("demo.mirror"),
            key: b"weth_decimals".to_vec(),
        },
        Instr::Halt,
    ];

    // ── the guardrail ──
    let mut node = ExecutionPipeline::new();
    node.claim_policy = ClaimPolicy::Verified {
        verifier: Box::new(StrictVerifier {
            expected_image_id: [0xAA; 32],
        }),
        chain_id: 1,
    };
    node.apply_payload(&WirePayload::TalonTx {
        program: reader.clone(),
    });
    println!("a contract reads WETH.decimals() with nothing proven yet:");
    println!(
        "  → tx trapped, nothing written … {}",
        ok(node
            .prove_read(TableId::named("demo.mirror"), b"weth_decimals")
            .is_none())
    );
    println!("     (LoadEthState refuses to return 0 for unverified state)");

    let claim = NativeProver.prove(Journal {
        chain_id: 1,
        block_number: 25_580_735,
        block_hash,
        state_root: [0x22; 32],
        claim: Claim::Storage {
            address: WETH,
            slot,
            value,
        },
    })?;
    println!(
        "  → a claim with no ZK proof is rejected … {}",
        ok(node.apply_foreign_claim(&claim).is_err())
    );

    // ── the success path, explicitly insecure ──
    println!("\n\x1b[33m  [demo-only: accepting an unproven claim so the rest can run]\x1b[0m");
    let mut node = ExecutionPipeline::new();
    node.claim_policy = ClaimPolicy::Verified {
        verifier: Box::new(NativeVerifier),
        chain_id: 1,
    };
    node.anchors.insert(Anchor {
        slot: 14_817_376,
        block_number: 25_580_735,
        block_hash,
        state_root: [0x22; 32],
    })?;
    node.apply_foreign_claim(&claim)
        .map_err(|e| anyhow::anyhow!(e))?;
    println!(
        "  → verified Ethereum state stored in sys.eth_state … {}",
        ok(node
            .prove_read(eth_state_table(), &eth_state_key(1, &WETH, &slot))
            .is_some())
    );

    node.apply_payload(&WirePayload::TalonTx { program: reader });
    let mirrored = node
        .prove_read(TableId::named("demo.mirror"), b"weth_decimals")
        .ok_or_else(|| anyhow::anyhow!("contract should have read the verified value"))?;
    println!(
        "  → contract read WETH.decimals() = {}",
        u64::from_le_bytes(mirrored.value[..8].try_into()?)
    );

    let root = node.store_root();
    println!(
        "  → and it is provable against Peregrine's root … {}",
        ok(mirrored.verify(&root))
    );
    println!("\n  In production the claim carries an SP1 proof and the block must be");
    println!("  anchored by a BLS-verified beacon update. Both are implemented; see");
    println!("  `cargo test -p peregrine-interop --features bls`.");
    Ok(())
}
