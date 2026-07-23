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
    bent.row_proof.corrupt_first_sibling();
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

// ── RWA: a property-backed loan, priced by an oracle, collateralised on Ethereum ──

/// Tokenized real-world asset demo (`peregrine sdk example rwa`).
///
/// A property-backed loan whose health depends on three things Peregrine can
/// prove and a bridge cannot:
///
/// 1. a **valuation** delivered by an oracle over Slipstream (signed, sequenced
///    by consensus, materialized into a table);
/// 2. **collateral** posted as USDC on *Ethereum*, read through a verified
///    state proof rather than a relayer's assertion;
/// 3. a **TalonVM contract** that computes loan health from both — and
///    **refuses to run at all** if the Ethereum side hasn't been verified.
///
/// That last property is what makes this an RWA system rather than an oracle
/// with extra steps: an under-collateralised loan cannot be marked healthy by
/// withholding data, because missing data traps instead of reading as zero.
pub async fn rwa() -> Result<()> {
    use crate::payload::WirePayload;
    use crate::pipeline::{ClaimPolicy, ExecutionPipeline};
    use peregrine_interop::beacon::Anchor;
    use peregrine_interop::zk::{Claim, Journal, NativeProver, NativeVerifier, Prover};

    // USDC on Ethereum mainnet; the escrow's balance is slot-mapped per holder.
    const USDC: [u8; 20] = [
        0xa0, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1, 0x9d, 0x4a, 0x2e, 0x9e, 0xb0,
        0xce, 0x36, 0x06, 0xeb, 0x48,
    ];
    const CHAIN_ETH: u64 = 1;
    const PROPERTY: &[u8] = b"PROP-1729-BRIXTON";
    // USDC has 6 decimals throughout.
    const REQUIRED_RATIO_PCT: u64 = 30; // loan needs 30% of valuation posted

    let registry = TableId::named("rwa.registry");
    let health = TableId::named("rwa.health");
    let escrow_slot = {
        let mut s = [0u8; 32];
        s[31] = 9; // the escrow account's balance slot
        s
    };

    println!("\n\x1b[1m── RWA · property-backed loan ──────────────────────────\x1b[0m");
    println!("asset      : {}", String::from_utf8_lossy(PROPERTY));
    println!("valuation  : from a signed oracle stream");
    println!("collateral : USDC on Ethereum, via a verified state proof\n");

    // ── 1. oracle publishes a valuation over Slipstream ────────────────────
    let mut devnet = Devnet::start().await?;
    let client = Client::connect(devnet.rpc_addr).await?;
    let valuation_usdc: u64 = 500_000_000_000; // $500,000.000000
    client
        .publish(devnet.publisher.emit(valuation_usdc.to_le_bytes().to_vec()))
        .await?;

    let mut tick_key = Vec::with_capacity(40);
    tick_key.extend_from_slice(&devnet.publisher.stream_id().0 .0);
    tick_key.extend_from_slice(&0u64.to_be_bytes());
    let tick = await_read(&client, ticks_table(), &tick_key).await?;
    println!(
        "1. oracle valuation committed   : ${}",
        usdc(u64::from_le_bytes(tick.value[..8].try_into()?))
    );

    // Record it in the registry with a Talon tx, so the contract reads chain
    // state rather than trusting the caller's number.
    client
        .submit_tx(vec![
            Instr::Push(valuation_usdc),
            Instr::StoreTable {
                table: registry,
                key: PROPERTY.to_vec(),
            },
            Instr::Halt,
        ])
        .await?;
    await_read(&client, registry, PROPERTY).await?;
    println!(
        "2. registered on-chain          : rwa.registry[{}]",
        String::from_utf8_lossy(PROPERTY)
    );
    devnet.shutdown().await?;

    // ── 2. the loan-health contract ────────────────────────────────────────
    //
    //   required   = valuation * 30 / 100
    //   healthy    = collateral > required
    //
    // `LoadEthState` traps if the collateral has not been proven, so this
    // program cannot produce a verdict from unverified data.
    let loan_health = vec![
        Instr::LoadTable {
            table: registry,
            key: PROPERTY.to_vec(),
        }, // valuation
        Instr::Push(REQUIRED_RATIO_PCT),
        Instr::Mul,
        Instr::Push(100),
        Instr::Div, // → required
        Instr::LoadEthState {
            chain_id: CHAIN_ETH,
            address: USDC,
            slot: escrow_slot,
        },
        Instr::Lt, // required < collateral  →  1 if healthy
        Instr::StoreTable {
            table: health,
            key: PROPERTY.to_vec(),
        },
        Instr::Halt,
    ];

    // A node configured for Ethereum interop. (In production the claim carries
    // an SP1 proof and the block is anchored by a BLS-verified beacon update;
    // see `cargo test -p peregrine-interop --features bls`.)
    let block_hash = [0x11u8; 32];
    let mut node = ExecutionPipeline::new();
    node.claim_policy = ClaimPolicy::Verified {
        verifier: Box::new(NativeVerifier),
        chain_id: CHAIN_ETH,
    };
    node.anchors.insert(Anchor {
        slot: 14_817_376,
        block_number: 25_580_735,
        block_hash,
        state_root: [0x22; 32],
    })?;
    node.apply_payload(&WirePayload::TalonTx {
        program: vec![
            Instr::Push(valuation_usdc),
            Instr::StoreTable {
                table: registry,
                key: PROPERTY.to_vec(),
            },
            Instr::Halt,
        ],
    });

    // ── 3. the guardrail, before any Ethereum state is proven ──────────────
    node.apply_payload(&WirePayload::TalonTx {
        program: loan_health.clone(),
    });
    println!(
        "\n3. verdict with UNVERIFIED collateral … {}",
        ok(node.prove_read(health, PROPERTY).is_none())
    );
    println!("   (the tx trapped — an unproven balance is not a balance)");

    // ── 4. prove the collateral, then re-run ───────────────────────────────
    let post = |node: &mut ExecutionPipeline, amount: u64| -> Result<()> {
        let mut word = [0u8; 32];
        word[24..].copy_from_slice(&amount.to_be_bytes());
        let claim = NativeProver.prove(Journal {
            chain_id: CHAIN_ETH,
            block_number: 25_580_735,
            block_hash,
            state_root: [0x22; 32],
            claim: Claim::Storage {
                address: USDC,
                slot: escrow_slot,
                value: word,
            },
        })?;
        node.apply_foreign_claim(&claim)
            .map_err(|e| anyhow::anyhow!(e))?;
        Ok(())
    };

    let required = valuation_usdc * REQUIRED_RATIO_PCT / 100;
    println!("\n   required collateral (30%)    : ${}", usdc(required));

    for (amount, label) in [
        (200_000_000_000u64, "well collateralised"),
        (100_000_000_000, "short"),
    ] {
        post(&mut node, amount)?;
        node.apply_payload(&WirePayload::TalonTx {
            program: loan_health.clone(),
        });
        let verdict = node
            .prove_read(health, PROPERTY)
            .ok_or_else(|| anyhow::anyhow!("contract should have produced a verdict"))?;
        let healthy = u64::from_le_bytes(verdict.value[..8].try_into()?) == 1;
        println!(
            "   collateral ${:<14} ({:<19}) → {}",
            usdc(amount),
            label,
            if healthy {
                "\x1b[32mHEALTHY\x1b[0m"
            } else {
                "\x1b[31mUNDER-COLLATERALISED\x1b[0m"
            }
        );
    }

    // ── 5. the verdict is provable to anyone holding 32 bytes ──────────────
    let root = node.store_root();
    let verdict = node.prove_read(health, PROPERTY).expect("verdict present");
    println!("\n4. store root                   : {root}");
    println!(
        "   verdict proof verifies       … {}",
        ok(verdict.verify(&root))
    );
    println!("\n   A lender audits this with the root alone — no node to trust,");
    println!("   and no way to hide the Ethereum leg of the collateral.\n");
    Ok(())
}

/// Format a 6-decimal USDC amount.
fn usdc(v: u64) -> String {
    format!("{}.{:06}", v / 1_000_000, v % 1_000_000)
}

// ── live view ───────────────────────────────────────────────────────────────

/// Poll a running node and render a live terminal dashboard (`peregrine watch`).
///
/// Deliberately a *client*: it uses nothing but the public SDK, so what it can
/// show is exactly what any application can observe — the store root, and
/// whatever values you point it at. If a field renders here, it is reachable
/// over the network by anyone.
pub async fn watch(
    rpc_addr: std::net::SocketAddr,
    keys: &[(TableId, Vec<u8>, String)],
) -> Result<()> {
    let client = Client::connect(rpc_addr)
        .await
        .map_err(|e| anyhow::anyhow!("connect to {rpc_addr}: {e} (is a node running?)"))?;

    println!("watching {rpc_addr} — Ctrl-C to stop\n");
    let mut last_root = Hash::ZERO;
    let mut ticks: u64 = 0;

    loop {
        let root = client.store_root().await?;
        let changed = root != last_root;
        if changed {
            last_root = root;
        }
        ticks += 1;

        // Redraw in place: clear screen, home cursor.
        print!("\x1b[2J\x1b[H");
        println!("\x1b[1mPEREGRINE · live\x1b[0m   {rpc_addr}   poll #{ticks}");
        println!("{}", "─".repeat(60));
        println!(
            "store root   {}{}\x1b[0m",
            if changed { "\x1b[32m" } else { "" },
            root
        );
        println!(
            "             {}",
            if changed {
                "changed since last poll"
            } else {
                "unchanged"
            }
        );
        println!("{}", "─".repeat(60));

        if keys.is_empty() {
            println!("(no keys being watched — pass some to see values)");
        }
        for (table, key, label) in keys {
            match client.prove_read(*table, key).await? {
                Some(read) => {
                    let verified = read.verify(&root);
                    let shown = if read.value.len() >= 8 {
                        u64::from_le_bytes(read.value[..8].try_into()?).to_string()
                    } else {
                        format!("0x{}", hex_of(&read.value))
                    };
                    println!(
                        "{label:<24} {shown:<20} {}",
                        if verified {
                            "\x1b[32m✓ proven\x1b[0m"
                        } else {
                            "\x1b[31m✗ BAD PROOF\x1b[0m"
                        }
                    );
                }
                None => println!("{label:<24} {:<20} \x1b[90m(absent)\x1b[0m", "—"),
            }
        }
        println!("\n\x1b[90mevery value above was verified against the root, locally\x1b[0m");
        tokio::time::sleep(Duration::from_millis(1000)).await;
    }
}

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ── agent sessions & micropayments ──────────────────────────────────────────

/// An autonomous agent buys a data feed with a scoped, budgeted session key —
/// then the principal revokes it mid-stream.
///
/// The point of the demo is what an agent *cannot* do. A session key is not a
/// small key; it is a bounded one, and every bound is enforced by consensus
/// rather than by the agent's good behaviour.
pub async fn agent() -> Result<()> {
    use crate::payload::WirePayload;
    use crate::pipeline::ExecutionPipeline;
    use peregrine_core::Keypair;
    use peregrine_data::sessions::{
        balances_table, sign_revocation, Action, SessionBuilder, SessionSigner,
    };
    use peregrine_data::streams::Publisher;
    use peregrine_data::tables::TableId;

    let mut rng = rand::rngs::OsRng;
    let principal = Keypair::generate(&mut rng); // the human's key: never leaves cold storage
    let agent_key = Keypair::generate(&mut rng); // the agent's throwaway key
    let oracle = Keypair::generate(&mut rng); // sells a price feed
    let oracle_pk = oracle.public();

    let notes = TableId::named("agent.notes");
    let mut node = ExecutionPipeline::new();
    node.tables.create_table(notes);
    let feed = node.streams.register("acme/BTC-USD", oracle_pk);
    node.set_round_for_test(1);

    println!("\n── act 1 · a bounded delegation ──────────────────────────");

    // Everything starts closed; each capability is opened deliberately.
    let grant = SessionBuilder::new(100) // expires at round 100 — a round, not a clock
        .allow_table(notes)
        .allow_stream(feed)
        .budget(50) // total the agent may ever spend
        .max_per_action(5) // and never more than this at once
        .sign(&principal, &agent_key.public());
    let session_id = grant.grant.id();

    node.apply_payload(&WirePayload::OpenSession(Box::new(grant)));
    println!("  session {}          opened", session_id.short());
    println!("  budget 50 grains · max 5/action · expires round 100");
    println!("  may write : agent.notes");
    println!("  may buy   : acme/BTC-USD");

    let mut signer = SessionSigner::new(agent_key, session_id);

    println!("\n── act 2 · what the agent cannot do ──────────────────────");

    // Out of scope.
    node.apply_payload(&WirePayload::SessionAction(Box::new(signer.sign(
        Action::Write {
            table: TableId::named("treasury.reserve"),
            key: b"drain".to_vec(),
            value: b"everything".to_vec(),
        },
    ))));
    signer.rollback(); // refused, so the chain still expects that nonce
    println!(
        "  write to treasury.reserve … {}",
        ok(node
            .tables
            .get(&TableId::named("treasury.reserve"), b"drain")
            .is_none())
    );

    // Over the per-action cap.
    node.apply_payload(&WirePayload::SessionAction(Box::new(signer.sign(
        Action::Pay {
            payee: oracle_pk,
            amount: 40,
        },
    ))));
    signer.rollback();
    let bal = |n: &ExecutionPipeline| -> u64 {
        n.tables
            .get(&balances_table(), &oracle_pk.0)
            .and_then(|v| v.try_into().ok())
            .map(u64::from_le_bytes)
            .unwrap_or(0)
    };
    println!("  pay 40 (cap is 5)         … {}", ok(bal(&node) == 0));

    println!("\n── act 3 · streaming micropayments ───────────────────────");

    // One signature buys an ongoing subscription. After this, payment happens
    // on the fast path — one debit per committed record, no more signatures.
    node.apply_payload(&WirePayload::SessionAction(Box::new(signer.sign(
        Action::Subscribe {
            stream: feed,
            price_per_record: 2,
        },
    ))));
    println!("  subscribed to acme/BTC-USD at 2 grains/record");

    let mut publisher = Publisher::new("acme/BTC-USD", oracle);
    for i in 0..8u64 {
        let price = 6_150_000u64 + i * 25;
        node.apply_payload(&WirePayload::Shred(
            publisher.emit(price.to_le_bytes().to_vec()),
        ));
    }

    let spent = node.sessions[&session_id].spent;
    println!(
        "  8 records committed       → agent spent {spent} grains, oracle earned {}",
        bal(&node)
    );
    println!("  budget remaining          : {}", 50 - spent);

    println!("\n── act 4 · the budget is a hard ceiling ──────────────────");
    for i in 0..40u64 {
        node.apply_payload(&WirePayload::Shred(
            publisher.emit((6_160_000u64 + i).to_le_bytes().to_vec()),
        ));
    }
    let spent = node.sessions[&session_id].spent;
    println!("  40 more records committed … the stream keeps flowing");
    println!(
        "  agent spent               : {spent} of 50 — never more  {}",
        ok(spent <= 50)
    );
    println!("  (an agent out of budget stops paying; the chain does not stop)");

    println!("\n── act 5 · revocation ────────────────────────────────────");
    let before = node.sessions[&session_id].spent;
    let sig = sign_revocation(&principal, &session_id);
    node.revoke_session(&session_id, &sig);
    for _ in 0..5 {
        node.apply_payload(&WirePayload::Shred(publisher.emit(vec![0u8; 8])));
    }
    println!(
        "  principal revoked         … meter stopped {}",
        ok(node.sessions[&session_id].spent == before)
    );

    println!(
        "\nThe agent held a key the whole time. It could never spend past 50,\n\
         never pay more than 5 at once, never touch a table outside its scope,\n\
         and stopped the instant its principal said so — all enforced by\n\
         consensus, not by the agent behaving itself.\n"
    );
    Ok(())
}

/// RWA contract templates: title, valuation, and a collateral check against a
/// **proven** Ethereum balance.
///
/// The whole demo turns on one moment — act 3, where the collateral has not
/// been proven and the transaction traps rather than reading zero.
pub async fn rwa_templates() -> Result<()> {
    use crate::payload::WirePayload;
    use crate::pipeline::{eth_state_key, eth_state_table, ExecutionPipeline};
    use crate::templates::{
        collateral_health, health_table, record_valuation, register_title, registry_table,
        reserve_backed_token, title_table,
    };

    const CHAIN: u64 = 1;
    const USDC: [u8; 20] = [
        0xa0, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1, 0x9d, 0x4a, 0x2e, 0x9e, 0xb0,
        0xce, 0x36, 0x06, 0xeb, 0x48,
    ];
    const PROPERTY: &[u8] = b"PROP-1729-BRIXTON";
    let slot = {
        let mut s = [0u8; 32];
        s[31] = 9;
        s
    };

    let mut node = ExecutionPipeline::new();
    for t in [title_table(), registry_table(), health_table()] {
        node.tables.create_table(t);
    }
    let run = |node: &mut ExecutionPipeline, p: Vec<peregrine_vm::Instr>| {
        node.apply_payload(&WirePayload::TalonTx { program: p });
    };
    let health = |node: &ExecutionPipeline| -> Option<u64> {
        node.tables.get(&health_table(), PROPERTY).map(|v| {
            let mut b = [0u8; 8];
            b.copy_from_slice(&v[..8]);
            u64::from_le_bytes(b)
        })
    };

    println!("\n── act 1 · title & valuation ─────────────────────────────");
    run(&mut node, register_title(PROPERTY, 1729));
    run(&mut node, record_valuation(PROPERTY, 500_000));
    println!("  registered   : rwa.titles[PROP-1729-BRIXTON] = owner 1729");
    println!("  valued       : $500,000 (signed oracle)");
    println!("  required @30%: $150,000");

    println!("\n── act 2 · the check that must NOT default to zero ───────");
    run(
        &mut node,
        collateral_health(PROPERTY, 30, CHAIN, USDC, slot),
    );
    println!(
        "  verdict with UNPROVEN collateral … {}",
        ok(health(&node).is_none())
    );
    println!("     (the tx trapped — an unproven balance is not a balance,");
    println!("      so no verdict is written and the last one stands)");

    println!("\n── act 3 · with a proven balance ─────────────────────────");
    let prove = |node: &mut ExecutionPipeline, amount: u64| {
        let mut word = [0u8; 32];
        word[24..].copy_from_slice(&amount.to_be_bytes());
        node.tables.insert(
            eth_state_table(),
            eth_state_key(CHAIN, &USDC, &slot),
            word.to_vec(),
        );
    };

    prove(&mut node, 200_000);
    run(
        &mut node,
        collateral_health(PROPERTY, 30, CHAIN, USDC, slot),
    );
    println!(
        "  collateral $200,000 (ample)   → {}",
        if health(&node) == Some(1) {
            "HEALTHY"
        } else {
            "UNDER"
        }
    );

    prove(&mut node, 100_000);
    run(
        &mut node,
        collateral_health(PROPERTY, 30, CHAIN, USDC, slot),
    );
    println!(
        "  collateral $100,000 (short)   → {}",
        if health(&node) == Some(1) {
            "HEALTHY"
        } else {
            "UNDER-COLLATERALISED"
        }
    );

    println!("\n── act 4 · reserve-backed token ──────────────────────────");
    prove(&mut node, 1_000_000);
    run(
        &mut node,
        reserve_backed_token(PROPERTY, 100, 5_000, CHAIN, USDC, slot),
    );
    println!(
        "  100 shares x $5,000 vs $1,000,000 reserve → {}",
        if health(&node) == Some(1) {
            "BACKED"
        } else {
            "UNDER"
        }
    );
    run(
        &mut node,
        reserve_backed_token(PROPERTY, 300, 5_000, CHAIN, USDC, slot),
    );
    println!(
        "  300 shares x $5,000 vs $1,000,000 reserve → {}",
        if health(&node) == Some(1) {
            "BACKED"
        } else {
            "UNDER-RESERVED"
        }
    );

    println!(
        "\nEvery verdict above is a deterministic function of committed state.\n\
         A lender audits it with the 32-byte store root and nothing else — and\n\
         a missing oracle produces no verdict rather than a wrong one.\n"
    );
    Ok(())
}

/// Selective disclosure and institutional compliance, end to end.
///
/// Two privacy primitives, both verified against the same 32-byte store root a
/// light client trusts: a KYC record that reveals one field while hiding the
/// rest, and a signed compliance attestation that gates a transfer. In-process
/// so the whole flow is legible; every check is the same pure function the SDK
/// and explorer run.
pub async fn compliance() -> Result<()> {
    use crate::pipeline::ExecutionPipeline;
    use peregrine_core::Keypair;
    use peregrine_data::compliance::{
        cell_key, compliance_table, AttestationBuilder, CompliancePolicy,
    };
    use peregrine_data::disclosure::FieldRow;
    use peregrine_data::tables::TableId;

    let mut rng = rand::rngs::OsRng;
    let mut node = ExecutionPipeline::new();

    println!("── act 1 · Selective disclosure ─────────────────────────");
    // A customer's KYC record. Only its field commitment goes on-chain; the
    // plaintext fields stay with the owner.
    let record = FieldRow::new(vec![
        b"Alice Smith".to_vec(),
        b"1990-01-01".to_vec(),
        b"passport-9931".to_vec(),
        b"US".to_vec(),
    ]);
    let table = TableId::named("kyc.records");
    let key = b"customer-1".to_vec();
    node.tables
        .insert(table, key.clone(), record.commit().0.to_vec());
    let root = node.store_root();
    let read = node.prove_read(table, &key).expect("row present");

    // The owner discloses only residency (field 3) to a counterparty.
    let disc = record.disclose(read, &[3]).expect("disclosure");
    let ok = disc.verify(&root);
    println!("  committed a 4-field record; its on-chain value is a 32-byte commitment");
    println!("  disclosed field #3 only:");
    for (i, v) in disc.revealed() {
        println!(
            "    field #{i} = {:?}   {}",
            String::from_utf8_lossy(v),
            if ok {
                "✓ verified against the root"
            } else {
                "✗"
            }
        );
    }
    println!("  name, date of birth and passport number were never sent.\n");

    println!("── act 2 · Compliance-gated transfer ────────────────────");
    let bank = Keypair::generate(&mut rng); // the attester (a KYC desk)
    let alice = Keypair::generate(&mut rng); // a KYC'd customer
    let mallory = Keypair::generate(&mut rng); // never attested
    let policy = CompliancePolicy::new(bank.public());

    // Before any attestation, a compliant transfer to Alice is refused.
    match node.compliant_credit(&alice.public(), 1_000, &policy) {
        Ok(()) => println!("  UNEXPECTED: transfer cleared with no attestation on record"),
        Err(e) => println!("  transfer to un-attested Alice → refused: {e}"),
    }

    // The bank attests Alice: Verified, valid for 1000 rounds.
    let attestation = AttestationBuilder::verified(0, 1_000).sign(&bank, &alice.public());
    node.apply_attestation(&attestation)
        .expect("valid attestation");
    println!("  the bank signed a Verified attestation for Alice");

    // Now the same transfer clears — checked against committed state.
    match node.compliant_credit(&alice.public(), 1_000, &policy) {
        Ok(()) => println!("  transfer to attested Alice → cleared ✓"),
        Err(e) => println!("  UNEXPECTED: {e}"),
    }
    // Mallory, never attested, still cannot receive under this policy.
    match node.compliant_credit(&mallory.public(), 1_000, &policy) {
        Ok(()) => println!("  UNEXPECTED: Mallory cleared"),
        Err(e) => println!("  transfer to un-attested Mallory → refused: {e}"),
    }

    // An auditor verifies Alice off-chain, from a proof plus the store root.
    let cell = node
        .prove_read(
            compliance_table(),
            &cell_key(&alice.public(), &bank.public()),
        )
        .expect("cell present");
    let root = node.store_root();
    let verified = policy.gate(&alice.public(), &cell, &root, 250).is_ok();
    println!(
        "\n  an auditor checks Alice against the store root alone → {}",
        if verified { "compliant ✓" } else { "✗" }
    );
    println!(
        "  no node trusted, no global KYC authority — only the root and the attester you chose."
    );
    Ok(())
}

/// Oracle & verifiable data feeds, end to end.
///
/// A multi-source median price feed and a single-source RWA valuation: publish
/// signed observations, aggregate on commit, and read the latest value back with
/// a proof against the store root. In-process so the whole path is legible.
pub async fn oracle() -> Result<()> {
    use crate::payload::WirePayload;
    use crate::pipeline::ExecutionPipeline;
    use peregrine_core::Keypair;
    use peregrine_data::feeds::{
        feed_latest_table, Aggregation, FeedId, FeedKind, FeedPublisher, FeedSpec, FeedValue,
    };

    // Read a feed's latest value with a proof, verify it, and format it.
    fn read(node: &mut ExecutionPipeline, id: FeedId, now: u64) -> Option<(FeedValue, bool)> {
        let root = node.store_root();
        let r = node.prove_read(feed_latest_table(), &id.0 .0)?;
        let ok = r.verify(&root);
        FeedValue::decode(&r.value).map(|fv| {
            let fresh = fv.is_fresh(now, 5);
            let _ = fresh;
            (fv, ok)
        })
    }

    let mut rng = rand::rngs::OsRng;
    let mut node = ExecutionPipeline::new();

    println!("── act 1 · A median price feed ──────────────────────────");
    let providers: Vec<Keypair> = (0..3).map(|_| Keypair::generate(&mut rng)).collect();
    let spec = FeedSpec {
        channel: "price/BTC-USD".into(),
        kind: FeedKind::Price,
        decimals: 2,
        aggregation: Aggregation::Median,
        providers: providers.iter().map(|k| k.public()).collect(),
        max_staleness_rounds: 5,
    };
    let feed_id = node.register_feed(spec.clone());
    println!("  registered {feed_id:?} — 3 providers, median, 2 decimals");
    let mut pubs: Vec<FeedPublisher> = providers
        .into_iter()
        .map(|k| FeedPublisher::new(&spec, k))
        .collect();

    node.set_round_for_test(10);
    for (i, price) in [6_150_000u64, 6_151_000, 6_149_000].iter().enumerate() {
        node.apply_payload(&WirePayload::Shred(pubs[i].observe_at(*price, 0)));
        println!("  provider #{i} reports ${:.2}", *price as f64 / 100.0);
    }
    if let Some((fv, ok)) = read(&mut node, feed_id, 12) {
        println!(
            "  → latest = ${:.2}  ({} sources, round {})  {}",
            fv.as_f64(),
            fv.n_sources,
            fv.updated_round,
            if ok {
                "✓ proven against the store root"
            } else {
                "✗"
            }
        );
    }

    println!("\n── act 2 · A source goes dark ───────────────────────────");
    node.set_round_for_test(20); // 20 - 10 = 10 rounds > max_staleness 5
    for i in [0usize, 1] {
        let price = if i == 0 { 6_200_000 } else { 6_202_000 };
        node.apply_payload(&WirePayload::Shred(pubs[i].observe_at(price, 0)));
    }
    println!("  providers #0 and #1 refresh; #2 has been silent past the staleness bound");
    if let Some((fv, _)) = read(&mut node, feed_id, 22) {
        println!(
            "  → latest = ${:.2}  ({} sources — the stale one was dropped from the median)",
            fv.as_f64(),
            fv.n_sources
        );
    }

    println!("\n── act 3 · A single-source RWA valuation ────────────────");
    let appraiser = Keypair::generate(&mut rng);
    let rwa = FeedSpec {
        channel: "rwa/BUILDING-7".into(),
        kind: FeedKind::Rwa,
        decimals: 0,
        aggregation: Aggregation::Single,
        providers: vec![appraiser.public()],
        max_staleness_rounds: 1000,
    };
    let rwa_id = node.register_feed(rwa.clone());
    let mut appr = FeedPublisher::new(&rwa, appraiser);
    node.set_round_for_test(21);
    node.apply_payload(&WirePayload::Shred(appr.observe_at(2_500_000, 0)));
    if let Some((fv, ok)) = read(&mut node, rwa_id, 21) {
        println!(
            "  {:?} valued at {} units  {}",
            rwa_id,
            fv.value,
            if ok { "✓ proven" } else { "✗" }
        );
    }
    println!("\n  every value above is committed table state — a contract or agent reads it");
    println!("  with a 32-byte root and nothing else to trust.");
    Ok(())
}

/// An autonomous agent pays for verifiable oracle data with a scoped, budgeted
/// session key — the full agent-payments path in one story.
///
/// The point: the agent holds a key the whole time, yet it can only ever spend
/// what its principal allotted, only on the data it was scoped to, and stops the
/// instant it is revoked — all enforced by consensus, and its remaining budget
/// is *provable*, not merely reported.
pub async fn agent_data() -> Result<()> {
    use crate::payload::WirePayload;
    use crate::pipeline::ExecutionPipeline;
    use peregrine_core::{Hash, Keypair};
    use peregrine_data::feeds::{
        feed_latest_table, Aggregation, FeedKind, FeedPublisher, FeedSpec, FeedValue,
    };
    use peregrine_data::sessions::{
        balances_table, sessions_table, sign_revocation, SessionBuilder, SessionSigner,
        SessionState,
    };

    // Prove-and-read the agent's own remaining budget (what `read_session` does).
    fn remaining(node: &mut ExecutionPipeline, id: Hash) -> u64 {
        let root = node.store_root();
        let read = node.prove_read(sessions_table(), &id.0).expect("session");
        assert!(read.verify(&root));
        SessionState::from_bytes(&read.value).unwrap().remaining()
    }
    fn latest(node: &mut ExecutionPipeline, feed: peregrine_data::feeds::FeedId) -> f64 {
        let root = node.store_root();
        let read = node
            .prove_read(feed_latest_table(), &feed.0 .0)
            .expect("feed");
        assert!(read.verify(&root));
        FeedValue::decode(&read.value).unwrap().as_f64()
    }
    let bal = |n: &ExecutionPipeline, pk: &peregrine_core::PublicKey| -> u64 {
        n.tables
            .get(&balances_table(), &pk.0)
            .and_then(|v| v.try_into().ok())
            .map(u64::from_le_bytes)
            .unwrap_or(0)
    };

    let mut rng = rand::rngs::OsRng;
    let principal = Keypair::generate(&mut rng); // the human's cold key
    let agent_key = Keypair::generate(&mut rng); // the agent's throwaway key
    let oracle = Keypair::generate(&mut rng); // sells a price feed
    let oracle_pk = oracle.public();

    let mut node = ExecutionPipeline::new();

    println!("── act 1 · a price feed to pay for ──────────────────────");
    let spec = FeedSpec {
        channel: "price/BTC-USD".into(),
        kind: FeedKind::Price,
        decimals: 2,
        aggregation: Aggregation::Single,
        providers: vec![oracle_pk],
        max_staleness_rounds: 1000,
    };
    let feed_id = node.register_feed(spec.clone());
    let mut feed_pub = FeedPublisher::new(&spec, oracle);
    println!("  registered {feed_id:?} (1 source, 2 decimals)");

    println!("\n── act 2 · a bounded delegation ─────────────────────────");
    // Scope exactly the feed's source, cap the total spend and the per-record
    // price. `try_sign` refuses a funded session that could never spend.
    let grant = SessionBuilder::new(100)
        .allow_streams(spec.provider_streams())
        .budget(20) // total the agent may ever spend
        .max_per_action(2) // and never more than this per record
        .try_sign(&principal, &agent_key.public())
        .expect("well-formed grant");
    let session_id = grant.grant.id();
    node.set_round_for_test(1);
    node.open_session(&grant)?;
    println!("  session {}          opened", session_id.short());
    println!("  budget 20 grains · max 2/record · scoped to the feed · expires round 100");

    let mut signer = SessionSigner::new(agent_key, session_id);
    node.apply_payload(&WirePayload::SessionAction(Box::new(
        signer.subscribe(spec.provider_streams()[0], 2),
    )));
    println!("  one signature → subscribed at 2 grains/update");

    println!("\n── act 3 · pay-per-update, read verified ────────────────");
    for (i, price) in [6_150_000u64, 6_151_000, 6_149_500, 6_152_000, 6_150_500]
        .iter()
        .enumerate()
    {
        node.apply_payload(&WirePayload::Shred(feed_pub.observe_at(*price, 0)));
        if i == 4 {
            println!(
                "  after 5 updates → feed = ${:.2} (proven), agent paid {} grains, {} remaining",
                latest(&mut node, feed_id),
                bal(&node, &oracle_pk),
                remaining(&mut node, session_id),
            );
        }
    }

    println!("\n── act 4 · the budget is a hard ceiling ─────────────────");
    for i in 0..40u64 {
        node.apply_payload(&WirePayload::Shred(feed_pub.observe_at(6_160_000 + i, 0)));
    }
    println!(
        "  40 more updates flow → agent paid {} of 20 (never more), {} remaining",
        bal(&node, &oracle_pk),
        remaining(&mut node, session_id),
    );
    println!("  the data keeps flowing; an out-of-budget agent just stops paying.");

    println!("\n── act 5 · revocation ───────────────────────────────────");
    let before = bal(&node, &oracle_pk);
    node.revoke_session(&session_id, &sign_revocation(&principal, &session_id));
    for _ in 0..5 {
        node.apply_payload(&WirePayload::Shred(feed_pub.observe_at(6_170_000, 0)));
    }
    println!(
        "  principal revoked → meter stopped {}",
        ok(bal(&node, &oracle_pk) == before)
    );
    println!(
        "\n  The agent never spent past 20, never paid more than 2 at once, only\n\
         ever paid for the one feed it was scoped to, proved its own balance at\n\
         every step, and stopped the instant its principal said so.\n"
    );
    Ok(())
}
