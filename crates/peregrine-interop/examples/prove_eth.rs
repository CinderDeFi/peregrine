//! Generate and verify a **real SP1 proof** of Ethereum verification.
//!
//! Run (Linux/macOS/WSL2, after `sp1up` and `cargo prove build`):
//!
//! ```bash
//! cargo run --release -p peregrine-interop --features sp1 --example prove_eth
//! ```
//!
//! This drives the same [`Sp1Prover`] / [`Sp1Verifier`] the node uses, over the
//! same real mainnet fixture the unit tests verify natively — so a successful
//! run proves three things at once: the guest computes the right journal, the
//! host verifies it, and the two agree on the statement.
//!
//! Set `PEREGRINE_ETH_GUEST_ELF` to the ELF produced by `cargo prove build`.

#[cfg(not(feature = "sp1"))]
fn main() {
    eprintln!("this example requires --features sp1");
    std::process::exit(1);
}

#[cfg(feature = "sp1")]
fn main() -> anyhow::Result<()> {
    use peregrine_interop::sp1_backend::{Sp1Mode, Sp1Prover, Sp1Verifier};
    use peregrine_interop::witness::Witness;
    use peregrine_interop::zk::{Claim, Verifier};
    use serde_json::Value;
    use std::time::Instant;

    const MAINNET: u64 = 1;

    let f: Value = serde_json::from_str(include_str!("../tests/fixtures/mainnet.json"))?;
    let header = header_from(&f);

    // Sanity-check natively first. If this fails the proof would be of a
    // failing program, and the guest would simply panic.
    let expected = header.hash()?;
    println!("mainnet block   : #{}", header.number);
    println!("block hash      : 0x{}", hex::encode(expected));

    // Prove a single-header chain: a genuine Ethereum verification, and the
    // cheapest witness to start from (one keccak over the RLP, versus a full
    // Merkle-Patricia walk).
    let witness = Witness::HeaderChain {
        chain_id: MAINNET,
        headers: vec![header],
        trusted_anchor: Some(expected),
    };
    let native = witness.verify()?;
    println!("native journal  : block {} verified\n", native.block_number);

    let prover = Sp1Prover::new(Sp1Mode::Compressed)?;
    let image_id = prover.image_id()?;
    println!("program image id: 0x{}", hex::encode(image_id));
    println!("proving (compressed STARK — no trusted setup)…");

    let t0 = Instant::now();
    let claim = prover.prove_witness(&witness)?;
    println!("proved in       : {:.1?}", t0.elapsed());
    println!("proof is ZK     : {}", claim.proof.is_zk());

    // The journal must be what the *guest* committed, matching the native run.
    assert_eq!(
        claim.journal, native,
        "guest and host must agree on the statement"
    );
    println!("journal matches native verification: yes");

    // Verify with the pinned image id — the check that makes the proof mean
    // what we think it means.
    let t1 = Instant::now();
    Sp1Verifier::new(image_id, MAINNET)?.verify(&claim)?;
    println!("verified in     : {:.1?}", t1.elapsed());

    // And a proof pinned to the wrong program must be refused.
    let mut wrong = image_id;
    wrong[0] ^= 0x01;
    let refused = Sp1Verifier::new(wrong, MAINNET)?.verify(&claim).is_err();
    println!("wrong image id refused: {refused}");
    assert!(refused, "image pinning must reject a mismatched program");

    match claim.journal.claim {
        Claim::HeaderChain {
            from_block,
            to_block,
        } => {
            println!("\nPROVEN: Ethereum blocks {from_block}..={to_block} verified inside a zkVM.");
        }
        other => println!("\nPROVEN: {other:?}"),
    }
    Ok(())
}

#[cfg(feature = "sp1")]
fn header_from(f: &serde_json::Value) -> peregrine_interop::BlockHeader {
    let h = &f["header"];
    let hex_bytes = |v: &serde_json::Value| -> Vec<u8> {
        let s = v.as_str().unwrap().trim_start_matches("0x");
        let s = if s.len() % 2 == 1 {
            format!("0{s}")
        } else {
            s.to_string()
        };
        hex::decode(s).unwrap()
    };
    let hex32 = |v: &serde_json::Value| -> [u8; 32] {
        let mut o = [0u8; 32];
        o.copy_from_slice(&hex_bytes(v));
        o
    };
    let num = |v: &serde_json::Value| -> u64 {
        u64::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
    };
    let minimal = |v: &serde_json::Value| -> Vec<u8> {
        let b = hex_bytes(v);
        let i = b.iter().position(|x| *x != 0).unwrap_or(b.len());
        b[i..].to_vec()
    };
    let mut beneficiary = [0u8; 20];
    beneficiary.copy_from_slice(&hex_bytes(&h["miner"]));
    peregrine_interop::BlockHeader {
        parent_hash: hex32(&h["parentHash"]),
        ommers_hash: hex32(&h["sha3Uncles"]),
        beneficiary,
        state_root: hex32(&h["stateRoot"]),
        transactions_root: hex32(&h["transactionsRoot"]),
        receipts_root: hex32(&h["receiptsRoot"]),
        logs_bloom: hex_bytes(&h["logsBloom"]),
        difficulty: minimal(&h["difficulty"]),
        number: num(&h["number"]),
        gas_limit: num(&h["gasLimit"]),
        gas_used: num(&h["gasUsed"]),
        timestamp: num(&h["timestamp"]),
        extra_data: hex_bytes(&h["extraData"]),
        mix_hash: hex32(&h["mixHash"]),
        nonce: hex_bytes(&h["nonce"]),
        base_fee_per_gas: Some(minimal(&h["baseFeePerGas"])),
        withdrawals_root: Some(hex32(&h["withdrawalsRoot"])),
        blob_gas_used: Some(num(&h["blobGasUsed"])),
        excess_blob_gas: Some(num(&h["excessBlobGas"])),
        parent_beacon_block_root: Some(hex32(&h["parentBeaconBlockRoot"])),
        requests_hash: Some(hex32(&h["requestsHash"])),
    }
}
