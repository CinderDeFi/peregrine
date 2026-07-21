//! Feasibility probe: can this machine produce a **Groth16** proof?
//!
//! Compressed STARK proofs are what Peregrine verifies internally, and those
//! are known to work here. Groth16 is a different question: it is what the EVM
//! verifier contract needs, and SP1 produces it by wrapping a STARK in a gnark
//! circuit — historically a Docker-only step, and there is no Docker on this
//! machine. Rather than guess, this measures it.
//!
//! Ignored by default: it downloads multi-gigabyte circuit artifacts on first
//! run and takes many minutes.
//!
//! ```bash
//! PEREGRINE_ETH_GUEST_ELF=<elf> cargo test -p peregrine-interop --features sp1 \
//!   --test groth16_probe -- --ignored --nocapture
//! ```
#![cfg(feature = "sp1")]

use peregrine_interop::witness::Witness;
use peregrine_interop::{BlockHeader, Sp1Mode, Sp1Prover};
use serde_json::Value;

fn hex_bytes(v: &Value) -> Vec<u8> {
    let s = v.as_str().unwrap().trim_start_matches("0x");
    let s = if s.len() % 2 == 1 {
        format!("0{s}")
    } else {
        s.to_string()
    };
    hex::decode(s).unwrap()
}
fn hex32(v: &Value) -> [u8; 32] {
    let mut o = [0u8; 32];
    o.copy_from_slice(&hex_bytes(v));
    o
}
fn num(v: &Value) -> u64 {
    u64::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}
fn minimal(v: &Value) -> Vec<u8> {
    let b = hex_bytes(v);
    let i = b.iter().position(|x| *x != 0).unwrap_or(b.len());
    b[i..].to_vec()
}

/// The cheapest real statement we have: a one-header chain over real mainnet
/// data. Content is irrelevant here — only whether the wrap step runs at all.
fn one_header_witness() -> Witness {
    let f: Value = serde_json::from_str(include_str!("fixtures/mainnet.json")).unwrap();
    let h = &f["header"];
    let mut beneficiary = [0u8; 20];
    beneficiary.copy_from_slice(&hex_bytes(&h["miner"]));
    let header = BlockHeader {
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
    };
    Witness::HeaderChain {
        chain_id: 1,
        headers: vec![header],
        trusted_anchor: None,
    }
}

#[test]
#[ignore = "downloads circuit artifacts and takes many minutes"]
fn groth16_proving_is_possible_here() {
    let prover = Sp1Prover::new(Sp1Mode::Groth16).expect("construct a Groth16 prover");
    eprintln!("image id: {:?}", prover.image_id().expect("image id"));

    let t0 = std::time::Instant::now();
    match prover.prove_witness(&one_header_witness()) {
        Ok(claim) => {
            eprintln!("GROTH16 OK in {:.1?}", t0.elapsed());
            assert!(claim.proof.is_zk(), "must be a real ZK proof");
        }
        Err(e) => panic!("GROTH16 UNAVAILABLE after {:.1?}: {e}", t0.elapsed()),
    }
}
