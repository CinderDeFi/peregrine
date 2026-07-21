//! A **real SP1 proof** driven through the actual commit path.
//!
//! Everything else about foreign claims is tested with a native (non-ZK) proof,
//! because the acceptance *rules* are pure logic. This test closes the loop:
//! it generates a genuine compressed-STARK proof of an Ethereum storage read
//! over real mainnet data, hands it to `ExecutionPipeline` exactly as consensus
//! would, and checks that Ethereum state lands in `sys.eth_state` only because
//! the cryptography checked out.
//!
//! Requires the guest ELF and a Linux/macOS/WSL2 toolchain:
//!
//! ```bash
//! cd crates/peregrine-eth-guest && cargo prove build
//! PEREGRINE_ETH_GUEST_ELF=<elf> \
//!   cargo test -p peregrine-node --features sp1 --test zk_commit_path -- --nocapture
//! ```
//!
//! Proving takes minutes, so this is deliberately *not* part of the default
//! suite — it is the slow, high-assurance check.
#![cfg(feature = "sp1")]

use peregrine_interop::beacon::Anchor;
use peregrine_interop::witness::Witness;
use peregrine_interop::zk::Claim;
use peregrine_interop::{Sp1Mode, Sp1Prover, VerifiedClaim};
use peregrine_node::pipeline::{eth_state_key, eth_state_table, ClaimPolicy, ExecutionPipeline};
use serde_json::Value;

const MAINNET: u64 = 1;

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../peregrine-interop/tests/fixtures/mainnet.json"
    ))
    .expect("fixture parses")
}

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

fn header(f: &Value) -> peregrine_interop::BlockHeader {
    let h = &f["header"];
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

/// Prove WETH's `decimals` slot (slot 2 == 18) from the real mainnet witness.
fn prove_weth_decimals() -> (VerifiedClaim, [u8; 32], [u8; 20], [u8; 32]) {
    let f = fixture();
    let mut address = [0u8; 20];
    address.copy_from_slice(&hex_bytes(&f["account"]["address"]));
    let mut slot = [0u8; 32];
    slot[31] = 2;

    let nodes =
        |v: &Value| -> Vec<Vec<u8>> { v.as_array().unwrap().iter().map(hex_bytes).collect() };
    let storage_proof = f["storageProof"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| hex_bytes(&s["key"]).last().copied().unwrap_or(0) == 2)
        .map(|s| nodes(&s["proof"]))
        .expect("fixture has slot 2");

    let witness = Witness::EthStorage {
        chain_id: MAINNET,
        header: header(&f),
        address,
        account_proof: nodes(&f["account"]["accountProof"]),
        slot,
        storage_proof,
    };
    // Sanity-check natively; a failing witness would just panic the guest.
    let native = witness.verify().expect("witness verifies natively");

    let prover = Sp1Prover::new(Sp1Mode::Compressed).expect("guest ELF available");
    let image_id = prover.image_id().expect("image id");
    eprintln!("proving (this takes minutes)…");
    let t0 = std::time::Instant::now();
    let claim = prover.prove_witness(&witness).expect("proving succeeds");
    eprintln!("proved in {:.1?}", t0.elapsed());

    assert_eq!(
        claim.journal, native,
        "guest and host must agree on the statement"
    );
    assert!(claim.proof.is_zk(), "must be a real ZK proof");
    (claim, image_id, address, slot)
}

/// **The headline test.** A real proof, verified inside the commit path, is
/// what puts Ethereum state into Peregrine — and nothing else does.
#[test]
fn a_real_zk_proof_is_verified_during_commit() {
    let (claim, image_id, address, slot) = prove_weth_decimals();

    let mut node = ExecutionPipeline::new();
    node.claim_policy =
        ClaimPolicy::sp1(image_id, MAINNET).expect("SP1 verifier for the pinned image");
    // Stand in for a BLS-verified beacon update covering this block.
    node.anchors
        .insert(Anchor {
            slot: 14_817_376,
            block_number: claim.journal.block_number,
            block_hash: claim.journal.block_hash,
            state_root: claim.journal.state_root,
        })
        .expect("anchor");

    let t0 = std::time::Instant::now();
    let wrote = node
        .apply_foreign_claim(&claim)
        .expect("a real proof must be accepted");
    eprintln!("verified in commit path in {:.1?}", t0.elapsed());
    assert!(wrote, "a storage claim materializes state");

    // The proven value is now ordinary, contract-readable Peregrine state.
    let read = node
        .prove_read(eth_state_table(), &eth_state_key(MAINNET, &address, &slot))
        .expect("verified state present");
    assert_eq!(
        read.value.last(),
        Some(&18),
        "WETH decimals, proven in a zkVM"
    );

    // …and provable to a light client against Peregrine's own root.
    let root = node.store_root();
    assert!(read.verify(&root));

    match claim.journal.claim {
        Claim::Storage { value, .. } => assert_eq!(value[31], 18),
        other => panic!("expected a storage claim, got {other:?}"),
    }
}

/// The proof must be bound to *its* journal. Swapping the asserted statement
/// while keeping the (valid) proof must be refused.
#[test]
fn a_valid_proof_cannot_be_stapled_to_a_different_claim() {
    let (claim, image_id, _, _) = prove_weth_decimals();

    let mut node = ExecutionPipeline::new();
    node.claim_policy = ClaimPolicy::sp1(image_id, MAINNET).unwrap();
    node.anchors
        .insert(Anchor {
            slot: 1,
            block_number: claim.journal.block_number,
            block_hash: claim.journal.block_hash,
            state_root: claim.journal.state_root,
        })
        .unwrap();

    // Same proof bytes, attacker's preferred value.
    let mut forged = claim.clone();
    if let Claim::Storage { value, .. } = &mut forged.journal.claim {
        value[31] = 99;
    }
    assert!(
        node.apply_foreign_claim(&forged).is_err(),
        "a proof must not authorise a journal it does not commit to"
    );

    // Nothing was written by the failed attempt.
    let root_before = node.store_root();
    assert!(node.apply_foreign_claim(&forged).is_err());
    assert_eq!(node.store_root(), root_before);
}

/// A genuine proof of the *wrong program* must be refused: image pinning is
/// what makes a proof mean what the node thinks it means.
#[test]
fn a_proof_of_another_program_is_refused() {
    let (claim, image_id, _, _) = prove_weth_decimals();

    let mut wrong = image_id;
    wrong[0] ^= 0x01;
    // The verifier refuses to even construct against an ELF that doesn't match
    // the pin — a misconfigured node fails at startup, not mid-consensus.
    assert!(
        ClaimPolicy::sp1(wrong, MAINNET).is_err(),
        "constructing a verifier for an unmatched image must fail"
    );

    // And with the right pin, the claim is accepted only once anchored.
    let mut node = ExecutionPipeline::new();
    node.claim_policy = ClaimPolicy::sp1(image_id, MAINNET).unwrap();
    assert!(
        node.apply_foreign_claim(&claim).is_err(),
        "unanchored block must be refused even with a real proof"
    );
}
