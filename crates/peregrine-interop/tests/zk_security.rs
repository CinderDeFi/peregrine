//! Security properties of ZK claim verification.
//!
//! These are the checks that stop a valid-looking proof from becoming an
//! exploit, and **all of them run without SP1 installed** — deliberately. The
//! expensive, environment-dependent part is *generating* a proof; the rules a
//! validator enforces when accepting one are pure logic, and pure logic should
//! be tested everywhere, every time.
//!
//! Each test corresponds to a way real bridges have been drained.

use peregrine_interop::witness::{decode_journal, encode_journal, Witness};
use peregrine_interop::zk::{
    Claim, Journal, NativeProver, NativeVerifier, Proof, ProofSystem, Prover, StrictVerifier,
    VerifiedClaim, Verifier, ZkError,
};
use serde_json::Value;

const MAINNET: u64 = 1;
const PINNED_IMAGE: [u8; 32] = [0xAA; 32];

fn journal() -> Journal {
    Journal {
        chain_id: MAINNET,
        block_number: 21_000_000,
        block_hash: [0x11; 32],
        state_root: [0x22; 32],
        claim: Claim::Storage {
            address: [0x33; 20],
            slot: [0x44; 32],
            value: [0x55; 32],
        },
    }
}

fn zk_claim(image_id: [u8; 32], journal: Journal) -> VerifiedClaim {
    VerifiedClaim {
        journal,
        proof: Proof::Zk {
            system: ProofSystem::Sp1,
            image_id,
            bytes: vec![1, 2, 3],
        },
    }
}

/// The headline rule: a validator must not accept a claim just because
/// something in-process asserted it.
#[test]
fn strict_verification_rejects_unproven_claims() {
    let claim = NativeProver.prove(journal()).unwrap();
    assert!(
        !claim.proof.is_zk(),
        "native proofs must never claim ZK force"
    );

    let strict = StrictVerifier {
        expected_image_id: PINNED_IMAGE,
    };
    match strict.verify(&claim) {
        Err(ZkError::Invalid(m)) => {
            assert!(
                m.contains("no cryptographic argument"),
                "unexpected message: {m}"
            )
        }
        other => panic!("strict verification must reject a native proof, got {other:?}"),
    }

    // The permissive verifier still accepts it — which is exactly why a node
    // must never be configured with one.
    assert!(NativeVerifier.verify(&claim).is_ok());
}

/// A proof of a *different program* is still a valid proof. Pinning the image
/// id is what makes a proof mean what we think it means.
#[test]
fn a_valid_proof_of_the_wrong_program_is_rejected() {
    let attacker_program = [0xEE; 32];
    let claim = zk_claim(attacker_program, journal());

    let strict = StrictVerifier {
        expected_image_id: PINNED_IMAGE,
    };
    match strict.verify(&claim) {
        Err(ZkError::Invalid(m)) => {
            assert!(
                m.contains("unexpected program image"),
                "unexpected message: {m}"
            )
        }
        other => panic!("image-id mismatch must be rejected, got {other:?}"),
    }
}

/// Image-id checking must not be fooled by a near-miss.
#[test]
fn image_id_comparison_is_exact() {
    let mut almost = PINNED_IMAGE;
    almost[31] ^= 0x01; // one bit
    let strict = StrictVerifier {
        expected_image_id: PINNED_IMAGE,
    };
    assert!(strict.verify(&zk_claim(almost, journal())).is_err());
}

/// With the correct image, this build still refuses because no SP1 backend is
/// compiled in. Failing *closed* is the right direction for a bridge: a node
/// that cannot check a proof must not accept the claim.
#[test]
fn without_a_backend_strict_verification_fails_closed() {
    let claim = zk_claim(PINNED_IMAGE, journal());
    let strict = StrictVerifier {
        expected_image_id: PINNED_IMAGE,
    };
    match strict.verify(&claim) {
        Err(ZkError::UnsupportedSystem(ProofSystem::Sp1)) => {}
        other => panic!("expected an unsupported-system refusal, got {other:?}"),
    }
}

/// The journal is the statement. If it can be swapped independently of the
/// proof, the proof is decorative — so the encoding must be a faithful,
/// order-sensitive commitment.
#[test]
fn journal_encoding_binds_every_field() {
    let base = journal();
    let encoded = encode_journal(&base);
    assert_eq!(decode_journal(&encoded).unwrap(), base);

    // Each mutation must change the committed bytes.
    let mut mutations = Vec::new();

    let mut j = base.clone();
    j.chain_id = 11_155_111; // sepolia
    mutations.push(("chain_id", j));

    let mut j = base.clone();
    j.block_number += 1;
    mutations.push(("block_number", j));

    let mut j = base.clone();
    j.block_hash[0] ^= 0x01;
    mutations.push(("block_hash", j));

    let mut j = base.clone();
    j.state_root[0] ^= 0x01;
    mutations.push(("state_root", j));

    let mut j = base.clone();
    j.claim = Claim::Storage {
        address: [0x33; 20],
        slot: [0x44; 32],
        value: [0x99; 32], // attacker's preferred value
    };
    mutations.push(("claim.value", j));

    for (what, mutated) in mutations {
        assert_ne!(
            encode_journal(&mutated),
            encoded,
            "mutating {what} must change the committed public values"
        );
    }
}

/// A witness that fails verification must never yield a journal — in the guest
/// this is what makes an unprovable claim stay unprovable.
#[test]
fn an_invalid_witness_produces_no_journal() {
    let f: Value = serde_json::from_str(include_str!("fixtures/mainnet.json")).unwrap();
    let header = fixture_header(&f);

    // Genuine witness verifies.
    let good = Witness::EthAccount {
        chain_id: MAINNET,
        header: header.clone(),
        address: fixture_address(&f),
        account_proof: fixture_nodes(&f["account"]["accountProof"]),
    };
    let journal = good.verify().expect("real witness verifies");
    assert_eq!(journal.chain_id, MAINNET);

    // Tamper with the state root: the account proof no longer resolves, so
    // there is nothing to commit.
    let mut forged_header = header.clone();
    forged_header.state_root[0] ^= 0x01;
    let bad = Witness::EthAccount {
        chain_id: MAINNET,
        header: forged_header,
        address: fixture_address(&f),
        account_proof: fixture_nodes(&f["account"]["accountProof"]),
    };
    assert!(
        bad.verify().is_err(),
        "a forged state root must not produce a journal"
    );

    // Truncated witness: an error, never a journal claiming absence.
    let mut short = fixture_nodes(&f["account"]["accountProof"]);
    short.truncate(short.len() - 1);
    let truncated = Witness::EthAccount {
        chain_id: MAINNET,
        header,
        address: fixture_address(&f),
        account_proof: short,
    };
    assert!(truncated.verify().is_err());
}

/// The journal a witness produces must commit to the roots the verification
/// *recomputed*, not to anything the submitter chose.
#[test]
fn journal_roots_come_from_the_verified_header() {
    let f: Value = serde_json::from_str(include_str!("fixtures/mainnet.json")).unwrap();
    let header = fixture_header(&f);
    let expected_hash = header.hash().unwrap();

    let w = Witness::EthAccount {
        chain_id: MAINNET,
        header: header.clone(),
        address: fixture_address(&f),
        account_proof: fixture_nodes(&f["account"]["accountProof"]),
    };
    let journal = w.verify().unwrap();
    assert_eq!(
        journal.block_hash, expected_hash,
        "block hash must be recomputed"
    );
    assert_eq!(
        journal.state_root, header.state_root,
        "state root must come from that header"
    );
    assert_eq!(journal.block_number, header.number);
}

/// A witness round-trips through serde, since it crosses into the guest.
#[test]
fn witness_survives_the_guest_boundary() {
    let f: Value = serde_json::from_str(include_str!("fixtures/mainnet.json")).unwrap();
    let w = Witness::EthAccount {
        chain_id: MAINNET,
        header: fixture_header(&f),
        address: fixture_address(&f),
        account_proof: fixture_nodes(&f["account"]["accountProof"]),
    };
    let bytes = bincode::serialize(&w).expect("witness serializes");
    let back: Witness = bincode::deserialize(&bytes).expect("witness deserializes");
    // And still verifies to the identical statement on the other side.
    assert_eq!(back.verify().unwrap(), w.verify().unwrap());
}

// ── fixture helpers (shared shape with tests/mainnet.rs) ────────────────────

fn hex_bytes(v: &Value) -> Vec<u8> {
    let s = v.as_str().expect("hex string").trim_start_matches("0x");
    let padded;
    let s = if s.len() % 2 == 1 {
        padded = format!("0{s}");
        padded.as_str()
    } else {
        s
    };
    hex::decode(s).expect("valid hex")
}

fn hex_b256(v: &Value) -> [u8; 32] {
    let b = hex_bytes(v);
    let mut out = [0u8; 32];
    out.copy_from_slice(&b);
    out
}

fn hex_u64(v: &Value) -> u64 {
    u64::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

fn hex_minimal(v: &Value) -> Vec<u8> {
    let b = hex_bytes(v);
    let i = b.iter().position(|x| *x != 0).unwrap_or(b.len());
    b[i..].to_vec()
}

fn fixture_address(f: &Value) -> [u8; 20] {
    let b = hex_bytes(&f["account"]["address"]);
    let mut out = [0u8; 20];
    out.copy_from_slice(&b);
    out
}

fn fixture_nodes(v: &Value) -> Vec<Vec<u8>> {
    v.as_array().unwrap().iter().map(hex_bytes).collect()
}

fn fixture_header(f: &Value) -> peregrine_interop::BlockHeader {
    let h = &f["header"];
    let mut beneficiary = [0u8; 20];
    beneficiary.copy_from_slice(&hex_bytes(&h["miner"]));
    peregrine_interop::BlockHeader {
        parent_hash: hex_b256(&h["parentHash"]),
        ommers_hash: hex_b256(&h["sha3Uncles"]),
        beneficiary,
        state_root: hex_b256(&h["stateRoot"]),
        transactions_root: hex_b256(&h["transactionsRoot"]),
        receipts_root: hex_b256(&h["receiptsRoot"]),
        logs_bloom: hex_bytes(&h["logsBloom"]),
        difficulty: hex_minimal(&h["difficulty"]),
        number: hex_u64(&h["number"]),
        gas_limit: hex_u64(&h["gasLimit"]),
        gas_used: hex_u64(&h["gasUsed"]),
        timestamp: hex_u64(&h["timestamp"]),
        extra_data: hex_bytes(&h["extraData"]),
        mix_hash: hex_b256(&h["mixHash"]),
        nonce: hex_bytes(&h["nonce"]),
        base_fee_per_gas: Some(hex_minimal(&h["baseFeePerGas"])),
        withdrawals_root: Some(hex_b256(&h["withdrawalsRoot"])),
        blob_gas_used: Some(hex_u64(&h["blobGasUsed"])),
        excess_blob_gas: Some(hex_u64(&h["excessBlobGas"])),
        parent_beacon_block_root: Some(hex_b256(&h["parentBeaconBlockRoot"])),
        requests_hash: Some(hex_b256(&h["requestsHash"])),
    }
}
