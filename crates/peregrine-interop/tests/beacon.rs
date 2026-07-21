//! Beacon light-client verification against **real Ethereum mainnet data**.
//!
//! `tests/fixtures/beacon.json` is a genuine light-client finality update from
//! a mainnet beacon API. These tests are decisive because the data is real and
//! self-checking:
//!
//! * the beacon chain publishes the root **it** computed for the finalized
//!   header, so our SSZ `hash_tree_root` has to reproduce it byte for byte —
//!   a single wrong field order, endianness, or padding rule could not match;
//! * the finality and execution branches are real Merkle proofs, so they only
//!   verify if our generalized-index constants and branch algorithm are right.

use peregrine_interop::beacon::{
    self, ssz, Anchor, AnchorStore, BeaconBlockHeader, BeaconError, ExecutionPayloadHeader,
    LightClientHeader, LightClientUpdate, RejectingBls, SyncAggregate,
};
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/beacon.json")).expect("fixture parses")
}

fn hex_bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex").trim_start_matches("0x")).expect("valid hex")
}

fn hex32(v: &Value) -> [u8; 32] {
    let b = hex_bytes(v);
    assert_eq!(b.len(), 32, "expected 32 bytes, got {}", b.len());
    let mut out = [0u8; 32];
    out.copy_from_slice(&b);
    out
}

fn num(v: &Value) -> u64 {
    v.as_str().expect("numeric string").parse().expect("u64")
}

/// Beacon APIs render `uint256` as a decimal string; SSZ wants big-endian bytes.
fn dec_to_be(v: &Value) -> Vec<u8> {
    let mut n: u128 = v.as_str().expect("decimal string").parse().expect("u128");
    let mut out = Vec::new();
    while n > 0 {
        out.push((n & 0xff) as u8);
        n >>= 8;
    }
    out.reverse();
    out
}

fn beacon_header(v: &Value) -> BeaconBlockHeader {
    BeaconBlockHeader {
        slot: num(&v["slot"]),
        proposer_index: num(&v["proposer_index"]),
        parent_root: hex32(&v["parent_root"]),
        state_root: hex32(&v["state_root"]),
        body_root: hex32(&v["body_root"]),
    }
}

fn execution_header(v: &Value) -> ExecutionPayloadHeader {
    let mut fee_recipient = [0u8; 20];
    fee_recipient.copy_from_slice(&hex_bytes(&v["fee_recipient"]));
    ExecutionPayloadHeader {
        parent_hash: hex32(&v["parent_hash"]),
        fee_recipient,
        state_root: hex32(&v["state_root"]),
        receipts_root: hex32(&v["receipts_root"]),
        logs_bloom: hex_bytes(&v["logs_bloom"]),
        prev_randao: hex32(&v["prev_randao"]),
        block_number: num(&v["block_number"]),
        gas_limit: num(&v["gas_limit"]),
        gas_used: num(&v["gas_used"]),
        timestamp: num(&v["timestamp"]),
        extra_data: hex_bytes(&v["extra_data"]),
        base_fee_per_gas_be: dec_to_be(&v["base_fee_per_gas"]),
        block_hash: hex32(&v["block_hash"]),
        transactions_root: hex32(&v["transactions_root"]),
        withdrawals_root: hex32(&v["withdrawals_root"]),
        blob_gas_used: num(&v["blob_gas_used"]),
        excess_blob_gas: num(&v["excess_blob_gas"]),
    }
}

fn branch(v: &Value) -> Vec<[u8; 32]> {
    v.as_array().expect("array").iter().map(hex32).collect()
}

fn light_client_header(v: &Value) -> LightClientHeader {
    LightClientHeader {
        beacon: beacon_header(&v["beacon"]),
        execution: execution_header(&v["execution"]),
        execution_branch: branch(&v["execution_branch"]),
    }
}

fn update(f: &Value) -> LightClientUpdate {
    let u = &f["update"];
    LightClientUpdate {
        attested_header: light_client_header(&u["attested_header"]),
        finalized_header: light_client_header(&u["finalized_header"]),
        finality_branch: branch(&u["finality_branch"]),
        next_sync_committee: None,
        next_sync_committee_branch: Vec::new(),
        sync_aggregate: SyncAggregate {
            sync_committee_bits: hex_bytes(&u["sync_aggregate"]["sync_committee_bits"]),
            sync_committee_signature: hex_bytes(&u["sync_aggregate"]["sync_committee_signature"]),
        },
        signature_slot: num(&u["signature_slot"]),
    }
}

/// The decisive SSZ test: our `hash_tree_root` must equal the root the beacon
/// chain computed for this very header.
#[test]
fn beacon_header_root_matches_consensus() {
    let f = fixture();
    let header = beacon_header(&f["update"]["finalized_header"]["beacon"]);
    let expected = hex32(&f["finalizedHeaderRoot"]);
    assert_eq!(
        header.hash_tree_root(),
        expected,
        "SSZ hash_tree_root must reproduce the beacon chain's own header root"
    );
}

/// Any change to any field must change the root — the property that makes the
/// header a binding commitment.
#[test]
fn beacon_header_root_binds_every_field() {
    let f = fixture();
    let good = beacon_header(&f["update"]["finalized_header"]["beacon"]);
    let root = good.hash_tree_root();

    let mut h = good.clone();
    h.slot += 1;
    assert_ne!(h.hash_tree_root(), root);

    let mut h = good.clone();
    h.proposer_index += 1;
    assert_ne!(h.hash_tree_root(), root);

    let mut h = good.clone();
    h.state_root[0] ^= 1;
    assert_ne!(h.hash_tree_root(), root);

    let mut h = good;
    h.body_root[0] ^= 1;
    assert_ne!(h.hash_tree_root(), root);
}

/// The execution payload header's SSZ root, proven against the beacon body
/// root by the real `execution_branch`. This is what ties an *execution* block
/// hash to a *consensus* block.
#[test]
fn execution_payload_branch_verifies_against_beacon_body() {
    let f = fixture();
    let u = update(&f);

    u.finalized_header
        .verify_execution()
        .expect("finalized header's execution payload must verify against its body root");
    u.attested_header
        .verify_execution()
        .expect("attested header's execution payload must verify too");
}

/// Tampering with the payload must break the branch — otherwise an attacker
/// could swap in a block hash of their choosing.
#[test]
fn tampered_execution_payload_is_rejected() {
    let f = fixture();
    let mut u = update(&f);

    u.finalized_header.execution.block_hash[0] ^= 0x01;
    assert!(matches!(
        u.finalized_header.verify_execution(),
        Err(BeaconError::BadExecutionBranch)
    ));

    let mut u = update(&f);
    u.finalized_header.execution.block_number += 1;
    assert!(u.finalized_header.verify_execution().is_err());
}

/// The finality branch links the finalized header into the attested header's
/// state root — the step that carries the sync committee's endorsement down to
/// the block we anchor on.
#[test]
fn finality_branch_verifies_against_attested_state_root() {
    let f = fixture();
    let u = update(&f);
    let (depth, index) = ssz::gindex_parts(beacon::FINALIZED_ROOT_GINDEX);

    assert!(
        ssz::verify_merkle_branch(
            &u.finalized_header.beacon.hash_tree_root(),
            &u.finality_branch,
            depth,
            index,
            &u.attested_header.beacon.state_root,
        ),
        "real finality branch must verify with FINALIZED_ROOT_GINDEX"
    );

    // A forged finalized header must not verify under the same branch.
    let mut forged = u.finalized_header.beacon.clone();
    forged.state_root[0] ^= 0x01;
    assert!(!ssz::verify_merkle_branch(
        &forged.hash_tree_root(),
        &u.finality_branch,
        depth,
        index,
        &u.attested_header.beacon.state_root,
    ));
}

/// Real mainnet participation is far above the threshold.
#[test]
fn real_update_has_supermajority_participation() {
    let f = fixture();
    let u = update(&f);
    let n = u
        .sync_aggregate
        .check_participation()
        .expect("mainnet update is well-attested");
    assert!(n >= beacon::MIN_SYNC_PARTICIPANTS);
    assert!(n <= beacon::SYNC_COMMITTEE_SIZE);
}

/// **The security-critical outcome for this build:** every structural check
/// passes on real data, and the update *still* yields no anchor, because the
/// BLS signature cannot be verified. Failing closed is the whole point — a
/// self-consistent update that nobody endorsed must not become an anchor.
#[test]
fn verified_structure_still_produces_no_anchor_without_bls() {
    let f = fixture();
    let u = update(&f);
    let gvr = hex32(&f["genesisValidatorsRoot"]);

    let result = beacon::verify_update(&u, &[0, 0, 0, 0], &gvr, &RejectingBls);
    match result {
        Err(BeaconError::BadSignature(m)) => {
            assert!(m.contains("not implemented"), "unexpected message: {m}");
        }
        Err(other) => panic!("structural checks should pass on real data; got {other:?}"),
        Ok(_) => panic!("an anchor must not be produced without a verified BLS signature"),
    }
}

/// Structural failures are caught *before* the signature check, so a malformed
/// update is rejected for the honest reason.
#[test]
fn structural_failures_precede_the_signature_check() {
    let f = fixture();

    // Too few signers.
    let mut u = update(&f);
    u.sync_aggregate.sync_committee_bits = vec![0u8; 64];
    assert!(matches!(
        beacon::verify_update(&u, &[0, 0, 0, 0], &[0u8; 32], &RejectingBls),
        Err(BeaconError::InsufficientParticipation { .. })
    ));

    // Broken finality branch.
    let mut u = update(&f);
    u.attested_header.beacon.state_root[0] ^= 0x01;
    assert!(matches!(
        beacon::verify_update(&u, &[0, 0, 0, 0], &[0u8; 32], &RejectingBls),
        Err(BeaconError::BadFinalityBranch)
    ));
}

/// A test-only BLS stand-in, to exercise the path *after* the signature check.
/// It is defined here rather than shipped so no build can accidentally use it.
struct AcceptingBls;
impl beacon::SyncCommitteeVerifier for AcceptingBls {
    fn verify_aggregate(&self, _: &[u8; 32], _: &[u8], _: &[u8]) -> Result<(), BeaconError> {
        Ok(())
    }
}

/// With the signature check satisfied, a real update yields an anchor whose
/// fields come from the *verified* execution payload.
#[test]
fn a_verified_update_yields_the_expected_anchor() {
    let f = fixture();
    let u = update(&f);
    let gvr = hex32(&f["genesisValidatorsRoot"]);

    let anchor = beacon::verify_update(&u, &[0, 0, 0, 0], &gvr, &AcceptingBls)
        .expect("all structural checks pass on real mainnet data");

    let exec = &u.finalized_header.execution;
    assert_eq!(anchor.slot, u.finalized_header.beacon.slot);
    assert_eq!(anchor.block_number, exec.block_number);
    assert_eq!(anchor.block_hash, exec.block_hash);
    assert_eq!(anchor.state_root, exec.state_root);

    // And it can be stored and queried.
    let mut store = AnchorStore::new(8);
    store.insert(anchor).unwrap();
    assert!(store.is_anchored(&exec.block_hash));
    assert!(!store.is_anchored(&[0u8; 32]));
}

/// An anchor is only useful if it names a real, recent execution block.
#[test]
fn anchor_points_at_a_plausible_execution_block() {
    let f = fixture();
    let u = update(&f);
    let anchor = beacon::verify_update(
        &u,
        &[0, 0, 0, 0],
        &hex32(&f["genesisValidatorsRoot"]),
        &AcceptingBls,
    )
    .unwrap();
    assert!(
        anchor.block_number > 20_000_000,
        "post-merge mainnet block height"
    );
    assert_ne!(anchor.block_hash, [0u8; 32]);
    assert_ne!(anchor.state_root, [0u8; 32]);
    let _ = Anchor { ..anchor };
}
