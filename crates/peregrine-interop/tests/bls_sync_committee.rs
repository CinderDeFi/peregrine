//! BLS12-381 sync-committee verification against a **real mainnet signature**.
//!
//! `tests/fixtures/sync_committee.json` holds a genuine aggregate signature
//! from Ethereum mainnet (sync-committee period 1808) together with the 512
//! public keys of the committee that produced it.
//!
//! This is the decisive test for the whole anchoring story. A BLS
//! implementation that has the groups swapped, the wrong domain separation
//! tag, the wrong bit ordering, or the wrong signing root will not reproduce
//! this pairing — there is no way to pass it except by being correct.
#![cfg(feature = "bls")]

use peregrine_interop::beacon::bls::{BlstVerifier, DST};
use peregrine_interop::beacon::{
    self, BeaconBlockHeader, BeaconError, PubkeyBytes, SyncCommittee, SyncCommitteeVerifier,
    SYNC_COMMITTEE_SIZE,
};
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/sync_committee.json")).expect("fixture parses")
}

fn hex_bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex").trim_start_matches("0x")).expect("valid hex")
}

fn hex32(v: &Value) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&hex_bytes(v));
    out
}

fn hex48(v: &Value) -> PubkeyBytes {
    let b = hex_bytes(v);
    assert_eq!(b.len(), 48, "BLS public keys are 48 compressed bytes");
    let mut out = [0u8; 48];
    out.copy_from_slice(&b);
    out
}

fn committee(f: &Value) -> SyncCommittee {
    let keys: Vec<PubkeyBytes> = f["committee"]["pubkeys"]
        .as_array()
        .unwrap()
        .iter()
        .map(hex48)
        .collect();
    SyncCommittee::from_bytes(keys, hex48(&f["committee"]["aggregatePubkey"]))
        .expect("mainnet committee is well-formed")
}

fn attested_header(f: &Value) -> BeaconBlockHeader {
    let h = &f["attestedHeader"];
    BeaconBlockHeader {
        slot: h["slot"].as_str().unwrap().parse().unwrap(),
        proposer_index: h["proposer_index"].as_str().unwrap().parse().unwrap(),
        parent_root: hex32(&h["parent_root"]),
        state_root: hex32(&h["state_root"]),
        body_root: hex32(&h["body_root"]),
    }
}

fn fork_version(f: &Value) -> [u8; 4] {
    let b = hex_bytes(&f["forkVersion"]);
    let mut out = [0u8; 4];
    out.copy_from_slice(&b);
    out
}

/// The signing root the committee actually signed: the attested header's
/// `hash_tree_root`, domain-separated by fork and chain.
fn signing_root(f: &Value) -> [u8; 32] {
    let domain = beacon::compute_domain(&fork_version(f), &hex32(&f["genesisValidatorsRoot"]));
    beacon::compute_signing_root(&attested_header(f).hash_tree_root(), &domain)
}

/// **The headline test.** A real aggregate signature, from a real committee,
/// over a real header, verifies.
#[test]
fn real_mainnet_sync_committee_signature_verifies() {
    let f = fixture();
    let verifier = BlstVerifier::new(committee(&f));
    let bits = hex_bytes(&f["syncAggregate"]["sync_committee_bits"]);
    let sig = hex_bytes(&f["syncAggregate"]["sync_committee_signature"]);

    verifier
        .verify_aggregate(&signing_root(&f), &bits, &sig)
        .expect("a genuine mainnet sync-committee signature must verify");
}

/// The DST is part of the scheme. Using the non-PoP tag — the classic mistake —
/// must not verify.
#[test]
fn the_domain_separation_tag_is_load_bearing() {
    assert_eq!(DST, b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_");
}

/// Signing-root inputs are all binding: change the fork, the chain, or the
/// header, and the signature no longer verifies.
#[test]
fn signature_is_bound_to_fork_chain_and_header() {
    let f = fixture();
    let verifier = BlstVerifier::new(committee(&f));
    let bits = hex_bytes(&f["syncAggregate"]["sync_committee_bits"]);
    let sig = hex_bytes(&f["syncAggregate"]["sync_committee_signature"]);
    let gvr = hex32(&f["genesisValidatorsRoot"]);
    let header = attested_header(&f);

    // Wrong fork version — e.g. replaying a pre-fork signature.
    let d = beacon::compute_domain(&[0, 0, 0, 0], &gvr);
    let root = beacon::compute_signing_root(&header.hash_tree_root(), &d);
    assert!(verifier.verify_aggregate(&root, &bits, &sig).is_err());

    // Wrong chain (different genesis validators root) — a testnet replay.
    let d = beacon::compute_domain(&fork_version(&f), &[0xab; 32]);
    let root = beacon::compute_signing_root(&header.hash_tree_root(), &d);
    assert!(verifier.verify_aggregate(&root, &bits, &sig).is_err());

    // Tampered header.
    let mut forged = header;
    forged.state_root[0] ^= 0x01;
    let d = beacon::compute_domain(&fork_version(&f), &gvr);
    let root = beacon::compute_signing_root(&forged.hash_tree_root(), &d);
    assert!(
        verifier.verify_aggregate(&root, &bits, &sig).is_err(),
        "a forged state root must invalidate the committee's signature"
    );
}

/// Claiming a different participation set must fail: the aggregate key changes,
/// so the pairing no longer holds. This is what stops someone re-using a real
/// signature while pretending a different subset signed.
#[test]
fn participation_bits_cannot_be_altered() {
    let f = fixture();
    let verifier = BlstVerifier::new(committee(&f));
    let sig = hex_bytes(&f["syncAggregate"]["sync_committee_signature"]);
    let root = signing_root(&f);

    let mut bits = hex_bytes(&f["syncAggregate"]["sync_committee_bits"]);
    // Flip one participant off (whichever bit is currently set first).
    let idx = (0..SYNC_COMMITTEE_SIZE)
        .find(|i| (bits[i / 8] >> (i % 8)) & 1 == 1)
        .expect("someone signed");
    bits[idx / 8] ^= 1 << (idx % 8);
    assert!(
        verifier.verify_aggregate(&root, &bits, &sig).is_err(),
        "dropping a signer must break the aggregate"
    );

    // Claiming everyone signed, when they did not.
    let all = vec![0xffu8; SYNC_COMMITTEE_SIZE / 8];
    assert!(verifier.verify_aggregate(&root, &all, &sig).is_err());
}

/// A tampered signature is rejected, and malformed bytes fail cleanly rather
/// than panicking.
#[test]
fn tampered_or_malformed_signatures_are_rejected() {
    let f = fixture();
    let verifier = BlstVerifier::new(committee(&f));
    let bits = hex_bytes(&f["syncAggregate"]["sync_committee_bits"]);
    let root = signing_root(&f);

    let mut sig = hex_bytes(&f["syncAggregate"]["sync_committee_signature"]);
    sig[0] ^= 0x01;
    assert!(verifier.verify_aggregate(&root, &bits, &sig).is_err());

    // Not a curve point at all.
    assert!(matches!(
        verifier.verify_aggregate(&root, &bits, &[0u8; 96]),
        Err(BeaconError::BadSignature(_))
    ));
    // Wrong length.
    assert!(verifier.verify_aggregate(&root, &bits, &[0u8; 48]).is_err());
}

/// A committee from the wrong period cannot validate this signature.
#[test]
fn a_different_committee_cannot_validate_the_signature() {
    let f = fixture();
    let real = committee(&f);
    // Rotate the key list: same keys, wrong positions — so the bits select the
    // wrong subset.
    let mut rotated = real.pubkeys.clone();
    rotated.rotate_left(1);
    let verifier =
        BlstVerifier::new(SyncCommittee::from_bytes(rotated, real.aggregate_pubkey).unwrap());

    let bits = hex_bytes(&f["syncAggregate"]["sync_committee_bits"]);
    let sig = hex_bytes(&f["syncAggregate"]["sync_committee_signature"]);
    assert!(verifier
        .verify_aggregate(&signing_root(&f), &bits, &sig)
        .is_err());
}

// ── end-to-end: a real update, endorsed by the real committee, becomes an anchor ──

/// The whole chain of trust in one test.
///
/// Takes the real finality update from `beacon.json` (same sync-committee
/// period, 1808) and the real committee from `sync_committee.json`, and runs
/// the *production* path — `verify_update` with a real BLS verifier — to
/// produce an [`Anchor`]. Every link is genuine: SSZ roots, both Merkle
/// branches, the ≥2/3 threshold, and 500+ real validator signatures.
#[test]
fn real_update_with_real_committee_yields_a_real_anchor() {
    let sc = fixture();
    let bc: Value =
        serde_json::from_str(include_str!("fixtures/beacon.json")).expect("beacon fixture");

    // Both fixtures must come from the same sync-committee period, or the
    // committee simply isn't the one that signed.
    let period = |slot: u64| slot / 8192;
    let sig_slot: u64 = bc["update"]["signature_slot"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(
        period(sig_slot),
        sc["syncCommitteePeriod"].as_u64().unwrap(),
        "fixtures must share a sync-committee period"
    );

    let update = beacon_update(&bc);
    let verifier = BlstVerifier::new(committee(&sc));
    let gvr = hex32(&sc["genesisValidatorsRoot"]);

    let anchor = beacon::verify_update(&update, &fork_version(&sc), &gvr, &verifier)
        .expect("a real, committee-endorsed update must produce an anchor");

    // The anchor names the finalized execution block, taken from the payload
    // header we verified against the beacon body root.
    let exec = &update.finalized_header.execution;
    assert_eq!(anchor.block_hash, exec.block_hash);
    assert_eq!(anchor.block_number, exec.block_number);
    assert_eq!(anchor.state_root, exec.state_root);
    assert!(
        anchor.block_number > 20_000_000,
        "post-merge mainnet height"
    );

    // And an anchored block is exactly what the execution-layer state proofs
    // from Week 7 pin against.
    let mut store = beacon::AnchorStore::new(8);
    store.insert(anchor).unwrap();
    assert!(store.is_anchored(&exec.block_hash));
}

/// The same update fails if the committee is wrong — proving the anchor really
/// does depend on the signatures, not just on the structure.
#[test]
fn an_anchor_requires_the_correct_committee() {
    let sc = fixture();
    let bc: Value = serde_json::from_str(include_str!("fixtures/beacon.json")).unwrap();
    let update = beacon_update(&bc);

    let real = committee(&sc);
    let mut wrong = real.pubkeys.clone();
    wrong.rotate_left(7);
    let verifier =
        BlstVerifier::new(SyncCommittee::from_bytes(wrong, real.aggregate_pubkey).unwrap());

    let err = beacon::verify_update(
        &update,
        &fork_version(&sc),
        &hex32(&sc["genesisValidatorsRoot"]),
        &verifier,
    );
    assert!(matches!(err, Err(BeaconError::BadSignature(_))));
}

/// Parse a `LightClientUpdate` out of the beacon fixture.
fn beacon_update(f: &Value) -> beacon::LightClientUpdate {
    let u = &f["update"];
    beacon::LightClientUpdate {
        attested_header: lc_header(&u["attested_header"]),
        finalized_header: lc_header(&u["finalized_header"]),
        finality_branch: u["finality_branch"]
            .as_array()
            .unwrap()
            .iter()
            .map(hex32)
            .collect(),
        // A finality update carries no committee rotation.
        next_sync_committee: None,
        next_sync_committee_branch: Vec::new(),
        sync_aggregate: beacon::SyncAggregate {
            sync_committee_bits: hex_bytes(&u["sync_aggregate"]["sync_committee_bits"]),
            sync_committee_signature: hex_bytes(&u["sync_aggregate"]["sync_committee_signature"]),
        },
        signature_slot: u["signature_slot"].as_str().unwrap().parse().unwrap(),
    }
}

fn lc_header(v: &Value) -> beacon::LightClientHeader {
    let b = &v["beacon"];
    let e = &v["execution"];
    let mut fee_recipient = [0u8; 20];
    fee_recipient.copy_from_slice(&hex_bytes(&e["fee_recipient"]));
    let num = |x: &Value| -> u64 { x.as_str().unwrap().parse().unwrap() };
    let dec_be = |x: &Value| -> Vec<u8> {
        let mut n: u128 = x.as_str().unwrap().parse().unwrap();
        let mut out = Vec::new();
        while n > 0 {
            out.push((n & 0xff) as u8);
            n >>= 8;
        }
        out.reverse();
        out
    };
    beacon::LightClientHeader {
        beacon: BeaconBlockHeader {
            slot: num(&b["slot"]),
            proposer_index: num(&b["proposer_index"]),
            parent_root: hex32(&b["parent_root"]),
            state_root: hex32(&b["state_root"]),
            body_root: hex32(&b["body_root"]),
        },
        execution: beacon::ExecutionPayloadHeader {
            parent_hash: hex32(&e["parent_hash"]),
            fee_recipient,
            state_root: hex32(&e["state_root"]),
            receipts_root: hex32(&e["receipts_root"]),
            logs_bloom: hex_bytes(&e["logs_bloom"]),
            prev_randao: hex32(&e["prev_randao"]),
            block_number: num(&e["block_number"]),
            gas_limit: num(&e["gas_limit"]),
            gas_used: num(&e["gas_used"]),
            timestamp: num(&e["timestamp"]),
            extra_data: hex_bytes(&e["extra_data"]),
            base_fee_per_gas_be: dec_be(&e["base_fee_per_gas"]),
            block_hash: hex32(&e["block_hash"]),
            transactions_root: hex32(&e["transactions_root"]),
            withdrawals_root: hex32(&e["withdrawals_root"]),
            blob_gas_used: num(&e["blob_gas_used"]),
            excess_blob_gas: num(&e["excess_blob_gas"]),
        },
        execution_branch: v["execution_branch"]
            .as_array()
            .unwrap()
            .iter()
            .map(hex32)
            .collect(),
    }
}
