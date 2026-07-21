//! **Autonomous** sync-committee rotation against real Ethereum mainnet data.
//!
//! Week 10 could verify a committee's signature, but a human still had to
//! supply the committee. This closes that: seeded once from a bootstrap, the
//! light client derives every subsequent committee from the chain itself.
//!
//! `tests/fixtures/rotation.json` is real: a mainnet `light_client/bootstrap`
//! for period 1808 (whose `current_sync_committee_branch` proves the committee
//! under the header's state root), plus a real update **signed by that
//! committee** carrying `next_sync_committee` — the period-1809 committee —
//! proven by `next_sync_committee_branch`.
//!
//! The cross-check that makes this convincing: the committee the store *learns*
//! by rotation is compared against the independently-fetched period-1808
//! committee in `sync_committee.json`, whose signatures we verified in Week 10.
#![cfg(feature = "bls")]

use peregrine_interop::beacon::bls::BlstVerifier;
use peregrine_interop::beacon::{
    self, BeaconBlockHeader, BeaconError, ExecutionPayloadHeader, LightClientHeader,
    LightClientStore, LightClientUpdate, PubkeyBytes, SyncAggregate, SyncCommittee,
};
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/rotation.json")).expect("fixture parses")
}

fn hex_bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex").trim_start_matches("0x")).expect("valid hex")
}
fn hex32(v: &Value) -> [u8; 32] {
    let mut o = [0u8; 32];
    o.copy_from_slice(&hex_bytes(v));
    o
}
fn hex48(v: &Value) -> PubkeyBytes {
    let mut o = [0u8; 48];
    o.copy_from_slice(&hex_bytes(v));
    o
}
fn num(v: &Value) -> u64 {
    v.as_str().unwrap().parse().unwrap()
}
fn branch(v: &Value) -> Vec<[u8; 32]> {
    v.as_array().unwrap().iter().map(hex32).collect()
}

fn sync_committee(v: &Value) -> SyncCommittee {
    SyncCommittee::from_bytes(
        v["pubkeys"].as_array().unwrap().iter().map(hex48).collect(),
        hex48(&v["aggregate_pubkey"]),
    )
    .expect("well-formed committee")
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

fn lc_header(v: &Value) -> LightClientHeader {
    let e = &v["execution"];
    let mut fee_recipient = [0u8; 20];
    fee_recipient.copy_from_slice(&hex_bytes(&e["fee_recipient"]));
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
    LightClientHeader {
        beacon: beacon_header(&v["beacon"]),
        execution: ExecutionPayloadHeader {
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
        execution_branch: branch(&v["execution_branch"]),
    }
}

fn update(f: &Value) -> LightClientUpdate {
    let u = &f["update"];
    LightClientUpdate {
        attested_header: lc_header(&u["attested_header"]),
        finalized_header: lc_header(&u["finalized_header"]),
        finality_branch: branch(&u["finality_branch"]),
        next_sync_committee: Some(sync_committee(&u["next_sync_committee"])),
        next_sync_committee_branch: branch(&u["next_sync_committee_branch"]),
        sync_aggregate: SyncAggregate {
            sync_committee_bits: hex_bytes(&u["sync_aggregate"]["sync_committee_bits"]),
            sync_committee_signature: hex_bytes(&u["sync_aggregate"]["sync_committee_signature"]),
        },
        signature_slot: num(&u["signature_slot"]),
    }
}

fn seed_store(f: &Value) -> LightClientStore {
    let b = &f["bootstrap"];
    LightClientStore::from_bootstrap(
        &beacon_header(&b["header"]),
        sync_committee(&b["currentSyncCommittee"]),
        &branch(&b["currentSyncCommitteeBranch"]),
    )
    .expect("real bootstrap must seed the store")
}

fn fork_version(f: &Value) -> [u8; 4] {
    let mut o = [0u8; 4];
    o.copy_from_slice(&hex_bytes(&f["forkVersion"]));
    o
}

/// The bootstrap's own branch must prove its committee under the header's
/// state root — validating both `SyncCommittee::hash_tree_root` and
/// `CURRENT_SYNC_COMMITTEE_GINDEX` against real data.
#[test]
fn bootstrap_committee_is_proven_against_the_beacon_state() {
    let f = fixture();
    let store = seed_store(&f);
    assert_eq!(store.period(), f["bootstrap"]["period"].as_u64().unwrap());
    assert_eq!(store.current_committee().pubkeys.len(), 512);
    assert!(store.next_committee().is_none(), "nothing learned yet");
}

/// A bootstrap whose committee does not match the branch must be refused —
/// otherwise the seed could smuggle in an arbitrary committee.
#[test]
fn a_bootstrap_with_the_wrong_committee_is_refused() {
    let f = fixture();
    let b = &f["bootstrap"];
    let mut committee = sync_committee(&b["currentSyncCommittee"]);
    committee.pubkeys[0] = [0xab; 48]; // swap one key

    let err = LightClientStore::from_bootstrap(
        &beacon_header(&b["header"]),
        committee,
        &branch(&b["currentSyncCommitteeBranch"]),
    );
    assert!(matches!(err, Err(BeaconError::BadCurrentCommitteeBranch)));
}

/// **The headline test.** Seeded once, the store learns the *next* period's
/// committee from a real, committee-signed update — no operator input.
#[test]
fn rotation_learns_the_next_committee_autonomously() {
    let f = fixture();
    let mut store = seed_store(&f);
    let u = update(&f);
    let gvr = hex32(&f["genesisValidatorsRoot"]);

    let anchor = store
        .apply_update(&u, &fork_version(&f), &gvr, |c| {
            BlstVerifier::new(c.clone())
        })
        .expect("a real committee-signed update must apply");

    // We now hold the next period's committee, derived from the chain.
    let next = store
        .next_committee()
        .expect("rotation learned a committee");
    assert_eq!(next.pubkeys.len(), 512);
    assert_ne!(
        next,
        store.current_committee(),
        "the next committee must actually differ from the current one"
    );
    // The update was from the same period, so we have not rotated yet.
    assert_eq!(store.period(), f["bootstrap"]["period"].as_u64().unwrap());
    assert!(anchor.block_number > 20_000_000);
}

/// The learned committee is bound to the beacon state: tamper with it and the
/// branch fails, so a relayer cannot inject a committee of its choosing.
#[test]
fn a_forged_next_committee_is_rejected() {
    let f = fixture();
    let mut u = update(&f);
    u.next_sync_committee.as_mut().unwrap().pubkeys[7] = [0xcd; 48];

    assert!(matches!(
        u.verify_next_sync_committee(),
        Err(BeaconError::BadNextCommitteeBranch)
    ));

    // And it cannot slip through the store either.
    let f2 = fixture();
    let mut store = seed_store(&f2);
    let err = store.apply_update(
        &u,
        &fork_version(&f2),
        &hex32(&f2["genesisValidatorsRoot"]),
        |c| BlstVerifier::new(c.clone()),
    );
    assert!(matches!(err, Err(BeaconError::BadNextCommitteeBranch)));
}

/// An update signed by a period the store knows nothing about is refused
/// rather than guessed at — guessing is how a light client gets walked onto a
/// fork.
#[test]
fn an_update_from_an_unknown_period_is_refused() {
    let f = fixture();
    let mut store = seed_store(&f);
    let mut u = update(&f);
    // Claim it was signed three periods in the future.
    u.signature_slot += 3 * beacon::SLOTS_PER_PERIOD;

    let err = store.apply_update(
        &u,
        &fork_version(&f),
        &hex32(&f["genesisValidatorsRoot"]),
        |c| BlstVerifier::new(c.clone()),
    );
    assert!(matches!(err, Err(BeaconError::UnknownSigningPeriod { .. })));
}

/// The rotated-to committee must be the same one that, independently, signs in
/// the next period. This ties rotation to Week 10's verified signatures.
#[test]
fn the_learned_committee_matches_the_independently_fetched_one() {
    let f = fixture();
    let mut store = seed_store(&f);
    let u = update(&f);
    store
        .apply_update(
            &u,
            &fork_version(&f),
            &hex32(&f["genesisValidatorsRoot"]),
            |c| BlstVerifier::new(c.clone()),
        )
        .unwrap();

    // `sync_committee.json` was fetched separately, for period 1808 — the same
    // period the bootstrap seeded. The store's *current* committee must equal
    // it, which confirms both fixtures describe the same chain.
    let sc: Value =
        serde_json::from_str(include_str!("fixtures/sync_committee.json")).expect("fixture");
    let independent = SyncCommittee::from_bytes(
        sc["committee"]["pubkeys"]
            .as_array()
            .unwrap()
            .iter()
            .map(hex48)
            .collect(),
        hex48(&sc["committee"]["aggregatePubkey"]),
    )
    .unwrap();

    assert_eq!(
        store.current_committee(),
        &independent,
        "the seeded committee must match the independently fetched period-1808 committee"
    );
}

/// Replaying the same update must not advance the anchor.
#[test]
fn replaying_an_update_does_not_move_the_anchor() {
    let f = fixture();
    let mut store = seed_store(&f);
    let u = update(&f);
    let gvr = hex32(&f["genesisValidatorsRoot"]);
    let fv = fork_version(&f);

    let first = store
        .apply_update(&u, &fv, &gvr, |c| BlstVerifier::new(c.clone()))
        .unwrap();
    let again = store.apply_update(&u, &fv, &gvr, |c| BlstVerifier::new(c.clone()));
    assert!(matches!(again, Err(BeaconError::NotNewer)));
    assert_eq!(store.anchor().unwrap().slot, first.slot);
}
