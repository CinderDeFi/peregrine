//! Integration: the testnet faucet, with its limits enforced through the
//! pipeline (i.e. as they are during commit on a real validator). The whole
//! point of the faucet is that it cannot be drained, so every limit is tested.

use peregrine_core::{Keypair, PublicKey};
use peregrine_data::faucet::{FaucetDrip, FaucetPolicy, SignedDrip, FAUCET_DOMAIN};
use peregrine_data::sessions::balances_table;
use peregrine_node::payload::WirePayload;
use peregrine_node::pipeline::ExecutionPipeline;

fn balance(node: &ExecutionPipeline, who: &PublicKey) -> u64 {
    node.tables
        .get(&balances_table(), &who.0)
        .and_then(|v| v.try_into().ok())
        .map(u64::from_le_bytes)
        .unwrap_or(0)
}

fn drip(recipient: PublicKey, amount: u64, nonce: u64) -> FaucetDrip {
    FaucetDrip {
        recipient,
        amount,
        nonce,
    }
}

/// A pipeline with a faucet whose authority is `auth`.
fn with_faucet(auth: &Keypair) -> ExecutionPipeline {
    let mut node = ExecutionPipeline::new();
    node.faucet = Some(FaucetPolicy {
        authority: auth.public(),
        per_request: 1_000,
        cooldown_rounds: 100,
        lifetime_cap: 2_500,
    });
    node
}

#[test]
fn a_signed_drip_credits_the_recipient_and_records_it() {
    let auth = Keypair::from_bytes(&[1; 32]);
    let alice = Keypair::from_bytes(&[9; 32]).public();
    let mut node = with_faucet(&auth);
    node.set_round_for_test(10);

    node.apply_payload(&WirePayload::FaucetDrip(Box::new(SignedDrip::new(
        &auth,
        drip(alice, 1_000, 0),
    ))));
    assert_eq!(balance(&node, &alice), 1_000);
    assert_eq!(node.metrics.faucet_drips_applied, 1);

    let rec = node.faucet_record(&alice).expect("recorded");
    assert_eq!(rec.total, 1_000);
    assert_eq!(rec.count, 1);
    assert_eq!(rec.last_round, 10);
}

#[test]
fn a_fauceted_chain_refuses_an_unsigned_or_forged_drip() {
    let auth = Keypair::from_bytes(&[1; 32]);
    let impostor = Keypair::from_bytes(&[2; 32]);
    let alice = Keypair::from_bytes(&[9; 32]).public();
    let mut node = with_faucet(&auth);

    // Signed by someone who is not the authority.
    let mut forged = SignedDrip::new(&auth, drip(alice, 500, 0));
    forged.signature = impostor.sign(FAUCET_DOMAIN, &forged.drip.signing_bytes());
    node.apply_payload(&WirePayload::FaucetDrip(Box::new(forged)));
    assert_eq!(balance(&node, &alice), 0, "a forged drip credits nothing");
    assert_eq!(node.metrics.faucet_drips_rejected, 1);
}

#[test]
fn a_chain_with_no_faucet_refuses_every_drip() {
    let auth = Keypair::from_bytes(&[1; 32]);
    let alice = Keypair::from_bytes(&[9; 32]).public();
    let mut node = ExecutionPipeline::new(); // faucet = None → fail-closed
    node.apply_payload(&WirePayload::FaucetDrip(Box::new(SignedDrip::new(
        &auth,
        drip(alice, 500, 0),
    ))));
    assert_eq!(balance(&node, &alice), 0);
    assert_eq!(node.metrics.faucet_drips_rejected, 1);
}

#[test]
fn the_per_request_cap_bounds_a_single_drip() {
    let auth = Keypair::from_bytes(&[1; 32]);
    let alice = Keypair::from_bytes(&[9; 32]).public();
    let mut node = with_faucet(&auth); // per_request = 1000
    node.apply_payload(&WirePayload::FaucetDrip(Box::new(SignedDrip::new(
        &auth,
        drip(alice, 1_001, 0),
    ))));
    assert_eq!(balance(&node, &alice), 0);
}

#[test]
fn a_recipient_is_rate_limited_by_cooldown_then_lifetime() {
    let auth = Keypair::from_bytes(&[1; 32]);
    let alice = Keypair::from_bytes(&[9; 32]).public();
    let mut node = with_faucet(&auth); // cooldown 100, lifetime 2500

    // Round 0: first drip clears.
    node.set_round_for_test(0);
    node.apply_payload(&WirePayload::FaucetDrip(Box::new(SignedDrip::new(
        &auth,
        drip(alice, 1_000, 0),
    ))));
    assert_eq!(balance(&node, &alice), 1_000);

    // Round 50: still inside the 100-round cooldown → refused.
    node.set_round_for_test(50);
    node.apply_payload(&WirePayload::FaucetDrip(Box::new(SignedDrip::new(
        &auth,
        drip(alice, 1_000, 1),
    ))));
    assert_eq!(balance(&node, &alice), 1_000, "cooldown holds");

    // Round 100: cooldown elapsed → clears (total 2000).
    node.set_round_for_test(100);
    node.apply_payload(&WirePayload::FaucetDrip(Box::new(SignedDrip::new(
        &auth,
        drip(alice, 1_000, 2),
    ))));
    assert_eq!(balance(&node, &alice), 2_000);

    // Round 300: another 1000 would blow the 2500 lifetime cap → refused.
    node.set_round_for_test(300);
    node.apply_payload(&WirePayload::FaucetDrip(Box::new(SignedDrip::new(
        &auth,
        drip(alice, 1_000, 3),
    ))));
    assert_eq!(balance(&node, &alice), 2_000, "lifetime cap holds");

    // But 500 fits exactly.
    node.apply_payload(&WirePayload::FaucetDrip(Box::new(SignedDrip::new(
        &auth,
        drip(alice, 500, 4),
    ))));
    assert_eq!(balance(&node, &alice), 2_500);
}

#[test]
fn genesis_allocations_credit_balances() {
    let alice = Keypair::from_bytes(&[9; 32]).public();
    let mut node = ExecutionPipeline::new();
    node.allocate(&alice, 1_000_000);
    assert_eq!(balance(&node, &alice), 1_000_000);
}
