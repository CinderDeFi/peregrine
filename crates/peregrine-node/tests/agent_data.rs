//! Integration: an autonomous agent pays for verifiable feed data with a
//! scoped, budgeted session key. Exercises the full path — open, subscribe, pay
//! per feed update, read the verified value, prove the session's remaining
//! budget — and the edge cases that make it safe: budget exhaustion, out-of-
//! scope refusal, and revocation.

use peregrine_core::Keypair;
use peregrine_data::feeds::{
    feed_latest_table, Aggregation, FeedKind, FeedPublisher, FeedSpec, FeedValue,
};
use peregrine_data::sessions::{
    balances_table, sessions_table, sign_revocation, SessionBuilder, SessionSigner, SessionState,
};
use peregrine_node::payload::WirePayload;
use peregrine_node::pipeline::ExecutionPipeline;

fn balance(node: &ExecutionPipeline, who: &peregrine_core::PublicKey) -> u64 {
    node.tables
        .get(&balances_table(), &who.0)
        .and_then(|v| v.try_into().ok())
        .map(u64::from_le_bytes)
        .unwrap_or(0)
}

/// Read a session's committed state with a proof (what `Client::read_session`
/// does), verifying against the store root.
fn read_session(node: &mut ExecutionPipeline, id: peregrine_core::Hash) -> SessionState {
    let root = node.store_root();
    let read = node
        .prove_read(sessions_table(), &id.0)
        .expect("session present");
    assert!(
        read.verify(&root),
        "session state must verify against the store root"
    );
    SessionState::from_bytes(&read.value).expect("session decodes")
}

/// Read the feed's latest value with a proof.
fn read_feed(node: &mut ExecutionPipeline, feed_id: peregrine_data::feeds::FeedId) -> FeedValue {
    let root = node.store_root();
    let read = node
        .prove_read(feed_latest_table(), &feed_id.0 .0)
        .expect("feed value present");
    assert!(read.verify(&root));
    FeedValue::decode(&read.value).expect("feed decodes")
}

/// Set up a single-source price feed and an agent session scoped + budgeted to
/// pay for it. Returns everything the tests drive.
struct World {
    node: ExecutionPipeline,
    provider: peregrine_core::PublicKey,
    feed_id: peregrine_data::feeds::FeedId,
    feed_pub: FeedPublisher,
    signer: SessionSigner,
    session_id: peregrine_core::Hash,
    principal: Keypair,
    stream: peregrine_data::streams::StreamId,
}

fn setup(budget: u64, per_record_price: u64) -> World {
    let provider_kp = Keypair::from_bytes(&[7; 32]);
    let spec = FeedSpec {
        channel: "price/BTC-USD".into(),
        kind: FeedKind::Price,
        decimals: 2,
        aggregation: Aggregation::Single,
        providers: vec![provider_kp.public()],
        max_staleness_rounds: 1000,
    };
    let mut node = ExecutionPipeline::new();
    let feed_id = node.register_feed(spec.clone());
    let stream = spec.provider_streams()[0];

    let principal = Keypair::from_bytes(&[1; 32]);
    let agent = Keypair::from_bytes(&[2; 32]);
    // A data-consuming agent: scope exactly the feed's source, a total budget,
    // and a per-record ceiling.
    let grant = SessionBuilder::new(100)
        .allow_streams(spec.provider_streams())
        .budget(budget)
        .max_per_action(per_record_price)
        .try_sign(&principal, &agent.public())
        .expect("well-formed grant");
    let session_id = grant.grant.id();

    node.set_round_for_test(1);
    node.open_session(&grant).expect("open");
    let mut signer = SessionSigner::new(agent, session_id);
    // One signature buys the ongoing subscription.
    node.apply_payload(&WirePayload::SessionAction(Box::new(
        signer.subscribe(stream, per_record_price),
    )));

    World {
        node,
        provider: provider_kp.public(),
        feed_id,
        feed_pub: FeedPublisher::new(&spec, provider_kp),
        signer,
        session_id,
        principal,
        stream,
    }
}

#[test]
fn an_agent_pays_per_update_and_reads_the_verified_feed() {
    let mut w = setup(20, 2);

    // The provider pushes five price updates; each committed record charges the
    // agent 2 grains and updates the feed.
    for price in [6_150_000u64, 6_151_000, 6_149_000, 6_152_000, 6_150_500] {
        w.node
            .apply_payload(&WirePayload::Shred(w.feed_pub.observe_at(price, 0)));
    }

    // The agent read the *verified* feed value all along; the last one is
    // committed and provable.
    let fv = read_feed(&mut w.node, w.feed_id);
    assert_eq!(fv.value, 6_150_500);
    assert_eq!(fv.kind, FeedKind::Price);

    // It paid 5 × 2 = 10 grains; the provider earned them.
    assert_eq!(balance(&w.node, &w.provider), 10);

    // And the agent can *prove* its own remaining budget, not just be told.
    let st = read_session(&mut w.node, w.session_id);
    assert_eq!(st.spent, 10);
    assert_eq!(st.remaining(), 10);
    assert!(st.is_subscribed(&w.stream));
    assert!(st.is_active(50));
}

#[test]
fn the_budget_is_a_hard_ceiling_and_the_stream_keeps_flowing() {
    let mut w = setup(20, 2); // affords exactly 10 records

    for i in 0..40u64 {
        w.node
            .apply_payload(&WirePayload::Shred(w.feed_pub.observe_at(6_000_000 + i, 0)));
    }
    // Never spends past the budget…
    let st = read_session(&mut w.node, w.session_id);
    assert_eq!(st.spent, 20, "agent never overspends its budget");
    assert_eq!(st.remaining(), 0);
    assert_eq!(balance(&w.node, &w.provider), 20);
    // …but the data kept flowing and the feed kept updating.
    assert_eq!(read_feed(&mut w.node, w.feed_id).value, 6_000_039);
}

#[test]
fn revocation_stops_payment_immediately() {
    let mut w = setup(1_000, 2);
    for _ in 0..3 {
        w.node
            .apply_payload(&WirePayload::Shred(w.feed_pub.observe_at(6_000_000, 0)));
    }
    let spent_before = read_session(&mut w.node, w.session_id).spent;
    assert_eq!(spent_before, 6);

    // The principal revokes; further committed records charge nothing.
    let sig = sign_revocation(&w.principal, &w.session_id);
    assert!(w.node.revoke_session(&w.session_id, &sig));
    for _ in 0..10 {
        w.node
            .apply_payload(&WirePayload::Shred(w.feed_pub.observe_at(6_000_000, 0)));
    }
    let st = read_session(&mut w.node, w.session_id);
    assert_eq!(
        st.spent, spent_before,
        "a revoked session pays nothing more"
    );
    assert!(!st.is_active(2));
}

#[test]
fn unsubscribing_stops_the_meter() {
    let mut w = setup(1_000, 2);
    w.node
        .apply_payload(&WirePayload::Shred(w.feed_pub.observe_at(1, 0)));
    assert_eq!(read_session(&mut w.node, w.session_id).spent, 2);

    w.node.apply_payload(&WirePayload::SessionAction(Box::new(
        w.signer.unsubscribe(w.stream),
    )));
    for _ in 0..5 {
        w.node
            .apply_payload(&WirePayload::Shred(w.feed_pub.observe_at(2, 0)));
    }
    assert_eq!(
        read_session(&mut w.node, w.session_id).spent,
        2,
        "no charge after unsubscribe"
    );
}

#[test]
fn an_out_of_scope_subscription_is_refused() {
    let mut w = setup(1_000, 2);
    // A stream the session was never scoped to.
    let other = peregrine_data::streams::StreamId::derive("price/DOGE", &w.provider);
    let before = w.signer.next_nonce();
    w.node.apply_payload(&WirePayload::SessionAction(Box::new(
        w.signer.subscribe(other, 2),
    )));
    // The action was refused; the session never subscribed to it. (The agent
    // must roll its nonce back after a rejection — see the SessionSigner docs.)
    w.signer.rollback();
    let st = read_session(&mut w.node, w.session_id);
    assert!(!st.is_subscribed(&other));
    let _ = before;
}
