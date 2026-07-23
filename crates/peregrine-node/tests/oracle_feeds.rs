//! Integration: oracle feeds end to end — register a feed, publish signed
//! observations from several providers, aggregate, and read the latest value
//! back **with a proof** against the store root. Also covers staleness (a dark
//! source is dropped) and single-source feeds.

use peregrine_core::{Keypair, PublicKey};
use peregrine_data::feeds::{
    feed_latest_table, feeds_table, Aggregation, FeedId, FeedKind, FeedPublisher, FeedSpec,
    FeedValue,
};
use peregrine_node::payload::WirePayload;
use peregrine_node::pipeline::ExecutionPipeline;

fn kp(seed: u8) -> Keypair {
    Keypair::from_bytes(&[seed; 32])
}

/// Read a feed's latest value with a proof and verify it against the store root.
fn read_feed(node: &mut ExecutionPipeline, feed_id: FeedId) -> Option<FeedValue> {
    let root = node.store_root();
    let read = node.prove_read(feed_latest_table(), &feed_id.0 .0)?;
    assert!(
        read.verify(&root),
        "feed proof must verify against the store root"
    );
    assert!(
        !read.verify(&peregrine_core::Hash::ZERO),
        "feed proof must not verify against a wrong root"
    );
    Some(FeedValue::decode(&read.value).expect("feed value decodes"))
}

fn price_feed(providers: Vec<PublicKey>) -> FeedSpec {
    FeedSpec {
        channel: "price/BTC-USD".into(),
        kind: FeedKind::Price,
        decimals: 2,
        aggregation: Aggregation::Median,
        providers,
        max_staleness_rounds: 5,
    }
}

#[test]
fn a_median_price_feed_aggregates_and_reads_back_with_a_proof() {
    let keys = [kp(1), kp(2), kp(3)];
    let spec = price_feed(keys.iter().map(|k| k.public()).collect());
    let mut node = ExecutionPipeline::new();
    let feed_id = node.register_feed(spec.clone());

    // The registration is itself provable: sys.feeds carries the summary.
    assert!(node.tables.get(&feeds_table(), &feed_id.0 .0).is_some());

    // Three providers publish their latest prices (in cents).
    let mut pubs: Vec<FeedPublisher> = keys
        .into_iter()
        .map(|k| FeedPublisher::new(&spec, k))
        .collect();
    node.set_round_for_test(0);
    for (i, price) in [6_150_000u64, 6_151_000, 6_149_000].iter().enumerate() {
        let shred = pubs[i].observe_at(*price, 0);
        node.apply_payload(&WirePayload::Shred(shred));
    }

    let fv = read_feed(&mut node, feed_id).expect("feed has a value");
    assert_eq!(fv.value, 6_150_000, "median of the three prices");
    assert_eq!(fv.n_sources, 3);
    assert_eq!(fv.updated_round, 0);
    assert_eq!(fv.decimals, 2);
    assert_eq!(fv.kind, FeedKind::Price);
    assert!((fv.as_f64() - 61_500.0).abs() < 1e-9);
    assert!(fv.is_fresh(3, spec.max_staleness_rounds));
}

#[test]
fn a_dark_source_is_dropped_from_the_aggregate() {
    let keys = [kp(10), kp(11), kp(12)];
    let spec = price_feed(keys.iter().map(|k| k.public()).collect());
    let mut node = ExecutionPipeline::new();
    let feed_id = node.register_feed(spec.clone());
    let mut pubs: Vec<FeedPublisher> = keys
        .into_iter()
        .map(|k| FeedPublisher::new(&spec, k))
        .collect();

    // Round 0: all three report.
    node.set_round_for_test(0);
    for (i, price) in [100u64, 101, 99].iter().enumerate() {
        let shred = pubs[i].observe_at(*price, 0);
        node.apply_payload(&WirePayload::Shred(shred));
    }
    assert_eq!(read_feed(&mut node, feed_id).unwrap().n_sources, 3);

    // Round 10 (> max_staleness 5): only providers 0 and 1 refresh; provider 2
    // has been silent since round 0 and is now stale.
    node.set_round_for_test(10);
    for i in [0usize, 1] {
        let price = if i == 0 { 200 } else { 202 };
        let shred = pubs[i].observe_at(price, 0);
        node.apply_payload(&WirePayload::Shred(shred));
    }
    let fv = read_feed(&mut node, feed_id).unwrap();
    assert_eq!(fv.n_sources, 2, "the dark source is excluded");
    assert_eq!(fv.value, 201, "median of only the two fresh sources");
    assert_eq!(fv.updated_round, 10);
}

#[test]
fn a_single_source_rwa_feed_tracks_its_provider() {
    let appraiser = kp(20);
    let spec = FeedSpec {
        channel: "rwa/BUILDING-7-valuation".into(),
        kind: FeedKind::Rwa,
        decimals: 0,
        aggregation: Aggregation::Single,
        providers: vec![appraiser.public()],
        max_staleness_rounds: 100,
    };
    let mut node = ExecutionPipeline::new();
    let feed_id = node.register_feed(spec.clone());
    let mut pubr = FeedPublisher::new(&spec, appraiser);

    node.set_round_for_test(1);
    node.apply_payload(&WirePayload::Shred(pubr.observe_at(2_500_000, 0)));
    let fv = read_feed(&mut node, feed_id).unwrap();
    assert_eq!(fv.value, 2_500_000);
    assert_eq!(fv.kind, FeedKind::Rwa);
    assert_eq!(fv.n_sources, 1);

    // A revaluation moves the feed.
    node.set_round_for_test(2);
    node.apply_payload(&WirePayload::Shred(pubr.observe_at(2_600_000, 0)));
    assert_eq!(read_feed(&mut node, feed_id).unwrap().value, 2_600_000);
}

#[test]
fn registration_is_permissionless_via_a_payload_and_idempotent() {
    let spec = price_feed(vec![kp(30).public(), kp(31).public()]);
    let feed_id = spec.id();
    let mut node = ExecutionPipeline::new();

    // Register through the committed payload path (what an RPC submission does).
    node.apply_payload(&WirePayload::RegisterFeed(Box::new(spec.clone())));
    assert!(node.feeds.contains(&feed_id));
    let count = node.metrics.feeds_registered;

    // Re-registering the same content-addressed spec changes nothing.
    node.apply_payload(&WirePayload::RegisterFeed(Box::new(spec)));
    assert_eq!(node.metrics.feeds_registered, count, "idempotent");
}

#[test]
fn an_unauthorised_publisher_cannot_feed_a_feed() {
    let real = kp(40);
    let spec = FeedSpec {
        channel: "price/ETH-USD".into(),
        kind: FeedKind::Price,
        decimals: 2,
        aggregation: Aggregation::Single,
        providers: vec![real.public()],
        max_staleness_rounds: 100,
    };
    let mut node = ExecutionPipeline::new();
    let feed_id = node.register_feed(spec.clone());

    // An impostor publishes to the same channel — a *different* stream, since
    // stream id derives from the publisher key, so it is not indexed to the feed
    // and never touches sys.feed_latest.
    let impostor = kp(41);
    let mut bad = FeedPublisher::new(&spec, impostor);
    node.set_round_for_test(1);
    node.apply_payload(&WirePayload::Shred(bad.observe_at(1, 0)));
    assert!(
        read_feed(&mut node, feed_id).is_none(),
        "an unauthorised source produces no feed value"
    );
}
