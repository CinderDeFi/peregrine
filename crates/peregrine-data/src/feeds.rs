//! # Oracle & verifiable data feeds
//!
//! A production-shaped oracle layer built *on top of* Streams and Tables, with
//! no new trust assumptions: a feed value is just committed table state, so
//! every read is a [`ProvenRead`](crate::tables::ProvenRead) against the 32-byte
//! store root.
//!
//! ## The shape of a feed
//!
//! ```text
//!   providers ──sign observations──▶ Streams ──commit──▶ per-source cells
//!                                                              │ aggregate fresh
//!                                                              ▼
//!                                        sys.feed_latest[feed_id]  (value + round)
//! ```
//!
//! * A **[`FeedSpec`]** names a channel, a value kind, its decimals, an
//!   aggregation rule, the set of authorised **providers**, and a staleness
//!   bound. Its identity [`FeedSpec::id`] is the **hash of the spec**, so the
//!   feed id commits to *who may publish* and *how it aggregates* — trusting a
//!   feed id transitively fixes its provider set. There is no registration
//!   authority: registering a feed is publishing its (self-authenticating) spec.
//! * Each provider publishes **[`FeedObservation`]s** to its own stream,
//!   `StreamId::derive(channel, provider)`. Only the named provider can sign
//!   them (Streams already enforces this).
//! * On commit the node writes the provider's latest into a per-source cell,
//!   then re-aggregates the **fresh** sources into `sys.feed_latest[feed_id]`.
//!   Stale sources are dropped from the aggregate, so a provider that goes dark
//!   stops skewing the median.
//!
//! ## Reading a feed
//!
//! A contract or agent reads `sys.feed_latest[feed_id]` with a proof, decodes a
//! [`FeedValue`], and checks it is not stale for the current round. That is the
//! whole trust surface: the store root, and the provider set the feed id commits
//! to.
//!
//! ## Encodings
//!
//! Everything on-chain is ≤32 bytes so it fits a light-client / EVM row, and
//! `value` is the first field of each cell so a contract that only wants the
//! number can read the low 8 bytes.

use crate::streams::StreamId;
use crate::tables::TableId;
use peregrine_core::{Hash, PublicKey, Round};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Version byte on every feed encoding, so the layout can evolve without a
/// silent misread (an unknown version is refused, never guessed).
const FEED_ENC_V1: u8 = 1;

/// Table of registered feed spec summaries, keyed by feed id.
pub fn feeds_table() -> TableId {
    TableId::named("sys.feeds")
}
/// Table of aggregated latest values, keyed by feed id.
pub fn feed_latest_table() -> TableId {
    TableId::named("sys.feed_latest")
}
/// Table of per-source latest values, keyed by `feed_id ‖ provider`.
pub fn feed_source_table() -> TableId {
    TableId::named("sys.feed_source")
}

/// The cell address for one provider's latest under a feed.
pub fn source_key(feed_id: &FeedId, provider: &PublicKey) -> Vec<u8> {
    let mut k = Vec::with_capacity(64);
    k.extend_from_slice(&feed_id.0 .0);
    k.extend_from_slice(&provider.0);
    k
}

/// What a feed measures. Advisory metadata — it does not change how a value is
/// stored, but it tells a consumer how to interpret it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FeedKind {
    /// A price, as a fixed-point integer scaled by `decimals`.
    Price,
    /// A real-world-asset valuation (e.g. property, reserve), same scaling.
    Rwa,
    /// Any other scalar real-world datum.
    Generic,
}

impl FeedKind {
    pub fn code(self) -> u8 {
        match self {
            FeedKind::Price => 0,
            FeedKind::Rwa => 1,
            FeedKind::Generic => 2,
        }
    }
    pub fn from_code(c: u8) -> Option<Self> {
        Some(match c {
            0 => FeedKind::Price,
            1 => FeedKind::Rwa,
            2 => FeedKind::Generic,
            _ => return None,
        })
    }
}

/// How multiple providers' latest values are combined into the feed value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Aggregation {
    /// A single authoritative source; the feed value is that provider's latest.
    Single,
    /// The median of the fresh providers' latest values — robust to one bad or
    /// lagging source.
    Median,
}

impl Aggregation {
    pub fn code(self) -> u8 {
        match self {
            Aggregation::Single => 0,
            Aggregation::Median => 1,
        }
    }
    pub fn from_code(c: u8) -> Option<Self> {
        Some(match c {
            0 => Aggregation::Single,
            1 => Aggregation::Median,
            _ => return None,
        })
    }
}

/// Feed identity — the hash of its spec. Content-addressed, so two identical
/// specs are the same feed and a different provider set is a different feed.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FeedId(pub Hash);

impl std::fmt::Debug for FeedId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "feed:{}", self.0.short())
    }
}

/// The public description of a feed. Its [`id`](Self::id) is the hash of these
/// fields, so the id commits to the provider set and the aggregation rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedSpec {
    /// Human channel name; each provider publishes to `derive(channel, provider)`.
    pub channel: String,
    pub kind: FeedKind,
    /// Fixed-point scale: the real value is `value * 10^-decimals`.
    pub decimals: u8,
    pub aggregation: Aggregation,
    /// Authorised providers. Only these keys' signed observations count, and the
    /// set is bound into the feed id.
    pub providers: Vec<PublicKey>,
    /// A source (and hence the feed) is stale if it has not updated within this
    /// many committed rounds. Stale sources are dropped from the aggregate.
    pub max_staleness_rounds: u64,
}

impl FeedSpec {
    /// Canonical bytes the feed id hashes over. Providers are sorted so the id
    /// is independent of the order they were listed in.
    fn canonical(&self) -> Vec<u8> {
        let mut providers = self.providers.clone();
        providers.sort_by_key(|p| p.0);
        let canon = (
            &self.channel,
            self.kind.code(),
            self.decimals,
            self.aggregation.code(),
            providers.iter().map(|p| p.0).collect::<Vec<_>>(),
            self.max_staleness_rounds,
        );
        bincode::serialize(&canon).expect("feed spec serialize")
    }

    /// The content-addressed feed id.
    pub fn id(&self) -> FeedId {
        FeedId(Hash::digest(&self.canonical()))
    }

    /// The stream a given provider publishes this feed's observations on.
    pub fn provider_stream(&self, provider: &PublicKey) -> StreamId {
        StreamId::derive(&self.channel, provider)
    }

    /// Every source stream of this feed — one per provider. An agent scopes a
    /// session to a whole feed with
    /// `SessionBuilder::new(..).allow_streams(spec.provider_streams())`.
    pub fn provider_streams(&self) -> Vec<StreamId> {
        self.providers.iter().map(|p| self.provider_stream(p)).collect()
    }

    /// Compact on-chain summary written to `sys.feeds[feed_id]`: enough to prove
    /// a feed is registered and read its basic parameters. The provider set is
    /// bound into the id, so it is committed implicitly.
    pub fn summary_bytes(&self) -> Vec<u8> {
        let n = self.providers.len().min(u8::MAX as usize) as u8;
        let mut v = Vec::with_capacity(13);
        v.push(FEED_ENC_V1);
        v.push(self.kind.code());
        v.push(self.decimals);
        v.push(self.aggregation.code());
        v.push(n);
        v.extend_from_slice(&self.max_staleness_rounds.to_le_bytes());
        v
    }
}

/// One provider's signed data point, carried in a stream record's `payload`.
///
/// Deliberately tiny — value plus the provider's advisory timestamp. The
/// authoritative time is the committed round, assigned on materialization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeedObservation {
    pub value: u64,
    pub timestamp_ns: u64,
}

impl FeedObservation {
    pub fn new(value: u64, timestamp_ns: u64) -> Self {
        Self {
            value,
            timestamp_ns,
        }
    }

    /// Encode for a stream record payload: `[version][value:8][timestamp:8]`.
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(17);
        v.push(FEED_ENC_V1);
        v.extend_from_slice(&self.value.to_le_bytes());
        v.extend_from_slice(&self.timestamp_ns.to_le_bytes());
        v
    }

    /// Decode; `None` if the version is unknown or the length is wrong.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 17 || bytes[0] != FEED_ENC_V1 {
            return None;
        }
        Some(Self {
            value: u64::from_le_bytes(bytes[1..9].try_into().ok()?),
            timestamp_ns: u64::from_le_bytes(bytes[9..17].try_into().ok()?),
        })
    }
}

/// Encode a per-source cell: `[value:8][round:8]`.
pub fn encode_source(value: u64, round: Round) -> Vec<u8> {
    let mut v = Vec::with_capacity(16);
    v.extend_from_slice(&value.to_le_bytes());
    v.extend_from_slice(&round.to_le_bytes());
    v
}

/// Decode a per-source cell into `(value, round)`.
pub fn decode_source(bytes: &[u8]) -> Option<(u64, Round)> {
    if bytes.len() != 16 {
        return None;
    }
    Some((
        u64::from_le_bytes(bytes[0..8].try_into().ok()?),
        u64::from_le_bytes(bytes[8..16].try_into().ok()?),
    ))
}

/// The aggregated latest value of a feed, as stored in `sys.feed_latest` and
/// read by consumers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeedValue {
    pub value: u64,
    pub decimals: u8,
    pub kind: FeedKind,
    pub aggregation: Aggregation,
    /// Number of fresh sources that contributed to this value.
    pub n_sources: u8,
    /// Committed round at which this value was last recomputed.
    pub updated_round: Round,
}

impl FeedValue {
    /// Encode: `[version][kind][decimals][aggregation][n_sources][value:8][round:8]`.
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(21);
        v.push(FEED_ENC_V1);
        v.push(self.kind.code());
        v.push(self.decimals);
        v.push(self.aggregation.code());
        v.push(self.n_sources);
        v.extend_from_slice(&self.value.to_le_bytes());
        v.extend_from_slice(&self.updated_round.to_le_bytes());
        v
    }

    /// Decode a `sys.feed_latest` cell; `None` if malformed or an unknown
    /// version/kind/aggregation.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 21 || bytes[0] != FEED_ENC_V1 {
            return None;
        }
        Some(Self {
            kind: FeedKind::from_code(bytes[1])?,
            decimals: bytes[2],
            aggregation: Aggregation::from_code(bytes[3])?,
            n_sources: bytes[4],
            value: u64::from_le_bytes(bytes[5..13].try_into().ok()?),
            updated_round: u64::from_le_bytes(bytes[13..21].try_into().ok()?),
        })
    }

    /// How many committed rounds old this value is at `now`.
    pub fn staleness(&self, now: Round) -> u64 {
        now.saturating_sub(self.updated_round)
    }

    /// Whether the value is fresh enough at `now` for a `max_staleness` bound.
    pub fn is_fresh(&self, now: Round, max_staleness: u64) -> bool {
        self.staleness(now) <= max_staleness
    }

    /// The value as a floating-point number, applying `decimals`. Convenience
    /// for display; on-chain logic should stay in the integer domain.
    pub fn as_f64(&self) -> f64 {
        self.value as f64 / 10f64.powi(self.decimals as i32)
    }
}

/// Combine fresh source values under an aggregation rule. `values` must be
/// non-empty. The median of an even count is the lower-of-the-two-middles' mean
/// via integer division — deterministic, no floating point on the consensus
/// path.
pub fn aggregate(values: &[u64], rule: Aggregation) -> u64 {
    debug_assert!(!values.is_empty(), "aggregate over an empty source set");
    match rule {
        Aggregation::Single => *values.first().unwrap_or(&0),
        Aggregation::Median => {
            let mut v = values.to_vec();
            v.sort_unstable();
            let n = v.len();
            if n % 2 == 1 {
                v[n / 2]
            } else {
                // Average the two middle values, integer-exact via u128.
                let a = v[n / 2 - 1] as u128;
                let b = v[n / 2] as u128;
                ((a + b) / 2) as u64
            }
        }
    }
}

/// A convenience publisher for a data provider: wraps a stream
/// [`Publisher`](crate::streams::Publisher) and encodes observations, so a data
/// source just calls [`observe`](Self::observe). The keypair must be one of the
/// feed's providers for its observations to count.
pub struct FeedPublisher {
    publisher: crate::streams::Publisher,
}

impl FeedPublisher {
    /// A publisher for `keypair` on `spec`'s channel.
    pub fn new(spec: &FeedSpec, keypair: peregrine_core::Keypair) -> Self {
        Self {
            publisher: crate::streams::Publisher::new(&spec.channel, keypair),
        }
    }

    /// The stream these observations ride on (== `spec.provider_stream(key)`).
    pub fn stream_id(&self) -> StreamId {
        self.publisher.stream_id()
    }

    pub fn public_key(&self) -> PublicKey {
        self.publisher.public_key()
    }

    /// Sign the next observation of `value`, stamping it with the current
    /// wall-clock as an advisory timestamp. The authoritative time is the
    /// committed round assigned on materialization.
    pub fn observe(&mut self, value: u64) -> crate::streams::StreamShred {
        self.observe_at(value, now_ns())
    }

    /// As [`observe`](Self::observe), with an explicit timestamp — deterministic,
    /// for tests and replay.
    pub fn observe_at(&mut self, value: u64, timestamp_ns: u64) -> crate::streams::StreamShred {
        self.publisher
            .emit(FeedObservation::new(value, timestamp_ns).encode())
    }
}

fn now_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// The node-side registry of live feeds: their specs and the reverse index from
/// a provider's stream to `(feed, provider)`. In-memory and deterministic —
/// registration rides a committed payload, so every validator builds the same
/// index. The authoritative values themselves live in tables.
#[derive(Default)]
pub struct FeedRegistry {
    specs: BTreeMap<FeedId, FeedSpec>,
    stream_index: BTreeMap<StreamId, (FeedId, PublicKey)>,
}

impl FeedRegistry {
    pub fn contains(&self, id: &FeedId) -> bool {
        self.specs.contains_key(id)
    }

    /// Register a spec, indexing each provider's stream. Idempotent: a spec is
    /// content-addressed, so re-inserting the same one changes nothing.
    pub fn insert(&mut self, spec: FeedSpec) -> FeedId {
        let id = spec.id();
        for p in &spec.providers {
            self.stream_index.insert(spec.provider_stream(p), (id, *p));
        }
        self.specs.insert(id, spec);
        id
    }

    /// Which feed and provider a committed stream belongs to, if any.
    pub fn feed_for_stream(&self, stream: &StreamId) -> Option<(FeedId, PublicKey)> {
        self.stream_index.get(stream).copied()
    }

    pub fn spec(&self, id: &FeedId) -> Option<&FeedSpec> {
        self.specs.get(id)
    }

    pub fn len(&self) -> usize {
        self.specs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.specs.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use peregrine_core::Keypair;

    fn providers(n: u8) -> Vec<PublicKey> {
        (0..n)
            .map(|i| Keypair::from_bytes(&[i + 1; 32]).public())
            .collect()
    }

    fn spec(agg: Aggregation, provs: Vec<PublicKey>) -> FeedSpec {
        FeedSpec {
            channel: "price/BTC-USD".into(),
            kind: FeedKind::Price,
            decimals: 2,
            aggregation: agg,
            providers: provs,
            max_staleness_rounds: 10,
        }
    }

    #[test]
    fn feed_id_is_content_addressed_and_provider_order_independent() {
        let p = providers(3);
        let a = spec(Aggregation::Median, p.clone());
        let mut reordered = p.clone();
        reordered.reverse();
        let b = spec(Aggregation::Median, reordered);
        assert_eq!(a.id(), b.id(), "provider order must not change the id");

        // A different provider set is a different feed.
        let c = spec(Aggregation::Median, providers(4));
        assert_ne!(a.id(), c.id());
        // A different aggregation rule is a different feed.
        let d = spec(Aggregation::Single, p);
        assert_ne!(a.id(), d.id());
    }

    #[test]
    fn observation_round_trips_and_refuses_junk() {
        let obs = FeedObservation::new(6_150_000, 1_720_000_000_000);
        assert_eq!(FeedObservation::decode(&obs.encode()), Some(obs));
        assert_eq!(FeedObservation::decode(&[]), None);
        assert_eq!(FeedObservation::decode(&[9u8; 17]), None); // bad version
    }

    #[test]
    fn feed_value_round_trips_and_reports_freshness() {
        let fv = FeedValue {
            value: 6_150_000,
            decimals: 2,
            kind: FeedKind::Price,
            aggregation: Aggregation::Median,
            n_sources: 3,
            updated_round: 100,
        };
        assert_eq!(FeedValue::decode(&fv.encode()), Some(fv));
        assert_eq!(fv.staleness(105), 5);
        assert!(fv.is_fresh(108, 10));
        assert!(!fv.is_fresh(120, 10));
        assert!((fv.as_f64() - 61_500.0).abs() < 1e-9);
    }

    #[test]
    fn source_cell_round_trips() {
        assert_eq!(decode_source(&encode_source(42, 7)), Some((42, 7)));
        assert_eq!(decode_source(&[0u8; 3]), None);
    }

    #[test]
    fn median_is_deterministic_for_odd_and_even() {
        assert_eq!(aggregate(&[10, 30, 20], Aggregation::Median), 20);
        assert_eq!(aggregate(&[10, 20, 30, 40], Aggregation::Median), 25);
        // A single outlier does not move the median much.
        assert_eq!(aggregate(&[100, 101, 99, 100, 1_000_000], Aggregation::Median), 100);
        // Single takes the first (the sole source).
        assert_eq!(aggregate(&[7], Aggregation::Single), 7);
    }

    #[test]
    fn summary_encodes_basic_params() {
        let s = spec(Aggregation::Median, providers(3));
        let sum = s.summary_bytes();
        assert_eq!(sum[0], FEED_ENC_V1);
        assert_eq!(sum[1], FeedKind::Price.code());
        assert_eq!(sum[2], 2); // decimals
        assert_eq!(sum[3], Aggregation::Median.code());
        assert_eq!(sum[4], 3); // n providers
    }
}
