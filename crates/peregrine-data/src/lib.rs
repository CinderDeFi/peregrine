//! # peregrine-data — the Slipstream data plane (bootstrap)
//!
//! Implements the wedge we are proving first (design doc §4.5):
//!
//! * [`streams`] — protocol-level pub/sub: publishers sign fixed-schema
//!   records; records ride *inside consensus dissemination* as vertex
//!   payload items; committed records fan out to subscribers.
//! * [`merkle`] — a simple binary Merkle tree with inclusion proofs.
//!   Verkle/multiproof commitments replace this later behind the same
//!   `root()/prove()/verify()` shape.
//! * [`tables`] — first-class key/value tables with a per-table root, a
//!   store-wide state root, and **verifiable reads** (value + two-level
//!   proof against the state root) — the seed of StateSQL.
//! * [`fees`] — the dual-meter economy: compute gas and data bytes metered
//!   and priced independently, with the 50/30/20 burn/validator/endowment
//!   split from §5.2.

pub mod compliance;
pub mod disclosure;
pub mod faucet;
pub mod fees;
#[cfg(feature = "streams")]
pub mod feeds;
pub mod merkle;
#[cfg(feature = "streams")]
pub mod sessions;
pub mod smt;
pub mod smt_v2;
#[cfg(feature = "streams")]
pub mod streams;
pub mod tables;

pub use compliance::{
    cell_key, check_attestation, compliance_table, ComplianceAttestation, CompliancePolicy,
    ComplianceStatus, SignedAttestation,
};
pub use disclosure::{FieldRow, SelectiveDisclosure};
pub use faucet::{faucet_table, FaucetDrip, FaucetPolicy, SignedDrip};
pub use fees::{DualMeter, FeeQuote, FeeSchedule, FeeSplit};
#[cfg(feature = "streams")]
pub use feeds::{
    feed_latest_table, feed_source_table, feeds_table, Aggregation, FeedId, FeedKind,
    FeedObservation, FeedPublisher, FeedRegistry, FeedSpec, FeedValue,
};
pub use merkle::{MerkleProof, MerkleTree};
pub use smt::{SmtProof, SparseMerkleTree};
#[cfg(feature = "streams")]
pub use streams::{StreamId, StreamRecord, StreamRegistry, StreamShred, SubscriberHandle};
pub use tables::{ProvenAbsence, ProvenRead, RangeProof, TableId, TableStore};
