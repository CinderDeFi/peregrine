//! # peregrine-core
//!
//! Foundational types shared by every Peregrine subsystem:
//!
//! * [`Hash`] — 32-byte BLAKE3 content hash, the universal identifier.
//! * [`Keypair`] / [`PublicKey`] / [`Signature`] — Ed25519 validator identity.
//!   (Production will move hot-path signing to a batched, HW-accelerated
//!   pipeline inside the sig-verify tile; the *types* stay stable.)
//! * [`ValidatorId`], [`Round`], [`Committee`] — consensus identity & stake.
//!
//! Design rule: this crate has **no async, no I/O, no globals** — pure data
//! and pure functions only, so every other crate can depend on it freely.

pub mod committee;
pub mod crypto;

pub use committee::{Committee, ValidatorId, ValidatorInfo};
pub use crypto::{Hash, Keypair, PublicKey, Signature};

/// Consensus round number. Rounds advance as the DAG frontier advances;
/// wall-clock time is *not* a consensus input (timestamps are advisory).
pub type Round = u64;

/// Monotonic sequence number within a stream (assigned by the publisher,
/// re-sequenced authoritatively by DAG commit order).
pub type StreamSeq = u64;

/// Errors that can occur in core primitives.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("signature verification failed")]
    BadSignature,
    #[error("unknown validator: {0}")]
    UnknownValidator(String),
    #[error("serialization failure: {0}")]
    Codec(String),
}
