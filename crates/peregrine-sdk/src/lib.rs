//! # peregrine-sdk — Rust client for Peregrine
//!
//! A small, ergonomic async client that speaks the node's QUIC RPC protocol so
//! applications (and light clients) can:
//!
//! * **publish** signed stream records (oracle ticks, sensor/agent data),
//! * **submit** Talon transactions,
//! * run **proven reads** — fetch a value *plus* an inclusion proof, and
//! * **verify** that proof against the 32-byte store root with zero trust in
//!   the node (the light-client path).
//!
//! ```no_run
//! use peregrine_sdk::{Client, Keypair, Publisher, TableId};
//!
//! # async fn demo() -> anyhow::Result<()> {
//! let client = Client::connect("127.0.0.1:9000".parse()?).await?;
//!
//! // Publish a signed price tick.
//! let mut pubr = Publisher::new("acme/BTC-USD", Keypair::generate(&mut rand::rngs::OsRng));
//! client.publish(pubr.emit(61_500_00u64.to_le_bytes().to_vec())).await?;
//!
//! // Read a contract table cell with proof and verify it locally.
//! let root = client.store_root().await?;
//! if let Some(read) = client.prove_read(TableId::named("contract.answers"), b"sum").await? {
//!     assert!(read.verify(&root)); // trustless: only the 32-byte root is trusted
//! }
//! # Ok(()) }
//! ```
//!
//! The wire [`protocol`] is defined here so the node depends on the SDK to
//! serve it, keeping one source of truth for the contract. Dev TLS only (see
//! [`tls`]); the transport is never the trust boundary — proofs and publisher
//! signatures are what carry integrity.

pub mod client;
pub mod protocol;
pub mod tls;

pub use client::{Client, SdkError};

// ── re-exported type surface (so apps need only depend on the SDK) ──
pub use peregrine_core::{Hash, Keypair, PublicKey, Signature, ValidatorId};
pub use peregrine_data::streams::{Publisher, StreamId, StreamRecord, StreamShred};
pub use peregrine_data::tables::{ProvenAbsence, ProvenRead, RangeProof, TableId};
// ── agent sessions & micropayments ──────────────────────────────────────────
// Re-exported so an agent depends only on `peregrine-sdk`.
pub use peregrine_data::sessions::{
    Action, Grains, Scope, SessionBuilder, SessionGrant, SessionSigner, SignedAction, SignedGrant,
};
pub use peregrine_vm::Instr;

// ── cross-chain verification (pure, local) ──────────────────────────────────
// Re-exported so an application verifies foreign state *in its own process*:
// these are pure functions over bytes, so no node is trusted and no round-trip
// is needed. See `peregrine-interop` for the trust model.
pub use peregrine_interop::{
    verify_checkpoint, verify_eth_headers, verify_eth_storage, BlockHeader as EthBlockHeader,
    Checkpoint, Claim, EthError, Journal, SignedCheckpoint, VerifiedClaim,
};
