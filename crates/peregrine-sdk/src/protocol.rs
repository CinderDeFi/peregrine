//! The client↔node wire protocol.
//!
//! One request → one response, each a length-prefixed bincode frame over a
//! fresh QUIC bidirectional stream. Defined here (not in the node) so the SDK
//! owns the contract and the node depends on *it* to serve the same shapes.

use peregrine_core::{Hash, Signature};
use peregrine_data::streams::StreamShred;
use peregrine_data::tables::{ProvenRead, TableId};
use peregrine_interop::VerifiedClaim;
use peregrine_vm::Instr;
use serde::{Deserialize, Serialize};

/// Reject absurd frame lengths before allocating.
pub const MAX_FRAME: usize = 64 * 1024 * 1024;

/// Largest accepted claim submission.
///
/// A compressed STARK proof runs to a few MB; anything an order of magnitude
/// past that is not a claim we can use, and refusing it *before* allocating
/// keeps a single request from deciding how much memory the node commits.
pub const MAX_CLAIM_BYTES: usize = 8 * 1024 * 1024;

/// A request from a client to a node.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RpcRequest {
    /// Liveness check.
    Ping,
    /// Submit a signed stream record for inclusion (rides consensus as a shred).
    Publish(StreamShred),
    /// Submit a Talon program to execute on commit.
    SubmitTx(Vec<Instr>),
    /// Submit a proof-carrying claim about another chain's state.
    ///
    /// Boxed because a claim carrying a real ZK proof is orders of magnitude
    /// larger than every other request — keeping it off the stack stops the
    /// whole enum from being sized by its worst case.
    ///
    /// Anyone may submit one: it needs no signature because it carries its own
    /// proof, and every validator re-verifies it during commit. What the RPC
    /// layer must do is stop a *flood* of them from crowding out consensus
    /// traffic — see the rate limiting in `peregrine-node::rpc`.
    SubmitClaim(Box<VerifiedClaim>),
    /// Open a session (a principal's signed delegation to a session key).
    OpenSession(Box<peregrine_data::sessions::SignedGrant>),
    /// An action authorised by a session key.
    SessionAction(Box<peregrine_data::sessions::SignedAction>),
    /// Revoke a session. Signed by the principal.
    RevokeSession {
        session_id: Hash,
        signature: Signature,
    },
    /// Submit a KYC/AML attestation, signed by an attester. Like a claim it
    /// carries its own authorisation (the attester's signature), which every
    /// validator verifies during commit before the flag is materialized.
    SubmitAttestation(Box<peregrine_data::compliance::SignedAttestation>),
    /// Register an oracle feed. Permissionless — a spec is content-addressed, so
    /// its id commits to its provider set and aggregation rule.
    RegisterFeed(Box<peregrine_data::feeds::FeedSpec>),
    /// A testnet faucet drip, signed by the faucet authority. The signature and
    /// the per-recipient rate limits are enforced during commit.
    FaucetDrip(Box<peregrine_data::faucet::SignedDrip>),
    /// Ask for a value plus an inclusion proof against the current store root.
    ProveRead { table: TableId, key: Vec<u8> },
    /// Ask for the node's current 32-byte store root.
    StoreRoot,
}

/// A node's reply to an [`RpcRequest`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RpcResponse {
    Pong,
    /// The submission was accepted into the ingest queue (not yet committed).
    Accepted,
    /// A proven read result (`None` if the key is absent).
    ///
    /// Boxed: a `ProvenRead` carries a full Merkle path and dwarfs every other
    /// variant, so an unboxed one would make `Pong` cost as much to move as a
    /// proof. It grew again when row proofs became version-tagged.
    Proof(Option<Box<ProvenRead>>),
    /// The current store root.
    Root(Hash),
    /// The node could not service the request.
    Error(String),
}

/// Write a length-prefixed frame to a QUIC send stream.
pub async fn write_frame(send: &mut quinn::SendStream, bytes: &[u8]) -> std::io::Result<()> {
    send.write_all(&(bytes.len() as u32).to_le_bytes())
        .await
        .map_err(std::io::Error::other)?;
    send.write_all(bytes).await.map_err(std::io::Error::other)?;
    Ok(())
}

/// Read one length-prefixed frame, rejecting anything larger than [`MAX_FRAME`].
pub async fn read_frame(recv: &mut quinn::RecvStream) -> std::io::Result<Vec<u8>> {
    read_frame_capped(recv, MAX_FRAME).await
}

/// Read one length-prefixed frame, rejecting anything larger than `max`
/// **before allocating**.
///
/// AUDIT I-1: the length prefix is checked against `max` before the buffer is
/// sized, so a peer cannot force an allocation larger than the caller is willing
/// to accept. Callers that know a tighter bound than [`MAX_FRAME`] (the RPC
/// server accepts at most [`MAX_CLAIM_BYTES`]) should pass it here rather than
/// allocating up to 64 MiB for a request they will reject anyway.
pub async fn read_frame_capped(
    recv: &mut quinn::RecvStream,
    max: usize,
) -> std::io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    recv.read_exact(&mut len)
        .await
        .map_err(std::io::Error::other)?;
    let n = u32::from_le_bytes(len) as usize;
    if n > max {
        return Err(std::io::Error::other(format!(
            "frame length {n} exceeds cap {max}"
        )));
    }
    let mut buf = vec![0u8; n];
    recv.read_exact(&mut buf)
        .await
        .map_err(std::io::Error::other)?;
    Ok(buf)
}
