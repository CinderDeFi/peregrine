//! The client↔node wire protocol.
//!
//! One request → one response, each a length-prefixed bincode frame over a
//! fresh QUIC bidirectional stream. Defined here (not in the node) so the SDK
//! owns the contract and the node depends on *it* to serve the same shapes.

use peregrine_core::Hash;
use peregrine_data::streams::StreamShred;
use peregrine_data::tables::{ProvenRead, TableId};
use peregrine_vm::Instr;
use serde::{Deserialize, Serialize};

/// Reject absurd frame lengths before allocating.
pub const MAX_FRAME: usize = 64 * 1024 * 1024;

/// A request from a client to a node.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RpcRequest {
    /// Liveness check.
    Ping,
    /// Submit a signed stream record for inclusion (rides consensus as a shred).
    Publish(StreamShred),
    /// Submit a Talon program to execute on commit.
    SubmitTx(Vec<Instr>),
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
    Proof(Option<ProvenRead>),
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

/// Read one length-prefixed frame from a QUIC recv stream.
pub async fn read_frame(recv: &mut quinn::RecvStream) -> std::io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    recv.read_exact(&mut len)
        .await
        .map_err(std::io::Error::other)?;
    let n = u32::from_le_bytes(len) as usize;
    if n > MAX_FRAME {
        return Err(std::io::Error::other(format!(
            "frame length {n} exceeds cap {MAX_FRAME}"
        )));
    }
    let mut buf = vec![0u8; n];
    recv.read_exact(&mut buf)
        .await
        .map_err(std::io::Error::other)?;
    Ok(buf)
}
