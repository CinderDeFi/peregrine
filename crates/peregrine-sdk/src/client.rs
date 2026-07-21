//! The async client: connect to a node over QUIC and drive it.

use crate::protocol::{read_frame, write_frame, RpcRequest, RpcResponse};
use crate::tls;
use peregrine_core::Hash;
use peregrine_data::streams::StreamShred;
use peregrine_data::tables::{ProvenRead, TableId};
use peregrine_vm::Instr;
use std::net::{Ipv4Addr, SocketAddr};

/// Errors surfaced by the SDK. Transport/codec faults are separated from a
/// node-reported error so callers can distinguish "couldn't reach the node"
/// from "the node refused the request".
#[derive(Debug, thiserror::Error)]
pub enum SdkError {
    #[error("connect failed: {0}")]
    Connect(String),
    #[error("transport error: {0}")]
    Transport(String),
    #[error("codec error: {0}")]
    Codec(String),
    #[error("node reported: {0}")]
    Node(String),
    #[error("unexpected response for request")]
    Unexpected,
}

/// A connection to one Peregrine node.
///
/// Cheap to clone-free share behind an `Arc` if desired; each call opens its
/// own QUIC bidirectional stream, so calls are independent and can be issued
/// concurrently over one connection.
pub struct Client {
    // Held so the client endpoint stays alive for the connection's lifetime.
    _endpoint: quinn::Endpoint,
    conn: quinn::Connection,
}

impl Client {
    /// Connect to a node's RPC endpoint.
    pub async fn connect(addr: SocketAddr) -> Result<Self, SdkError> {
        let bind = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        let mut endpoint =
            quinn::Endpoint::client(bind).map_err(|e| SdkError::Connect(e.to_string()))?;
        endpoint.set_default_client_config(
            tls::client_config().map_err(|e| SdkError::Connect(e.to_string()))?,
        );
        let conn = endpoint
            .connect(addr, "localhost")
            .map_err(|e| SdkError::Connect(e.to_string()))?
            .await
            .map_err(|e| SdkError::Connect(e.to_string()))?;
        Ok(Self {
            _endpoint: endpoint,
            conn,
        })
    }

    /// One request → one response over a fresh bidirectional stream.
    async fn request(&self, req: RpcRequest) -> Result<RpcResponse, SdkError> {
        let (mut send, mut recv) = self
            .conn
            .open_bi()
            .await
            .map_err(|e| SdkError::Transport(e.to_string()))?;
        let bytes = bincode::serialize(&req).map_err(|e| SdkError::Codec(e.to_string()))?;
        write_frame(&mut send, &bytes)
            .await
            .map_err(|e| SdkError::Transport(e.to_string()))?;
        send.finish()
            .map_err(|e| SdkError::Transport(e.to_string()))?;
        let resp = read_frame(&mut recv)
            .await
            .map_err(|e| SdkError::Transport(e.to_string()))?;
        bincode::deserialize(&resp).map_err(|e| SdkError::Codec(e.to_string()))
    }

    /// Liveness check.
    pub async fn ping(&self) -> Result<(), SdkError> {
        match self.request(RpcRequest::Ping).await? {
            RpcResponse::Pong => Ok(()),
            RpcResponse::Error(e) => Err(SdkError::Node(e)),
            _ => Err(SdkError::Unexpected),
        }
    }

    /// Publish a signed stream record. Sign one with a [`peregrine_data::streams::Publisher`]:
    /// `client.publish(publisher.emit(bytes)).await?`.
    pub async fn publish(&self, shred: StreamShred) -> Result<(), SdkError> {
        self.expect_accepted(RpcRequest::Publish(shred)).await
    }

    /// Submit a Talon program to run on commit.
    pub async fn submit_tx(&self, program: Vec<Instr>) -> Result<(), SdkError> {
        self.expect_accepted(RpcRequest::SubmitTx(program)).await
    }

    /// Read `key` from `table` with an inclusion proof against the store root,
    /// or `None` if absent. Verify the returned proof with
    /// [`ProvenRead::verify`] against [`store_root`](Self::store_root).
    pub async fn prove_read(
        &self,
        table: TableId,
        key: &[u8],
    ) -> Result<Option<ProvenRead>, SdkError> {
        match self
            .request(RpcRequest::ProveRead {
                table,
                key: key.to_vec(),
            })
            .await?
        {
            RpcResponse::Proof(p) => Ok(p),
            RpcResponse::Error(e) => Err(SdkError::Node(e)),
            _ => Err(SdkError::Unexpected),
        }
    }

    /// The node's current 32-byte store root (what a light client pins).
    pub async fn store_root(&self) -> Result<Hash, SdkError> {
        match self.request(RpcRequest::StoreRoot).await? {
            RpcResponse::Root(h) => Ok(h),
            RpcResponse::Error(e) => Err(SdkError::Node(e)),
            _ => Err(SdkError::Unexpected),
        }
    }

    async fn expect_accepted(&self, req: RpcRequest) -> Result<(), SdkError> {
        match self.request(req).await? {
            RpcResponse::Accepted => Ok(()),
            RpcResponse::Error(e) => Err(SdkError::Node(e)),
            _ => Err(SdkError::Unexpected),
        }
    }
}
