//! Client-facing QUIC RPC server.
//!
//! This is the node's *public* surface — distinct from the validator mesh in
//! [`crate::quic`], which carries consensus traffic between validators. It
//! binds its own endpoint and speaks the protocol defined by the SDK
//! ([`peregrine_sdk::protocol`]), so the client and server share one contract.
//!
//! ## How a request is served
//! ```text
//!   SDK --QUIC bi-stream--> rpc server --+--> ingest_tx  (publish / submit tx)
//!                                        `--> query_tx --> validator loop
//!                                                          (owns the pipeline)
//! ```
//! Writes ride the *existing* ingest queue — the same path the sim feeds — so
//! a client submission is indistinguishable from any other payload once it
//! enters consensus. Reads become a [`Query`] message answered **inside** the
//! validator loop, which keeps the pipeline single-owner: committed state is
//! never shared behind a lock.
//!
//! Each request gets its own bidirectional stream and is handled in its own
//! task, so a slow proven-read never head-of-line-blocks other clients.
//!
//! ## Bootstrap limitations
//! * **Dev TLS** (self-signed, skip-verify) — the transport is not the trust
//!   boundary: proofs verify against the 32-byte store root and stream records
//!   carry publisher signatures.
//! * **No auth, quotas, or rate limits** — a public deployment needs stake- or
//!   API-key-weighted admission control in front of `ingest_tx`.
//! * Reads are served by **one** validator and reflect *its* committed
//!   frontier; a client wanting cross-validator agreement should read from
//!   several and compare roots.

use crate::payload::WirePayload;
use crate::quic::dev_endpoint;
use crate::validator::Query;
use peregrine_sdk::protocol::{read_frame, write_frame, RpcRequest, RpcResponse};
use quinn::Endpoint;
use std::net::SocketAddr;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

/// A running RPC listener. Dropping it stops serving and closes the endpoint.
pub struct RpcServer {
    /// The address actually bound (useful when binding port 0).
    pub addr: SocketAddr,
    endpoint: Endpoint,
    task: JoinHandle<()>,
}

impl RpcServer {
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for RpcServer {
    fn drop(&mut self) {
        self.task.abort();
        self.endpoint.close(0u32.into(), b"rpc shutdown");
    }
}

/// Bind an RPC listener on `bind` (port 0 = OS-assigned) and serve clients.
///
/// `ingest_tx` is the validator's payload queue; `query_tx` must be the sender
/// half of the channel handed to `ValidatorConfig::query_rx`. Must be called
/// from within a Tokio runtime.
pub fn serve(
    bind: SocketAddr,
    ingest_tx: mpsc::Sender<WirePayload>,
    query_tx: mpsc::Sender<Query>,
) -> anyhow::Result<RpcServer> {
    let endpoint = dev_endpoint(bind)?;
    let addr = endpoint.local_addr()?;
    let ep = endpoint.clone();

    let task = tokio::spawn(async move {
        while let Some(incoming) = ep.accept().await {
            let (itx, qtx) = (ingest_tx.clone(), query_tx.clone());
            tokio::spawn(async move {
                match incoming.await {
                    Ok(conn) => handle_conn(conn, itx, qtx).await,
                    Err(e) => tracing::debug!("rpc handshake failed: {e}"),
                }
            });
        }
    });

    tracing::info!("rpc listening on {addr}");
    Ok(RpcServer {
        addr,
        endpoint,
        task,
    })
}

/// Serve one client connection: every bidirectional stream is one request.
async fn handle_conn(
    conn: quinn::Connection,
    ingest_tx: mpsc::Sender<WirePayload>,
    query_tx: mpsc::Sender<Query>,
) {
    loop {
        let (send, recv) = match conn.accept_bi().await {
            Ok(pair) => pair,
            // Clean close or connection loss — the client is done with us.
            Err(_) => return,
        };
        let (itx, qtx) = (ingest_tx.clone(), query_tx.clone());
        tokio::spawn(async move {
            if let Err(e) = serve_stream(send, recv, itx, qtx).await {
                tracing::debug!("rpc stream ended: {e}");
            }
        });
    }
}

async fn serve_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    ingest_tx: mpsc::Sender<WirePayload>,
    query_tx: mpsc::Sender<Query>,
) -> anyhow::Result<()> {
    let bytes = read_frame(&mut recv).await?;
    let req: RpcRequest = bincode::deserialize(&bytes)?;
    let resp = dispatch(req, &ingest_tx, &query_tx).await;
    write_frame(&mut send, &bincode::serialize(&resp)?).await?;
    send.finish()?;
    Ok(())
}

async fn dispatch(
    req: RpcRequest,
    ingest_tx: &mpsc::Sender<WirePayload>,
    query_tx: &mpsc::Sender<Query>,
) -> RpcResponse {
    match req {
        RpcRequest::Ping => RpcResponse::Pong,

        RpcRequest::Publish(shred) => accept(ingest_tx.send(WirePayload::Shred(shred)).await),
        RpcRequest::SubmitTx(program) => {
            accept(ingest_tx.send(WirePayload::TalonTx { program }).await)
        }

        RpcRequest::ProveRead { table, key } => {
            let (reply, rx) = oneshot::channel();
            if query_tx
                .send(Query::ProveRead { table, key, reply })
                .await
                .is_err()
            {
                return RpcResponse::Error("validator stopped".into());
            }
            match rx.await {
                Ok(proof) => RpcResponse::Proof(proof),
                Err(_) => RpcResponse::Error("query dropped by validator".into()),
            }
        }

        RpcRequest::StoreRoot => {
            let (reply, rx) = oneshot::channel();
            if query_tx.send(Query::StoreRoot { reply }).await.is_err() {
                return RpcResponse::Error("validator stopped".into());
            }
            match rx.await {
                Ok(root) => RpcResponse::Root(root),
                Err(_) => RpcResponse::Error("query dropped by validator".into()),
            }
        }
    }
}

/// Map an ingest send result to a response. A closed queue means the validator
/// has shut down — report it rather than silently dropping the submission.
fn accept<E>(sent: Result<(), E>) -> RpcResponse {
    match sent {
        Ok(()) => RpcResponse::Accepted,
        Err(_) => RpcResponse::Error("node ingest queue closed".into()),
    }
}
