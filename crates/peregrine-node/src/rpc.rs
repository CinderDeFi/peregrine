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
//! * **Admission control is per-connection only** ([`crate::rpc_limits`]):
//!   weighted token-bucket rate limiting, a request size cap, and optional
//!   bearer auth. That bounds what one client can push, but it is **not Sybil
//!   resistance** — many connections get many buckets. A public deployment
//!   needs stake- or key-weighted admission across connections.
//! * Reads are served by **one** validator and reflect *its* committed
//!   frontier; a client wanting cross-validator agreement should read from
//!   several and compare roots.

use crate::payload::WirePayload;
use crate::quic::dev_endpoint;
use crate::rpc_limits::{cost, RpcLimits, TokenBucket};
use crate::validator::Query;
use peregrine_sdk::protocol::{
    read_frame_capped, write_frame, RpcRequest, RpcResponse, MAX_CLAIM_BYTES,
};
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
    serve_with_limits(bind, ingest_tx, query_tx, RpcLimits::default())
}

/// As [`serve`], with explicit admission control.
pub fn serve_with_limits(
    bind: SocketAddr,
    ingest_tx: mpsc::Sender<WirePayload>,
    query_tx: mpsc::Sender<Query>,
    limits: RpcLimits,
) -> anyhow::Result<RpcServer> {
    let endpoint = dev_endpoint(bind)?;
    let addr = endpoint.local_addr()?;
    let ep = endpoint.clone();

    let task = tokio::spawn(async move {
        while let Some(incoming) = ep.accept().await {
            let (itx, qtx) = (ingest_tx.clone(), query_tx.clone());
            let lim = limits.clone();
            tokio::spawn(async move {
                match incoming.await {
                    Ok(conn) => handle_conn(conn, itx, qtx, lim).await,
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
    limits: RpcLimits,
) {
    // One bucket per connection, shared across that connection's streams.
    let bucket = std::sync::Arc::new(std::sync::Mutex::new(limits.bucket()));
    loop {
        let (send, recv) = match conn.accept_bi().await {
            Ok(pair) => pair,
            // Clean close or connection loss — the client is done with us.
            Err(_) => return,
        };
        let (itx, qtx) = (ingest_tx.clone(), query_tx.clone());
        let (lim, bkt) = (limits.clone(), bucket.clone());
        tokio::spawn(async move {
            if let Err(e) = serve_stream(send, recv, itx, qtx, lim, bkt).await {
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
    limits: RpcLimits,
    bucket: std::sync::Arc<std::sync::Mutex<TokenBucket>>,
) -> anyhow::Result<()> {
    // AUDIT I-1: cap the read at MAX_CLAIM_BYTES up front, so a client cannot
    // force a larger allocation than the server will ever accept. The redundant
    // post-read length check below stays as defence in depth and to return a
    // clean protocol error rather than a transport error.
    let bytes = read_frame_capped(&mut recv, MAX_CLAIM_BYTES).await?;

    // Size-check before deserializing: a request must not get to decide how
    // much memory we allocate.
    if bytes.len() > MAX_CLAIM_BYTES {
        let resp = RpcResponse::Error(format!(
            "request is {} bytes, limit is {MAX_CLAIM_BYTES}",
            bytes.len()
        ));
        write_frame(&mut send, &bincode::serialize(&resp)?).await?;
        send.finish()?;
        return Ok(());
    }

    let req: RpcRequest = bincode::deserialize(&bytes)?;

    // Admission control, cheapest checks first.
    let resp = if !limits.authorize(None) {
        // Auth is configured but this transport carries no credential.
        RpcResponse::Error("unauthorized".into())
    } else if !spend(&bucket, request_cost(&req)) {
        RpcResponse::Error("rate limit exceeded; retry shortly".into())
    } else {
        dispatch(req, &ingest_tx, &query_tx).await
    };
    write_frame(&mut send, &bincode::serialize(&resp)?).await?;
    send.finish()?;
    Ok(())
}

/// What this request costs against the connection's budget.
fn request_cost(req: &RpcRequest) -> u32 {
    match req {
        RpcRequest::Ping => cost::PING,
        RpcRequest::ProveRead { .. } | RpcRequest::StoreRoot => cost::QUERY,
        RpcRequest::Publish(_) | RpcRequest::SubmitTx(_) => cost::SUBMIT,
        RpcRequest::SubmitClaim(_) => cost::CLAIM,
        // A session action is one signature to verify and one policy check —
        // the same order of work as any other submission. Opening a session
        // costs more: it is a signature plus permanent state.
        RpcRequest::SessionAction(_) | RpcRequest::RevokeSession { .. } => cost::SUBMIT,
        RpcRequest::OpenSession(_) => cost::SUBMIT * 2,
    }
}

/// Spend from the shared bucket. A poisoned lock fails closed.
fn spend(bucket: &std::sync::Mutex<TokenBucket>, cost: u32) -> bool {
    bucket
        .lock()
        .map(|mut b| b.try_spend(cost))
        .unwrap_or(false)
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

        RpcRequest::OpenSession(grant) => {
            accept(ingest_tx.send(WirePayload::OpenSession(grant)).await)
        }

        RpcRequest::SessionAction(action) => {
            accept(ingest_tx.send(WirePayload::SessionAction(action)).await)
        }

        RpcRequest::RevokeSession {
            session_id,
            signature,
        } => accept(
            ingest_tx
                .send(WirePayload::RevokeSession {
                    session_id,
                    signature,
                })
                .await,
        ),

        RpcRequest::SubmitClaim(claim) => {
            // Straight onto the same ingest queue as everything else: the
            // proof is verified during commit by every validator, not here.
            // The RPC layer's job is admission control, not verification.
            accept(ingest_tx.send(WirePayload::ForeignClaim(claim)).await)
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
                Ok(proof) => RpcResponse::Proof(proof.map(Box::new)),
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
