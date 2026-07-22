//! JSON/HTTP gateway that fronts a node's QUIC RPC.
//!
//! Browsers cannot open raw QUIC sockets, so the block explorer (and any other
//! web client) cannot dial a validator directly. This gateway is the missing
//! hop: it speaks HTTP to the browser and QUIC to the node, translating the
//! JSON request shapes the TypeScript SDK defines
//! ([`peregrine_sdk::protocol`] mirrored as JSON) into calls on the async
//! [`Client`].
//!
//! ```text
//!   browser --HTTP/JSON--> gateway --QUIC/bincode--> node RPC
//! ```
//!
//! ## The gateway is not the trust boundary
//! It is deliberately **read-only** (`ping`, `storeRoot`, `proveRead`). A block
//! explorer observes; it does not submit. More importantly, every proof it
//! forwards is re-verified *in the browser* against the store root — the same
//! arithmetic in `sdk/js/src/verify.ts`. A hostile or buggy gateway can drop or
//! stall a response, but it cannot forge a value: a tampered proof fails the
//! client-side check. That is the whole point of shipping proofs instead of
//! answers.
//!
//! The JSON shapes match what `provenReadFromJson` in the TS SDK consumes; the
//! `proveRead` mapping is the same one `examples/gen_js_fixture.rs` uses to
//! generate the cross-language test fixtures, so the two cannot drift.

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use peregrine_core::Hash;
use peregrine_sdk::Client;
use peregrine_data::tables::{ProvenRead, RowProof, TableId};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::CorsLayer;

/// Shared state: one QUIC connection to the node, reused across HTTP requests.
/// Each RPC call opens its own bidirectional stream, so concurrent HTTP
/// requests do not serialize behind one another.
struct GatewayState {
    client: Client,
    node_addr: SocketAddr,
}

/// Connect to a node and build the gateway's HTTP router. Exposed so tests can
/// bind their own ephemeral listener; [`serve`] is the production entry point.
pub async fn build_router(node_addr: SocketAddr) -> anyhow::Result<Router> {
    let client = Client::connect(node_addr)
        .await
        .map_err(|e| anyhow::anyhow!("connect to node RPC at {node_addr}: {e}"))?;
    // Confirm the node is actually answering before we advertise ourselves.
    client
        .ping()
        .await
        .map_err(|e| anyhow::anyhow!("node at {node_addr} did not answer ping: {e}"))?;

    let state = Arc::new(GatewayState { client, node_addr });

    Ok(Router::new()
        .route("/", get(index))
        .route("/health", get(health))
        .route("/rpc", post(rpc))
        // Permissive CORS: the explorer may be served from GitHub Pages (a
        // different origin) while the gateway runs on localhost. Dev-only, like
        // the rest of the bootstrap transport.
        .layer(CorsLayer::permissive())
        .with_state(state))
}

/// Run the gateway until the process is stopped.
///
/// * `http_bind` — where the browser connects (e.g. `127.0.0.1:8080`).
/// * `node_addr` — the node's QUIC RPC endpoint (from `peregrine node run`).
pub async fn serve(http_bind: SocketAddr, node_addr: SocketAddr) -> anyhow::Result<()> {
    let app = build_router(node_addr).await?;
    let listener = tokio::net::TcpListener::bind(http_bind).await?;
    let actual = listener.local_addr()?;
    tracing::info!("gateway listening on http://{actual}  ->  node {node_addr}");
    println!("gateway: http://{actual}/rpc  ->  node {node_addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn index(State(state): State<Arc<GatewayState>>) -> impl IntoResponse {
    Json(json!({
        "service": "peregrine-gateway",
        "node": state.node_addr.to_string(),
        "endpoints": { "rpc": "POST /rpc", "health": "GET /health" },
        "supports": ["ping", "storeRoot", "proveRead"],
        "note": "read-only; every proof is re-verified in the client against the store root",
    }))
}

async fn health(State(state): State<Arc<GatewayState>>) -> impl IntoResponse {
    match state.client.ping().await {
        Ok(()) => (StatusCode::OK, Json(json!({ "ok": true }))),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "ok": false, "error": e.to_string() })),
        ),
    }
}

/// The single JSON-RPC endpoint. Body is `{ "kind": "...", ... }`.
async fn rpc(State(state): State<Arc<GatewayState>>, Json(req): Json<Value>) -> impl IntoResponse {
    let resp = dispatch(&state.client, req).await;
    (StatusCode::OK, Json(resp))
}

/// Translate one JSON request into a node call and back into a JSON response.
/// Response shapes mirror the TS SDK's `RpcResponse` exactly.
async fn dispatch(client: &Client, req: Value) -> Value {
    let kind = req.get("kind").and_then(Value::as_str).unwrap_or("");
    match kind {
        "ping" => match client.ping().await {
            Ok(()) => json!({ "kind": "pong" }),
            Err(e) => err(e.to_string()),
        },

        "storeRoot" => match client.store_root().await {
            Ok(root) => json!({ "kind": "root", "root": hex::encode(root.0) }),
            Err(e) => err(e.to_string()),
        },

        "proveRead" => {
            let table = match req.get("table").and_then(Value::as_str).and_then(parse_table) {
                Some(t) => t,
                None => return err("proveRead: `table` must be 32-byte hex".into()),
            };
            let key = match req.get("key").and_then(Value::as_str).and_then(parse_hex) {
                Some(k) => k,
                None => return err("proveRead: `key` must be hex".into()),
            };
            match client.prove_read(table, &key).await {
                Ok(Some(read)) => json!({ "kind": "proof", "read": proven_read_json(&read) }),
                Ok(None) => json!({ "kind": "proof", "read": Value::Null }),
                Err(e) => err(e.to_string()),
            }
        }

        // Writes are intentionally not proxied: an explorer reads. Submitting
        // records or transactions is signing work that belongs in the CLI/SDK.
        "publish" | "submitTx" | "submitClaim" | "openSession" | "sessionAction"
        | "revokeSession" => err(format!(
            "the gateway is read-only; `{kind}` must go through the CLI or a native SDK client"
        )),

        "" => err("request is missing a `kind`".into()),
        other => err(format!("unknown request kind `{other}`")),
    }
}

fn err(message: String) -> Value {
    json!({ "kind": "error", "message": message })
}

/// Parse a 32-byte hex table id into a [`TableId`].
fn parse_table(s: &str) -> Option<TableId> {
    let bytes = parse_hex(s)?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    Some(TableId(Hash(arr)))
}

fn parse_hex(s: &str) -> Option<Vec<u8>> {
    hex::decode(s.strip_prefix("0x").unwrap_or(s)).ok()
}

/// Serialise an inclusion proof into the exact JSON `provenReadFromJson`
/// consumes. Kept identical to `examples/gen_js_fixture.rs` so the gateway and
/// the cross-language fixtures cannot drift.
fn proven_read_json(read: &ProvenRead) -> Value {
    json!({
        "table": hex::encode(read.table.0 .0),
        "key": hex::encode(&read.key),
        "value": hex::encode(&read.value),
        "tableRoot": hex::encode(read.table_root.0),
        "treeVersion": read.row_proof.version().as_str(),
        "rowProof": row_proof_json(&read.row_proof),
        "storeProof": {
            "leafIndex": read.store_proof.leaf_index,
            "siblings": read.store_proof.siblings.iter()
                .map(|h| hex::encode(h.0)).collect::<Vec<_>>(),
        },
    })
}

fn row_proof_json(p: &RowProof) -> Value {
    let siblings: Vec<String> = p.siblings().iter().map(|h| hex::encode(h.0)).collect();
    match p {
        RowProof::V1(_) => json!({ "siblings": siblings }),
        RowProof::V2(v2) => json!({
            "siblings": siblings,
            "otherLeaf": v2.other_leaf.as_ref().map(|(k, val)| json!({
                "key": hex::encode(k),
                "value": hex::encode(val),
            })),
        }),
    }
}
