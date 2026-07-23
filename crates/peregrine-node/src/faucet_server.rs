//! A small, rate-limited **web faucet**.
//!
//! It holds the faucet key, accepts `POST /drip {"address": "<hex>"}`, signs a
//! drip, and submits it to a node over the SDK. Two layers of protection:
//!
//! * **Soft, here:** a per-IP cooldown, so a single client can't hammer the HTTP
//!   endpoint. Best-effort — IPs are cheap.
//! * **Hard, on-chain:** the per-recipient cooldown and lifetime cap in
//!   [`peregrine_data::faucet`], enforced by consensus. This is what actually
//!   bounds how much any address can ever receive; the web layer is convenience.
//!
//! Read-only otherwise and CORS-permissive, so a static web page can call it.

use axum::{
    extract::{ConnectInfo, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use peregrine_core::{Keypair, PublicKey};
use peregrine_data::faucet::{FaucetDrip, SignedDrip};
use peregrine_sdk::Client;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tower_http::cors::CorsLayer;

/// How to run the web faucet.
pub struct FaucetServerConfig {
    pub bind: SocketAddr,
    pub node: SocketAddr,
    pub faucet: Keypair,
    pub amount: u64,
    pub per_ip_cooldown: Duration,
}

struct FaucetState {
    client: Client,
    faucet: Keypair,
    amount: u64,
    cooldown: Duration,
    last_by_ip: Mutex<HashMap<IpAddr, Instant>>,
    nonce: Mutex<u64>,
}

/// Serve the faucet until the process stops.
pub async fn serve(cfg: FaucetServerConfig) -> anyhow::Result<()> {
    let client = Client::connect(cfg.node)
        .await
        .map_err(|e| anyhow::anyhow!("connect to node {}: {e}", cfg.node))?;
    client
        .ping()
        .await
        .map_err(|e| anyhow::anyhow!("node {} did not answer ping: {e}", cfg.node))?;

    let state = Arc::new(FaucetState {
        client,
        faucet: cfg.faucet,
        amount: cfg.amount,
        cooldown: cfg.per_ip_cooldown,
        last_by_ip: Mutex::new(HashMap::new()),
        nonce: Mutex::new(0),
    });

    let app = Router::new()
        .route("/", get(index))
        .route("/health", get(health))
        .route("/drip", post(drip))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(cfg.bind).await?;
    let actual = listener.local_addr()?;
    println!(
        "faucet: http://{actual}  ->  node {}  ({} grains/request, {}s per IP)",
        cfg.node,
        cfg.amount,
        cfg.per_ip_cooldown.as_secs()
    );
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

async fn index(State(s): State<Arc<FaucetState>>) -> impl IntoResponse {
    Json(json!({
        "service": "peregrine-faucet",
        "amount_per_request": s.amount,
        "drip": "POST /drip  {\"address\": \"<64 hex chars>\"}",
        "note": "per-recipient limits are enforced on-chain",
    }))
}

async fn health(State(s): State<Arc<FaucetState>>) -> impl IntoResponse {
    match s.client.ping().await {
        Ok(()) => (StatusCode::OK, Json(json!({ "ok": true }))),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "ok": false, "error": e.to_string() })),
        ),
    }
}

#[derive(serde::Deserialize)]
struct DripReq {
    address: String,
}

async fn drip(
    State(s): State<Arc<FaucetState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req): Json<DripReq>,
) -> (StatusCode, Json<Value>) {
    // Soft per-IP rate limit. The hard cap is the on-chain per-recipient policy.
    {
        let mut map = s.last_by_ip.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(prev) = map.get(&peer.ip()) {
            if prev.elapsed() < s.cooldown {
                let wait = (s.cooldown - prev.elapsed()).as_secs() + 1;
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(
                        json!({ "ok": false, "error": format!("rate limited; retry in {wait}s") }),
                    ),
                );
            }
        }
        map.insert(peer.ip(), Instant::now());
    }

    let Some(recipient) = parse_pubkey(&req.address) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "error": "address must be 64 hex characters" })),
        );
    };
    let nonce = {
        let mut n = s.nonce.lock().unwrap_or_else(|e| e.into_inner());
        let v = *n;
        *n = n.wrapping_add(1);
        v
    };
    let signed = SignedDrip::new(
        &s.faucet,
        FaucetDrip {
            recipient,
            amount: s.amount,
            nonce,
        },
    );
    match s.client.submit_drip(signed).await {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "amount": s.amount,
                "note": "queued; on-chain per-recipient limits still apply",
            })),
        ),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "ok": false, "error": e.to_string() })),
        ),
    }
}

fn parse_pubkey(s: &str) -> Option<PublicKey> {
    let bytes = hex::decode(s.trim()).ok()?;
    let arr: [u8; 32] = bytes.as_slice().try_into().ok()?;
    Some(PublicKey(arr))
}
