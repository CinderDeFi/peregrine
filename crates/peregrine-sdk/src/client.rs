//! The async client: connect to a node over QUIC and drive it.

use crate::protocol::{read_frame, write_frame, RpcRequest, RpcResponse};
use crate::tls;
use peregrine_core::{Hash, Keypair, PublicKey};
use peregrine_data::compliance::SignedAttestation;
use peregrine_data::faucet::SignedDrip;
use peregrine_data::feeds::{feed_latest_table, FeedId, FeedSpec, FeedValue};
use peregrine_data::sessions::balances_table;
use peregrine_data::sessions::{sessions_table, SessionState, SignedAction, SignedGrant};
use peregrine_data::streams::StreamShred;
use peregrine_data::tables::{ProvenRead, TableId};
use peregrine_interop::VerifiedClaim;
use peregrine_vm::Instr;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

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
        let endpoint = client_endpoint(addr)?;
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

    /// Submit a proof-carrying claim about another chain's state.
    ///
    /// `Accepted` means the claim entered the ingest queue — **not** that it
    /// verified. Verification happens during commit on every validator, and a
    /// claim that fails is dropped there. Poll the value with
    /// [`prove_read`](Self::prove_read) to learn whether it was applied.
    pub async fn submit_claim(&self, claim: VerifiedClaim) -> Result<(), SdkError> {
        self.expect_accepted(RpcRequest::SubmitClaim(Box::new(claim)))
            .await
    }

    /// Submit a KYC/AML attestation about an account, signed by an attester.
    ///
    /// As with every submission, `Ok` means "queued" — the attester's signature
    /// is verified during commit, on every validator, before the compact flag is
    /// materialized into `sys.compliance`. Read it back with
    /// [`prove_read`](Self::prove_read) against
    /// [`compliance_table`](peregrine_data::compliance::compliance_table).
    pub async fn submit_attestation(&self, signed: SignedAttestation) -> Result<(), SdkError> {
        self.expect_accepted(RpcRequest::SubmitAttestation(Box::new(signed)))
            .await
    }

    /// Register an oracle feed so its providers' observations are aggregated
    /// into `sys.feed_latest`. Permissionless and idempotent — the feed id is
    /// the hash of the spec. Returns the feed id.
    pub async fn register_feed(&self, spec: FeedSpec) -> Result<FeedId, SdkError> {
        let id = spec.id();
        self.expect_accepted(RpcRequest::RegisterFeed(Box::new(spec)))
            .await?;
        Ok(id)
    }

    /// Read a feed's aggregated latest value **with a proof**, verify it against
    /// the store root, and decode it. Returns `None` if the feed has no value
    /// yet. This is the trustless read path: only the 32-byte root is trusted.
    ///
    /// Pass a `root` you already trust to avoid taking the node's word for it;
    /// otherwise the node's current root is fetched and used.
    pub async fn read_feed(&self, feed_id: FeedId) -> Result<Option<FeedValue>, SdkError> {
        let read = match self.prove_read(feed_latest_table(), &feed_id.0 .0).await? {
            Some(r) => r,
            None => return Ok(None),
        };
        let root = self.store_root().await?;
        if !read.verify(&root) {
            return Err(SdkError::Node("feed proof failed to verify".into()));
        }
        FeedValue::decode(&read.value)
            .map(Some)
            .ok_or_else(|| SdkError::Codec("malformed feed value".into()))
    }

    /// Open a session: delegate scoped, budgeted, expiring authority to a
    /// session key. Build the grant with
    /// [`SessionBuilder`](peregrine_data::sessions::SessionBuilder).
    ///
    /// As with every submission, `Ok` means "queued" — the grant is verified
    /// during commit, on every validator.
    pub async fn open_session(&self, grant: SignedGrant) -> Result<(), SdkError> {
        self.expect_accepted(RpcRequest::OpenSession(Box::new(grant)))
            .await
    }

    /// Submit an action authorised by a session key. Sign it with
    /// [`SessionSigner`](peregrine_data::sessions::SessionSigner), which tracks
    /// the nonce for you.
    pub async fn session_action(&self, action: SignedAction) -> Result<(), SdkError> {
        self.expect_accepted(RpcRequest::SessionAction(Box::new(action)))
            .await
    }

    /// Revoke a session. Must be signed by the **principal** — a session key
    /// cannot revoke itself, and more importantly cannot prevent its own
    /// revocation.
    pub async fn revoke_session(
        &self,
        principal: &Keypair,
        session_id: Hash,
    ) -> Result<(), SdkError> {
        let signature = peregrine_data::sessions::sign_revocation(principal, &session_id);
        self.expect_accepted(RpcRequest::RevokeSession {
            session_id,
            signature,
        })
        .await
    }

    /// Read a session's committed state **with a proof** — its remaining budget,
    /// next nonce, subscriptions, and whether it is still live — verified against
    /// the store root. `None` if the session is unknown.
    ///
    /// This is how an agent checks its own limits without trusting the node:
    /// what it can spend is proven, not reported.
    pub async fn read_session(&self, session_id: Hash) -> Result<Option<SessionState>, SdkError> {
        let read = match self.prove_read(sessions_table(), &session_id.0).await? {
            Some(r) => r,
            None => return Ok(None),
        };
        let root = self.store_root().await?;
        if !read.verify(&root) {
            return Err(SdkError::Node("session proof failed to verify".into()));
        }
        SessionState::from_bytes(&read.value)
            .map(Some)
            .ok_or_else(|| SdkError::Codec("malformed session state".into()))
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
            RpcResponse::Proof(p) => Ok(p.map(|b| *b)),
            RpcResponse::Error(e) => Err(SdkError::Node(e)),
            _ => Err(SdkError::Unexpected),
        }
    }

    /// Submit a signed faucet drip (as the faucet operator). `Ok` means queued;
    /// the authority signature and the per-recipient limits are enforced during
    /// commit, so a queued drip may still be refused there — read the recipient's
    /// balance with [`balance_of`](Self::balance_of) to confirm.
    pub async fn submit_drip(&self, signed: SignedDrip) -> Result<(), SdkError> {
        self.expect_accepted(RpcRequest::FaucetDrip(Box::new(signed)))
            .await
    }

    /// The grain balance of `account` in `sys.balances`, **verified** against the
    /// store root. `0` if the account has never been credited.
    pub async fn balance_of(&self, account: &PublicKey) -> Result<u64, SdkError> {
        let read = match self.prove_read(balances_table(), &account.0).await? {
            Some(r) => r,
            None => return Ok(0),
        };
        let root = self.store_root().await?;
        if !read.verify(&root) {
            return Err(SdkError::Node("balance proof failed to verify".into()));
        }
        let bytes: [u8; 8] = read
            .value
            .as_slice()
            .try_into()
            .map_err(|_| SdkError::Codec("malformed balance".into()))?;
        Ok(u64::from_le_bytes(bytes))
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

/// Build (and bind) a QUIC client endpoint able to reach `addr`, with the
/// offload-safe transport config. Split out from [`Client::connect`] so the
/// bind-and-config path can be exercised without a live server.
///
/// Two things make this work across hosts:
/// * it binds the **unspecified** address of `addr`'s family (`0.0.0.0:0` /
///   `[::]:0`), never loopback — a `127.0.0.1`-bound UDP socket cannot route to
///   a remote host, so every send fails with `sendmsg: EINVAL`, which quinn-udp
///   surfaces as a segmentation-offload / ECN error before the handshake times
///   out. That was the cross-host `--against <peer>` failure; loopback masked it
///   because a loopback socket can reach `127.0.0.1`;
/// * it disables UDP generic segmentation offload on transmit. Some kernels
///   (seen on Ubuntu 26.04) reject the batched `sendmsg` with EINVAL ("halting
///   segmentation offload"); per-packet sends are a touch less efficient but
///   always work. ECN has no public toggle in Quinn 0.11 and needs none — with
///   a routable bind it sends fine (the validator mesh proves it on the same
///   stack). No sysctl required on any host.
fn client_endpoint(addr: SocketAddr) -> Result<quinn::Endpoint, SdkError> {
    let bind: SocketAddr = if addr.is_ipv6() {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    };
    let mut endpoint =
        quinn::Endpoint::client(bind).map_err(|e| SdkError::Connect(e.to_string()))?;

    let mut cfg = tls::client_config().map_err(|e| SdkError::Connect(e.to_string()))?;
    let mut transport = quinn::TransportConfig::default();
    transport.enable_segmentation_offload(false);
    cfg.transport_config(Arc::new(transport));
    endpoint.set_default_client_config(cfg);
    Ok(endpoint)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The client must bind a *routable* (unspecified) local address, not
    /// loopback — the regression that made cross-host `--against <peer>` fail.
    /// Uses a documentation/TEST-NET target (RFC 5737), never actually dialed.
    /// `Endpoint::client` binds a socket and starts a driver, so it needs a
    /// Tokio runtime — hence `#[tokio::test]`, not a plain `#[test]`.
    #[tokio::test]
    async fn client_binds_unspecified_not_loopback() {
        let v4: SocketAddr = "203.0.113.10:8080".parse().unwrap();
        let ep = client_endpoint(v4).expect("build v4 client endpoint with safe config");
        let local = ep.local_addr().expect("bound local addr");
        assert!(
            local.ip().is_unspecified(),
            "client must bind 0.0.0.0, not {} (loopback can't reach a remote host)",
            local.ip()
        );
        assert!(local.ip().is_ipv4(), "v4 target should bind a v4 socket");
    }

    #[tokio::test]
    async fn client_binds_unspecified_for_ipv6_target() {
        let v6: SocketAddr = "[2001:db8::1]:8080".parse().unwrap();
        // Skip gracefully on hosts without IPv6 (some CI runners): the point is
        // family-matched *unspecified* binding, which the v4 test already pins.
        let Ok(ep) = client_endpoint(v6) else {
            return;
        };
        let local = ep.local_addr().expect("bound local addr");
        assert!(local.ip().is_unspecified(), "v6 client must bind [::]");
        assert!(local.ip().is_ipv6(), "v6 target should bind a v6 socket");
    }
}
