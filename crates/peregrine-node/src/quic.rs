//! Real QUIC transport for the validator mesh (replaces the in-process
//! loopback for the sim and benchmark).
//!
//! ## Shape
//! It produces the *same* [`Broadcaster`] / [`Inbox`] surface the in-process
//! transport does, so [`crate::validator::run_validator`] and the consensus
//! loop are untouched — only the wiring that builds the transport changes.
//!
//! ## Topology
//! Full directional mesh. Each node owns one [`quinn::Endpoint`] that both
//! accepts inbound connections and dials every peer:
//!
//! * **outbound** — one unbounded queue + one **writer task** per peer. The
//!   writer dials the peer (retry/backoff), opens a single ordered
//!   unidirectional stream, and writes length-prefixed bincode frames. On a
//!   broken connection it *holds the un-acked frame and resends it after
//!   reconnect*, so a dropped link never silently loses a sync request (which,
//!   because the fetch layer dedups by hash, would otherwise strand recovery).
//! * **inbound** — an **accept loop** spawns a reader per connection that
//!   decodes frames and pushes [`NetMessage`]s into the local inbox.
//! * **self** — a node's own broadcasts go straight to its inbox (a local
//!   channel), never over the wire.
//!
//! ## Reconnect
//! Reconnection is implicit: a peer's writer task keeps redialing a dead
//! address, so when a killed node rebinds to the *same* address ([`rebind_node`])
//! both directions heal with no coordination. This is what the restart path
//! and the reconnect test rely on.
//!
//! ## Bootstrap limitations
//! * **Dev TLS**: a fresh self-signed cert per node and a skip-verification
//!   client. Production binds the validator's ed25519 identity into the
//!   certificate and pins it. This layer is transport only — every vertex is
//!   still independently signature-checked by consensus, so an unauthenticated
//!   link cannot forge blocks, only waste bandwidth.
//! * **Full mesh**, not Turbine-style stake-weighted fanout (a later
//!   optimization); fine at bootstrap validator counts.
//! * **Unbounded** outbound queues: a permanently-slow peer can grow memory.
//!   A bounded, drop-oldest queue is the follow-up.

use crate::network::{Broadcaster, Inbox, NetMessage};
use peregrine_core::ValidatorId;
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// Reject absurd frame lengths before allocating (guards against garbage or a
/// hostile peer). A `SyncResponse` batch of ~1k vertices with payloads stays
/// well under this.
const MAX_FRAME: usize = 64 * 1024 * 1024;
const DIAL_BACKOFF_START: Duration = Duration::from_millis(50);
const DIAL_BACKOFF_MAX: Duration = Duration::from_secs(2);
const IDLE_TIMEOUT: Duration = Duration::from_secs(10);
const KEEP_ALIVE: Duration = Duration::from_secs(2);

/// Repeat the "still cannot reach peer" line every Nth failed dial. At the
/// capped backoff that is roughly every 30s — enough to make an unreachable
/// peer obvious in `journalctl` without burying everything else. Peering
/// failures must be visible at `info`: a silent redial loop is why an
/// unreachable peer on the testnet was indistinguishable from a consensus hang.
const DIAL_LOG_EVERY: u64 = 15;

// ─────────────────────────────── TLS (dev) ──────────────────────────────────

mod insecure_tls {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};
    use std::sync::Arc;

    /// A client cert verifier that accepts any server certificate. Dev/loopback
    /// only — see the module docs. Signature checks on the handshake still run
    /// (via the crypto provider); only chain/name validation is skipped.
    #[derive(Debug)]
    pub struct SkipServerVerification(Arc<CryptoProvider>);

    impl SkipServerVerification {
        pub fn new() -> Arc<Self> {
            Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
        }
    }

    impl ServerCertVerifier for SkipServerVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            verify_tls12_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            verify_tls13_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }
}

/// Install the process-wide rustls crypto provider once (idempotent).
fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn transport_config() -> Arc<quinn::TransportConfig> {
    let mut t = quinn::TransportConfig::default();
    t.max_idle_timeout(Some(IDLE_TIMEOUT.try_into().expect("valid idle timeout")));
    t.keep_alive_interval(Some(KEEP_ALIVE));
    Arc::new(t)
}

fn server_config() -> anyhow::Result<quinn::ServerConfig> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_der = cert.cert.der().clone();
    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let mut cfg = quinn::ServerConfig::with_single_cert(vec![cert_der], key_der.into())?;
    cfg.transport_config(transport_config());
    Ok(cfg)
}

fn client_config() -> anyhow::Result<quinn::ClientConfig> {
    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(insecure_tls::SkipServerVerification::new())
        .with_no_client_auth();
    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?;
    let mut cfg = quinn::ClientConfig::new(Arc::new(quic_crypto));
    cfg.transport_config(transport_config());
    Ok(cfg)
}

// ─────────────────────────────── framing ────────────────────────────────────

async fn write_frame(send: &mut SendStream, bytes: &[u8]) -> anyhow::Result<()> {
    send.write_all(&(bytes.len() as u32).to_le_bytes()).await?;
    send.write_all(bytes).await?;
    Ok(())
}

/// Read one frame, or `Ok(None)` at a clean end of stream.
async fn read_frame(recv: &mut RecvStream) -> anyhow::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match recv.read_exact(&mut len).await {
        Ok(()) => {}
        Err(quinn::ReadExactError::FinishedEarly(0)) => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let n = u32::from_le_bytes(len) as usize;
    if n > MAX_FRAME {
        anyhow::bail!("frame length {n} exceeds cap {MAX_FRAME}");
    }
    let mut buf = vec![0u8; n];
    recv.read_exact(&mut buf).await?;
    Ok(Some(buf))
}

// ─────────────────────────────── tasks ──────────────────────────────────────

/// Accept inbound connections forever, spawning a reader per connection.
async fn accept_loop(endpoint: Endpoint, inbox_tx: mpsc::UnboundedSender<NetMessage>) {
    while let Some(incoming) = endpoint.accept().await {
        let tx = inbox_tx.clone();
        let from = incoming.remote_address();
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    tracing::info!(peer = %from, "inbound QUIC session accepted");
                    reader_conn(conn, tx).await;
                }
                // Info, not debug: a handshake that keeps failing (wrong port,
                // a middlebox eating UDP) is an operator problem, and it must
                // not be invisible at the default log level.
                Err(e) => tracing::info!(peer = %from, "inbound handshake failed: {e}"),
            }
        });
    }
}

/// Read framed messages from one connection's single uni-stream into the inbox.
async fn reader_conn(conn: Connection, inbox_tx: mpsc::UnboundedSender<NetMessage>) {
    let peer = conn.remote_address();
    let mut recv = match conn.accept_uni().await {
        Ok(r) => r,
        Err(e) => {
            tracing::info!(peer = %peer, "inbound stream never opened: {e}");
            return;
        }
    };
    loop {
        match read_frame(&mut recv).await {
            Ok(Some(bytes)) => match bincode::deserialize::<NetMessage>(&bytes) {
                Ok(msg) => {
                    if inbox_tx.send(msg).is_err() {
                        return; // node shut down
                    }
                }
                Err(e) => tracing::warn!("undecodable frame ({} bytes): {e}", bytes.len()),
            },
            Ok(None) => {
                tracing::info!(peer = %peer, "inbound QUIC session closed cleanly");
                return;
            }
            Err(e) => {
                tracing::info!(peer = %peer, "inbound QUIC session ended: {e}");
                return;
            }
        }
    }
}

/// Maintain a connection to one peer and stream this node's outbound messages
/// to it, redialing on failure. Holds the frame that failed to send so a
/// reconnect resends it rather than dropping it.
async fn writer_task(
    endpoint: Endpoint,
    peer: SocketAddr,
    mut out_rx: mpsc::UnboundedReceiver<NetMessage>,
) {
    let mut backoff = DIAL_BACKOFF_START;
    let mut pending: Option<Vec<u8>> = None;
    // Consecutive failed dials since the link was last up. Drives both the
    // backoff and the rate-limited "cannot reach peer" reporting.
    let mut failures = 0u64;
    loop {
        let conn = match dial(&endpoint, peer).await {
            Some(c) => c,
            None => {
                failures += 1;
                if failures == 1 || failures.is_multiple_of(DIAL_LOG_EVERY) {
                    tracing::info!(
                        peer = %peer,
                        failed_dials = failures,
                        retry_in = ?backoff,
                        "peer unreachable — still redialing"
                    );
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(DIAL_BACKOFF_MAX);
                continue;
            }
        };
        tracing::info!(
            peer = %peer,
            after_failed_dials = failures,
            "outbound QUIC session established"
        );
        failures = 0;
        backoff = DIAL_BACKOFF_START;
        let mut send = match conn.open_uni().await {
            Ok(s) => s,
            Err(e) => {
                // Back off here too: without it a peer that accepts the
                // handshake but refuses streams spins this task on a tight
                // dial loop.
                tracing::info!(peer = %peer, "opening outbound stream failed: {e}");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(DIAL_BACKOFF_MAX);
                continue; // reconnect
            }
        };

        // Drain the queue onto the stream until a write error forces a redial.
        loop {
            let frame = match pending.take() {
                Some(f) => f,
                None => match out_rx.recv().await {
                    Some(msg) => match bincode::serialize(&msg) {
                        Ok(b) => b,
                        Err(e) => {
                            tracing::error!("encode failed, dropping message: {e}");
                            continue;
                        }
                    },
                    None => {
                        // Broadcaster dropped → this node is gone. Close cleanly.
                        let _ = send.finish();
                        return;
                    }
                },
            };
            if let Err(e) = write_frame(&mut send, &frame).await {
                tracing::info!(
                    peer = %peer,
                    "outbound QUIC session dropped ({e}); redialing, holding 1 frame for resend"
                );
                pending = Some(frame); // resend after reconnect
                break;
            }
        }
    }
}

/// One dial attempt. `None` on any failure — the caller owns backoff and
/// reporting so the two failure modes (setup vs handshake) stay one code path.
async fn dial(endpoint: &Endpoint, peer: SocketAddr) -> Option<Connection> {
    match endpoint.connect(peer, "localhost") {
        Ok(connecting) => match connecting.await {
            Ok(c) => Some(c),
            Err(e) => {
                tracing::debug!("dial {peer} failed: {e}");
                None
            }
        },
        Err(e) => {
            tracing::debug!("dial setup {peer} failed: {e}");
            None
        }
    }
}

// ─────────────────────────────── nodes ──────────────────────────────────────

/// A running QUIC transport for one validator: its endpoint plus the accept
/// and per-peer writer tasks. Hand [`take_inbox`](Self::take_inbox) and
/// [`broadcaster`](Self::broadcaster) to `run_validator`; keep the `QuicNode`
/// alive for as long as the validator should be reachable. Dropping it (or
/// [`shutdown`](Self::shutdown)) takes the node off the network — a "crash".
pub struct QuicNode {
    pub id: ValidatorId,
    pub addr: SocketAddr,
    inbox: Option<Inbox>,
    net: Broadcaster,
    endpoint: Endpoint,
    tasks: Vec<JoinHandle<()>>,
}

impl QuicNode {
    /// Take the inbox (once) to hand to `run_validator`.
    pub fn take_inbox(&mut self) -> Inbox {
        self.inbox.take().expect("inbox already taken")
    }

    /// A broadcaster wired to this node's outbound queues (and local self-loop).
    pub fn broadcaster(&self) -> Broadcaster {
        self.net.clone()
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Explicitly take the node off the network: abort its tasks and close the
    /// endpoint so peers observe the drop and start redialing.
    pub fn shutdown(self) {
        // Drop does the work; this is the explicit, self-documenting form.
    }
}

impl Drop for QuicNode {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
        self.endpoint.close(0u32.into(), b"node shutdown");
    }
}

/// Wire an already-bound endpoint into a [`QuicNode`]: spawn its accept loop
/// and one writer task per peer, and build its broadcaster (self routes to the
/// local inbox).
fn wire_node(
    id: ValidatorId,
    endpoint: Endpoint,
    addr: SocketAddr,
    peer_addrs: &[SocketAddr],
) -> QuicNode {
    let (inbox_tx, inbox_rx) = mpsc::unbounded_channel();
    let mut tasks = Vec::with_capacity(peer_addrs.len());

    tasks.push(tokio::spawn(accept_loop(
        endpoint.clone(),
        inbox_tx.clone(),
    )));

    let mut senders = Vec::with_capacity(peer_addrs.len());
    for (j, &paddr) in peer_addrs.iter().enumerate() {
        if j == id.0 as usize {
            senders.push(inbox_tx.clone()); // self: local loopback
            continue;
        }
        // Info: the dial targets are the single most useful thing to confirm
        // when a mesh will not form, and they are cheap — one line per peer,
        // once, at startup.
        tracing::info!(id = ?id, listen = %addr, peer = %paddr, index = j, "dialing mesh peer");
        let (out_tx, out_rx) = mpsc::unbounded_channel();
        senders.push(out_tx);
        tasks.push(tokio::spawn(writer_task(endpoint.clone(), paddr, out_rx)));
    }

    QuicNode {
        id,
        addr,
        inbox: Some(Inbox { id, rx: inbox_rx }),
        net: Broadcaster::from_senders(senders),
        endpoint,
        tasks,
    }
}

/// Bind a dev QUIC endpoint that can both accept and dial (self-signed cert,
/// skip-verify client). Used for the validator mesh and, via
/// [`crate::rpc`], for the client-facing RPC listener. Pass port `0` to let
/// the OS choose; read the result back with [`Endpoint::local_addr`].
pub fn dev_endpoint(addr: SocketAddr) -> anyhow::Result<Endpoint> {
    install_crypto_provider();
    let mut endpoint = Endpoint::server(server_config()?, addr)?;
    endpoint.set_default_client_config(client_config()?);
    Ok(endpoint)
}

/// A whole cluster of QUIC nodes on loopback, fully meshed. `addrs[i]` is the
/// bound address of node `i`, retained so a killed node can be rebuilt on the
/// same address with [`rebind_node`].
pub struct QuicCluster {
    pub nodes: Vec<QuicNode>,
    pub addrs: Vec<SocketAddr>,
}

/// Build `n` fully-meshed QUIC nodes bound to ephemeral loopback ports.
///
/// Two phases: bind every endpoint first (so all addresses — and the QUIC
/// endpoint drivers — exist), then wire the tasks. That ordering means every
/// peer a writer dials is already accepting.
pub async fn quic_cluster(n: u16) -> anyhow::Result<QuicCluster> {
    let mut endpoints = Vec::with_capacity(n as usize);
    let mut addrs = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let endpoint = dev_endpoint(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
        addrs.push(endpoint.local_addr()?);
        endpoints.push(endpoint);
    }

    let mut nodes = Vec::with_capacity(n as usize);
    for (i, endpoint) in endpoints.into_iter().enumerate() {
        nodes.push(wire_node(ValidatorId(i as u16), endpoint, addrs[i], &addrs));
    }
    Ok(QuicCluster { nodes, addrs })
}

/// Rebuild a single node (e.g. after a crash) bound to `addr`, meshed against
/// `peer_addrs`. Peers that were redialing `addr` reconnect automatically.
pub async fn rebind_node(
    id: ValidatorId,
    addr: SocketAddr,
    peer_addrs: Vec<SocketAddr>,
) -> anyhow::Result<QuicNode> {
    let endpoint = dev_endpoint(addr)?;
    Ok(wire_node(id, endpoint, addr, &peer_addrs))
}
