//! One-call local devnet: a running validator set with a client-facing RPC
//! endpoint, for SDK examples and integration tests.
//!
//! It is a *real* network — QUIC transport, real consensus, real pipeline.
//! Everything the SDK talks to (ingest, proven reads, store root) is the same
//! code path a production deployment uses; only the scale and the dev TLS
//! differ.
//!
//! ## Why four validators, not one
//! A lone validator is **unpaced**: its own proposal self-delivers instantly,
//! so the round it just proposed immediately reaches quorum and it proposes
//! again — a hot loop that burns a core and grows the DAG without bound, with
//! no network round-trip to rate-limit it. With a real quorum, a node must
//! wait for its peers' vertices before advancing, and that wait is what paces
//! the chain. Four is the smallest set that also exercises fault tolerance
//! (quorum = 3), matching the sim.

use crate::payload::WirePayload;
use crate::pipeline::ExecutionPipeline;
use crate::quic::{quic_cluster, rebind_node, QuicCluster, QuicNode};
use crate::rpc::{self, RpcServer};
use crate::store::Store;
use crate::tiles::TilePool;
use crate::validator::{run_validator, NodeReport, Query, ValidatorConfig};
use anyhow::{bail, Context};
use peregrine_core::{Committee, Keypair, PublicKey, ValidatorId, ValidatorInfo};
use peregrine_data::faucet::FaucetPolicy;
use peregrine_data::streams::Publisher;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

/// Stream the devnet pre-registers, so a client can publish immediately.
pub const DEMO_STREAM: &str = "devnet/demo";

/// Validators in the devnet (see module docs for why this isn't 1).
pub const VALIDATORS: u16 = 4;

const MAX_ITEMS_PER_VERTEX: usize = 512;

/// How to build a devnet. [`DevnetOptions::default`] is what
/// [`Devnet::start`] uses.
#[derive(Clone, Debug)]
pub struct DevnetOptions {
    /// Committee size. Must be ≥ 2 — see the module docs on pacing.
    pub validators: u16,
    /// Address for the client-facing RPC listener (port 0 = OS-assigned).
    pub rpc_addr: SocketAddr,
    /// Payload items batched into each proposal.
    pub max_items_per_vertex: usize,
    /// Stream pre-registered on every validator.
    pub stream: String,
    /// Directory for per-validator redb files. `None` = pure in-memory.
    pub storage: Option<PathBuf>,
}

impl Default for DevnetOptions {
    fn default() -> Self {
        Self {
            validators: VALIDATORS,
            rpc_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            max_items_per_vertex: MAX_ITEMS_PER_VERTEX,
            stream: DEMO_STREAM.to_string(),
            storage: None,
        }
    }
}

/// A running local devnet. Holds the QUIC cluster, validator tasks, and RPC
/// listener alive; drop it (or call [`shutdown`](Self::shutdown)) to stop.
pub struct Devnet {
    /// Address the SDK should connect to (validator 0's RPC endpoint).
    pub rpc_addr: SocketAddr,
    /// Publisher for [`DEMO_STREAM`], registered on every validator.
    /// Sign records with `devnet.publisher.emit(bytes)`.
    pub publisher: Publisher,
    shutdown_tx: watch::Sender<bool>,
    handles: Vec<JoinHandle<NodeReport>>,
    // Ordering matters on drop: stop accepting clients, then tear down the mesh.
    _rpc: RpcServer,
    _cluster: QuicCluster,
}

impl Devnet {
    /// Start a devnet whose RPC endpoint binds an OS-assigned port. Read
    /// [`rpc_addr`](Self::rpc_addr) for the address to connect to.
    pub async fn start() -> anyhow::Result<Self> {
        Self::launch(DevnetOptions::default()).await
    }

    /// Start a devnet with the RPC endpoint on a specific address
    /// (port 0 = OS-assigned).
    pub async fn bind(rpc_bind: SocketAddr) -> anyhow::Result<Self> {
        Self::launch(DevnetOptions {
            rpc_addr: rpc_bind,
            ..Default::default()
        })
        .await
    }

    /// Start a devnet from explicit options, with freshly-generated validator
    /// keys and no chain id / faucet.
    pub async fn launch(opts: DevnetOptions) -> anyhow::Result<Self> {
        Self::launch_inner(opts, None).await
    }

    /// Start a devnet **from genesis**: the committee, chain id, faucet policy,
    /// and initial allocations all come from the [`GenesisRuntime`], and the
    /// validator count is genesis's. Used by `peregrine node run --genesis`.
    pub async fn launch_from_genesis(
        opts: DevnetOptions,
        genesis: crate::genesis::GenesisRuntime,
    ) -> anyhow::Result<Self> {
        Self::launch_inner(opts, Some(genesis)).await
    }

    async fn launch_inner(
        opts: DevnetOptions,
        genesis: Option<crate::genesis::GenesisRuntime>,
    ) -> anyhow::Result<Self> {
        // Resolve the validator keys + stakes from genesis, else generate them.
        let (keypairs, stakes): (Vec<Keypair>, Vec<u64>) = match &genesis {
            Some(g) => (
                g.validators
                    .iter()
                    .map(|(kp, _)| Keypair::from_bytes(&kp.to_bytes()))
                    .collect(),
                g.validators.iter().map(|(_, s)| *s).collect(),
            ),
            None => {
                let mut rng = rand::rngs::OsRng;
                let kps: Vec<Keypair> = (0..opts.validators)
                    .map(|_| Keypair::generate(&mut rng))
                    .collect();
                let stakes = vec![100u64; kps.len()];
                (kps, stakes)
            }
        };
        let n_validators = keypairs.len() as u16;
        if n_validators < 2 {
            anyhow::bail!(
                "a devnet needs at least 2 validators: a lone validator's own proposal \
                 self-delivers instantly, so it re-proposes in a hot loop with no network \
                 round-trip to pace it"
            );
        }
        if let Some(dir) = &opts.storage {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("create storage dir {}", dir.display()))?;
        }
        let rpc_bind = opts.rpc_addr;
        let mut rng = rand::rngs::OsRng;

        let committee = Committee::new(
            keypairs
                .iter()
                .zip(&stakes)
                .enumerate()
                .map(|(i, (kp, stake))| ValidatorInfo {
                    id: ValidatorId(i as u16),
                    public_key: kp.public(),
                    stake: *stake,
                })
                .collect(),
        );

        let mut cluster = quic_cluster(n_validators).await?;

        // Pre-register the demo publisher so client-published records validate
        // on every validator (this is genesis config in a real deployment).
        let publisher = Publisher::new(&opts.stream, Keypair::generate(&mut rng));
        let publisher_pk = publisher.public_key();

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut handles = Vec::with_capacity(opts.validators as usize);
        // One tile pool shared by the in-process validators (see bench.rs for
        // why sharing rather than one pool each).
        let tiles = Arc::new(TilePool::sized_for_machine());

        // Validator 0's channels are the ones the RPC server drives.
        let mut rpc_channels = None;

        for (kp, node) in keypairs.into_iter().zip(cluster.nodes.iter_mut()) {
            let id = node.id;
            let inbox = node.take_inbox();
            let net = node.broadcaster();
            let mut pipeline = ExecutionPipeline::new().with_tiles(Arc::clone(&tiles));
            pipeline.streams.register(&opts.stream, publisher_pk);

            // Genesis state, applied identically on every validator so their
            // store roots agree from the first round: chain id, faucet policy,
            // and initial balance allocations.
            if let Some(g) = &genesis {
                pipeline.chain_id = g.chain_id;
                pipeline.faucet = g.faucet;
                for (account, grains) in &g.allocations {
                    pipeline.allocate(account, *grains);
                }
            }

            // Each validator gets its own redb file when persistence is on, so
            // a restart reloads that node's own committed state.
            let store = match &opts.storage {
                Some(dir) => Some(
                    Store::open(dir.join(format!("validator-{}.redb", id.0)))
                        .with_context(|| format!("open store for validator {}", id.0))?,
                ),
                None => None,
            };

            let (ingest_tx, ingest_rx) = mpsc::channel::<WirePayload>(65_536);
            // Only the RPC-serving validator needs a query channel.
            let query_rx = if id == ValidatorId(0) {
                let (query_tx, query_rx) = mpsc::channel::<Query>(1024);
                rpc_channels = Some((ingest_tx, query_tx));
                Some(query_rx)
            } else {
                None
            };

            handles.push(tokio::spawn(run_validator(ValidatorConfig {
                id,
                keypair: kp,
                committee: committee.clone(),
                inbox,
                net,
                ingest_rx,
                shutdown: shutdown_rx.clone(),
                pipeline,
                max_items_per_vertex: opts.max_items_per_vertex,
                store,
                query_rx,
            })));
        }

        let (ingest_tx, query_tx) = rpc_channels.expect("validator 0 exists");
        let rpc = rpc::serve(rpc_bind, ingest_tx, query_tx)?;
        Ok(Self {
            rpc_addr: rpc.addr,
            publisher,
            shutdown_tx,
            handles,
            _rpc: rpc,
            _cluster: cluster,
        })
    }

    /// Stop every validator and return their final reports, validator 0 first
    /// (the one the SDK was reading from).
    pub async fn shutdown(self) -> anyhow::Result<Vec<NodeReport>> {
        let _ = self.shutdown_tx.send(true);
        let mut reports = Vec::with_capacity(self.handles.len());
        for h in self.handles {
            reports.push(h.await?);
        }
        reports.sort_by_key(|r| r.id.0);
        Ok(reports)
    }
}

// ── single-validator (distributed) mode ─────────────────────────────────────

/// How to run **one** validator identity as its own process — the distributed
/// launch path, where each physical server runs a single member of the
/// committee and dials the others over real QUIC.
///
/// The committee (and thus every validator's public key and stake) comes from
/// genesis; this process supplies only *its own* secret key and the network
/// addresses of the set.
pub struct SingleValidatorOptions {
    /// This node's index into the genesis validator list.
    pub identity: ValidatorId,
    /// This node's secret key. Must match the genesis public key at `identity`.
    pub keypair: Keypair,
    /// The full committee, from genesis.
    pub committee: Committee,
    /// Every validator's mesh address, **in committee-index order** — this
    /// node's own listen address at position `identity`, the peers elsewhere.
    /// Order matters: sync requests are addressed by index.
    pub addrs: Vec<SocketAddr>,
    /// Where the client RPC listens.
    pub rpc_addr: SocketAddr,
    pub max_items_per_vertex: usize,
    /// Directory for this identity's redb file (`validator-{i}.redb`). `None` =
    /// in-memory.
    pub storage: Option<PathBuf>,
    /// Genesis-derived state, applied identically on every validator.
    pub chain_id: u64,
    pub faucet: Option<FaucetPolicy>,
    pub allocations: Vec<(PublicKey, u64)>,
}

/// A single running validator identity: its RPC endpoint, consensus task, and
/// QUIC transport. Drop it (or [`shutdown`](Self::shutdown)) to take the node
/// off the network.
pub struct Validator {
    /// Address the SDK connects to.
    pub rpc_addr: SocketAddr,
    pub id: ValidatorId,
    /// This node's mesh listen address.
    pub listen: SocketAddr,
    shutdown_tx: watch::Sender<bool>,
    handle: JoinHandle<NodeReport>,
    _rpc: RpcServer,
    _node: QuicNode,
}

impl Validator {
    /// Stop this validator and return its final report.
    pub async fn shutdown(self) -> anyhow::Result<NodeReport> {
        let _ = self.shutdown_tx.send(true);
        Ok(self.handle.await?)
    }
}

/// Run a single validator identity over real QUIC against an explicit peer set.
///
/// **Fails closed** if the identity is out of range, the address list does not
/// cover the committee, or the loaded key does not match the genesis public key
/// for this identity — so a misconfigured server never joins under a borrowed
/// identity.
///
/// It deliberately pre-registers **no** streams: unlike the in-process devnet
/// (where every validator shares one generated demo-publisher key), separate
/// processes have no shared key to register, and registering different keys per
/// node would diverge their state. Streams/feeds are registered through
/// committed payloads (`RegisterFeed`), which every validator applies identically.
pub async fn run_single_validator(opts: SingleValidatorOptions) -> anyhow::Result<Validator> {
    let n = opts.committee.size();
    let i = opts.identity.0 as usize;
    if i >= n {
        bail!(
            "identity {i} is out of range: genesis lists {n} validators (valid indices 0..{})",
            n - 1
        );
    }
    if opts.addrs.len() != n {
        bail!(
            "expected {n} validator addresses (one per committee member), got {}",
            opts.addrs.len()
        );
    }
    // Fail-closed identity check: the loaded key must be exactly this index's
    // committee key, so a server cannot start under an identity it lacks the key for.
    let expected = opts
        .committee
        .validator(opts.identity)
        .expect("in range")
        .public_key;
    if opts.keypair.public() != expected {
        bail!(
            "public key mismatch for identity {i}: the loaded key does not match the genesis \
             validator at that index (fail-closed — check --identity and --keys-dir)"
        );
    }

    if let Some(dir) = &opts.storage {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("create storage dir {}", dir.display()))?;
    }
    let listen = opts.addrs[i];

    // Transport: bind our endpoint to `listen` and mesh against the full address
    // list (our own slot loops back locally; peers dial with retry/backoff, so
    // start order between servers does not matter — they heal as each comes up).
    let mut node = rebind_node(opts.identity, listen, opts.addrs.clone())
        .await
        .with_context(|| format!("bind QUIC transport on {listen}"))?;
    let inbox = node.take_inbox();
    let net = node.broadcaster();

    let mut pipeline = ExecutionPipeline::new().with_tiles(Arc::new(TilePool::sized_for_machine()));
    pipeline.chain_id = opts.chain_id;
    pipeline.faucet = opts.faucet;
    for (account, grains) in &opts.allocations {
        pipeline.allocate(account, *grains);
    }

    let store = match &opts.storage {
        Some(dir) => Some(
            Store::open(dir.join(format!("validator-{i}.redb")))
                .with_context(|| format!("open store for identity {i}"))?,
        ),
        None => None,
    };

    let (ingest_tx, ingest_rx) = mpsc::channel::<WirePayload>(65_536);
    let (query_tx, query_rx) = mpsc::channel::<Query>(1024);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let handle = tokio::spawn(run_validator(ValidatorConfig {
        id: opts.identity,
        keypair: opts.keypair,
        committee: opts.committee,
        inbox,
        net,
        ingest_rx,
        shutdown: shutdown_rx,
        pipeline,
        max_items_per_vertex: opts.max_items_per_vertex,
        store,
        query_rx: Some(query_rx),
    }));

    let rpc = rpc::serve(opts.rpc_addr, ingest_tx, query_tx)?;
    Ok(Validator {
        rpc_addr: rpc.addr,
        id: opts.identity,
        listen,
        shutdown_tx,
        handle,
        _rpc: rpc,
        _node: node,
    })
}
