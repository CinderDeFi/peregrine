//! # peregrine — the command-line interface
//!
//! One binary for everything you do with this workspace: run a node, drive the
//! demo, benchmark it, make keys, and query committed state with proofs.
//!
//! ```text
//! peregrine node run            # a local network with a client RPC endpoint
//! peregrine sim                 # the end-to-end demonstration
//! peregrine bench               # throughput & latency
//! peregrine keygen              # an ed25519 keypair
//! peregrine config init|show    # scaffold / inspect configuration
//! peregrine sdk example <name>  # runnable SDK walkthroughs
//! peregrine read <table> <key>  # proven read, verified locally
//! peregrine gateway             # HTTP/JSON gateway for the web explorer
//! ```
//!
//! Configuration layers defaults → `peregrine.toml` → flags; see [`config`].

mod config;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use config::Config;
use peregrine_core::Keypair;
use peregrine_data::tables::TableId;
use peregrine_node::bench::{BenchOptions, Transport};
use peregrine_node::devnet::{Devnet, DevnetOptions};
use peregrine_node::sim::SimOptions;
use peregrine_sdk::Client;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "peregrine",
    version,
    about = "Peregrine — data-native real-time Layer-1",
    long_about = "Run nodes, simulate a network, benchmark it, manage keys, and read \
                  committed state with light-client proofs.",
    propagate_version = true
)]
struct Cli {
    /// Path to a config file (default: ./peregrine.toml, or $PEREGRINE_CONFIG).
    #[arg(long, short = 'c', global = true, value_name = "PATH")]
    config: Option<PathBuf>,

    /// Increase log verbosity (overrides logging.level).
    #[arg(long, short = 'v', global = true, conflicts_with = "quiet")]
    verbose: bool,

    /// Only log warnings and errors.
    #[arg(long, short = 'q', global = true)]
    quiet: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the full end-to-end tour: streams, VM, proofs, Ethereum interop.
    Demo,
    /// One-command local devnet.
    #[command(subcommand)]
    Devnet(DevnetCmd),
    /// Run a validator node.
    #[command(subcommand)]
    Node(NodeCmd),
    /// Run the local multi-validator demonstration.
    Sim(SimArgs),
    /// Measure sustained throughput and publish→commit latency.
    Bench(BenchArgs),
    /// Generate an ed25519 keypair.
    Keygen(KeygenArgs),
    /// Inspect or scaffold configuration.
    #[command(subcommand)]
    Config(ConfigCmd),
    /// SDK helpers.
    #[command(subcommand)]
    Sdk(SdkCmd),
    /// Submit a Talon transaction that writes a value into a table.
    SubmitTx(SubmitTxArgs),
    /// Live terminal dashboard for a running node.
    Watch(WatchArgs),
    /// Submit a proof-carrying foreign claim (Ethereum state) to a node.
    SubmitClaim(SubmitClaimArgs),
    /// Read a table key from a running node and verify the proof locally.
    Read(ReadArgs),
    /// Serve an HTTP/JSON gateway that fronts a node's QUIC RPC (for the web
    /// explorer and other browser clients). Read-only; CORS-permissive.
    Gateway(GatewayArgs),
    /// Generate or inspect a testnet genesis.
    #[command(subcommand)]
    Genesis(GenesisCmd),
    /// Testnet faucet: drip tokens (as the operator) or serve a web faucet.
    #[command(subcommand)]
    Faucet(FaucetCmd),
}

#[derive(Subcommand)]
enum GenesisCmd {
    /// Generate a fresh testnet genesis plus the validator and faucet keys.
    New(GenesisNewArgs),
    /// Summarise a genesis file (chain id, validators, faucet, allocations).
    Show(GenesisShowArgs),
}

#[derive(Args)]
struct GenesisNewArgs {
    /// Number of validators (>= 2; 4 for fault tolerance).
    #[arg(long, default_value_t = 4)]
    validators: u16,
    /// The network's chain id (non-zero). Pinned by the EVM light client.
    #[arg(long)]
    chain_id: u64,
    /// Human-readable network name.
    #[arg(long, default_value = "peregrine-testnet")]
    network: String,
    /// Include a faucet authority (on by default; pass --no-faucet to omit).
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    faucet: bool,
    /// Where to write the genesis file.
    #[arg(long, short = 'o', value_name = "PATH", default_value = "genesis.toml")]
    out: PathBuf,
    /// Directory for the generated secret keys.
    #[arg(long, value_name = "DIR", default_value = "testnet-keys")]
    keys_dir: PathBuf,
    /// Overwrite existing files.
    #[arg(long)]
    force: bool,
}

#[derive(Args)]
struct GenesisShowArgs {
    /// The genesis file to summarise.
    #[arg(default_value = "genesis.toml")]
    path: PathBuf,
}

#[derive(Subcommand)]
enum FaucetCmd {
    /// Drip tokens to an address, signing with the faucet key (operator use).
    Drip(FaucetDripArgs),
    /// Serve a rate-limited web faucet over HTTP.
    Serve(FaucetServeArgs),
}

#[derive(Args)]
struct FaucetDripArgs {
    /// Recipient public key (64 hex chars).
    recipient: String,
    /// Grains to drip (subject to the on-chain per-request cap).
    #[arg(long, default_value_t = 1_000)]
    amount: u64,
    /// The faucet secret key file.
    #[arg(long, value_name = "PATH", default_value = "testnet-keys/faucet.key")]
    faucet_key: PathBuf,
    /// A nonce distinguishing this drip from an identical earlier one.
    #[arg(long, default_value_t = 0)]
    nonce: u64,
    /// Node RPC address (default: the configured node.rpc_addr).
    #[arg(long, value_name = "ADDR")]
    rpc_addr: Option<SocketAddr>,
}

#[derive(Args)]
struct FaucetServeArgs {
    /// HTTP address to listen on.
    #[arg(long, value_name = "ADDR", default_value = "127.0.0.1:8088")]
    bind: SocketAddr,
    /// Node RPC address to submit drips to (default: the configured node.rpc_addr).
    #[arg(long, value_name = "ADDR")]
    node: Option<SocketAddr>,
    /// The faucet secret key file.
    #[arg(long, value_name = "PATH", default_value = "testnet-keys/faucet.key")]
    faucet_key: PathBuf,
    /// Grains per web request (subject to the on-chain per-request cap).
    #[arg(long, default_value_t = 1_000)]
    amount: u64,
    /// Minimum seconds between requests from the same IP (soft, on top of the
    /// hard on-chain per-recipient cooldown).
    #[arg(long, default_value_t = 60)]
    per_ip_cooldown_secs: u64,
}

#[derive(Args)]
struct GatewayArgs {
    /// HTTP address for the gateway to listen on (browsers connect here).
    #[arg(long, value_name = "ADDR", default_value = "127.0.0.1:8080")]
    bind: SocketAddr,
    /// The node's QUIC RPC address to front (default: the configured node.rpc_addr).
    #[arg(long, value_name = "ADDR")]
    node: Option<SocketAddr>,
}

#[derive(Args)]
struct SubmitTxArgs {
    /// Table name (e.g. "contract.answers") or a 32-byte hex table id.
    table: String,
    /// Key, as a UTF-8 string or `hex:`-prefixed bytes.
    key: String,
    /// Value to store (u64, little-endian on chain).
    value: u64,
    /// Node RPC address (default: the configured node.rpc_addr).
    #[arg(long, value_name = "ADDR")]
    rpc_addr: Option<SocketAddr>,
}

#[derive(Subcommand)]
enum DevnetCmd {
    /// Start a local devnet with a client RPC endpoint, until Ctrl-C.
    Up(NodeRunArgs),
}

#[derive(Subcommand)]
enum NodeCmd {
    /// Run a local network with a client-facing RPC endpoint until Ctrl-C.
    Run(NodeRunArgs),
}

#[derive(Args)]
struct NodeRunArgs {
    /// Validators in the committee (>= 2).
    #[arg(long)]
    validators: Option<u16>,
    /// Address for the client RPC listener.
    #[arg(long, value_name = "ADDR")]
    rpc_addr: Option<SocketAddr>,
    /// Directory for persistence. Omit to use the configured value.
    #[arg(long, value_name = "DIR")]
    storage: Option<PathBuf>,
    /// Run purely in memory, ignoring any configured storage path.
    #[arg(long, conflicts_with = "storage")]
    in_memory: bool,
    /// Launch from a genesis file (sets the committee, chain id, faucet, and
    /// initial allocations). Requires `--keys-dir` holding the validator keys.
    #[arg(long, value_name = "PATH")]
    genesis: Option<PathBuf>,
    /// Directory holding `validator-{i}.key` for a genesis launch.
    #[arg(long, value_name = "DIR", requires = "genesis")]
    keys_dir: Option<PathBuf>,
    /// Run as ONE validator identity (0-based index into the genesis validator
    /// list) — the distributed launch path, where each server is one member of
    /// the committee. Loads only `validator-{index}.key` and fails closed if it
    /// does not match genesis. Omit to keep the local all-in-one mode.
    #[arg(long, value_name = "INDEX", requires = "genesis")]
    identity: Option<u16>,
    /// This identity's QUIC mesh listen address, e.g. `0.0.0.0:9001`.
    #[arg(long, value_name = "ADDR", requires = "identity")]
    listen: Option<SocketAddr>,
    /// The OTHER validators' mesh addresses, comma-separated, **in genesis
    /// index order** (skipping this identity). Order matters — sync is addressed
    /// by index. e.g. `--peers 1.2.3.4:9001,5.6.7.8:9001`.
    #[arg(
        long,
        value_name = "ADDRS",
        value_delimiter = ',',
        requires = "identity"
    )]
    peers: Vec<SocketAddr>,
}

#[derive(Args)]
struct SimArgs {
    #[arg(long)]
    validators: Option<u16>,
    /// Signed stream records to publish.
    #[arg(long)]
    ticks: Option<u64>,
}

#[derive(Args)]
struct BenchArgs {
    #[arg(long)]
    validators: Option<u16>,
    /// How long to sustain load, in seconds.
    #[arg(long, value_name = "SECS")]
    duration: Option<u64>,
    /// Total records/sec across publishers; 0 floods as fast as possible.
    #[arg(long)]
    rate: Option<u64>,
    /// Transport to drive the mesh over.
    #[arg(long, value_enum)]
    transport: Option<TransportArg>,
    /// Payload items batched into each proposal.
    #[arg(long)]
    items_per_vertex: Option<usize>,
}

#[derive(Clone, Copy, ValueEnum)]
enum TransportArg {
    /// Real QUIC sockets on loopback (the honest number).
    Quic,
    /// In-process channels — isolates consensus cost from the network.
    Inproc,
}

#[derive(Args)]
struct KeygenArgs {
    /// Write the secret seed here instead of printing it.
    #[arg(long, short = 'o', value_name = "PATH")]
    out: Option<PathBuf>,
    /// Overwrite an existing key file.
    #[arg(long)]
    force: bool,
}

#[derive(Subcommand)]
enum ConfigCmd {
    /// Write a commented starter config file.
    Init {
        /// Where to write it.
        #[arg(default_value = config::DEFAULT_CONFIG_FILE)]
        path: PathBuf,
        /// Overwrite an existing file.
        #[arg(long)]
        force: bool,
    },
    /// Print the effective configuration after layering file and flags.
    Show,
}

#[derive(Subcommand)]
enum SdkCmd {
    /// Run a runnable SDK walkthrough.
    Example {
        #[arg(value_enum)]
        name: ExampleName,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum ExampleName {
    /// Tokenized real-world asset: a property loan collateralised on Ethereum.
    Rwa,
    /// Publish signed stream records, then read one back with a proof.
    PublishStream,
    /// Submit a Talon transaction and read back its result.
    SubmitTx,
    /// Verify a read against the store root, then try to forge it.
    LightClient,
    /// An autonomous agent buying a data feed with a scoped, budgeted,
    /// revocable session key.
    Agent,
    /// RWA contract templates: title, valuation, proven-collateral health.
    RwaTemplates,
    /// Selective disclosure of a KYC record + a compliance-gated transfer.
    Compliance,
    /// Oracle feeds: a multi-source median price feed and an RWA valuation.
    Oracle,
    /// An agent pays for verifiable oracle data with a scoped, budgeted session.
    AgentData,
}

#[derive(Args)]
struct SubmitClaimArgs {
    /// Path to a JSON-encoded `VerifiedClaim` (as written by the RWA example).
    #[arg(value_name = "FILE")]
    file: PathBuf,
    /// Node RPC address (default: the configured node.rpc_addr).
    #[arg(long, value_name = "ADDR")]
    rpc_addr: Option<SocketAddr>,
}

#[derive(Args)]
struct WatchArgs {
    /// Node RPC address (default: the configured node.rpc_addr).
    #[arg(long, value_name = "ADDR")]
    rpc_addr: Option<SocketAddr>,
    /// Values to watch, as `table:key` (repeatable).
    #[arg(long = "key", value_name = "TABLE:KEY")]
    keys: Vec<String>,
}

#[derive(Args)]
struct ReadArgs {
    /// Table name (e.g. "contract.answers") or a 32-byte hex table id.
    table: String,
    /// Key, as a UTF-8 string or `hex:`-prefixed bytes.
    key: String,
    /// Node RPC address (default: the configured node.rpc_addr).
    #[arg(long, value_name = "ADDR")]
    rpc_addr: Option<SocketAddr>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let (mut cfg, source) = Config::load(cli.config.as_deref())?;

    // Verbosity flags win over the file.
    if cli.verbose {
        cfg.logging.level = "debug".into();
    } else if cli.quiet {
        cfg.logging.level = "warn".into();
    }
    init_logging(&cfg.logging.level);

    if let Some(path) = &source {
        tracing::debug!("loaded config from {}", path.display());
    }
    cfg.validate()?;

    // `config` subcommands are pure file operations; everything else needs a
    // runtime. Building it here (rather than with #[tokio::main]) keeps
    // `config init` usable even on a machine where the runtime can't start.
    match cli.command {
        Command::Config(cmd) => run_config(cmd, &cfg, source.as_deref()),
        Command::Keygen(args) => run_keygen(args),
        // Genesis is pure file work; no runtime needed.
        Command::Genesis(cmd) => run_genesis(cmd),
        other => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .context("start async runtime")?;
            rt.block_on(run_async(other, cfg))
        }
    }
}

async fn run_async(cmd: Command, cfg: Config) -> Result<()> {
    match cmd {
        Command::Demo => peregrine_node::demos::full_demo().await,
        Command::Devnet(DevnetCmd::Up(args)) | Command::Node(NodeCmd::Run(args)) => {
            run_node(args, cfg).await
        }
        Command::Sim(args) => {
            let s = &cfg.sim;
            peregrine_node::sim::run(SimOptions {
                validators: args.validators.unwrap_or(s.validators),
                ticks: args.ticks.unwrap_or(s.ticks),
                max_items_per_vertex: s.max_items_per_vertex,
            })
            .await
        }
        Command::Bench(args) => {
            let b = &cfg.bench;
            let transport = match args.transport {
                Some(TransportArg::Quic) => Transport::Quic,
                Some(TransportArg::Inproc) => Transport::InProcess,
                None if b.transport == "inproc" => Transport::InProcess,
                None => Transport::Quic,
            };
            peregrine_node::bench::run(BenchOptions {
                validators: args.validators.unwrap_or(b.validators),
                duration: Duration::from_secs(args.duration.unwrap_or(b.duration_secs)),
                rate: args.rate.unwrap_or(b.rate),
                items_per_vertex: args.items_per_vertex.unwrap_or(b.items_per_vertex),
                transport,
            })
            .await
        }
        Command::Sdk(SdkCmd::Example { name }) => match name {
            ExampleName::Rwa => peregrine_node::demos::rwa().await,
            ExampleName::PublishStream => peregrine_node::demos::publish_stream().await,
            ExampleName::SubmitTx => peregrine_node::demos::submit_tx().await,
            ExampleName::LightClient => peregrine_node::demos::light_client().await,
            ExampleName::Agent => peregrine_node::demos::agent().await,
            ExampleName::RwaTemplates => peregrine_node::demos::rwa_templates().await,
            ExampleName::Compliance => peregrine_node::demos::compliance().await,
            ExampleName::Oracle => peregrine_node::demos::oracle().await,
            ExampleName::AgentData => peregrine_node::demos::agent_data().await,
        },
        Command::SubmitTx(args) => run_submit_tx(args, cfg).await,
        Command::Watch(args) => {
            let addr = args.rpc_addr.unwrap_or(cfg.node.rpc_addr);
            let mut watched = Vec::new();
            for spec in &args.keys {
                let (t, k) = spec
                    .split_once(':')
                    .ok_or_else(|| anyhow::anyhow!("--key expects TABLE:KEY, got {spec:?}"))?;
                watched.push((parse_table(t)?, parse_key(k)?, spec.clone()));
            }
            peregrine_node::demos::watch(addr, &watched).await
        }
        Command::SubmitClaim(args) => run_submit_claim(args, cfg).await,
        Command::Read(args) => run_read(args, cfg).await,
        Command::Gateway(args) => {
            let node = args.node.unwrap_or(cfg.node.rpc_addr);
            peregrine_node::gateway::serve(args.bind, node).await
        }
        Command::Faucet(FaucetCmd::Drip(args)) => run_faucet_drip(args, cfg).await,
        Command::Faucet(FaucetCmd::Serve(args)) => run_faucet_serve(args, cfg).await,
        // Handled synchronously in `main`.
        Command::Config(_) | Command::Keygen(_) | Command::Genesis(_) => unreachable!(),
    }
}

async fn run_node(args: NodeRunArgs, cfg: Config) -> Result<()> {
    let storage = if args.in_memory {
        None
    } else {
        args.storage.clone().or(cfg.storage.path.clone())
    };

    let rpc_addr = args.rpc_addr.unwrap_or(cfg.node.rpc_addr);

    // Single-validator (distributed) mode, selected on the command line: run
    // exactly the identity at `--identity`.
    if let Some(idx) = args.identity {
        return run_single_identity(idx, &args, rpc_addr, storage).await;
    }
    // The same distributed path, driven entirely by `peregrine.toml`
    // (`node.identity_key` + `listen_addr` + `peers` + `genesis`). `validate()`
    // has already checked those four are coherent.
    if cfg.node.is_multi_machine() {
        return run_multi_machine(&args, &cfg, rpc_addr, storage).await;
    }
    // A genesis may come from the flag or the config; the flag wins.
    let genesis_path = args.genesis.clone().or_else(|| cfg.node.genesis.clone());
    let (devnet, n_validators) = if let Some(gpath) = &genesis_path {
        // Launch from a genesis: committee, chain id, faucet, and allocations
        // all come from the file, and each validator loads its own key.
        let genesis = peregrine_node::genesis::Genesis::load(gpath).context("load genesis")?;
        let keys_dir = args
            .keys_dir
            .clone()
            .ok_or_else(|| anyhow::anyhow!("--keys-dir is required with --genesis"))?;
        let keys = load_validator_keys(&keys_dir, genesis.validators.len())?;
        let n = genesis.validators.len() as u16;
        println!(
            "launching from genesis: chain_id {} ({}), {} validators",
            genesis.chain_id, genesis.network, n
        );
        if genesis.faucet.is_some() {
            println!("  faucet     : configured");
        }
        let runtime = genesis.runtime(keys).context("bind genesis to keys")?;
        let opts = DevnetOptions {
            validators: n,
            rpc_addr,
            max_items_per_vertex: genesis.params.max_items_per_vertex,
            stream: cfg.node.stream.clone(),
            storage: storage.clone(),
        };
        (
            Devnet::launch_from_genesis(opts, runtime)
                .await
                .context("launch from genesis")?,
            n,
        )
    } else {
        let n = args.validators.unwrap_or(cfg.node.validators);
        let opts = DevnetOptions {
            validators: n,
            rpc_addr,
            max_items_per_vertex: cfg.node.max_items_per_vertex,
            stream: cfg.node.stream.clone(),
            storage: storage.clone(),
        };
        (Devnet::launch(opts).await.context("launch node")?, n)
    };

    println!("peregrine node running");
    println!("  validators : {n_validators}");
    println!("  rpc        : {}", devnet.rpc_addr);
    println!("  stream     : {}", cfg.node.stream);
    println!(
        "  storage    : {}",
        storage
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "in-memory".into())
    );
    println!("\nready — press Ctrl-C to stop.");

    tokio::signal::ctrl_c().await.context("wait for Ctrl-C")?;
    println!("\nshutting down…");
    let reports = devnet.shutdown().await?;
    for r in &reports {
        println!(
            "  {:?}: {} commits, {} records, {} txs",
            r.id, r.commits, r.pipeline.metrics.committed_records, r.pipeline.metrics.committed_txs
        );
    }
    Ok(())
}

/// Run exactly one validator identity, selected on the command line with
/// `--identity <i>`, `--listen`, and `--peers`.
async fn run_single_identity(
    idx: u16,
    args: &NodeRunArgs,
    rpc_addr: SocketAddr,
    storage: Option<PathBuf>,
) -> Result<()> {
    use peregrine_node::genesis::Genesis;

    let gpath = args
        .genesis
        .as_ref()
        .expect("clap: --identity requires --genesis");
    let genesis = Genesis::load(gpath).context("load genesis")?;
    let n = genesis.validators.len();
    if (idx as usize) >= n {
        anyhow::bail!(
            "identity {idx} has no matching validator: genesis lists {n} (valid indices 0..{})",
            n - 1
        );
    }
    let keys_dir = args
        .keys_dir
        .clone()
        .ok_or_else(|| anyhow::anyhow!("--keys-dir is required with --identity"))?;
    let keypair = load_secret_key(&keys_dir.join(format!("validator-{idx}.key")))
        .with_context(|| format!("load key for identity {idx}"))?;
    let listen = args
        .listen
        .ok_or_else(|| anyhow::anyhow!("--listen is required with --identity"))?;

    launch_single_validator(
        &genesis,
        keypair,
        idx,
        listen,
        &args.peers,
        rpc_addr,
        storage,
    )
    .await
}

/// Run exactly one validator identity, driven by `peregrine.toml`'s
/// `node.identity_key` / `listen_addr` / `peers` / `genesis`.
///
/// Unlike the flag path, the committee index isn't given: we derive it by
/// matching this node's public key against the shared committee, and **fail
/// closed** if the key isn't a member.
async fn run_multi_machine(
    args: &NodeRunArgs,
    cfg: &Config,
    rpc_addr: SocketAddr,
    storage: Option<PathBuf>,
) -> Result<()> {
    use peregrine_node::genesis::Genesis;

    // validate() guarantees these are present in multi-machine mode; the flag
    // still overrides the configured genesis path.
    let gpath = args
        .genesis
        .clone()
        .or_else(|| cfg.node.genesis.clone())
        .expect("validate: multi-machine requires node.genesis");
    let key_path = cfg
        .node
        .identity_key
        .as_ref()
        .expect("validate: multi-machine requires node.identity_key");
    let listen = cfg
        .node
        .listen_addr
        .expect("validate: multi-machine requires node.listen_addr");

    let genesis = Genesis::load(&gpath).context("load genesis")?;
    let keypair = load_secret_key(key_path)
        .with_context(|| format!("load identity key {}", key_path.display()))?;

    // Which committee member is this key? Fail closed if it is none of them.
    let committee = genesis.committee()?;
    let me = keypair.public();
    let idx = committee_index_of(&committee, me).ok_or_else(|| {
        anyhow::anyhow!(
            "identity key {} (public key {}) is not in the committee defined by {} — \
             fail-closed. Check you distributed the right genesis and key, and that this \
             node's public key was included in the shared committee.",
            key_path.display(),
            hex::encode(me.0),
            gpath.display(),
        )
    })?;

    launch_single_validator(
        &genesis,
        keypair,
        idx,
        listen,
        &cfg.node.peers,
        rpc_addr,
        storage,
    )
    .await
}

/// The shared body of both distributed launch paths: verify the key against its
/// committee slot, build the index-ordered mesh address list, start the one
/// validator, log the committee it joined, and block until Ctrl-C.
async fn launch_single_validator(
    genesis: &peregrine_node::genesis::Genesis,
    keypair: Keypair,
    idx: u16,
    listen: SocketAddr,
    peers: &[SocketAddr],
    rpc_addr: SocketAddr,
    storage: Option<PathBuf>,
) -> Result<()> {
    use peregrine_core::ValidatorId;
    use peregrine_node::devnet::{run_single_validator, SingleValidatorOptions};

    let n = genesis.validators.len();
    if (idx as usize) >= n {
        anyhow::bail!(
            "identity {idx} out of range: committee has {n} members (0..{})",
            n - 1
        );
    }
    let committee = genesis.committee()?;
    let me = keypair.public();
    let expected = committee
        .validator(ValidatorId(idx))
        .expect("in range")
        .public_key;
    if me != expected {
        anyhow::bail!(
            "public key mismatch for identity {idx}: the key holds {} but the committee lists {} \
             (fail-closed — check the key file and the shared genesis)",
            hex::encode(me.0),
            hex::encode(expected.0),
        );
    }
    if peers.len() != n - 1 {
        anyhow::bail!(
            "expected {} peer addresses (the other validators, in committee-index order, skipping \
             this one), got {}",
            n - 1,
            peers.len()
        );
    }
    // Full index-ordered address list: our listen at `idx`, the peers elsewhere.
    let mut addrs = Vec::with_capacity(n);
    let mut it = peers.iter().copied();
    for j in 0..n {
        if j == idx as usize {
            addrs.push(listen);
        } else {
            addrs.push(it.next().expect("count checked"));
        }
    }

    let chain_id = genesis.chain_id;
    let network = genesis.network.clone();
    let v = run_single_validator(SingleValidatorOptions {
        identity: ValidatorId(idx),
        keypair,
        committee: committee.clone(),
        addrs: addrs.clone(),
        rpc_addr,
        max_items_per_vertex: genesis.params.max_items_per_vertex,
        storage,
        chain_id,
        faucet: genesis.faucet_policy()?,
        allocations: genesis.allocations()?,
    })
    .await
    .context("start validator")?;

    println!("peregrine validator running (multi-machine mode)");
    println!("  identity   : #{idx} of {n}  ({network})");
    println!("  public key : {}", hex::encode(me.0));
    println!("  chain id   : {chain_id}");
    println!("  listen     : {}  (validator mesh)", v.listen);
    println!("  rpc        : {}  (clients)", v.rpc_addr);
    println!("  committee  :");
    for (j, addr) in addrs.iter().enumerate() {
        let info = committee
            .validator(ValidatorId(j as u16))
            .expect("in range");
        let marker = if j == idx as usize { "self " } else { "" };
        println!(
            "    #{j} stake {:<5} {} @ {addr}  {marker}",
            info.stake,
            &hex::encode(info.public_key.0)[..16],
        );
    }
    println!("\nready — press Ctrl-C to stop.");

    tokio::signal::ctrl_c().await.context("wait for Ctrl-C")?;
    println!("\nshutting down…");
    let report = v.shutdown().await?;
    println!(
        "  {:?}: {} commits, {} records, {} txs",
        report.id,
        report.commits,
        report.pipeline.metrics.committed_records,
        report.pipeline.metrics.committed_txs
    );
    Ok(())
}

async fn run_submit_tx(args: SubmitTxArgs, cfg: Config) -> Result<()> {
    let table = parse_table(&args.table)?;
    let key = parse_key(&args.key)?;
    let addr = args.rpc_addr.unwrap_or(cfg.node.rpc_addr);
    let client = connect(addr).await?;

    // The smallest useful program: push the value, store it, halt. Unlike a
    // stream record this needs no genesis-registered key, which is why it is
    // the CLI's write path.
    client
        .submit_tx(vec![
            peregrine_sdk::Instr::Push(args.value),
            peregrine_sdk::Instr::StoreTable {
                table,
                key: key.clone(),
            },
            peregrine_sdk::Instr::Halt,
        ])
        .await
        .context("submit transaction")?;

    println!("submitted: {} [{}] = {}", args.table, args.key, args.value);
    println!("(commit is asynchronous — read it back with `peregrine read`)");
    Ok(())
}

/// Hand a proof-carrying claim to a node.
///
/// The node will *accept* it into the ingest queue on nothing more than a size
/// and rate check — the cryptography is checked later, by every validator, at
/// commit time. So a success here means "queued", not "believed"; the claim is
/// only real once it shows up in `sys.eth_state`, which `peregrine read` can
/// confirm. That split is deliberate: an RPC front door must never be the thing
/// deciding what consensus accepts.
async fn run_submit_claim(args: SubmitClaimArgs, cfg: Config) -> Result<()> {
    let bytes = std::fs::read(&args.file)
        .with_context(|| format!("read claim from {}", args.file.display()))?;
    if bytes.len() > peregrine_sdk::protocol::MAX_CLAIM_BYTES {
        anyhow::bail!(
            "claim is {} bytes, over the {} byte limit the node will accept",
            bytes.len(),
            peregrine_sdk::protocol::MAX_CLAIM_BYTES
        );
    }
    let claim: peregrine_sdk::VerifiedClaim =
        serde_json::from_slice(&bytes).context("parse claim JSON")?;

    let j = &claim.journal;
    println!("claim  : chain {} block {}", j.chain_id, j.block_number);
    println!(
        "proof  : {}",
        if claim.proof.is_zk() {
            "ZK"
        } else {
            "native (will be REFUSED by a strict node)"
        }
    );

    let addr = args.rpc_addr.unwrap_or(cfg.node.rpc_addr);
    let client = connect(addr).await?;
    client.submit_claim(claim).await.context("submit claim")?;

    println!("queued for verification at {addr}");
    println!(
        "(consensus verifies it — read it back with `peregrine read` to confirm it was accepted)"
    );
    Ok(())
}

async fn run_read(args: ReadArgs, cfg: Config) -> Result<()> {
    let table = parse_table(&args.table)?;
    let key = parse_key(&args.key)?;
    let addr = args.rpc_addr.unwrap_or(cfg.node.rpc_addr);

    let client = connect(addr).await?;

    let Some(read) = client.prove_read(table, &key).await? else {
        println!("(absent)");
        return Ok(());
    };
    let root = client.store_root().await?;

    // Never print a value we haven't verified: the whole point of a proven
    // read is that the node's word alone isn't good enough.
    if !read.verify(&root) {
        anyhow::bail!("PROOF FAILED to verify against store root {root} — do not trust this value");
    }
    println!("value  : 0x{}", hex::encode(&read.value));
    if read.value.len() >= 8 {
        let le = u64::from_le_bytes(read.value[..8].try_into().expect("checked len"));
        println!("as u64 : {le}");
    }
    println!("root   : {root}");
    println!("proof  : ✓ verified locally");
    Ok(())
}

/// Connect to a node, with an error that says what to check.
async fn connect(addr: SocketAddr) -> Result<Client> {
    Client::connect(addr)
        .await
        .with_context(|| format!("connect to node at {addr} (is `peregrine node run` up?)"))
}

fn run_config(cmd: ConfigCmd, cfg: &Config, source: Option<&std::path::Path>) -> Result<()> {
    match cmd {
        ConfigCmd::Init { path, force } => {
            if path.exists() && !force {
                anyhow::bail!(
                    "{} already exists (pass --force to overwrite)",
                    path.display()
                );
            }
            std::fs::write(&path, config::TEMPLATE)
                .with_context(|| format!("write {}", path.display()))?;
            println!("wrote {}", path.display());
            Ok(())
        }
        ConfigCmd::Show => {
            match source {
                Some(p) => println!("# effective configuration (from {})", p.display()),
                None => println!("# effective configuration (built-in defaults — no config file)"),
            }
            print!("{}", cfg.to_toml()?);
            Ok(())
        }
    }
}

/// Load an ed25519 secret from a keyfile (hex seed, as `keygen` writes).
fn load_secret_key(path: &Path) -> Result<Keypair> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read key file {}", path.display()))?;
    let bytes =
        hex::decode(text.trim()).with_context(|| format!("decode key file {}", path.display()))?;
    let seed: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("{}: key must be 32 bytes", path.display()))?;
    Ok(Keypair::from_bytes(&seed))
}

/// Load `validator-{0..n}.key` from a directory, in committee order.
fn load_validator_keys(dir: &Path, n: usize) -> Result<Vec<Keypair>> {
    (0..n)
        .map(|i| load_secret_key(&dir.join(format!("validator-{i}.key"))))
        .collect()
}

/// Which committee slot a public key occupies, if any. This is how
/// multi-machine mode turns "here is my key" into "I am validator #i" without
/// the operator having to track indices — and how it fails closed when the key
/// belongs to no committee member.
fn committee_index_of(
    committee: &peregrine_core::Committee,
    key: peregrine_core::PublicKey,
) -> Option<u16> {
    use peregrine_core::ValidatorId;
    (0..committee.size())
        .find(|&i| {
            committee
                .validator(ValidatorId(i as u16))
                .map(|v| v.public_key)
                == Some(key)
        })
        .map(|i| i as u16)
}

/// Parse a 64-hex-char public key.
fn parse_pubkey_hex(s: &str) -> Result<peregrine_core::PublicKey> {
    let bytes = hex::decode(s.trim()).context("decode public key hex")?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("public key must be 32 bytes, got {}", bytes.len()))?;
    Ok(peregrine_core::PublicKey(arr))
}

fn run_genesis(cmd: GenesisCmd) -> Result<()> {
    use peregrine_node::genesis::Genesis;
    match cmd {
        GenesisCmd::New(args) => {
            if args.chain_id == 0 {
                anyhow::bail!("--chain-id must be non-zero");
            }
            if args.out.exists() && !args.force {
                anyhow::bail!("{} already exists (pass --force)", args.out.display());
            }
            let (genesis, validators, faucet) =
                Genesis::generate(args.validators, args.chain_id, &args.network, args.faucet);
            genesis.validate()?;

            std::fs::create_dir_all(&args.keys_dir)
                .with_context(|| format!("create {}", args.keys_dir.display()))?;
            std::fs::write(&args.out, genesis.to_toml()?)
                .with_context(|| format!("write {}", args.out.display()))?;
            for (i, kp) in validators.iter().enumerate() {
                let p = args.keys_dir.join(format!("validator-{i}.key"));
                std::fs::write(&p, format!("{}\n", hex::encode(kp.to_bytes())))?;
                restrict_permissions(&p);
            }
            if let Some(f) = &faucet {
                let p = args.keys_dir.join("faucet.key");
                std::fs::write(&p, format!("{}\n", hex::encode(f.to_bytes())))?;
                restrict_permissions(&p);
            }

            println!("genesis written to {}", args.out.display());
            println!("  chain id   : {}", genesis.chain_id);
            println!("  network    : {}", genesis.network);
            println!("  validators : {}", genesis.validators.len());
            println!("  keys       : {}/", args.keys_dir.display());
            if let Some(f) = &faucet {
                println!("  faucet     : {}", hex::encode(f.public().0));
            }
            println!(
                "\nStart it with:\n  peregrine node run --genesis {} --keys-dir {}",
                args.out.display(),
                args.keys_dir.display()
            );
            Ok(())
        }
        GenesisCmd::Show(args) => {
            let g = Genesis::load(&args.path)?;
            println!("chain id   : {}", g.chain_id);
            println!("network    : {}", g.network);
            println!(
                "params     : max_items_per_vertex={}",
                g.params.max_items_per_vertex
            );
            println!("validators : {}", g.validators.len());
            for (i, v) in g.validators.iter().enumerate() {
                println!("  [{i}] stake {:<6} {}", v.stake, v.public_key);
            }
            match &g.faucet {
                Some(f) => println!(
                    "faucet     : {}\n             per_request {}, cooldown {} rounds, lifetime {}",
                    f.authority, f.per_request, f.cooldown_rounds, f.lifetime_cap
                ),
                None => println!("faucet     : none"),
            }
            println!("allocations: {}", g.allocations.len());
            Ok(())
        }
    }
}

async fn run_faucet_drip(args: FaucetDripArgs, cfg: Config) -> Result<()> {
    let faucet = load_secret_key(&args.faucet_key)?;
    let recipient = parse_pubkey_hex(&args.recipient)?;
    let addr = args.rpc_addr.unwrap_or(cfg.node.rpc_addr);
    let client = connect(addr).await?;

    let drip = peregrine_data::faucet::FaucetDrip {
        recipient,
        amount: args.amount,
        nonce: args.nonce,
    };
    client
        .submit_drip(peregrine_data::faucet::SignedDrip::new(&faucet, drip))
        .await
        .context("submit drip")?;
    println!(
        "dripped {} grains to {} (queued)",
        args.amount, args.recipient
    );
    println!(
        "the on-chain per-recipient limits still apply — confirm with the recipient's balance."
    );
    Ok(())
}

async fn run_faucet_serve(args: FaucetServeArgs, cfg: Config) -> Result<()> {
    let faucet = load_secret_key(&args.faucet_key)?;
    let node = args.node.unwrap_or(cfg.node.rpc_addr);
    peregrine_node::faucet_server::serve(peregrine_node::faucet_server::FaucetServerConfig {
        bind: args.bind,
        node,
        faucet,
        amount: args.amount,
        per_ip_cooldown: std::time::Duration::from_secs(args.per_ip_cooldown_secs),
    })
    .await
}

fn run_keygen(args: KeygenArgs) -> Result<()> {
    let keypair = Keypair::generate(&mut rand::rngs::OsRng);
    let secret = hex::encode(keypair.to_bytes());
    let public = hex::encode(keypair.public().0);

    match args.out {
        Some(path) => {
            if path.exists() && !args.force {
                anyhow::bail!(
                    "{} already exists (pass --force to overwrite)",
                    path.display()
                );
            }
            std::fs::write(&path, format!("{secret}\n"))
                .with_context(|| format!("write {}", path.display()))?;
            restrict_permissions(&path);
            println!("public key : {public}");
            println!("secret key : written to {}", path.display());
        }
        None => {
            println!("public key : {public}");
            println!("secret key : {secret}");
            eprintln!(
                "\nwarning: the secret was printed to stdout and is now in your shell history \
                 and scrollback. Use --out <PATH> to write it to a file instead."
            );
        }
    }
    Ok(())
}

/// Best-effort `0600` on the key file. No-op off Unix.
fn restrict_permissions(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

fn init_logging(level: &str) {
    use tracing_subscriber::EnvFilter;
    // RUST_LOG still wins, so the usual Rust reflex works.
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(level))
        .unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}

/// A table name (hashed like `TableId::named`) or a 32-byte hex id.
fn parse_table(s: &str) -> Result<TableId> {
    let hex_body = s.strip_prefix("0x").unwrap_or(s);
    if hex_body.len() == 64 && hex_body.chars().all(|c| c.is_ascii_hexdigit()) {
        let bytes = hex::decode(hex_body).context("decode table id")?;
        let mut id = [0u8; 32];
        id.copy_from_slice(&bytes);
        return Ok(TableId(peregrine_core::Hash(id)));
    }
    Ok(TableId::named(s))
}

/// A UTF-8 key, or `hex:`-prefixed raw bytes for binary keys.
fn parse_key(s: &str) -> Result<Vec<u8>> {
    match s.strip_prefix("hex:") {
        Some(h) => hex::decode(h).context("decode hex key"),
        None => Ok(s.as_bytes().to_vec()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        // Catches conflicting flags, duplicate names, bad defaults at test time
        // rather than when a user runs the command.
        Cli::command().debug_assert();
    }

    #[test]
    fn table_accepts_names_and_hex_ids() {
        let named = parse_table("contract.answers").unwrap();
        assert_eq!(named, TableId::named("contract.answers"));
        // A hex id round-trips to the same table.
        let hex_form = hex::encode(named.0 .0);
        assert_eq!(parse_table(&hex_form).unwrap(), named);
        assert_eq!(parse_table(&format!("0x{hex_form}")).unwrap(), named);
    }

    #[test]
    fn key_accepts_utf8_and_hex() {
        assert_eq!(parse_key("sum").unwrap(), b"sum".to_vec());
        assert_eq!(parse_key("hex:0a0b").unwrap(), vec![0x0a, 0x0b]);
        assert!(parse_key("hex:zz").is_err());
    }

    /// Multi-machine mode resolves "my key" → "my committee index", and a key
    /// that isn't a committee member resolves to nothing (→ fail closed).
    #[test]
    fn committee_index_matches_the_owning_key_and_rejects_strangers() {
        use peregrine_core::Keypair;
        let (genesis, keys, _) =
            peregrine_node::genesis::Genesis::generate(3, 42, "idx-test", false);
        let committee = genesis.committee().unwrap();

        // Each generated key maps to its own distinct slot, in order.
        for (i, kp) in keys.iter().enumerate() {
            assert_eq!(committee_index_of(&committee, kp.public()), Some(i as u16));
        }
        // A key nobody put in the committee has no slot.
        let stranger = Keypair::from_bytes(&[7u8; 32]);
        assert_eq!(committee_index_of(&committee, stranger.public()), None);
    }
}
