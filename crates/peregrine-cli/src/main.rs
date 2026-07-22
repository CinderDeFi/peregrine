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
use std::path::PathBuf;
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
        // Handled synchronously in `main`.
        Command::Config(_) | Command::Keygen(_) => unreachable!(),
    }
}

async fn run_node(args: NodeRunArgs, cfg: Config) -> Result<()> {
    let storage = if args.in_memory {
        None
    } else {
        args.storage.or(cfg.storage.path.clone())
    };

    let opts = DevnetOptions {
        validators: args.validators.unwrap_or(cfg.node.validators),
        rpc_addr: args.rpc_addr.unwrap_or(cfg.node.rpc_addr),
        max_items_per_vertex: cfg.node.max_items_per_vertex,
        stream: cfg.node.stream.clone(),
        storage: storage.clone(),
    };

    let devnet = Devnet::launch(opts).await.context("launch node")?;
    println!("peregrine node running");
    println!(
        "  validators : {}",
        args.validators.unwrap_or(cfg.node.validators)
    );
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
}
