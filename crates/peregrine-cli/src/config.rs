//! Configuration: TOML file + defaults + CLI overrides.
//!
//! ## Layering
//! Lowest precedence wins first:
//!
//! 1. **defaults** — every field has one, so the CLI works with no config at
//!    all;
//! 2. **file** — `--config <path>`, else `$PEREGRINE_CONFIG`, else
//!    `./peregrine.toml` if it exists;
//! 3. **flags** — anything passed explicitly on the command line.
//!
//! Every table and key is optional in the file: partial configs are merged
//! over the defaults rather than replacing them, so you only write what you
//! want to change.
//!
//! ## Validation
//! [`Config::validate`] runs before anything starts, so misconfiguration fails
//! immediately with a message that says what to do — never as a confusing
//! runtime failure ten seconds in.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// Config file consulted when `--config` is not given.
pub const DEFAULT_CONFIG_FILE: &str = "peregrine.toml";
/// Environment variable holding a config path.
pub const CONFIG_ENV: &str = "PEREGRINE_CONFIG";

/// The whole configuration tree.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub node: NodeConfig,
    pub storage: StorageConfig,
    pub logging: LoggingConfig,
    pub sim: SimConfig,
    pub bench: BenchConfig,
}

/// A locally-run validator network and its client-facing endpoint.
///
/// Two launch modes share this table:
///
/// * **local (default)** — one process runs the whole `validators`-member
///   committee, meshed in-process. Nothing below `stream` is set.
/// * **multi-machine** — set [`identity_key`](Self::identity_key),
///   [`listen_addr`](Self::listen_addr), [`peers`](Self::peers), and
///   [`genesis`](Self::genesis), and the process runs as the single committee
///   member its key identifies, peering with the listed addresses over QUIC.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct NodeConfig {
    /// Validators in the committee (local mode only; multi-machine takes the
    /// committee from `genesis`).
    pub validators: u16,
    /// Address the client RPC listener binds (port 0 = OS-assigned).
    pub rpc_addr: SocketAddr,
    /// Payload items batched into each proposal.
    pub max_items_per_vertex: usize,
    /// Stream pre-registered on every validator at genesis.
    pub stream: String,

    // --- multi-machine mode (all four required together) ---
    /// Path to this node's ed25519 key (hex seed, as written by
    /// `peregrine keygen --out`). Setting this switches the process into
    /// multi-machine mode: it runs as the one committee member whose public key
    /// this file holds, and **fails closed** if that key is not in the
    /// committee.
    pub identity_key: Option<PathBuf>,
    /// QUIC/UDP address this node binds for the validator mesh — the address the
    /// other validators dial (e.g. `0.0.0.0:9100`). Required in multi-machine
    /// mode; distinct from `rpc_addr`, the client endpoint.
    pub listen_addr: Option<SocketAddr>,
    /// The other validators' `listen_addr`s, in committee (genesis) index order,
    /// **skipping this node**. Order matters — ancestor sync is addressed by
    /// committee index. Required in multi-machine mode.
    pub peers: Vec<SocketAddr>,
    /// The shared `genesis.toml` every validator agrees on — the ordered
    /// validator public keys + stakes, chain id, faucet, and allocations.
    /// Required in multi-machine mode; also usable in local mode to launch from
    /// a genesis. `--genesis` on the command line overrides it.
    pub genesis: Option<PathBuf>,
}

impl NodeConfig {
    /// True when any multi-machine field is set — i.e. the operator is asking
    /// for the distributed launch path rather than the local all-in-one one.
    pub fn is_multi_machine(&self) -> bool {
        self.identity_key.is_some() || self.listen_addr.is_some() || !self.peers.is_empty()
    }
}

/// Where committed state is persisted.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct StorageConfig {
    /// Directory for per-validator redb files. Unset = keep everything in
    /// memory (state is lost on exit).
    pub path: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingConfig {
    /// `tracing` filter: `error` | `warn` | `info` | `debug` | `trace`, or a
    /// full directive like `peregrine_node=debug,quinn=warn`.
    pub level: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SimConfig {
    pub validators: u16,
    /// Signed stream records to publish.
    pub ticks: u64,
    pub max_items_per_vertex: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct BenchConfig {
    pub validators: u16,
    pub duration_secs: u64,
    /// Total records/sec across all publishers; `0` = flood as fast as possible.
    pub rate: u64,
    /// `quic` (real sockets) or `inproc` (in-process channels).
    pub transport: String,
    pub items_per_vertex: usize,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            validators: 4,
            rpc_addr: "127.0.0.1:9000".parse().expect("valid default addr"),
            max_items_per_vertex: 512,
            stream: peregrine_node::devnet::DEMO_STREAM.to_string(),
            identity_key: None,
            listen_addr: None,
            peers: Vec::new(),
            genesis: None,
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".into(),
        }
    }
}

impl Default for SimConfig {
    fn default() -> Self {
        Self {
            validators: 4,
            ticks: 5_000,
            max_items_per_vertex: 512,
        }
    }
}

impl Default for BenchConfig {
    fn default() -> Self {
        Self {
            validators: 4,
            duration_secs: 5,
            rate: 0,
            transport: "quic".into(),
            items_per_vertex: 512,
        }
    }
}

impl Config {
    /// Resolve the config file to read, honouring `--config`, then
    /// `$PEREGRINE_CONFIG`, then `./peregrine.toml` if it exists.
    pub fn resolve_path(explicit: Option<&Path>) -> Option<PathBuf> {
        if let Some(p) = explicit {
            return Some(p.to_path_buf());
        }
        if let Some(p) = std::env::var_os(CONFIG_ENV) {
            return Some(PathBuf::from(p));
        }
        let default = PathBuf::from(DEFAULT_CONFIG_FILE);
        default.exists().then_some(default)
    }

    /// Load configuration, layering a file (if any) over the defaults.
    ///
    /// An explicitly-requested file that does not exist is an error; the
    /// implicit `./peregrine.toml` simply falls back to defaults when absent.
    pub fn load(explicit: Option<&Path>) -> Result<(Self, Option<PathBuf>)> {
        let Some(path) = Self::resolve_path(explicit) else {
            return Ok((Self::default(), None));
        };
        if !path.exists() {
            if explicit.is_some() || std::env::var_os(CONFIG_ENV).is_some() {
                bail!("config file not found: {}", path.display());
            }
            return Ok((Self::default(), None));
        }
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("read config {}", path.display()))?;
        // `deny_unknown_fields` turns a typo'd key into an error naming the
        // key, rather than silently ignoring the setting you thought you set.
        let cfg: Config =
            toml::from_str(&text).with_context(|| format!("parse config {}", path.display()))?;
        Ok((cfg, Some(path)))
    }

    /// Reject configurations that cannot work, and warn about ones that will
    /// work but probably aren't what you want.
    pub fn validate(&self) -> Result<()> {
        // Multi-machine mode is opt-in and all-or-nothing: setting one of its
        // fields without the others is almost always a half-finished config, so
        // fail closed with the specific missing piece rather than silently
        // falling back to a local committee that ignores what was set.
        if self.node.is_multi_machine() {
            if self.node.identity_key.is_none() {
                bail!(
                    "node.listen_addr / node.peers are set, but node.identity_key is not. \
                     Multi-machine mode needs this node's key file to know which committee member \
                     it is. Set node.identity_key = \"path/to/validator.key\" (from `peregrine \
                     keygen --out`), or remove listen_addr/peers to run the local committee."
                );
            }
            if self.node.listen_addr.is_none() {
                bail!(
                    "node.identity_key is set (multi-machine mode) but node.listen_addr is not. \
                     Set the QUIC/UDP address other validators dial, e.g. \"0.0.0.0:9100\"."
                );
            }
            if self.node.peers.is_empty() {
                bail!(
                    "node.identity_key is set (multi-machine mode) but node.peers is empty. \
                     List the other validators' listen addresses in committee-index order. \
                     A single-node committee cannot reach quorum and makes no progress."
                );
            }
            if self.node.genesis.is_none() {
                bail!(
                    "multi-machine mode needs the shared committee: set node.genesis to the \
                     genesis.toml every validator agrees on (or pass --genesis)."
                );
            }
            if self.node.listen_addr == self.node.rpc_addr.into() {
                bail!(
                    "node.listen_addr and node.rpc_addr are the same address ({}). The mesh \
                     (validator↔validator) and the RPC (client→node) are different listeners and \
                     must not share a port.",
                    self.node.rpc_addr
                );
            }
            // The mesh + genesis define the committee, so `validators` is unused
            // here; skip the local-committee sizing checks below.
            if self.node.max_items_per_vertex == 0 {
                bail!("node.max_items_per_vertex must be at least 1");
            }
            if self.logging.level.trim().is_empty() {
                bail!("logging.level must not be empty (try \"info\")");
            }
            return Ok(());
        }

        // A lone validator's own proposal self-delivers instantly, so it
        // re-proposes in a hot loop with no network round-trip to pace it —
        // it burns a core and grows the DAG without bound.
        for (label, n) in [
            ("node", self.node.validators),
            ("sim", self.sim.validators),
            ("bench", self.bench.validators),
        ] {
            if n < 2 {
                bail!(
                    "{label}.validators = {n}: need at least 2. A lone validator's own proposal \
                     self-delivers instantly, so it re-proposes in a hot loop with nothing to \
                     pace it. Use 4 for a fault-tolerant committee."
                );
            }
        }
        if self.node.validators < 4 {
            tracing::warn!(
                validators = self.node.validators,
                "committee smaller than 4 tolerates no faults (BFT needs 3f+1); fine for local \
                 experiments, not for anything else"
            );
        }
        if self.node.max_items_per_vertex == 0 || self.sim.max_items_per_vertex == 0 {
            bail!("max_items_per_vertex must be at least 1");
        }
        if self.bench.items_per_vertex == 0 {
            bail!("bench.items_per_vertex must be at least 1");
        }
        if self.sim.ticks == 0 {
            bail!("sim.ticks must be at least 1");
        }
        if self.bench.duration_secs == 0 {
            bail!("bench.duration_secs must be at least 1");
        }
        if !matches!(self.bench.transport.as_str(), "quic" | "inproc") {
            bail!(
                "bench.transport = {:?}: expected \"quic\" (real sockets) or \"inproc\"",
                self.bench.transport
            );
        }
        if self.logging.level.trim().is_empty() {
            bail!("logging.level must not be empty (try \"info\")");
        }
        Ok(())
    }

    /// Serialize back to TOML — used by `peregrine config show`.
    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self).context("serialize config")
    }
}

/// A commented starter file, written by `peregrine config init`.
pub const TEMPLATE: &str = r#"# Peregrine configuration.
#
# Every key is optional: what you omit falls back to the built-in default, and
# command-line flags override whatever is here. Check the effective result with
#   peregrine config show

[node]
# Validators in the local committee. Must be >= 2 (a lone validator hot-loops,
# because its own proposal self-delivers with no round-trip to pace it).
validators = 4
# Client-facing RPC listener. Port 0 lets the OS choose.
rpc_addr = "127.0.0.1:9000"
# Payload items batched into each proposal.
max_items_per_vertex = 512
# Stream pre-registered on every validator at genesis.
stream = "devnet/demo"

# --- Multi-machine mode (one process = one committee member) ---------------
# Uncomment all four to run this host as a single validator that peers with the
# others over QUIC. The committee (ordered public keys + stakes) comes from the
# shared genesis.toml; this host contributes exactly the key below.
#
# Bootstrap (do this once, together):
#   1. Every operator runs `peregrine keygen --out validator.key` and shares
#      the printed PUBLIC key.
#   2. One operator writes those public keys (in an agreed order) into a shared
#      genesis.toml — `peregrine genesis new --validators N ...` scaffolds one,
#      or edit the [[validators]] list by hand. Distribute that same file to
#      every host.
#   3. On each host, point `genesis` at that file, `identity_key` at this host's
#      own key, and list the OTHER validators' listen addresses in `peers`, in
#      the same committee order, skipping yourself.
#
# genesis      = "genesis.toml"
# identity_key = "validator.key"
# listen_addr  = "0.0.0.0:9100"          # what your peers dial (mesh, not RPC)
# peers        = ["10.0.0.2:9100", "10.0.0.3:9100"]  # others, committee order

[storage]
# Directory for per-validator redb files. Comment this out to run purely in
# memory (state is lost on exit).
path = "./peregrine-data"

[logging]
# error | warn | info | debug | trace, or a directive like
# "peregrine_node=debug,quinn=warn".
level = "info"

[sim]
validators = 4
ticks = 5000
max_items_per_vertex = 512

[bench]
validators = 4
duration_secs = 5
# Total records/sec across all publishers; 0 = flood as fast as possible.
rate = 0
# "quic" (real sockets) or "inproc" (isolates consensus cost from the network).
transport = "quic"
items_per_vertex = 512
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        Config::default()
            .validate()
            .expect("shipped defaults must be usable");
    }

    #[test]
    fn template_parses_and_validates() {
        let cfg: Config = toml::from_str(TEMPLATE).expect("template parses");
        cfg.validate().expect("template is valid");
        // The template should agree with the defaults it documents.
        assert_eq!(cfg.node.validators, Config::default().node.validators);
        assert_eq!(cfg.bench.transport, Config::default().bench.transport);
    }

    #[test]
    fn partial_config_merges_over_defaults() {
        let cfg: Config = toml::from_str("[node]\nvalidators = 7\n").expect("parses");
        assert_eq!(cfg.node.validators, 7); // from file
        assert_eq!(cfg.node.max_items_per_vertex, 512); // from defaults
        assert_eq!(cfg.sim.ticks, 5_000); // whole table defaulted
    }

    #[test]
    fn round_trips_through_toml() {
        let cfg = Config::default();
        let reparsed: Config = toml::from_str(&cfg.to_toml().unwrap()).unwrap();
        assert_eq!(reparsed.node.rpc_addr, cfg.node.rpc_addr);
        assert_eq!(reparsed.logging.level, cfg.logging.level);
    }

    #[test]
    fn rejects_single_validator_with_an_explanation() {
        let mut cfg = Config::default();
        cfg.node.validators = 1;
        let err = cfg.validate().unwrap_err().to_string();
        assert!(
            err.contains("at least 2"),
            "message should say what to do: {err}"
        );
    }

    #[test]
    fn rejects_unknown_keys() {
        // A typo must fail loudly rather than being silently ignored.
        let err = toml::from_str::<Config>("[node]\nvalidatorz = 4\n")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("validatorz"),
            "error should name the bad key: {err}"
        );
    }

    /// A fully-specified multi-machine config parses and validates.
    #[test]
    fn accepts_complete_multi_machine_config() {
        let cfg: Config = toml::from_str(
            r#"
            [node]
            genesis      = "genesis.toml"
            identity_key = "validator.key"
            listen_addr  = "0.0.0.0:9100"
            peers        = ["10.0.0.2:9100", "10.0.0.3:9100"]
            rpc_addr     = "0.0.0.0:9000"
            "#,
        )
        .expect("parses");
        assert!(cfg.node.is_multi_machine());
        cfg.validate()
            .expect("complete multi-machine config is valid");
    }

    /// Each missing piece of a multi-machine config fails closed, naming it.
    #[test]
    fn multi_machine_fails_closed_on_missing_pieces() {
        let base = r#"
            [node]
            genesis      = "genesis.toml"
            identity_key = "validator.key"
            listen_addr  = "0.0.0.0:9100"
            peers        = ["10.0.0.2:9100"]
        "#;
        // Sanity: the base is valid.
        toml::from_str::<Config>(base).unwrap().validate().unwrap();

        // listen_addr/peers without identity_key.
        let err = toml::from_str::<Config>(
            "[node]\nlisten_addr = \"0.0.0.0:9100\"\npeers = [\"10.0.0.2:9100\"]\n",
        )
        .unwrap()
        .validate()
        .unwrap_err()
        .to_string();
        assert!(err.contains("identity_key"), "got: {err}");

        // identity_key without listen_addr.
        let err = toml::from_str::<Config>(
            "[node]\ngenesis = \"g.toml\"\nidentity_key = \"v.key\"\npeers = [\"10.0.0.2:9100\"]\n",
        )
        .unwrap()
        .validate()
        .unwrap_err()
        .to_string();
        assert!(err.contains("listen_addr"), "got: {err}");

        // identity_key without peers.
        let err = toml::from_str::<Config>(
            "[node]\ngenesis = \"g.toml\"\nidentity_key = \"v.key\"\nlisten_addr = \"0.0.0.0:9100\"\n",
        )
        .unwrap()
        .validate()
        .unwrap_err()
        .to_string();
        assert!(err.contains("peers"), "got: {err}");

        // identity_key without genesis (no shared committee).
        let err = toml::from_str::<Config>(
            "[node]\nidentity_key = \"v.key\"\nlisten_addr = \"0.0.0.0:9100\"\npeers = [\"10.0.0.2:9100\"]\n",
        )
        .unwrap()
        .validate()
        .unwrap_err()
        .to_string();
        assert!(err.contains("genesis"), "got: {err}");
    }

    /// The mesh and the RPC must not share a port.
    #[test]
    fn multi_machine_rejects_listen_equal_rpc() {
        let err = toml::from_str::<Config>(
            r#"
            [node]
            genesis      = "g.toml"
            identity_key = "v.key"
            listen_addr  = "0.0.0.0:9100"
            rpc_addr     = "0.0.0.0:9100"
            peers        = ["10.0.0.2:9100"]
            "#,
        )
        .unwrap()
        .validate()
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("same address") || err.contains("share a port"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_bad_transport_and_zero_ticks() {
        let mut cfg = Config::default();
        cfg.bench.transport = "carrier-pigeon".into();
        assert!(cfg.validate().is_err());

        let mut cfg = Config::default();
        cfg.sim.ticks = 0;
        assert!(cfg.validate().is_err());
    }
}
