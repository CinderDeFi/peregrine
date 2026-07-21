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
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct NodeConfig {
    /// Validators in the committee.
    pub validators: u16,
    /// Address the client RPC listener binds (port 0 = OS-assigned).
    pub rpc_addr: SocketAddr,
    /// Payload items batched into each proposal.
    pub max_items_per_vertex: usize,
    /// Stream pre-registered on every validator at genesis.
    pub stream: String,
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
