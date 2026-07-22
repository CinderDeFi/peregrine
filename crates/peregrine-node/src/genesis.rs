//! Testnet genesis — the shared, human-editable description of a network.
//!
//! A `genesis.toml` fixes everything validators must agree on before the first
//! block: the **chain id**, the **validator set** and their stake, the network
//! parameters, an optional **faucet** authority and its limits, and any initial
//! balance **allocations**. Operators distribute the same file; each validator
//! loads it plus its own secret key.
//!
//! ```toml
//! chain_id = 424242
//! network  = "peregrine-testnet-1"
//!
//! [params]
//! max_items_per_vertex = 512
//!
//! [[validators]]
//! public_key = "…64 hex chars…"
//! stake = 100
//!
//! [faucet]
//! authority = "…64 hex…"
//! per_request = 1000
//! cooldown_rounds = 100
//! lifetime_cap = 10000
//!
//! [[allocations]]
//! account = "…64 hex…"
//! grains = 1000000
//! ```

use anyhow::{bail, Context, Result};
use peregrine_core::{Committee, Keypair, PublicKey, ValidatorId, ValidatorInfo};
use peregrine_data::faucet::FaucetPolicy;
use serde::{Deserialize, Serialize};
use std::path::Path;

fn hex_to_pubkey(s: &str) -> Result<PublicKey> {
    let bytes = hex::decode(s.trim()).with_context(|| format!("bad hex public key {s:?}"))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("public key must be 32 bytes, got {}", bytes.len()))?;
    Ok(PublicKey(arr))
}

/// A validator in the genesis set.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenesisValidator {
    /// 32-byte ed25519 public key, hex-encoded.
    pub public_key: String,
    /// Voting power.
    pub stake: u64,
}

/// The genesis faucet authority and its limits.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenesisFaucet {
    /// The only key whose drips are honoured (hex).
    pub authority: String,
    pub per_request: u64,
    pub cooldown_rounds: u64,
    pub lifetime_cap: u64,
}

/// An initial balance allocation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenesisAllocation {
    /// Recipient public key (hex).
    pub account: String,
    pub grains: u64,
}

/// Network parameters that are consensus-relevant and belong in genesis.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GenesisParams {
    pub max_items_per_vertex: usize,
    /// Round at which the store migrates to the v2 Merkle rule, or unset to stay
    /// on v1 (a coordinated upgrade — every validator must carry the same value).
    pub merkle_v2_activation_round: Option<u64>,
}

impl Default for GenesisParams {
    fn default() -> Self {
        Self {
            max_items_per_vertex: 512,
            merkle_v2_activation_round: None,
        }
    }
}

/// A whole genesis file.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Genesis {
    /// The network's chain id — carried in every committed checkpoint and pinned
    /// by the EVM light client, so a proof of this chain can't pass as another's.
    pub chain_id: u64,
    /// Human-readable network name.
    pub network: String,
    #[serde(default)]
    pub params: GenesisParams,
    pub validators: Vec<GenesisValidator>,
    #[serde(default)]
    pub faucet: Option<GenesisFaucet>,
    #[serde(default)]
    pub allocations: Vec<GenesisAllocation>,
}

impl Genesis {
    /// Generate a fresh testnet genesis and the secret keys behind it: one
    /// keypair per validator, and a faucet keypair if requested. The caller
    /// writes the secrets to keyfiles; the genesis holds only public keys.
    pub fn generate(
        n_validators: u16,
        chain_id: u64,
        network: &str,
        with_faucet: bool,
    ) -> (Self, Vec<Keypair>, Option<Keypair>) {
        let mut rng = rand::rngs::OsRng;
        let validators: Vec<Keypair> = (0..n_validators).map(|_| Keypair::generate(&mut rng)).collect();
        let faucet_kp = with_faucet.then(|| Keypair::generate(&mut rng));
        let genesis = Genesis {
            chain_id,
            network: network.to_string(),
            params: GenesisParams::default(),
            validators: validators
                .iter()
                .map(|kp| GenesisValidator {
                    public_key: hex::encode(kp.public().0),
                    stake: 100,
                })
                .collect(),
            // Sensible public-testnet defaults: a small per-request drip, a
            // cooldown so one address can't loop the faucet, and a lifetime cap.
            faucet: faucet_kp.as_ref().map(|kp| GenesisFaucet {
                authority: hex::encode(kp.public().0),
                per_request: 1_000,
                cooldown_rounds: 100,
                lifetime_cap: 10_000,
            }),
            allocations: Vec::new(),
        };
        (genesis, validators, faucet_kp)
    }

    /// Reject a genesis that cannot start a network.
    pub fn validate(&self) -> Result<()> {
        if self.chain_id == 0 {
            bail!("chain_id must be non-zero");
        }
        if self.network.trim().is_empty() {
            bail!("network name must not be empty");
        }
        if self.validators.len() < 2 {
            bail!(
                "a network needs at least 2 validators (a lone validator hot-loops); use 4 for \
                 fault tolerance"
            );
        }
        for v in &self.validators {
            hex_to_pubkey(&v.public_key)?;
            if v.stake == 0 {
                bail!("validator stake must be greater than 0");
            }
        }
        if self.params.max_items_per_vertex == 0 {
            bail!("params.max_items_per_vertex must be at least 1");
        }
        if let Some(f) = &self.faucet {
            hex_to_pubkey(&f.authority)?;
            if f.per_request == 0 || f.lifetime_cap == 0 {
                bail!("faucet per_request and lifetime_cap must be greater than 0");
            }
            if f.per_request > f.lifetime_cap {
                bail!("faucet per_request cannot exceed lifetime_cap");
            }
        }
        for a in &self.allocations {
            hex_to_pubkey(&a.account)?;
        }
        Ok(())
    }

    /// The stake-weighted committee this genesis defines.
    pub fn committee(&self) -> Result<Committee> {
        let infos: Result<Vec<ValidatorInfo>> = self
            .validators
            .iter()
            .enumerate()
            .map(|(i, v)| {
                Ok(ValidatorInfo {
                    id: ValidatorId(i as u16),
                    public_key: hex_to_pubkey(&v.public_key)?,
                    stake: v.stake,
                })
            })
            .collect();
        Ok(Committee::new(infos?))
    }

    /// The faucet policy, if a faucet is configured.
    pub fn faucet_policy(&self) -> Result<Option<FaucetPolicy>> {
        self.faucet
            .as_ref()
            .map(|f| {
                Ok(FaucetPolicy {
                    authority: hex_to_pubkey(&f.authority)?,
                    per_request: f.per_request,
                    cooldown_rounds: f.cooldown_rounds,
                    lifetime_cap: f.lifetime_cap,
                })
            })
            .transpose()
    }

    /// Initial `(account, grains)` allocations to credit at genesis.
    pub fn allocations(&self) -> Result<Vec<(PublicKey, u64)>> {
        self.allocations
            .iter()
            .map(|a| Ok((hex_to_pubkey(&a.account)?, a.grains)))
            .collect()
    }

    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self).context("serialize genesis")
    }

    /// Parse and validate a genesis from TOML text.
    pub fn from_toml(text: &str) -> Result<Self> {
        let g: Genesis = toml::from_str(text).context("parse genesis")?;
        g.validate()?;
        Ok(g)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read genesis {}", path.display()))?;
        Self::from_toml(&text)
    }

    /// Pair loaded validator **secret** keys with this genesis, in order,
    /// producing the runtime bundle a devnet launches from. Verifies that each
    /// key matches the genesis validator at its index, so a keys/genesis
    /// mismatch fails loudly rather than silently forming the wrong committee.
    pub fn runtime(&self, validator_keys: Vec<Keypair>) -> Result<GenesisRuntime> {
        if validator_keys.len() != self.validators.len() {
            bail!(
                "genesis lists {} validators but {} keys were provided",
                self.validators.len(),
                validator_keys.len()
            );
        }
        let mut validators = Vec::with_capacity(validator_keys.len());
        for (i, kp) in validator_keys.into_iter().enumerate() {
            let expected = hex_to_pubkey(&self.validators[i].public_key)?;
            if kp.public() != expected {
                bail!("validator key {i} does not match the genesis public key at that index");
            }
            validators.push((kp, self.validators[i].stake));
        }
        Ok(GenesisRuntime {
            chain_id: self.chain_id,
            max_items_per_vertex: self.params.max_items_per_vertex,
            faucet: self.faucet_policy()?,
            allocations: self.allocations()?,
            validators,
        })
    }
}

/// Everything a devnet needs to launch a network from genesis: the validator
/// keypairs (with stake), the chain id, the faucet policy, and the initial
/// balance allocations.
pub struct GenesisRuntime {
    pub chain_id: u64,
    pub max_items_per_vertex: usize,
    pub faucet: Option<FaucetPolicy>,
    pub allocations: Vec<(PublicKey, u64)>,
    /// `(keypair, stake)` per validator, in committee order.
    pub validators: Vec<(Keypair, u64)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_round_trips_through_toml_and_builds_a_committee() {
        let (g, keys, faucet) = Genesis::generate(4, 424242, "peregrine-testnet-1", true);
        assert_eq!(keys.len(), 4);
        assert!(faucet.is_some());

        let toml = g.to_toml().unwrap();
        let reparsed = Genesis::from_toml(&toml).unwrap();
        assert_eq!(reparsed.chain_id, 424242);
        assert_eq!(reparsed.validators.len(), 4);

        // The committee is stake-weighted and quorum math works.
        let committee = reparsed.committee().unwrap();
        assert_eq!(committee.total_stake(), 400);

        // The faucet authority matches the generated key.
        let policy = reparsed.faucet_policy().unwrap().unwrap();
        assert_eq!(policy.authority, faucet.unwrap().public());
    }

    #[test]
    fn validation_rejects_bad_genesis() {
        let (mut g, ..) = Genesis::generate(4, 1, "t", false);
        g.chain_id = 0;
        assert!(g.validate().is_err());

        let (mut g, ..) = Genesis::generate(1.max(2), 1, "t", false);
        g.validators.truncate(1);
        assert!(g.validate().is_err(), "one validator is refused");

        let (mut g, ..) = Genesis::generate(2, 1, "t", true);
        g.faucet.as_mut().unwrap().per_request = 0;
        assert!(g.validate().is_err());
    }

    #[test]
    fn allocations_parse_to_typed_keys() {
        let (mut g, keys, _) = Genesis::generate(2, 1, "t", false);
        g.allocations.push(GenesisAllocation {
            account: hex::encode(keys[0].public().0),
            grains: 5_000,
        });
        let allocs = g.allocations().unwrap();
        assert_eq!(allocs, vec![(keys[0].public(), 5_000)]);
    }
}
