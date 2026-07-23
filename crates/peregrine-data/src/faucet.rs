//! # Testnet faucet — a bounded funding primitive
//!
//! `sys.balances` is otherwise credit-only with no way for an account to start
//! with grains (see [`crate::sessions::balances_table`]). A public testnet needs
//! one, and it must not be drainable. This module is that faucet, with its
//! limits enforced **on-chain** — deterministically, on every validator — so
//! they cannot be bypassed by talking to a permissive node.
//!
//! ## Trust model
//!
//! * **Only the faucet authority can drip.** A drip is signed by the authority
//!   key named in genesis; an unsigned or wrongly-signed one is refused, so
//!   nobody can credit themselves.
//! * **Every recipient is rate-limited, by consensus.** Per drip: an amount cap.
//!   Per recipient: a cooldown between drips and a lifetime cap. These live in
//!   `sys.faucet`, are checked during commit, and are identical on every
//!   validator — a friendly RPC cannot wave them through.
//! * **Fail-closed.** A chain with no faucet configured refuses every drip.
//!
//! A web faucet adds IP-level rate limiting on top, but the guarantees that
//! actually bound token issuance are the ones here.

use crate::tables::TableId;
use peregrine_core::{crypto, PublicKey, Round, Signature};
use serde::{Deserialize, Serialize};

/// Domain tag for a drip signature — never mistakable for any other signed
/// object.
pub const FAUCET_DOMAIN: &[u8] = b"peregrine.faucet.drip.v1";

/// Per-recipient faucet bookkeeping table.
pub fn faucet_table() -> TableId {
    TableId::named("sys.faucet")
}

/// The faucet's policy, fixed in genesis. `authority` is the only key whose
/// drips are honoured.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaucetPolicy {
    pub authority: PublicKey,
    /// Largest single drip.
    pub per_request: u64,
    /// Committed rounds a recipient must wait between drips.
    pub cooldown_rounds: Round,
    /// Total a single recipient may ever receive from the faucet.
    pub lifetime_cap: u64,
}

/// One faucet request: give `recipient` `amount` grains. `nonce` distinguishes
/// otherwise-identical drips so an operator can issue several.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaucetDrip {
    pub recipient: PublicKey,
    pub amount: u64,
    pub nonce: u64,
}

impl FaucetDrip {
    pub fn signing_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("drip serialize")
    }
}

/// A drip plus the authority's signature over it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedDrip {
    pub drip: FaucetDrip,
    pub signature: Signature,
}

impl SignedDrip {
    /// Sign a drip as the faucet authority.
    pub fn new(authority_key: &peregrine_core::Keypair, drip: FaucetDrip) -> Self {
        let signature = authority_key.sign(FAUCET_DOMAIN, &drip.signing_bytes());
        Self { drip, signature }
    }

    /// Check the drip was signed by `authority`.
    pub fn verify(&self, authority: &PublicKey) -> bool {
        crypto::verify(
            authority,
            FAUCET_DOMAIN,
            &self.drip.signing_bytes(),
            &self.signature,
        )
        .is_ok()
    }
}

/// A recipient's committed faucet history, stored at `sys.faucet[recipient]`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DripRecord {
    /// Round of the most recent drip.
    pub last_round: Round,
    /// Total ever received.
    pub total: u64,
    /// Number of drips.
    pub count: u64,
}

impl DripRecord {
    /// Encode: `[last_round:8][total:8][count:8]`.
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(24);
        v.extend_from_slice(&self.last_round.to_le_bytes());
        v.extend_from_slice(&self.total.to_le_bytes());
        v.extend_from_slice(&self.count.to_le_bytes());
        v
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 24 {
            return None;
        }
        Some(Self {
            last_round: u64::from_le_bytes(bytes[0..8].try_into().ok()?),
            total: u64::from_le_bytes(bytes[8..16].try_into().ok()?),
            count: u64::from_le_bytes(bytes[16..24].try_into().ok()?),
        })
    }
}

/// Why a drip was refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FaucetError {
    #[error("no faucet is configured on this chain")]
    NotConfigured,
    #[error("drip is not signed by the faucet authority")]
    BadSignature,
    #[error("amount {amount} exceeds the per-request cap {cap}")]
    ExceedsPerRequest { amount: u64, cap: u64 },
    #[error("recipient dripped at round {last}, cooldown is {cooldown} rounds; now {now}")]
    Cooldown {
        last: Round,
        cooldown: Round,
        now: Round,
    },
    #[error(
        "drip of {amount} would exceed the {cap}-grain lifetime cap ({total} already received)"
    )]
    ExceedsLifetime { amount: u64, total: u64, cap: u64 },
    #[error("amount must be greater than zero")]
    ZeroAmount,
}

impl FaucetPolicy {
    /// **Pure verdict.** Decide whether a drip may proceed against a recipient's
    /// prior [`DripRecord`] at `now`, and if so return the record to write. Does
    /// not check the signature — the caller verifies that against
    /// [`authority`](Self::authority) first, so an unsigned amount never reaches
    /// this policy decision.
    pub fn authorize(
        &self,
        drip: &FaucetDrip,
        prior: Option<DripRecord>,
        now: Round,
    ) -> Result<DripRecord, FaucetError> {
        if drip.amount == 0 {
            return Err(FaucetError::ZeroAmount);
        }
        if drip.amount > self.per_request {
            return Err(FaucetError::ExceedsPerRequest {
                amount: drip.amount,
                cap: self.per_request,
            });
        }
        let prior = prior.unwrap_or_default();
        // A recipient with no prior drips (count 0) is not on cooldown.
        if prior.count > 0 && now.saturating_sub(prior.last_round) < self.cooldown_rounds {
            return Err(FaucetError::Cooldown {
                last: prior.last_round,
                cooldown: self.cooldown_rounds,
                now,
            });
        }
        let new_total = prior.total.saturating_add(drip.amount);
        if new_total > self.lifetime_cap {
            return Err(FaucetError::ExceedsLifetime {
                amount: drip.amount,
                total: prior.total,
                cap: self.lifetime_cap,
            });
        }
        Ok(DripRecord {
            last_round: now,
            total: new_total,
            count: prior.count + 1,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use peregrine_core::Keypair;

    fn policy(auth: PublicKey) -> FaucetPolicy {
        FaucetPolicy {
            authority: auth,
            per_request: 100,
            cooldown_rounds: 10,
            lifetime_cap: 250,
        }
    }

    fn drip(recipient: PublicKey, amount: u64, nonce: u64) -> FaucetDrip {
        FaucetDrip {
            recipient,
            amount,
            nonce,
        }
    }

    #[test]
    fn only_the_authority_can_sign_a_drip() {
        let auth = Keypair::from_bytes(&[1; 32]);
        let impostor = Keypair::from_bytes(&[2; 32]);
        let recipient = Keypair::from_bytes(&[3; 32]).public();
        let signed = SignedDrip::new(&auth, drip(recipient, 50, 0));
        assert!(signed.verify(&auth.public()));

        let mut forged = signed.clone();
        forged.signature = impostor.sign(FAUCET_DOMAIN, &forged.drip.signing_bytes());
        assert!(!forged.verify(&auth.public()));
    }

    #[test]
    fn a_drip_is_capped_per_request() {
        let auth = Keypair::from_bytes(&[1; 32]).public();
        let r = Keypair::from_bytes(&[3; 32]).public();
        assert_eq!(
            policy(auth).authorize(&drip(r, 101, 0), None, 5),
            Err(FaucetError::ExceedsPerRequest {
                amount: 101,
                cap: 100
            })
        );
        assert!(policy(auth).authorize(&drip(r, 100, 0), None, 5).is_ok());
        assert_eq!(
            policy(auth).authorize(&drip(r, 0, 0), None, 5),
            Err(FaucetError::ZeroAmount)
        );
    }

    #[test]
    fn a_recipient_must_wait_out_the_cooldown() {
        let auth = Keypair::from_bytes(&[1; 32]).public();
        let r = Keypair::from_bytes(&[3; 32]).public();
        let p = policy(auth);
        // First drip at round 5.
        let rec = p.authorize(&drip(r, 50, 0), None, 5).unwrap();
        assert_eq!(
            rec,
            DripRecord {
                last_round: 5,
                total: 50,
                count: 1
            }
        );
        // Too soon (5 + 10 = 15 needed).
        assert_eq!(
            p.authorize(&drip(r, 50, 1), Some(rec), 14),
            Err(FaucetError::Cooldown {
                last: 5,
                cooldown: 10,
                now: 14
            })
        );
        // Exactly the cooldown boundary is allowed.
        assert!(p.authorize(&drip(r, 50, 1), Some(rec), 15).is_ok());
    }

    #[test]
    fn a_recipient_cannot_exceed_the_lifetime_cap() {
        let auth = Keypair::from_bytes(&[1; 32]).public();
        let r = Keypair::from_bytes(&[3; 32]).public();
        let p = policy(auth);
        // Already received 220 of a 250 cap.
        let prior = DripRecord {
            last_round: 5,
            total: 220,
            count: 3,
        };
        assert_eq!(
            p.authorize(&drip(r, 50, 4), Some(prior), 100),
            Err(FaucetError::ExceedsLifetime {
                amount: 50,
                total: 220,
                cap: 250
            })
        );
        // 30 fits exactly.
        let rec = p.authorize(&drip(r, 30, 4), Some(prior), 100).unwrap();
        assert_eq!(rec.total, 250);
    }

    #[test]
    fn drip_record_round_trips() {
        let rec = DripRecord {
            last_round: 42,
            total: 100,
            count: 3,
        };
        assert_eq!(DripRecord::decode(&rec.encode()), Some(rec));
        assert_eq!(DripRecord::decode(&[0u8; 5]), None);
    }
}
