//! Validator committee: identities, stake weights, and quorum math.
//!
//! Bootstrap model: static committee fixed at genesis. The interface is
//! written against *stake*, not node-count, so the later move to epochless
//! dynamic membership (design doc §4.2) changes construction, not callers.

use crate::crypto::PublicKey;
use serde::{Deserialize, Serialize};

/// Dense index of a validator inside the current committee.
/// Cheap to copy, cheap to use as an array index in hot paths.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ValidatorId(pub u16);

impl std::fmt::Debug for ValidatorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "v{}", self.0)
    }
}

/// Public information about a single validator.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorInfo {
    pub id: ValidatorId,
    pub public_key: PublicKey,
    /// Voting power. Bootstrap: equal stake. Production: delegated stake
    /// weighted by proven serving capacity (bandwidth-weighted proposing).
    pub stake: u64,
}

/// The active validator set with quorum arithmetic.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Committee {
    validators: Vec<ValidatorInfo>,
    total_stake: u64,
}

impl Committee {
    pub fn new(validators: Vec<ValidatorInfo>) -> Self {
        let total_stake = validators.iter().map(|v| v.stake).sum();
        Self {
            validators,
            total_stake,
        }
    }

    pub fn size(&self) -> usize {
        self.validators.len()
    }

    pub fn total_stake(&self) -> u64 {
        self.total_stake
    }

    /// Stake threshold for a BFT quorum: > 2/3 of total stake.
    pub fn quorum_threshold(&self) -> u64 {
        (self.total_stake * 2) / 3 + 1
    }

    /// Stake threshold proving at least one honest participant: > 1/3.
    pub fn validity_threshold(&self) -> u64 {
        self.total_stake / 3 + 1
    }

    pub fn validator(&self, id: ValidatorId) -> Option<&ValidatorInfo> {
        self.validators.get(id.0 as usize)
    }

    pub fn iter(&self) -> impl Iterator<Item = &ValidatorInfo> {
        self.validators.iter()
    }

    /// Sum the stake of a set of validators (deduplication is the caller's
    /// responsibility — consensus structures guarantee it by construction).
    pub fn stake_of<'a>(&self, ids: impl Iterator<Item = &'a ValidatorId>) -> u64 {
        ids.filter_map(|id| self.validator(*id))
            .map(|v| v.stake)
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn committee(n: u16) -> Committee {
        Committee::new(
            (0..n)
                .map(|i| ValidatorInfo {
                    id: ValidatorId(i),
                    public_key: PublicKey([i as u8; 32]),
                    stake: 100,
                })
                .collect(),
        )
    }

    #[test]
    fn quorum_math() {
        let c = committee(4); // total 400
        assert_eq!(c.quorum_threshold(), 267); // > 2/3 of 400
        assert_eq!(c.validity_threshold(), 134); // > 1/3 of 400
    }
}
