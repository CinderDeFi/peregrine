//! The reciprocal direction: what *another* chain verifies about Peregrine.
//!
//! Ethereum or Solana should be able to check Peregrine state with the same
//! standard Peregrine applies to them — no multisig, no trusted relayer. The
//! statement a foreign verifier checks is deliberately small:
//!
//! > *A quorum of Peregrine's committee, by stake, signed a checkpoint
//! > committing to store root R at round N — and value V is in the table
//! > store under R.*
//!
//! Two independent halves, which is what keeps the trust assumption legible:
//!
//! 1. **Consensus** ([`verify_checkpoint`]) — stake-weighted signature
//!    verification against a known committee. This is the part a foreign chain
//!    must trust Peregrine's validator set for.
//! 2. **State** ([`peregrine_data::tables::ProvenRead::verify`]) — a Merkle
//!    inclusion proof against that root, which needs no trust at all.
//!
//! Verifying 512 ed25519 signatures on Ethereum L1 is prohibitively expensive,
//! which is exactly why this is written as a pure function: it is the guest
//! program for a zkVM proof, so the L1 contract verifies one succinct proof
//! instead. The same code serves a native verifier off-chain.
//!
//! **Status:** the checkpoint/quorum logic below is real and tested. What is
//! *not* here yet: a committee-rotation rule (a foreign verifier currently has
//! to be told the committee out of band), and the on-chain verifier contracts.
//! Both are called out in the README rather than stubbed with something that
//! looks finished.

use peregrine_core::{crypto, Committee, Hash, PublicKey, Signature, ValidatorId};
use serde::{Deserialize, Serialize};

/// Domain tag — a checkpoint signature must never be mistakable for a vertex
/// signature, or a validator could be tricked into signing one as the other.
pub const CHECKPOINT_DOMAIN: &[u8] = b"peregrine.checkpoint.v1";

/// What a validator signs to attest to committed state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Commit round this checkpoint attests to.
    pub round: u64,
    /// The 32-byte table-store root at that round.
    pub store_root: Hash,
}

impl Checkpoint {
    /// Exact bytes covered by a signature.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(40);
        out.extend_from_slice(&self.round.to_be_bytes());
        out.extend_from_slice(&self.store_root.0);
        out
    }
}

/// A checkpoint plus the validator signatures attesting to it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedCheckpoint {
    pub checkpoint: Checkpoint,
    /// `(validator, signature)` pairs. Order is irrelevant; duplicates are
    /// rejected so one validator cannot be counted twice toward quorum.
    pub signatures: Vec<(ValidatorId, Signature)>,
}

#[derive(Debug, thiserror::Error)]
pub enum CheckpointError {
    #[error("validator {0:?} is not in the committee")]
    UnknownValidator(ValidatorId),
    #[error("duplicate signature from validator {0:?}")]
    DuplicateValidator(ValidatorId),
    #[error("invalid signature from validator {0:?}")]
    BadSignature(ValidatorId),
    #[error("insufficient stake: {got} of {needed} required")]
    InsufficientStake { got: u64, needed: u64 },
}

/// Verify that a quorum of `committee`, weighted by stake, signed `checkpoint`.
///
/// Returns the stake that actually signed. Every signature is checked before
/// it counts — tallying stake from unverified signatures would let anyone mint
/// a checkpoint by listing validator ids.
pub fn verify_checkpoint(
    committee: &Committee,
    signed: &SignedCheckpoint,
) -> Result<u64, CheckpointError> {
    let msg = signed.checkpoint.signing_bytes();
    let mut seen: Vec<ValidatorId> = Vec::with_capacity(signed.signatures.len());
    let mut stake = 0u64;

    for (id, sig) in &signed.signatures {
        if seen.contains(id) {
            return Err(CheckpointError::DuplicateValidator(*id));
        }
        let info = committee
            .validator(*id)
            .ok_or(CheckpointError::UnknownValidator(*id))?;
        crypto::verify(&info.public_key, CHECKPOINT_DOMAIN, &msg, sig)
            .map_err(|_| CheckpointError::BadSignature(*id))?;
        seen.push(*id);
        stake = stake.saturating_add(info.stake);
    }

    let needed = committee.quorum_threshold();
    if stake < needed {
        return Err(CheckpointError::InsufficientStake { got: stake, needed });
    }
    Ok(stake)
}

/// Sign a checkpoint (validator side).
pub fn sign_checkpoint(keypair: &peregrine_core::Keypair, checkpoint: &Checkpoint) -> Signature {
    keypair.sign(CHECKPOINT_DOMAIN, &checkpoint.signing_bytes())
}

/// The committee a foreign verifier must know to check Peregrine checkpoints.
///
/// Rotation is the open problem: today this is supplied out of band. A
/// production design proves each committee transition from the previous one,
/// so a foreign chain follows the validator set with a single trusted genesis.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitteeDigest {
    pub epoch: u64,
    pub validators: Vec<(ValidatorId, PublicKey, u64)>,
}

impl CommitteeDigest {
    /// A stable 32-byte commitment a foreign chain can store cheaply.
    pub fn digest(&self) -> Hash {
        let mut buf = Vec::with_capacity(8 + self.validators.len() * 42);
        buf.extend_from_slice(&self.epoch.to_be_bytes());
        // Sorted by id so the digest is order-independent.
        let mut vs = self.validators.clone();
        vs.sort_by_key(|(id, _, _)| id.0);
        for (id, pk, stake) in &vs {
            buf.extend_from_slice(&id.0.to_be_bytes());
            buf.extend_from_slice(&pk.0);
            buf.extend_from_slice(&stake.to_be_bytes());
        }
        Hash::digest(&buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use peregrine_core::{Keypair, ValidatorInfo};

    fn committee(n: u16) -> (Committee, Vec<Keypair>) {
        let mut rng = rand::rngs::OsRng;
        let kps: Vec<Keypair> = (0..n).map(|_| Keypair::generate(&mut rng)).collect();
        let c = Committee::new(
            kps.iter()
                .enumerate()
                .map(|(i, kp)| ValidatorInfo {
                    id: ValidatorId(i as u16),
                    public_key: kp.public(),
                    stake: 100,
                })
                .collect(),
        );
        (c, kps)
    }

    fn checkpoint() -> Checkpoint {
        Checkpoint {
            round: 7,
            store_root: Hash::digest(b"state"),
        }
    }

    fn sign_with(kps: &[Keypair], idxs: &[usize], cp: &Checkpoint) -> SignedCheckpoint {
        SignedCheckpoint {
            checkpoint: *cp,
            signatures: idxs
                .iter()
                .map(|&i| (ValidatorId(i as u16), sign_checkpoint(&kps[i], cp)))
                .collect(),
        }
    }

    #[test]
    fn quorum_of_signatures_verifies() {
        let (c, kps) = committee(4);
        let cp = checkpoint();
        let stake = verify_checkpoint(&c, &sign_with(&kps, &[0, 1, 2], &cp)).unwrap();
        assert_eq!(stake, 300);
    }

    #[test]
    fn below_quorum_is_rejected() {
        let (c, kps) = committee(4);
        let cp = checkpoint();
        // 2 of 4 = 200 stake, below the 267 threshold.
        assert!(matches!(
            verify_checkpoint(&c, &sign_with(&kps, &[0, 1], &cp)),
            Err(CheckpointError::InsufficientStake { .. })
        ));
    }

    #[test]
    fn duplicate_validator_cannot_inflate_stake() {
        let (c, kps) = committee(4);
        let cp = checkpoint();
        let mut s = sign_with(&kps, &[0, 1], &cp);
        // Replay validator 0 to fake a third signer.
        s.signatures
            .push((ValidatorId(0), sign_checkpoint(&kps[0], &cp)));
        assert!(matches!(
            verify_checkpoint(&c, &s),
            Err(CheckpointError::DuplicateValidator(_))
        ));
    }

    #[test]
    fn signature_over_a_different_root_is_rejected() {
        let (c, kps) = committee(4);
        let cp = checkpoint();
        let mut s = sign_with(&kps, &[0, 1, 2], &cp);
        // Same signatures, but claim a different store root.
        s.checkpoint.store_root = Hash::digest(b"attacker state");
        assert!(matches!(
            verify_checkpoint(&c, &s),
            Err(CheckpointError::BadSignature(_))
        ));
    }

    #[test]
    fn unknown_validator_is_rejected() {
        let (c, kps) = committee(4);
        let cp = checkpoint();
        let mut s = sign_with(&kps, &[0, 1, 2], &cp);
        s.signatures
            .push((ValidatorId(99), sign_checkpoint(&kps[0], &cp)));
        assert!(matches!(
            verify_checkpoint(&c, &s),
            Err(CheckpointError::UnknownValidator(_))
        ));
    }

    #[test]
    fn committee_digest_is_order_independent() {
        let (c, _) = committee(4);
        let mut vs: Vec<_> = (0..4u16)
            .map(|i| {
                let v = c.validator(ValidatorId(i)).unwrap();
                (v.id, v.public_key, v.stake)
            })
            .collect();
        let a = CommitteeDigest {
            epoch: 1,
            validators: vs.clone(),
        };
        vs.reverse();
        let b = CommitteeDigest {
            epoch: 1,
            validators: vs,
        };
        assert_eq!(a.digest(), b.digest());
    }
}
