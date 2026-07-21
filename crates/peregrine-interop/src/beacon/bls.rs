//! BLS12-381 sync-committee signature verification (feature `bls`).
//!
//! This closes the anchoring hole: without it, a light-client update is only
//! *internally consistent*, and a relayer could fabricate one. With it, an
//! anchor requires the endorsement of ≥2/3 of Ethereum's 512-member sync
//! committee.
//!
//! # The scheme, precisely
//!
//! Ethereum consensus uses **`min_pk`**: public keys are compressed G1 points
//! (48 bytes), signatures are compressed G2 points (96 bytes), and messages
//! hash to G2 under the domain separation tag
//! `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`. Getting any of that wrong —
//! swapping the groups, using the plain (non-PoP) DST, hashing the wrong bytes
//! — yields a verifier that rejects everything, or worse, one that accepts.
//! The test suite therefore checks a **real mainnet sync-committee signature**;
//! nothing short of a correct implementation reproduces that pairing.
//!
//! # Why proof-of-possession matters here
//!
//! The `_POP_` DST is not cosmetic. Naive aggregate verification is vulnerable
//! to *rogue-key* attacks: an attacker who can choose a public key as a
//! function of others' keys can forge an aggregate signature. Ethereum defends
//! against this at the deposit boundary — every validator proves possession of
//! its secret key before joining — which is what makes it sound for us to
//! aggregate committee keys and do a single pairing check. We are relying on
//! that protocol-level property, so we use the DST that names it.
//!
//! # Why this is behind a feature flag
//!
//! `blst` compiles C and assembly, so it cannot build inside a zkVM guest. The
//! pure verification core must stay guest-compatible, so BLS lives here and is
//! selected by the node at the host level. A build without `bls` keeps
//! [`super::RejectingBls`] and therefore mints no anchors.

use super::{BeaconError, SyncCommittee, SyncCommitteeVerifier, SYNC_COMMITTEE_SIZE};
use blst::min_pk::{AggregatePublicKey, PublicKey, Signature};
use blst::BLST_ERROR;

/// Ethereum's sync-committee domain separation tag (proof-of-possession variant).
pub const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Verifies sync-committee aggregate signatures with `blst`.
pub struct BlstVerifier {
    committee: SyncCommittee,
}

impl BlstVerifier {
    pub fn new(committee: SyncCommittee) -> Self {
        Self { committee }
    }

    pub fn committee(&self) -> &SyncCommittee {
        &self.committee
    }
}

/// Is bit `i` set? Bitvectors are little-endian *within* each byte.
fn bit_set(bits: &[u8], i: usize) -> bool {
    bits.get(i / 8).is_some_and(|b| (b >> (i % 8)) & 1 == 1)
}

impl SyncCommitteeVerifier for BlstVerifier {
    fn verify_aggregate(
        &self,
        signing_root: &[u8; 32],
        bits: &[u8],
        signature: &[u8],
    ) -> Result<(), BeaconError> {
        // The bitvector must be exactly 512 bits: a longer one could set bits
        // with no corresponding key, and a shorter one silently drops signers.
        if bits.len() != SYNC_COMMITTEE_SIZE / 8 {
            return Err(BeaconError::Malformed(format!(
                "sync committee bits are {} bytes, expected {}",
                bits.len(),
                SYNC_COMMITTEE_SIZE / 8
            )));
        }

        // Select the participants. Deserializing each key validates it is a
        // point on the curve in the correct subgroup.
        let mut participants: Vec<PublicKey> = Vec::with_capacity(SYNC_COMMITTEE_SIZE);
        for (i, raw) in self.committee.pubkeys.iter().enumerate() {
            if bit_set(bits, i) {
                let pk = PublicKey::key_validate(raw).map_err(|e| {
                    BeaconError::BadSignature(format!("committee key {i} is invalid: {e:?}"))
                })?;
                participants.push(pk);
            }
        }
        if participants.is_empty() {
            return Err(BeaconError::BadSignature("no participants".into()));
        }

        let refs: Vec<&PublicKey> = participants.iter().collect();
        let aggregate = AggregatePublicKey::aggregate(&refs, false)
            .map_err(|e| BeaconError::BadSignature(format!("aggregation failed: {e:?}")))?
            .to_public_key();

        let sig = Signature::from_bytes(signature)
            .map_err(|e| BeaconError::BadSignature(format!("malformed signature: {e:?}")))?;

        // Single pairing check over the signing root. `sig_groupcheck` is on:
        // an attacker-supplied signature must be validated as a subgroup
        // element, not just decoded.
        match sig.verify(true, signing_root, DST, &[], &aggregate, true) {
            BLST_ERROR::BLST_SUCCESS => Ok(()),
            e => Err(BeaconError::BadSignature(format!(
                "pairing check failed: {e:?}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_selection_is_little_endian_within_bytes() {
        // bit 0 is the LSB of byte 0; bit 8 is the LSB of byte 1.
        let bits = [0b0000_0001u8, 0b0000_0010];
        assert!(bit_set(&bits, 0));
        assert!(!bit_set(&bits, 1));
        assert!(!bit_set(&bits, 8));
        assert!(bit_set(&bits, 9));
        // Out of range is simply unset, never a panic.
        assert!(!bit_set(&bits, 999));
    }

    #[test]
    fn committee_size_is_enforced() {
        let err = SyncCommittee::from_bytes(vec![[0u8; 48]; 8], [0u8; 48]);
        assert!(matches!(err, Err(BeaconError::Malformed(_))));
    }

    #[test]
    fn wrong_length_bitvector_is_rejected() {
        let committee =
            SyncCommittee::from_bytes(vec![[0u8; 48]; SYNC_COMMITTEE_SIZE], [0u8; 48]).unwrap();
        let v = BlstVerifier::new(committee);
        // 63 bytes instead of 64.
        let err = v.verify_aggregate(&[0u8; 32], &[0xff; 63], &[0u8; 96]);
        assert!(matches!(err, Err(BeaconError::Malformed(_))));
    }

    #[test]
    fn garbage_keys_are_rejected_not_panicked() {
        // All-zero "keys" are not valid curve points; verification must fail
        // cleanly rather than aborting.
        let committee =
            SyncCommittee::from_bytes(vec![[0u8; 48]; SYNC_COMMITTEE_SIZE], [0u8; 48]).unwrap();
        let v = BlstVerifier::new(committee);
        let err = v.verify_aggregate(&[0u8; 32], &[0xff; 64], &[0u8; 96]);
        assert!(matches!(err, Err(BeaconError::BadSignature(_))));
    }
}
