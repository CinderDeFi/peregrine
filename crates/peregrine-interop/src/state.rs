//! The **Peregrine → Ethereum** direction: proving Peregrine state to the EVM.
//!
//! This is the mirror of [`crate::witness`]. That module proves *Ethereum* state
//! to Peregrine; this one proves *Peregrine* state to a contract on Ethereum,
//! and the same rule governs both: **everything in a witness is
//! attacker-controlled**, so the journal must be *derived* by verification, not
//! copied out of the input.
//!
//! # What the guest proves
//!
//! Two things, in one statement:
//!
//! 1. A stake-weighted quorum of a **specific committee** signed a checkpoint
//!    committing to store root `R` at round `n`.
//! 2. Under that same `R`, `(table, key)` maps to `value`.
//!
//! Both halves matter. Without (1) anyone could invent a root; without (2) the
//! root proves nothing about the value being read. Splitting them across two
//! proofs would let a relayer pair a real checkpoint with a value from a
//! different one, so they are deliberately a single statement over a single
//! root.
//!
//! # Why the committee digest is a public output
//!
//! The guest is *told* which committee to check against — it has no way to know
//! the real validator set. So a proof generated against an attacker's committee
//! is a perfectly valid proof of this program. What makes it distinguishable is
//! that the committee's digest is committed as a **public** value, letting the
//! on-chain verifier pin it. Baking the committee into the ELF instead would
//! work, but it hides the trust root inside a binary nobody reads; this way the
//! contract states it in a public immutable that anyone can check.
//!
//! # Encoding
//!
//! Public values are **ABI-encoded** so Solidity can `abi.decode` them
//! directly. Every field is a static 32-byte word, so the encoding is plain
//! concatenation — written out by hand here rather than pulling an ABI crate
//! into a zkVM guest. `state_journal_abi_fixture` in the tests pins the exact
//! bytes, and the Solidity test decodes that same fixture, so the two sides
//! cannot drift apart silently.

use peregrine_core::{Committee, Hash};
use peregrine_data::tables::{ProvenRead, TableId};
use serde::{Deserialize, Serialize};

use crate::peregrine::{verify_checkpoint, CheckpointError, CommitteeDigest, SignedCheckpoint};

/// Wire encoding of a tree version in the journal.
pub const TREE_VERSION_V1: u64 = 1;
/// Path-compressed tree.
pub const TREE_VERSION_V2: u64 = 2;

/// Which rule a verified read's row proof followed.
fn tree_version_of(read: &ProvenRead) -> u64 {
    match read.row_proof.version() {
        peregrine_data::tables::TreeVersion::V1 => TREE_VERSION_V1,
        peregrine_data::tables::TreeVersion::V2 => TREE_VERSION_V2,
    }
}

/// Number of 32-byte words in an ABI-encoded [`StateJournal`].
pub const STATE_JOURNAL_WORDS: usize = 9;
/// Exact byte length of an ABI-encoded [`StateJournal`].
pub const STATE_JOURNAL_BYTES: usize = STATE_JOURNAL_WORDS * 32;

/// The largest Peregrine value an EVM consumer can represent in one word.
///
/// Longer values are refused rather than hashed or truncated: a truncated value
/// is a *wrong* value that still looks well-formed, which is the worst possible
/// failure for a verifier.
pub const MAX_EVM_VALUE_BYTES: usize = 32;

/// The public statement, mirroring `PeregrineLightClient.Journal` field for
/// field and in the same order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateJournal {
    /// Peregrine network this state belongs to.
    pub chain_id: u64,
    /// Commit round of the checkpoint.
    pub round: u64,
    /// Digest of the committee whose signatures were counted.
    pub committee_digest: Hash,
    /// Table-store root the checkpoint committed to.
    pub store_root: Hash,
    /// Which sparse-Merkle rule `store_root` was computed under.
    ///
    /// Committed publicly so the on-chain client can **pin** it. Without this,
    /// a proof built against the pre-upgrade tree is indistinguishable from one
    /// built against the current tree: both are valid proofs of this program,
    /// over roots that mean different things. Pinning turns a stale-rule proof
    /// into an explicit rejection.
    pub tree_version: u64,
    /// Table the key was read from.
    pub table: TableId,
    /// `blake3(key)` — the key's position in the sparse Merkle tree.
    ///
    /// The raw key is variable-length and the EVM wants a word, so the tree
    /// position is committed instead. A consumer that knows the key can
    /// recompute it; one that does not could not have used the raw bytes
    /// either.
    pub key_hash: Hash,
    /// The value, right-aligned in 32 bytes.
    pub value: [u8; 32],
    /// True length of the value in bytes.
    ///
    /// Without this, `0x01` and `0x0001` are the same word — two distinct
    /// Peregrine values that a consumer could not tell apart.
    pub value_len: u64,
}

/// A verification job: private input to the state guest.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateWitness {
    pub chain_id: u64,
    /// The committee to check signatures against. Untrusted — its *digest* is
    /// published so the consumer can pin it.
    pub committee: CommitteeDigest,
    /// The checkpoint and the signatures attesting to it.
    pub signed: SignedCheckpoint,
    /// An inclusion proof of `(table, key) → value` under the checkpoint root.
    pub read: ProvenRead,
}

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("checkpoint verification failed: {0}")]
    Checkpoint(#[from] CheckpointError),
    #[error("committee is empty")]
    EmptyCommittee,
    #[error("inclusion proof does not verify against the checkpoint's store root")]
    BadInclusionProof,
    #[error("value is {got} bytes; at most {max} can be represented on-chain")]
    ValueTooLong { got: usize, max: usize },
    #[error("malformed journal encoding: {0}")]
    Malformed(String),
}

impl StateWitness {
    /// Run the verification and derive the journal.
    ///
    /// This is *the* program: the guest calls it and commits the result; the
    /// host calls it to check the same statement natively. One implementation,
    /// so the proved statement and the checked statement cannot diverge.
    pub fn verify(&self) -> Result<StateJournal, StateError> {
        if self.committee.validators.is_empty() {
            // A committee with no validators has a quorum threshold of zero, so
            // an empty signature set would "reach quorum". Refuse explicitly
            // rather than relying on the threshold arithmetic to be defensive.
            return Err(StateError::EmptyCommittee);
        }

        // (1) A quorum signed this checkpoint. Every signature is verified
        //     before its stake counts — `verify_checkpoint` guarantees that.
        let committee = self.committee.to_committee();
        verify_checkpoint(&committee, &self.signed)?;

        // (2) The value is under *that* root. Note the root comes from the
        //     checkpoint we just verified, never from the read itself — the
        //     read carries a root field, and trusting it would let a relayer
        //     prove a value under a root nobody signed.
        let store_root = self.signed.checkpoint.store_root;
        if !self.read.verify(&store_root) {
            return Err(StateError::BadInclusionProof);
        }

        // (3) Representable on-chain, or refused.
        if self.read.value.len() > MAX_EVM_VALUE_BYTES {
            return Err(StateError::ValueTooLong {
                got: self.read.value.len(),
                max: MAX_EVM_VALUE_BYTES,
            });
        }
        let mut value = [0u8; 32];
        value[32 - self.read.value.len()..].copy_from_slice(&self.read.value);

        Ok(StateJournal {
            chain_id: self.chain_id,
            round: self.signed.checkpoint.round,
            committee_digest: self.committee.digest(),
            // Derived from the proof we actually verified, never taken as an
            // input. A relayer that could *declare* the version would simply
            // claim whatever the consumer pins, defeating the check.
            tree_version: tree_version_of(&self.read),
            store_root,
            table: self.read.table,
            key_hash: Hash::digest(&self.read.key),
            value,
            value_len: self.read.value.len() as u64,
        })
    }
}

/// ABI-encode a journal for Solidity's `abi.decode(bytes, (Journal))`.
///
/// Every field is static, so the encoding is eight 32-byte words in declaration
/// order with integers right-aligned big-endian. That is exactly what
/// `abi.encode` of an all-static struct produces — there is no offset word for
/// a static tuple, which is the detail worth getting right.
pub fn encode_state_journal(j: &StateJournal) -> Vec<u8> {
    let mut out = Vec::with_capacity(STATE_JOURNAL_BYTES);
    let mut word_u64 = |v: u64| {
        out.extend_from_slice(&[0u8; 24]);
        out.extend_from_slice(&v.to_be_bytes());
    };
    word_u64(j.chain_id);
    word_u64(j.round);
    word_u64(j.tree_version);
    out.extend_from_slice(&j.committee_digest.0);
    out.extend_from_slice(&j.store_root.0);
    out.extend_from_slice(&j.table.0 .0);
    out.extend_from_slice(&j.key_hash.0);
    out.extend_from_slice(&j.value);
    out.extend_from_slice(&[0u8; 24]);
    out.extend_from_slice(&j.value_len.to_be_bytes());
    debug_assert_eq!(out.len(), STATE_JOURNAL_BYTES);
    out
}

/// Decode public values produced by the guest.
///
/// The host reads the statement back out of the proof with this rather than
/// trusting whatever it computed locally.
pub fn decode_state_journal(bytes: &[u8]) -> Result<StateJournal, StateError> {
    if bytes.len() != STATE_JOURNAL_BYTES {
        return Err(StateError::Malformed(format!(
            "expected {STATE_JOURNAL_BYTES} bytes, got {}",
            bytes.len()
        )));
    }
    let word = |i: usize| -> [u8; 32] {
        let mut w = [0u8; 32];
        w.copy_from_slice(&bytes[i * 32..(i + 1) * 32]);
        w
    };
    // A u64 field must be zero above its low 8 bytes. Anything else means the
    // encoder and decoder disagree, and silently masking it off would hide the
    // disagreement instead of reporting it.
    let u64_at = |i: usize| -> Result<u64, StateError> {
        let w = word(i);
        if w[..24].iter().any(|b| *b != 0) {
            return Err(StateError::Malformed(format!("word {i} overflows u64")));
        }
        Ok(u64::from_be_bytes(w[24..].try_into().unwrap()))
    };

    let value_len = u64_at(8)?;
    if value_len as usize > MAX_EVM_VALUE_BYTES {
        return Err(StateError::ValueTooLong {
            got: value_len as usize,
            max: MAX_EVM_VALUE_BYTES,
        });
    }

    Ok(StateJournal {
        chain_id: u64_at(0)?,
        round: u64_at(1)?,
        tree_version: u64_at(2)?,
        committee_digest: Hash(word(3)),
        store_root: Hash(word(4)),
        table: TableId(Hash(word(5))),
        key_hash: Hash(word(6)),
        value: word(7),
        value_len,
    })
}

impl CommitteeDigest {
    /// Materialize the committee this digest describes.
    pub fn to_committee(&self) -> Committee {
        Committee::new(
            self.validators
                .iter()
                .map(|(id, pk, stake)| peregrine_core::ValidatorInfo {
                    id: *id,
                    public_key: *pk,
                    stake: *stake,
                })
                .collect(),
        )
    }
}
