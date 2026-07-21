//! The guest ⇄ host contract: private witnesses in, public [`Journal`] out.
//!
//! # The one rule that makes this sound
//!
//! **Everything in a witness is attacker-controlled.** A witness is whatever a
//! relayer handed us; none of it is trusted. The [`Journal`] must therefore be
//! *derived* from the witness by verification, never *copied* out of it — which
//! is why [`Witness::verify`] returns a journal built from values the
//! verification itself recomputed (the block hash it hashed, the state root it
//! read out of that header) rather than any field the submitter supplied.
//!
//! Keeping that derivation in **one function called by both the guest and the
//! host** is deliberate. If the guest proved one statement and the host's
//! native path checked a subtly different one, the difference would be exactly
//! the kind of gap that turns into an exploit. There is one implementation.
//!
//! # What a proof does and does not establish
//!
//! A valid proof over a [`Journal`] says: *"someone ran this exact program on
//! some witness, and the verification succeeded."* It says **nothing** about
//! whether the block is canonical on Ethereum. Anchoring is the consumer's job
//! (see [`crate::zk::StrictVerifier`] and the README): pin `block_hash`
//! against a finalized head you obtained independently, or the whole thing
//! reduces to trusting the relayer that built the witness.

use crate::eth::{self, BlockHeader, EthError};
use crate::zk::{Claim, Journal, B256};
use serde::{Deserialize, Serialize};

/// A verification job: private input to the guest.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Witness {
    /// Prove a contiguous, hash-linked run of Ethereum headers.
    HeaderChain {
        chain_id: u64,
        headers: Vec<BlockHeader>,
        /// Optional caller-pinned hash of `headers[0]`. Supplying it moves the
        /// anchoring check *inside* the proof; omitting it means the proof
        /// attests only to internal consistency.
        trusted_anchor: Option<B256>,
    },
    /// Prove one Ethereum storage slot under a header's state root.
    EthStorage {
        chain_id: u64,
        header: BlockHeader,
        address: [u8; 20],
        account_proof: Vec<Vec<u8>>,
        slot: B256,
        storage_proof: Vec<Vec<u8>>,
    },
    /// Prove an Ethereum account's fields under a header's state root.
    EthAccount {
        chain_id: u64,
        header: BlockHeader,
        address: [u8; 20],
        account_proof: Vec<Vec<u8>>,
    },
}

impl Witness {
    /// Run the verification and derive the journal.
    ///
    /// This is *the* program: the guest calls it and commits the result; the
    /// host calls it to check a claim natively. Same code, same statement.
    pub fn verify(&self) -> Result<Journal, EthError> {
        match self {
            Witness::HeaderChain {
                chain_id,
                headers,
                trusted_anchor,
            } => crate::verify_eth_headers(*chain_id, headers, *trusted_anchor),
            Witness::EthStorage {
                chain_id,
                header,
                address,
                account_proof,
                slot,
                storage_proof,
            } => crate::verify_eth_storage(
                *chain_id,
                header,
                address,
                account_proof,
                slot,
                storage_proof,
            ),
            Witness::EthAccount {
                chain_id,
                header,
                address,
                account_proof,
            } => {
                // The block hash is recomputed here, not taken on faith, and the
                // state root is read out of that verified header.
                let block_hash = header.hash()?;
                let account =
                    eth::verify_account_proof(&header.state_root, address, account_proof)?;
                Ok(Journal {
                    chain_id: *chain_id,
                    block_number: header.number,
                    block_hash,
                    state_root: header.state_root,
                    claim: Claim::Account {
                        address: *address,
                        nonce: account.nonce,
                        balance_be: account.balance_be,
                        storage_root: account.storage_root,
                        code_hash: account.code_hash,
                    },
                })
            }
        }
    }

    /// Chain this witness refers to, available without running verification.
    pub fn chain_id(&self) -> u64 {
        match self {
            Witness::HeaderChain { chain_id, .. }
            | Witness::EthStorage { chain_id, .. }
            | Witness::EthAccount { chain_id, .. } => *chain_id,
        }
    }
}

/// Canonical byte encoding of a journal, used as the proof's public values.
///
/// Host and guest must agree byte-for-byte, or a proof's public values will
/// not match the journal the consumer thinks it is checking.
pub fn encode_journal(journal: &Journal) -> Vec<u8> {
    bincode::serialize(journal).expect("journal is infallibly serializable")
}

/// Decode public values back into a journal.
pub fn decode_journal(bytes: &[u8]) -> Result<Journal, String> {
    bincode::deserialize(bytes).map_err(|e| format!("malformed journal: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_encoding_round_trips() {
        let j = Journal {
            chain_id: 1,
            block_number: 9,
            block_hash: [3u8; 32],
            state_root: [4u8; 32],
            claim: Claim::HeaderChain {
                from_block: 8,
                to_block: 9,
            },
        };
        assert_eq!(decode_journal(&encode_journal(&j)).unwrap(), j);
    }

    #[test]
    fn decoding_rejects_garbage() {
        assert!(decode_journal(b"not a journal").is_err());
    }

    #[test]
    fn witness_exposes_chain_id_without_verifying() {
        let w = Witness::HeaderChain {
            chain_id: 7,
            headers: vec![],
            trusted_anchor: None,
        };
        assert_eq!(w.chain_id(), 7);
        // An empty chain must still fail verification rather than produce a
        // journal about nothing.
        assert!(w.verify().is_err());
    }
}
