//! # peregrine-interop — trust-minimized cross-chain verification
//!
//! Bridges get drained because they are secured by a multisig or a relayer's
//! promise. This crate takes the other route: **every cross-chain fact is
//! re-derived from cryptography the verifier checks itself.** There is no
//! committee to bribe, no relayer to trust, and no privileged key anywhere in
//! this crate — by construction, not by policy.
//!
//! Two directions:
//!
//! * [`eth`] — **reading Ethereum from Peregrine.** Block headers are hashed
//!   canonically (`keccak256(rlp(header))`) and chained by parent hash; account
//!   and storage values are proven by Merkle-Patricia traversal from a state
//!   root. Tested against **real Ethereum mainnet** blocks and `eth_getProof`
//!   witnesses.
//! * [`peregrine`] — **reading Peregrine from elsewhere.** A stake-weighted
//!   quorum signs a checkpoint committing to a store root; a foreign verifier
//!   checks those signatures and then a Merkle proof against that root.
//!
//! Both are **pure functions over bytes** — no async, no I/O, no node access —
//! which is what lets them run unchanged inside a zkVM guest. [`zk`] defines
//! that boundary: the guest does the work above and commits a small
//! [`zk::Journal`], and Peregrine validators check one succinct proof instead
//! of re-executing Ethereum.
//!
//! ## What is real here, and what is not
//!
//! The **verification logic is real and tested against mainnet.** The
//! **proving backend is not wired up**: the only [`zk::Prover`] implementation
//! runs the verification natively and returns a proof that carries no
//! cryptographic argument, clearly marked ([`zk::Proof::is_zk`] returns
//! `false`, and [`zk::StrictVerifier`] rejects it). Nothing in this crate
//! claims ZK security it does not have. Wiring SP1 or RISC Zero replaces the
//! backend without touching a line of verification code — that is the whole
//! point of keeping this crate pure.

pub mod beacon;
pub mod eth;
pub mod peregrine;
pub mod sp1_backend;
pub mod witness;
pub mod zk;

pub use eth::{verify_account_proof, verify_storage_proof, Account, BlockHeader, EthError};
pub use peregrine::{verify_checkpoint, Checkpoint, SignedCheckpoint};
pub use witness::Witness;
pub use zk::{Claim, Journal, Proof, Prover, VerifiedClaim, Verifier, ZkError};

#[cfg(feature = "sp1")]
pub use sp1_backend::{Sp1Mode, Sp1Prover, Sp1Verifier};

use eth::header::verify_header_chain;

/// Verify a chain of Ethereum headers and produce the journal committing to it.
///
/// `trusted_anchor` is the caller's independently-known hash of `headers[0]`.
/// Passing `None` verifies only that the chain is internally consistent, which
/// is *not* enough to know it is canonical — see [`eth::header::verify_header_chain`].
pub fn verify_eth_headers(
    chain_id: u64,
    headers: &[BlockHeader],
    trusted_anchor: Option<zk::B256>,
) -> Result<Journal, EthError> {
    if let Some(anchor) = trusted_anchor {
        let first = headers
            .first()
            .ok_or(EthError::Header(eth::HeaderChainError::Empty))?;
        if first.hash()? != anchor {
            return Err(EthError::Header(eth::HeaderChainError::BrokenLink {
                index: 0,
            }));
        }
    }
    let (from, to, tip) = verify_header_chain(headers)?;
    let last = headers
        .last()
        .expect("non-empty: verify_header_chain checked");
    Ok(Journal {
        chain_id,
        block_number: to,
        block_hash: tip,
        state_root: last.state_root,
        claim: Claim::HeaderChain {
            from_block: from,
            to_block: to,
        },
    })
}

/// Verify an Ethereum storage slot against a **header**, producing a journal.
///
/// Taking the header (rather than a bare state root) is deliberate: the state
/// root is read *out of the verified header*, so a witness cannot supply a
/// state root of its choosing alongside a matching proof.
pub fn verify_eth_storage(
    chain_id: u64,
    header: &BlockHeader,
    address: &[u8; 20],
    account_proof: &[Vec<u8>],
    slot: &zk::B256,
    storage_proof: &[Vec<u8>],
) -> Result<Journal, EthError> {
    let block_hash = header.hash()?;
    let account = verify_account_proof(&header.state_root, address, account_proof)?;
    let value = verify_storage_proof(&account.storage_root, slot, storage_proof)?;
    Ok(Journal {
        chain_id,
        block_number: header.number,
        block_hash,
        state_root: header.state_root,
        claim: Claim::Storage {
            address: *address,
            slot: *slot,
            value,
        },
    })
}
