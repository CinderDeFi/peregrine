//! Ethereum verification: block headers and Merkle-Patricia state proofs.
//!
//! Pure functions over bytes — no network, no node, no trust in whoever
//! supplied the witness. This is the code that runs inside the zkVM guest.

pub mod header;
pub mod mpt;

pub use header::{BlockHeader, HeaderChainError};
pub use mpt::MptError;

use crate::zk::B256;

/// Ethereum mainnet.
pub const MAINNET_CHAIN_ID: u64 = 1;

/// keccak256 — Ethereum's hash everywhere (not SHA3-256; the padding differs).
pub fn keccak256(bytes: &[u8]) -> B256 {
    use tiny_keccak::{Hasher, Keccak};
    let mut k = Keccak::v256();
    let mut out = [0u8; 32];
    k.update(bytes);
    k.finalize(&mut out);
    out
}

/// keccak of the empty string — the trie's "nothing here" leaf hash.
pub fn empty_keccak() -> B256 {
    keccak256(&[])
}

/// Root of an empty Merkle-Patricia trie: `keccak(rlp(""))`.
pub fn empty_trie_root() -> B256 {
    keccak256(&[0x80])
}

#[derive(Debug, thiserror::Error)]
pub enum EthError {
    #[error("header: {0}")]
    Header(#[from] HeaderChainError),
    #[error("state proof: {0}")]
    Mpt(#[from] MptError),
    #[error("account is absent from the state trie")]
    AccountAbsent,
    #[error("malformed account RLP: {0}")]
    MalformedAccount(String),
}

/// An Ethereum account as stored in the state trie:
/// `rlp([nonce, balance, storageRoot, codeHash])`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    pub nonce: u64,
    /// Balance as big-endian 32 bytes (u256 without pulling in a bignum dep).
    pub balance_be: [u8; 32],
    pub storage_root: B256,
    pub code_hash: B256,
}

impl Account {
    /// Decode the RLP payload stored at an account's trie leaf.
    pub fn decode(rlp_bytes: &[u8]) -> Result<Self, EthError> {
        let r = rlp::Rlp::new(rlp_bytes);
        if !r.is_list() {
            return Err(EthError::MalformedAccount("expected a 4-item list".into()));
        }
        let item_count = r
            .item_count()
            .map_err(|e| EthError::MalformedAccount(e.to_string()))?;
        if item_count != 4 {
            return Err(EthError::MalformedAccount(format!(
                "expected 4 items, got {item_count}"
            )));
        }
        let nonce: u64 = r
            .val_at(0)
            .map_err(|e| EthError::MalformedAccount(e.to_string()))?;
        let balance: Vec<u8> = r
            .val_at(1)
            .map_err(|e| EthError::MalformedAccount(e.to_string()))?;
        let storage_root: Vec<u8> = r
            .val_at(2)
            .map_err(|e| EthError::MalformedAccount(e.to_string()))?;
        let code_hash: Vec<u8> = r
            .val_at(3)
            .map_err(|e| EthError::MalformedAccount(e.to_string()))?;

        Ok(Account {
            nonce,
            balance_be: left_pad_32(&balance)
                .ok_or_else(|| EthError::MalformedAccount("balance > 32 bytes".into()))?,
            storage_root: to_b256(&storage_root)
                .ok_or_else(|| EthError::MalformedAccount("storageRoot not 32 bytes".into()))?,
            code_hash: to_b256(&code_hash)
                .ok_or_else(|| EthError::MalformedAccount("codeHash not 32 bytes".into()))?,
        })
    }
}

/// Verify an account against a state root, returning its decoded fields.
///
/// The trie is keyed by `keccak(address)`, so the caller cannot choose where in
/// the trie to look — that is what stops a witness from answering for the
/// wrong account.
pub fn verify_account_proof(
    state_root: &B256,
    address: &[u8; 20],
    proof_nodes: &[Vec<u8>],
) -> Result<Account, EthError> {
    let path = keccak256(address);
    match mpt::verify_proof(state_root, &path, proof_nodes)? {
        Some(value) => Ok(Account::decode(&value)?),
        None => Err(EthError::AccountAbsent),
    }
}

/// Verify one storage slot against an account's storage root.
///
/// Returns the 32-byte value; an **absent** slot verifiably reads as zero,
/// which is Ethereum's own semantics — the proof establishes absence just as
/// strongly as presence, so a witness cannot hide a value by omitting it.
pub fn verify_storage_proof(
    storage_root: &B256,
    slot: &B256,
    proof_nodes: &[Vec<u8>],
) -> Result<B256, EthError> {
    let path = keccak256(slot);
    match mpt::verify_proof(storage_root, &path, proof_nodes)? {
        Some(encoded) => {
            // Storage values are stored RLP-encoded with leading zeros stripped.
            let r = rlp::Rlp::new(&encoded);
            let raw: Vec<u8> = r
                .as_val()
                .map_err(|e| EthError::MalformedAccount(format!("storage value: {e}")))?;
            left_pad_32(&raw)
                .ok_or_else(|| EthError::MalformedAccount("storage value > 32 bytes".into()))
        }
        None => Ok([0u8; 32]),
    }
}

fn to_b256(b: &[u8]) -> Option<B256> {
    (b.len() == 32).then(|| {
        let mut out = [0u8; 32];
        out.copy_from_slice(b);
        out
    })
}

/// Right-align `b` into 32 bytes (Ethereum stores integers minimally encoded).
fn left_pad_32(b: &[u8]) -> Option<[u8; 32]> {
    if b.len() > 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out[32 - b.len()..].copy_from_slice(b);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keccak_matches_known_vectors() {
        // The canonical keccak256("") — differs from SHA3-256(""), which is the
        // classic way to get Ethereum hashing subtly wrong.
        assert_eq!(
            hex::encode(empty_keccak()),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
        // keccak256("abc")
        assert_eq!(
            hex::encode(keccak256(b"abc")),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        );
    }

    #[test]
    fn empty_trie_root_is_canonical() {
        assert_eq!(
            hex::encode(empty_trie_root()),
            "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
        );
    }

    #[test]
    fn left_pad_rejects_oversize() {
        assert!(left_pad_32(&[0u8; 33]).is_none());
        assert_eq!(left_pad_32(&[0xff]).unwrap()[31], 0xff);
    }
}
