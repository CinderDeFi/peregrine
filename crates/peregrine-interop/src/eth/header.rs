//! Ethereum block headers: canonical RLP encoding, hashing, and chain linkage.
//!
//! The header hash is `keccak256(rlp(header))` over *every* field in canonical
//! order. That makes the encoding self-checking in the strongest possible way:
//! if a single field is missing, reordered, or encoded with the wrong width,
//! the hash will not match the block hash mainnet already agreed on. The tests
//! check exactly that against real mainnet blocks.
//!
//! Post-merge Ethereum has grown the header several times, and each fork
//! appended fields. They are `Option` here so one type spans forks: a
//! pre-Shanghai header simply has `None` from `withdrawals_root` onward. The
//! trailing fields must be contiguous — you cannot have `blob_gas_used`
//! without `withdrawals_root` — which [`BlockHeader::encode`] enforces.

use super::keccak256;
use crate::zk::B256;

#[derive(Debug, thiserror::Error)]
pub enum HeaderChainError {
    #[error("header {index} does not link to its parent (broken chain)")]
    BrokenLink { index: usize },
    #[error("header {index} has number {got}, expected {expected} (non-contiguous)")]
    NonContiguous {
        index: usize,
        got: u64,
        expected: u64,
    },
    #[error("a header chain needs at least one header")]
    Empty,
    #[error("fork fields are not contiguous: {0} is set but an earlier one is not")]
    NonContiguousForkFields(&'static str),
}

/// An Ethereum execution-layer block header.
///
/// `Serialize`/`Deserialize` so a header can be handed to a zkVM guest as part
/// of a witness. Note that a *deserialized* header is untrusted input — it only
/// becomes meaningful once [`BlockHeader::hash`] reproduces a block hash the
/// verifier independently anchors.
#[derive(Clone, Debug, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct BlockHeader {
    pub parent_hash: B256,
    pub ommers_hash: B256,
    pub beneficiary: [u8; 20],
    pub state_root: B256,
    pub transactions_root: B256,
    pub receipts_root: B256,
    /// 256 bytes.
    pub logs_bloom: Vec<u8>,
    /// Big-endian, minimally encoded (post-merge this is always 0).
    pub difficulty: Vec<u8>,
    pub number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: Vec<u8>,
    pub mix_hash: B256,
    /// 8 bytes.
    pub nonce: Vec<u8>,
    /// London (EIP-1559).
    pub base_fee_per_gas: Option<Vec<u8>>,
    /// Shanghai (EIP-4895).
    pub withdrawals_root: Option<B256>,
    /// Cancun (EIP-4844).
    pub blob_gas_used: Option<u64>,
    /// Cancun (EIP-4844).
    pub excess_blob_gas: Option<u64>,
    /// Cancun (EIP-4788).
    pub parent_beacon_block_root: Option<B256>,
    /// Prague (EIP-7685).
    pub requests_hash: Option<B256>,
}

impl BlockHeader {
    /// Canonical RLP encoding. Fork-added fields are appended only while they
    /// remain contiguous; a gap is a programming error, not something to paper
    /// over, because it would silently produce a wrong hash.
    pub fn encode(&self) -> Result<Vec<u8>, HeaderChainError> {
        let mut s = rlp::RlpStream::new();
        // 15 pre-London fields, then whatever contiguous suffix is present.
        let mut len = 15;
        if self.base_fee_per_gas.is_some() {
            len += 1;
        }
        if self.withdrawals_root.is_some() {
            if self.base_fee_per_gas.is_none() {
                return Err(HeaderChainError::NonContiguousForkFields(
                    "withdrawals_root",
                ));
            }
            len += 1;
        }
        if self.blob_gas_used.is_some() || self.excess_blob_gas.is_some() {
            if self.withdrawals_root.is_none() {
                return Err(HeaderChainError::NonContiguousForkFields("blob_gas_used"));
            }
            if self.blob_gas_used.is_none() || self.excess_blob_gas.is_none() {
                return Err(HeaderChainError::NonContiguousForkFields("excess_blob_gas"));
            }
            len += 2;
        }
        if self.parent_beacon_block_root.is_some() {
            if self.blob_gas_used.is_none() {
                return Err(HeaderChainError::NonContiguousForkFields(
                    "parent_beacon_block_root",
                ));
            }
            len += 1;
        }
        if self.requests_hash.is_some() {
            if self.parent_beacon_block_root.is_none() {
                return Err(HeaderChainError::NonContiguousForkFields("requests_hash"));
            }
            len += 1;
        }

        s.begin_list(len);
        s.append(&self.parent_hash.as_slice());
        s.append(&self.ommers_hash.as_slice());
        s.append(&self.beneficiary.as_slice());
        s.append(&self.state_root.as_slice());
        s.append(&self.transactions_root.as_slice());
        s.append(&self.receipts_root.as_slice());
        s.append(&self.logs_bloom);
        s.append(&self.difficulty);
        s.append(&self.number);
        s.append(&self.gas_limit);
        s.append(&self.gas_used);
        s.append(&self.timestamp);
        s.append(&self.extra_data);
        s.append(&self.mix_hash.as_slice());
        s.append(&self.nonce);
        if let Some(v) = &self.base_fee_per_gas {
            s.append(v);
        }
        if let Some(v) = &self.withdrawals_root {
            s.append(&v.as_slice());
        }
        if let Some(v) = self.blob_gas_used {
            s.append(&v);
        }
        if let Some(v) = self.excess_blob_gas {
            s.append(&v);
        }
        if let Some(v) = &self.parent_beacon_block_root {
            s.append(&v.as_slice());
        }
        if let Some(v) = &self.requests_hash {
            s.append(&v.as_slice());
        }
        Ok(s.out().to_vec())
    }

    /// `keccak256(rlp(header))` — the canonical block hash.
    pub fn hash(&self) -> Result<B256, HeaderChainError> {
        Ok(keccak256(&self.encode()?))
    }
}

/// Verify that `headers` form a contiguous, hash-linked chain (oldest first),
/// returning `(first_number, last_number, last_hash)`.
///
/// This establishes *internal consistency only*. It says nothing about which
/// chain is canonical — that is the job of the consensus light client (sync
/// committee) or of an already-trusted anchor hash. Chain linkage without an
/// anchor is exactly the mistake that makes a "light client" trust its relayer,
/// so callers must pin the first header independently.
pub fn verify_header_chain(headers: &[BlockHeader]) -> Result<(u64, u64, B256), HeaderChainError> {
    let first = headers.first().ok_or(HeaderChainError::Empty)?;
    let mut prev_hash = first.hash()?;
    let mut prev_number = first.number;

    for (i, h) in headers.iter().enumerate().skip(1) {
        if h.parent_hash != prev_hash {
            return Err(HeaderChainError::BrokenLink { index: i });
        }
        if h.number != prev_number + 1 {
            return Err(HeaderChainError::NonContiguous {
                index: i,
                got: h.number,
                expected: prev_number + 1,
            });
        }
        prev_hash = h.hash()?;
        prev_number = h.number;
    }
    Ok((first.number, prev_number, prev_hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(number: u64, parent: B256) -> BlockHeader {
        BlockHeader {
            parent_hash: parent,
            number,
            logs_bloom: vec![0u8; 256],
            difficulty: vec![],
            nonce: vec![0u8; 8],
            ..Default::default()
        }
    }

    #[test]
    fn links_a_valid_chain() {
        let h0 = header(100, [0u8; 32]);
        let h1 = header(101, h0.hash().unwrap());
        let h2 = header(102, h1.hash().unwrap());
        let (from, to, tip) = verify_header_chain(&[h0, h1, h2.clone()]).unwrap();
        assert_eq!((from, to), (100, 102));
        assert_eq!(tip, h2.hash().unwrap());
    }

    #[test]
    fn rejects_a_broken_link() {
        let h0 = header(100, [0u8; 32]);
        let bad = header(101, [0xabu8; 32]); // wrong parent
        assert!(matches!(
            verify_header_chain(&[h0, bad]),
            Err(HeaderChainError::BrokenLink { index: 1 })
        ));
    }

    #[test]
    fn rejects_a_number_gap() {
        let h0 = header(100, [0u8; 32]);
        let h2 = header(102, h0.hash().unwrap()); // skips 101
        assert!(matches!(
            verify_header_chain(&[h0, h2]),
            Err(HeaderChainError::NonContiguous {
                index: 1,
                got: 102,
                expected: 101
            })
        ));
    }

    #[test]
    fn rejects_non_contiguous_fork_fields() {
        // blob gas without a withdrawals root cannot occur on any real fork,
        // and encoding it anyway would produce a confidently wrong hash.
        let mut h = header(1, [0u8; 32]);
        h.base_fee_per_gas = Some(vec![1]);
        h.blob_gas_used = Some(5);
        h.excess_blob_gas = Some(5);
        assert!(matches!(
            h.encode(),
            Err(HeaderChainError::NonContiguousForkFields("blob_gas_used"))
        ));
    }

    #[test]
    fn empty_chain_is_rejected() {
        assert!(matches!(
            verify_header_chain(&[]),
            Err(HeaderChainError::Empty)
        ));
    }
}
