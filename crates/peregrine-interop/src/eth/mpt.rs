//! Merkle-Patricia Trie proof verification.
//!
//! This is the heart of trust-minimized Ethereum state reading, and the place
//! where a sloppy implementation quietly becomes a bridge exploit. The rules
//! it enforces, and why each one matters:
//!
//! * **Every node is addressed by its own hash.** We walk from the root
//!   downward, and at each step the node we are handed must hash to the value
//!   the *parent* pointed at. A witness therefore cannot substitute a node.
//! * **The path is not the witness's to choose.** The key is `keccak(address)`
//!   (or `keccak(slot)`), consumed nibble by nibble as we descend. A proof for
//!   a different key cannot be replayed for this one.
//! * **Absence is proven, not assumed.** Reaching a point where the path
//!   diverges — an empty branch child, or a leaf/extension whose remaining
//!   nibbles disagree — is a *positive* proof that the key is absent. Running
//!   out of nodes, by contrast, proves nothing and is an error.
//! * **Nothing is left over.** A leaf must consume exactly the remaining path.
//!
//! Node encodings (all RLP):
//! * **branch** — 17 items: 16 child slots (hash or empty) + an optional value;
//! * **extension** — 2 items: `[compact(shared nibbles), child]`;
//! * **leaf** — 2 items: `[compact(remaining nibbles), value]`.
//!
//! Extension and leaf are distinguished by the high nibble of their
//! compact-encoded path (the "hex-prefix" encoding), which also records whether
//! the nibble count was odd.

use super::keccak256;
use crate::zk::B256;

#[derive(Debug, thiserror::Error)]
pub enum MptError {
    #[error("proof is empty")]
    EmptyProof,
    #[error("node {index} does not hash to the value its parent points at")]
    HashMismatch { index: usize },
    #[error("malformed node at {index}: {reason}")]
    MalformedNode { index: usize, reason: String },
    #[error("proof ended before the path was resolved (truncated witness)")]
    ProofTruncated,
    #[error("path not fully consumed at a leaf")]
    TrailingPath,
    #[error("invalid hex-prefix encoding: {0}")]
    BadHexPrefix(String),
}

/// Verify a Merkle-Patricia proof for `path` (an already-hashed 32-byte key)
/// under `root`.
///
/// * `Ok(Some(value))` — the key is present and holds `value`;
/// * `Ok(None)` — the key is **provably absent**;
/// * `Err(_)` — the witness is malformed, truncated, or lying.
pub fn verify_proof(
    root: &B256,
    path: &B256,
    nodes: &[Vec<u8>],
) -> Result<Option<Vec<u8>>, MptError> {
    if nodes.is_empty() {
        return Err(MptError::EmptyProof);
    }
    let nibbles = to_nibbles(path);
    let mut offset = 0usize; // nibbles consumed so far
    let mut expected: B256 = *root;

    for (index, raw) in nodes.iter().enumerate() {
        // The binding step: this node must be the one the parent committed to.
        if keccak256(raw) != expected {
            return Err(MptError::HashMismatch { index });
        }

        let node = rlp::Rlp::new(raw);
        let count = node.item_count().map_err(|e| MptError::MalformedNode {
            index,
            reason: e.to_string(),
        })?;

        match count {
            // ── branch ────────────────────────────────────────────────────
            17 => {
                if offset == nibbles.len() {
                    // Path ends here: the answer is the branch's own value slot.
                    let value: Vec<u8> = node.val_at(16).map_err(|e| MptError::MalformedNode {
                        index,
                        reason: e.to_string(),
                    })?;
                    return Ok((!value.is_empty()).then_some(value));
                }
                let nibble = nibbles[offset] as usize;
                offset += 1;
                let child = node.at(nibble).map_err(|e| MptError::MalformedNode {
                    index,
                    reason: e.to_string(),
                })?;
                let child_bytes: Vec<u8> = child
                    .data()
                    .map_err(|e| MptError::MalformedNode {
                        index,
                        reason: e.to_string(),
                    })?
                    .to_vec();

                if child_bytes.is_empty() {
                    // Empty slot on our path: absence, proven.
                    return Ok(None);
                }
                expected = expect_hash(&child_bytes, index)?;
            }

            // ── leaf or extension ────────────────────────────────────────
            2 => {
                let encoded: Vec<u8> = node.val_at(0).map_err(|e| MptError::MalformedNode {
                    index,
                    reason: e.to_string(),
                })?;
                let (is_leaf, partial) = decode_hex_prefix(&encoded)?;
                let remaining = &nibbles[offset.min(nibbles.len())..];

                if !remaining.starts_with(&partial) {
                    // Our path diverges from this node's: the key cannot exist
                    // below here, so this is a valid non-inclusion proof.
                    return Ok(None);
                }
                offset += partial.len();

                if is_leaf {
                    if offset != nibbles.len() {
                        return Err(MptError::TrailingPath);
                    }
                    let value: Vec<u8> = node.val_at(1).map_err(|e| MptError::MalformedNode {
                        index,
                        reason: e.to_string(),
                    })?;
                    return Ok(Some(value));
                }

                let child: Vec<u8> = node.val_at(1).map_err(|e| MptError::MalformedNode {
                    index,
                    reason: e.to_string(),
                })?;
                expected = expect_hash(&child, index)?;
            }

            other => {
                return Err(MptError::MalformedNode {
                    index,
                    reason: format!("expected 2 or 17 items, got {other}"),
                })
            }
        }
    }

    // We consumed every node the witness supplied and still had path left.
    // This is *not* absence: a truncated witness must never read as "empty".
    Err(MptError::ProofTruncated)
}

/// A child reference must be a 32-byte hash.
///
/// Nodes shorter than 32 bytes are inlined rather than hashed in a real trie.
/// They cannot occur on a proof path for a 32-byte (hashed) key at these trie
/// depths, so rather than guess we reject — refusing an input we don't fully
/// understand is the right default in verification code.
fn expect_hash(bytes: &[u8], index: usize) -> Result<B256, MptError> {
    if bytes.len() != 32 {
        return Err(MptError::MalformedNode {
            index,
            reason: format!(
                "child reference is {} bytes, expected a 32-byte hash",
                bytes.len()
            ),
        });
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

/// Split a 32-byte key into 64 nibbles, high nibble first.
fn to_nibbles(key: &B256) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    for b in key {
        out.push(b >> 4);
        out.push(b & 0x0f);
    }
    out
}

/// Decode the hex-prefix ("compact") encoding.
///
/// The first nibble is a flag: bit 1 = leaf, bit 0 = odd number of nibbles
/// (in which case the low nibble of the first byte is already part of the path).
/// Returns `(is_leaf, nibbles)`.
fn decode_hex_prefix(encoded: &[u8]) -> Result<(bool, Vec<u8>), MptError> {
    let first = *encoded
        .first()
        .ok_or_else(|| MptError::BadHexPrefix("empty".into()))?;
    let flag = first >> 4;
    let is_leaf = flag & 0b10 != 0;
    let odd = flag & 0b01 != 0;
    if flag > 3 {
        return Err(MptError::BadHexPrefix(format!(
            "reserved flag nibble {flag:#x}"
        )));
    }

    let mut nibbles = Vec::with_capacity(encoded.len() * 2);
    if odd {
        nibbles.push(first & 0x0f);
    }
    for b in &encoded[1..] {
        nibbles.push(b >> 4);
        nibbles.push(b & 0x0f);
    }
    Ok((is_leaf, nibbles))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nibbles_split_high_first() {
        let mut key = [0u8; 32];
        key[0] = 0xab;
        let n = to_nibbles(&key);
        assert_eq!(n.len(), 64);
        assert_eq!(&n[..2], &[0x0a, 0x0b]);
    }

    #[test]
    fn hex_prefix_decodes_all_four_forms() {
        // 0x00 = extension, even  → no nibbles from the flag byte
        assert_eq!(
            decode_hex_prefix(&[0x00, 0x12]).unwrap(),
            (false, vec![1, 2])
        );
        // 0x1_ = extension, odd   → low nibble of flag byte is path
        assert_eq!(
            decode_hex_prefix(&[0x1a, 0x12]).unwrap(),
            (false, vec![0xa, 1, 2])
        );
        // 0x20 = leaf, even
        assert_eq!(
            decode_hex_prefix(&[0x20, 0x12]).unwrap(),
            (true, vec![1, 2])
        );
        // 0x3_ = leaf, odd
        assert_eq!(
            decode_hex_prefix(&[0x3a, 0x12]).unwrap(),
            (true, vec![0xa, 1, 2])
        );
    }

    #[test]
    fn hex_prefix_rejects_reserved_flags() {
        assert!(decode_hex_prefix(&[0x40]).is_err());
        assert!(decode_hex_prefix(&[]).is_err());
    }

    #[test]
    fn empty_proof_is_an_error_not_absence() {
        // A witness that supplies nothing must never be read as "key absent".
        assert!(matches!(
            verify_proof(&[0u8; 32], &[0u8; 32], &[]),
            Err(MptError::EmptyProof)
        ));
    }

    #[test]
    fn first_node_must_hash_to_the_root() {
        let node = vec![0x80u8]; // rlp("")
        let wrong_root = [0xffu8; 32];
        assert!(matches!(
            verify_proof(&wrong_root, &[0u8; 32], &[node]),
            Err(MptError::HashMismatch { index: 0 })
        ));
    }
}
