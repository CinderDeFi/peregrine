//! # Selective disclosure
//!
//! Reveal one field of a row — or a range of them — while hiding the rest, and
//! keep the whole thing verifiable against the 32-byte store root.
//!
//! ## How it composes with what already exists
//!
//! A normal row stores its value directly, and a [`ProvenRead`] reveals that
//! value in full. A *disclosable* row instead commits to a *field vector*: the
//! row's on-chain value is a **32-byte Merkle root over its fields**, and the
//! plaintext fields are held by the row's owner. To disclose, the owner sends a
//! verifier:
//!
//! 1. the ordinary [`ProvenRead`] proving that `field_root` is the committed
//!    value of `(table, key)` under the store root; and
//! 2. a Merkle path for each field it chooses to reveal, proving that field sits
//!    in `field_root`.
//!
//! ```text
//!   store_root ──ProvenRead──▶ field_root ──field Merkle paths──▶ field_i
//!   (public)                   (on-chain)                         (revealed)
//! ```
//!
//! The verifier learns exactly the revealed fields and nothing about the
//! hidden ones except that they exist. Trust is unchanged from any other read:
//! only the 32-byte root is trusted, and a tampered field or a swapped index
//! fails the check.
//!
//! ## Binding
//!
//! Each field leaf commits to **its index and the row's arity** as well as its
//! bytes: `domain ‖ index_u32 ‖ arity_u32 ‖ field`. Binding the index stops a
//! prover from presenting field *j* as if it were field *i*; binding the arity
//! stops it from lying about how many fields the row has. Both are authenticated
//! by `field_root`, which is fixed on-chain, so only the real row produces it.

use crate::merkle::{MerkleProof, MerkleTree};
use crate::tables::ProvenRead;
use peregrine_core::Hash;
use serde::{Deserialize, Serialize};

/// Domain tag for a field leaf. Separate from the store/table Merkle domains so
/// a field leaf can never be reinterpreted as a table leaf or vice versa.
const FIELD_LEAF_DOMAIN: &[u8] = b"peregrine.disclosure.field.v1";

/// The canonical bytes hashed into the field tree for field `index` of an
/// `arity`-field row. Index and arity are length-fixed so the encoding is
/// unambiguous regardless of the field's own bytes.
pub fn field_leaf_bytes(index: u32, arity: u32, field: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(FIELD_LEAF_DOMAIN.len() + 8 + field.len());
    out.extend_from_slice(FIELD_LEAF_DOMAIN);
    out.extend_from_slice(&index.to_le_bytes());
    out.extend_from_slice(&arity.to_le_bytes());
    out.extend_from_slice(field);
    out
}

/// A row expressed as an ordered vector of opaque fields, held by its owner.
///
/// The owner commits [`commit`](Self::commit) on-chain and keeps the fields; to
/// disclose a subset it calls [`disclose`](Self::disclose).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldRow {
    pub fields: Vec<Vec<u8>>,
}

impl FieldRow {
    pub fn new(fields: Vec<Vec<u8>>) -> Self {
        Self { fields }
    }

    pub fn len(&self) -> usize {
        self.fields.len()
    }

    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// The 32-byte commitment to store as the row's value. This is what a
    /// [`ProvenRead`] of the row returns, and what field paths are proven
    /// against.
    pub fn commit(&self) -> Hash {
        let arity = self.fields.len() as u32;
        let leaves: Vec<Vec<u8>> = self
            .fields
            .iter()
            .enumerate()
            .map(|(i, f)| field_leaf_bytes(i as u32, arity, f))
            .collect();
        MerkleTree::from_leaves(leaves.iter().map(|l| l.as_slice())).root()
    }

    /// Build a selective disclosure revealing the fields at `indices`, proven
    /// against `read` (which must be a proven read of this row's commitment).
    ///
    /// `indices` may be a single field, a contiguous range, or any subset; they
    /// are de-duplicated and order-independent.
    pub fn disclose(
        &self,
        read: ProvenRead,
        indices: &[usize],
    ) -> Result<SelectiveDisclosure, DisclosureError> {
        // The read must actually be OF this row's commitment, otherwise the
        // disclosure would prove fields against a root the read does not carry.
        let root = self.commit();
        if read.value.as_slice() != root.0.as_slice() {
            return Err(DisclosureError::RootMismatch);
        }
        let arity = self.fields.len() as u32;
        let leaves: Vec<Vec<u8>> = self
            .fields
            .iter()
            .enumerate()
            .map(|(i, f)| field_leaf_bytes(i as u32, arity, f))
            .collect();
        let tree = MerkleTree::from_leaves(leaves.iter().map(|l| l.as_slice()));

        // De-duplicate, preserving a deterministic (sorted) order.
        let mut want: Vec<usize> = indices.to_vec();
        want.sort_unstable();
        want.dedup();

        let mut reveals = Vec::with_capacity(want.len());
        for &i in &want {
            if i >= self.fields.len() {
                return Err(DisclosureError::IndexOutOfRange {
                    index: i,
                    arity: self.fields.len(),
                });
            }
            let proof = tree.prove(i).ok_or(DisclosureError::IndexOutOfRange {
                index: i,
                arity: self.fields.len(),
            })?;
            reveals.push(FieldReveal {
                index: i as u32,
                value: self.fields[i].clone(),
                proof,
            });
        }
        Ok(SelectiveDisclosure {
            read,
            arity,
            reveals,
        })
    }
}

/// One revealed field with the Merkle path proving it sits in `field_root`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FieldReveal {
    pub index: u32,
    pub value: Vec<u8>,
    pub proof: MerkleProof,
}

/// A selective disclosure: a proven read of a row's field commitment, plus
/// Merkle paths for the revealed fields.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SelectiveDisclosure {
    /// Proves `field_root` (`read.value`) is the committed value of the row.
    pub read: ProvenRead,
    /// The row's field count, as bound into every field leaf.
    pub arity: u32,
    /// The revealed fields, each with its path into `field_root`.
    pub reveals: Vec<FieldReveal>,
}

impl SelectiveDisclosure {
    /// The field-tree root this disclosure proves against: the row's on-chain
    /// value, interpreted as a 32-byte hash. `None` if the value is not a
    /// 32-byte commitment (so not a disclosable row).
    pub fn field_root(&self) -> Option<Hash> {
        let bytes: [u8; 32] = self.read.value.as_slice().try_into().ok()?;
        Some(Hash(bytes))
    }

    /// The revealed `(index, field)` pairs — what the verifier is allowed to
    /// see. Only meaningful once [`verify`](Self::verify) has returned true.
    pub fn revealed(&self) -> impl Iterator<Item = (u32, &[u8])> {
        self.reveals.iter().map(|r| (r.index, r.value.as_slice()))
    }

    /// Verify the whole disclosure against a trusted store root:
    ///
    /// 1. the field commitment is genuinely the committed value of the row; and
    /// 2. every revealed field sits in that commitment at the claimed index,
    ///    under the claimed arity.
    ///
    /// Reveals nothing about the hidden fields and cannot be made to accept a
    /// tampered field, a wrong index, or a foreign root.
    pub fn verify(&self, store_root: &Hash) -> bool {
        // (1) the on-chain row value is a 32-byte field root, committed under
        //     the store root.
        let Some(field_root) = self.field_root() else {
            return false;
        };
        if !self.read.verify(store_root) {
            return false;
        }
        // (2) each revealed field is in that field root, index- and arity-bound.
        for r in &self.reveals {
            if r.proof.leaf_index != r.index as u64 {
                return false;
            }
            if r.index >= self.arity {
                return false;
            }
            let leaf = field_leaf_bytes(r.index, self.arity, &r.value);
            if !r.proof.verify(&field_root, &leaf) {
                return false;
            }
        }
        true
    }
}

/// Why a disclosure could not be constructed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DisclosureError {
    #[error("the proven read is not of this row's field commitment")]
    RootMismatch,
    #[error("field index {index} out of range for a {arity}-field row")]
    IndexOutOfRange { index: usize, arity: usize },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tables::{TableId, TableStore};

    /// Commit a field row into a store and return (store, table, key, row).
    fn committed_row(fields: Vec<Vec<u8>>) -> (TableStore, TableId, Vec<u8>, FieldRow) {
        let row = FieldRow::new(fields);
        let table = TableId::named("kyc.records");
        let key = b"customer-42".to_vec();
        let mut store = TableStore::new();
        // some noise so the store has more than one row/table
        store.insert(TableId::named("other"), b"x".to_vec(), b"y".to_vec());
        store.insert(table, key.clone(), row.commit().0.to_vec());
        (store, table, key, row)
    }

    #[test]
    fn commit_is_deterministic_and_order_sensitive() {
        let a = FieldRow::new(vec![b"alice".to_vec(), b"1990".to_vec(), b"US".to_vec()]);
        let b = FieldRow::new(vec![b"alice".to_vec(), b"1990".to_vec(), b"US".to_vec()]);
        assert_eq!(a.commit(), b.commit());
        // Reordering the fields changes the commitment.
        let c = FieldRow::new(vec![b"1990".to_vec(), b"alice".to_vec(), b"US".to_vec()]);
        assert_ne!(a.commit(), c.commit());
    }

    #[test]
    fn discloses_a_single_field_and_hides_the_rest() {
        let fields = vec![
            b"Alice Smith".to_vec(),
            b"1990-01-01".to_vec(),
            b"passport-9931".to_vec(),
            b"US".to_vec(),
        ];
        let (mut store, table, key, row) = committed_row(fields.clone());
        let root = store.store_root();
        let read = store.prove_read(table, &key).unwrap();

        // Reveal only the country (index 3).
        let disc = row.disclose(read, &[3]).unwrap();
        assert!(disc.verify(&root));

        let revealed: Vec<_> = disc.revealed().collect();
        assert_eq!(revealed, vec![(3u32, b"US".as_slice())]);
        // The disclosure carries no other field's bytes anywhere.
        for f in [&fields[0], &fields[1], &fields[2]] {
            assert!(
                !bincode::serialize(&disc)
                    .unwrap()
                    .windows(f.len())
                    .any(|w| w == f.as_slice()),
                "hidden field must not appear in the disclosure"
            );
        }
    }

    #[test]
    fn discloses_a_contiguous_range() {
        let fields: Vec<Vec<u8>> = (0..8u8).map(|i| vec![i; 4]).collect();
        let (mut store, table, key, row) = committed_row(fields);
        let root = store.store_root();
        let read = store.prove_read(table, &key).unwrap();
        let disc = row.disclose(read, &[2, 3, 4]).unwrap();
        assert!(disc.verify(&root));
        let idxs: Vec<u32> = disc.revealed().map(|(i, _)| i).collect();
        assert_eq!(idxs, vec![2, 3, 4]);
    }

    #[test]
    fn a_tampered_field_value_is_rejected() {
        let (mut store, table, key, row) =
            committed_row(vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);
        let root = store.store_root();
        let read = store.prove_read(table, &key).unwrap();
        let mut disc = row.disclose(read, &[1]).unwrap();
        assert!(disc.verify(&root));
        disc.reveals[0].value = b"forged".to_vec();
        assert!(!disc.verify(&root), "a tampered revealed field must fail");
    }

    #[test]
    fn claiming_a_field_at_the_wrong_index_is_rejected() {
        let (mut store, table, key, row) =
            committed_row(vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);
        let root = store.store_root();
        let read = store.prove_read(table, &key).unwrap();
        let mut disc = row.disclose(read, &[0]).unwrap();
        // Move the reveal to claim it is field 2 while keeping field 0's path.
        disc.reveals[0].index = 2;
        assert!(!disc.verify(&root), "index must be bound to the proof");
    }

    #[test]
    fn a_disclosure_does_not_verify_against_the_wrong_root() {
        let (mut store, table, key, row) = committed_row(vec![b"a".to_vec(), b"b".to_vec()]);
        let _ = store.store_root();
        let read = store.prove_read(table, &key).unwrap();
        let disc = row.disclose(read, &[0]).unwrap();
        assert!(!disc.verify(&Hash::ZERO));
    }

    #[test]
    fn disclose_refuses_a_read_of_a_different_row() {
        let row = FieldRow::new(vec![b"a".to_vec(), b"b".to_vec()]);
        let table = TableId::named("kyc.records");
        let key = b"k".to_vec();
        let mut store = TableStore::new();
        // Store a DIFFERENT value than the row's commitment.
        store.insert(table, key.clone(), b"not-the-commitment".to_vec());
        let _ = store.store_root();
        let read = store.prove_read(table, &key).unwrap();
        assert_eq!(
            row.disclose(read, &[0]).unwrap_err(),
            DisclosureError::RootMismatch
        );
    }

    #[test]
    fn out_of_range_index_is_refused() {
        let (mut store, table, key, row) = committed_row(vec![b"a".to_vec()]);
        let _ = store.store_root();
        let read = store.prove_read(table, &key).unwrap();
        assert!(matches!(
            row.disclose(read, &[5]),
            Err(DisclosureError::IndexOutOfRange { index: 5, arity: 1 })
        ));
    }
}
