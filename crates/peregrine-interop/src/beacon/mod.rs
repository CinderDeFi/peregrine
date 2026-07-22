//! Ethereum beacon-chain light client — the **anchor** for everything else.
//!
//! Week 7 could verify that a run of execution headers was internally
//! consistent, but not that it was *Ethereum's* chain. That gap is what this
//! module closes. The trust chain, top to bottom:
//!
//! ```text
//!   sync committee (512 validators, BLS)  ── signs ──▶ attested beacon header
//!                                                          │ state_root
//!                                       finality_branch ───┤
//!                                                          ▼
//!                                                  finalized beacon header
//!                                                          │ body_root
//!                                      execution_branch ───┤
//!                                                          ▼
//!                                        execution payload header
//!                                                          │
//!                                                  block_hash  ← the anchor
//! ```
//!
//! That final `block_hash` is exactly what
//! [`crate::verify_eth_headers`] needs as its `trusted_anchor`: once a header
//! is anchored, the Merkle-Patricia state proofs from Week 7 inherit its
//! authority, and Ethereum state becomes usable inside Peregrine without
//! trusting a relayer.
//!
//! # What is verified here, and what is not
//!
//! Implemented and tested against **real mainnet beacon data**: SSZ
//! `hash_tree_root` for both header types (checked against the root the beacon
//! chain itself published), both Merkle branches, the ≥2/3 participation
//! threshold, and the fork-domain / signing-root derivation.
//!
//! **The BLS signature check is not implemented.** It is expressed as the
//! [`SyncCommitteeVerifier`] trait, and the shipped implementation
//! ([`RejectingBls`]) refuses everything. An update therefore cannot produce an
//! anchor in this build — which is the correct failure direction, and is
//! asserted by test. Without it, everything above proves *internal
//! consistency* of a light-client update, not that the sync committee endorsed
//! it; a relayer could fabricate a self-consistent update. Do not run this
//! against real value until the BLS half lands.

#[cfg(feature = "bls")]
pub mod bls;
pub mod ssz;

use crate::zk::B256;
use serde::{Deserialize, Serialize};
use ssz::{merkleize, verify_merkle_branch, Node};

/// Sync committee size on mainnet.
pub const SYNC_COMMITTEE_SIZE: usize = 512;
/// Minimum participants for an update to count (spec: > 2/3).
pub const MIN_SYNC_PARTICIPANTS: usize = (SYNC_COMMITTEE_SIZE * 2) / 3 + 1;

/// Generalized index of `finalized_checkpoint.root` in `BeaconState`
/// (Electra onward; the branch is 7 deep).
pub const FINALIZED_ROOT_GINDEX: usize = 169;
/// Generalized index of the execution payload in `BeaconBlockBody`.
pub const EXECUTION_PAYLOAD_GINDEX: usize = 25;
/// Generalized index of `current_sync_committee` in `BeaconState` (Electra+).
pub const CURRENT_SYNC_COMMITTEE_GINDEX: usize = 86;
/// Generalized index of `next_sync_committee` in `BeaconState` (Electra+).
pub const NEXT_SYNC_COMMITTEE_GINDEX: usize = 87;
/// Slots per sync-committee period (256 epochs x 32 slots).
pub const SLOTS_PER_PERIOD: u64 = 8192;

/// Sync-committee period containing `slot`.
pub const fn period_of(slot: u64) -> u64 {
    slot / SLOTS_PER_PERIOD
}

/// Compressed BLS12-381 G1 public key.
pub type PubkeyBytes = [u8; 48];

/// `DOMAIN_SYNC_COMMITTEE`.
pub const DOMAIN_SYNC_COMMITTEE: [u8; 4] = [0x07, 0x00, 0x00, 0x00];

#[derive(Debug, thiserror::Error)]
pub enum BeaconError {
    #[error("insufficient sync committee participation: {got} of {needed}")]
    InsufficientParticipation { got: usize, needed: usize },
    #[error("finality branch does not link the finalized header to the attested state")]
    BadFinalityBranch,
    #[error("execution branch does not link the payload to the beacon body")]
    BadExecutionBranch,
    #[error("sync committee signature rejected: {0}")]
    BadSignature(String),
    #[error("update is not newer than the current anchor")]
    NotNewer,
    #[error("next_sync_committee branch does not link to the attested beacon state")]
    BadNextCommitteeBranch,
    #[error("current_sync_committee branch does not link to the bootstrap state")]
    BadCurrentCommitteeBranch,
    #[error("update signed by period {got}, but the store knows {current} and {next:?}")]
    UnknownSigningPeriod {
        got: u64,
        current: u64,
        next: Option<u64>,
    },
    #[error("malformed update: {0}")]
    Malformed(String),
}

/// `BeaconBlockHeader` — five fields, merkleized into eight leaves.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeaconBlockHeader {
    pub slot: u64,
    pub proposer_index: u64,
    pub parent_root: B256,
    pub state_root: B256,
    pub body_root: B256,
}

impl BeaconBlockHeader {
    pub fn hash_tree_root(&self) -> Node {
        merkleize(
            &[
                ssz::uint64_leaf(self.slot),
                ssz::uint64_leaf(self.proposer_index),
                self.parent_root,
                self.state_root,
                self.body_root,
            ],
            None,
        )
    }
}

/// `ExecutionPayloadHeader` (Deneb/Electra shape: 17 fields).
///
/// Field order is consensus-critical — SSZ commits to position, so a reordered
/// or omitted field silently changes the root.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionPayloadHeader {
    pub parent_hash: B256,
    pub fee_recipient: [u8; 20],
    pub state_root: B256,
    pub receipts_root: B256,
    /// 256 bytes.
    pub logs_bloom: Vec<u8>,
    pub prev_randao: B256,
    pub block_number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    /// Variable-length (`List[byte, 32]`), so its root mixes in the length.
    pub extra_data: Vec<u8>,
    /// Big-endian; SSZ stores it little-endian as a `uint256`.
    pub base_fee_per_gas_be: Vec<u8>,
    /// The execution block hash — what we ultimately anchor on.
    pub block_hash: B256,
    pub transactions_root: B256,
    pub withdrawals_root: B256,
    pub blob_gas_used: u64,
    pub excess_blob_gas: u64,
}

impl ExecutionPayloadHeader {
    pub fn hash_tree_root(&self) -> Node {
        let extra_data_root = ssz::mix_in_length(
            // `List[byte, 32]` → one chunk, limit one chunk.
            &merkleize(&ssz::chunks(&self.extra_data), Some(1)),
            self.extra_data.len(),
        );
        merkleize(
            &[
                self.parent_hash,
                ssz::bytes_leaf(&self.fee_recipient),
                self.state_root,
                self.receipts_root,
                merkleize(&ssz::chunks(&self.logs_bloom), None),
                self.prev_randao,
                ssz::uint64_leaf(self.block_number),
                ssz::uint64_leaf(self.gas_limit),
                ssz::uint64_leaf(self.gas_used),
                ssz::uint64_leaf(self.timestamp),
                extra_data_root,
                ssz::uint256_leaf_from_be(&self.base_fee_per_gas_be),
                self.block_hash,
                self.transactions_root,
                self.withdrawals_root,
                ssz::uint64_leaf(self.blob_gas_used),
                ssz::uint64_leaf(self.excess_blob_gas),
            ],
            None,
        )
    }
}

/// A sync committee: 512 public keys plus their aggregate.
///
/// This is plain data — verifying *signatures* needs `blst` and lives behind
/// the `bls` feature, but a committee's SSZ root is needed for rotation
/// regardless, so the type itself is always available.
///
/// Note: no `serde` derives. `serde` does not implement `Serialize` for
/// `[u8; 48]`, and nothing currently needs a wire format for a committee — if
/// one is added later, use a big-array helper rather than weakening the type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncCommittee {
    pub pubkeys: Vec<PubkeyBytes>,
    pub aggregate_pubkey: PubkeyBytes,
}

impl SyncCommittee {
    /// Parse from compressed keys, rejecting a wrong-sized committee.
    pub fn from_bytes(
        pubkeys: Vec<PubkeyBytes>,
        aggregate_pubkey: PubkeyBytes,
    ) -> Result<Self, BeaconError> {
        if pubkeys.len() != SYNC_COMMITTEE_SIZE {
            return Err(BeaconError::Malformed(format!(
                "sync committee has {} keys, expected {SYNC_COMMITTEE_SIZE}",
                pubkeys.len()
            )));
        }
        Ok(Self {
            pubkeys,
            aggregate_pubkey,
        })
    }

    /// SSZ root: `merkleize([merkleize(pubkeys), root(aggregate_pubkey)])`.
    ///
    /// A 48-byte key spans two chunks, so each key is itself merkleized before
    /// the 512 results are combined. This root is what a rotation proof binds
    /// to the beacon state — getting it wrong means silently accepting some
    /// other committee.
    pub fn hash_tree_root(&self) -> Node {
        let key_root = |pk: &PubkeyBytes| merkleize(&ssz::chunks(pk), None);
        let keys: Vec<Node> = self.pubkeys.iter().map(key_root).collect();
        merkleize(
            &[
                merkleize(&keys, Some(SYNC_COMMITTEE_SIZE)),
                key_root(&self.aggregate_pubkey),
            ],
            None,
        )
    }
}

/// A beacon header paired with its execution payload and the branch proving
/// the payload belongs to it.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LightClientHeader {
    pub beacon: BeaconBlockHeader,
    pub execution: ExecutionPayloadHeader,
    pub execution_branch: Vec<Node>,
}

impl LightClientHeader {
    /// Check that `execution` really is this beacon block's payload.
    pub fn verify_execution(&self) -> Result<(), BeaconError> {
        let (depth, index) = ssz::gindex_parts(EXECUTION_PAYLOAD_GINDEX);
        verify_merkle_branch(
            &self.execution.hash_tree_root(),
            &self.execution_branch,
            depth,
            index,
            &self.beacon.body_root,
        )
        .then_some(())
        .ok_or(BeaconError::BadExecutionBranch)
    }
}

/// The sync committee's aggregate attestation.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SyncAggregate {
    /// One bit per committee member, little-endian within each byte.
    pub sync_committee_bits: Vec<u8>,
    /// BLS12-381 G2 aggregate signature (96 bytes).
    pub sync_committee_signature: Vec<u8>,
}

impl SyncAggregate {
    /// Number of committee members that signed.
    pub fn participants(&self) -> usize {
        self.sync_committee_bits
            .iter()
            .map(|b| b.count_ones() as usize)
            .sum()
    }

    /// Enforce the > 2/3 threshold.
    pub fn check_participation(&self) -> Result<usize, BeaconError> {
        // AUDIT I-2: enforce the bitvector length here, not only in the BLS
        // verifier. Otherwise this count and the verifier's participant
        // selection could be computed over different-length inputs — the
        // verifier rejects a wrong length, so there was no bypass, but the
        // participation count must not depend on that ordering. Exactly 512
        // bits = 64 bytes.
        if self.sync_committee_bits.len() != SYNC_COMMITTEE_SIZE / 8 {
            return Err(BeaconError::Malformed(format!(
                "sync committee bits are {} bytes, expected {}",
                self.sync_committee_bits.len(),
                SYNC_COMMITTEE_SIZE / 8
            )));
        }
        let got = self.participants();
        if got < MIN_SYNC_PARTICIPANTS {
            return Err(BeaconError::InsufficientParticipation {
                got,
                needed: MIN_SYNC_PARTICIPANTS,
            });
        }
        Ok(got)
    }
}

/// A light-client update.
#[derive(Clone, Debug, Default)]
pub struct LightClientUpdate {
    pub attested_header: LightClientHeader,
    pub finalized_header: LightClientHeader,
    /// Proves `finalized_header.beacon` under `attested_header.beacon.state_root`.
    pub finality_branch: Vec<Node>,
    /// The committee for the *next* period, when the update carries one.
    pub next_sync_committee: Option<SyncCommittee>,
    /// Proves `next_sync_committee` under `attested_header.beacon.state_root`.
    pub next_sync_committee_branch: Vec<Node>,
    pub sync_aggregate: SyncAggregate,
    pub signature_slot: u64,
}

impl LightClientUpdate {
    /// Verify that `next_sync_committee` really is the one the attested beacon
    /// state commits to.
    ///
    /// This single check is what makes anchoring autonomous: it lets a client
    /// that trusts period *P*'s committee derive period *P+1*'s from the chain
    /// itself, with no operator supplying keys.
    pub fn verify_next_sync_committee(&self) -> Result<&SyncCommittee, BeaconError> {
        let committee = self.next_sync_committee.as_ref().ok_or_else(|| {
            BeaconError::Malformed("update carries no next_sync_committee".into())
        })?;
        let (depth, index) = ssz::gindex_parts(NEXT_SYNC_COMMITTEE_GINDEX);
        if !verify_merkle_branch(
            &committee.hash_tree_root(),
            &self.next_sync_committee_branch,
            depth,
            index,
            &self.attested_header.beacon.state_root,
        ) {
            return Err(BeaconError::BadNextCommitteeBranch);
        }
        Ok(committee)
    }
}

/// A trusted execution-layer block, established by a verified update.
///
/// This is the object the rest of the system anchors on: a Peregrine node that
/// holds one of these can accept Week 7 state proofs against that block
/// without trusting whoever supplied them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Anchor {
    /// Beacon slot of the finalized header.
    pub slot: u64,
    /// Execution block number.
    pub block_number: u64,
    /// Execution block hash — the value [`crate::verify_eth_headers`] pins.
    pub block_hash: B256,
    /// Execution state root at that block.
    pub state_root: B256,
}

/// Verifies the sync committee's aggregate BLS signature.
///
/// Kept as a trait so the (heavy, dependency-bearing) BLS implementation can
/// land without touching any of the verified logic around it.
pub trait SyncCommitteeVerifier {
    /// Check `signature` over `signing_root` for the committee members
    /// selected by `bits`.
    fn verify_aggregate(
        &self,
        signing_root: &Node,
        bits: &[u8],
        signature: &[u8],
    ) -> Result<(), BeaconError>;
}

/// The shipped verifier: refuses every signature.
///
/// Not a placeholder that quietly passes — a build without real BLS must not
/// be able to produce an anchor, or the whole chain of trust is decorative.
#[derive(Debug, Default, Clone, Copy)]
pub struct RejectingBls;

impl SyncCommitteeVerifier for RejectingBls {
    fn verify_aggregate(&self, _: &Node, _: &[u8], _: &[u8]) -> Result<(), BeaconError> {
        Err(BeaconError::BadSignature(
            "BLS12-381 sync-committee verification is not implemented in this build".into(),
        ))
    }
}

/// `compute_fork_data_root(current_version, genesis_validators_root)`.
pub fn compute_fork_data_root(fork_version: &[u8; 4], genesis_validators_root: &Node) -> Node {
    merkleize(
        &[ssz::bytes_leaf(fork_version), *genesis_validators_root],
        None,
    )
}

/// `compute_domain(DOMAIN_SYNC_COMMITTEE, fork_version, genesis_validators_root)`.
///
/// The domain binds a signature to one fork of one chain, which is what stops
/// a signature gathered on a testnet — or before a fork — from being replayed.
pub fn compute_domain(fork_version: &[u8; 4], genesis_validators_root: &Node) -> Node {
    let fork_data_root = compute_fork_data_root(fork_version, genesis_validators_root);
    let mut domain = [0u8; 32];
    domain[..4].copy_from_slice(&DOMAIN_SYNC_COMMITTEE);
    domain[4..32].copy_from_slice(&fork_data_root[..28]);
    domain
}

/// `compute_signing_root(object_root, domain)` — what the committee signs.
pub fn compute_signing_root(object_root: &Node, domain: &Node) -> Node {
    merkleize(&[*object_root, *domain], None)
}

/// Verify a light-client update and, if it holds, produce an [`Anchor`].
///
/// Checks, in order (cheap and structural first, cryptography last):
/// 1. sync-committee participation ≥ 2/3;
/// 2. the attested header's execution payload branch;
/// 3. the finality branch — finalized header under the attested state root;
/// 4. the finalized header's execution payload branch;
/// 5. the aggregate BLS signature over the attested header's signing root.
pub fn verify_update<V: SyncCommitteeVerifier>(
    update: &LightClientUpdate,
    fork_version: &[u8; 4],
    genesis_validators_root: &Node,
    bls: &V,
) -> Result<Anchor, BeaconError> {
    update.sync_aggregate.check_participation()?;
    update.attested_header.verify_execution()?;

    let (depth, index) = ssz::gindex_parts(FINALIZED_ROOT_GINDEX);
    if !verify_merkle_branch(
        &update.finalized_header.beacon.hash_tree_root(),
        &update.finality_branch,
        depth,
        index,
        &update.attested_header.beacon.state_root,
    ) {
        return Err(BeaconError::BadFinalityBranch);
    }

    update.finalized_header.verify_execution()?;

    // The committee signs the *attested* header, which is what the finality
    // branch hangs off — so this signature is what gives the finalized header
    // (and therefore the anchor) its authority.
    let domain = compute_domain(fork_version, genesis_validators_root);
    let signing_root =
        compute_signing_root(&update.attested_header.beacon.hash_tree_root(), &domain);
    bls.verify_aggregate(
        &signing_root,
        &update.sync_aggregate.sync_committee_bits,
        &update.sync_aggregate.sync_committee_signature,
    )?;

    let exec = &update.finalized_header.execution;
    Ok(Anchor {
        slot: update.finalized_header.beacon.slot,
        block_number: exec.block_number,
        block_hash: exec.block_hash,
        state_root: exec.state_root,
    })
}

/// The set of execution blocks a node is willing to treat as canonical.
///
/// Deliberately tiny: a node keeps the latest anchor (and recent history), and
/// a state proof is only accepted if its block hash is in here. Anchors move
/// forward only.
#[derive(Debug, Default, Clone)]
pub struct AnchorStore {
    anchors: Vec<Anchor>,
    max_len: usize,
}

impl AnchorStore {
    pub fn new(max_len: usize) -> Self {
        Self {
            anchors: Vec::new(),
            max_len: max_len.max(1),
        }
    }

    /// Insert a verified anchor. Rejects anything not newer than the tip, so a
    /// replayed old update cannot roll the anchor backwards.
    pub fn insert(&mut self, anchor: Anchor) -> Result<(), BeaconError> {
        if let Some(tip) = self.tip() {
            if anchor.slot <= tip.slot {
                return Err(BeaconError::NotNewer);
            }
        }
        self.anchors.push(anchor);
        if self.anchors.len() > self.max_len {
            self.anchors.remove(0);
        }
        Ok(())
    }

    /// Most recent anchor.
    pub fn tip(&self) -> Option<&Anchor> {
        self.anchors.last()
    }

    /// Whether this execution block hash has been anchored.
    pub fn is_anchored(&self, block_hash: &B256) -> bool {
        self.anchors.iter().any(|a| a.block_hash == *block_hash)
    }

    pub fn len(&self) -> usize {
        self.anchors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn participation_threshold_is_two_thirds_plus_one() {
        assert_eq!(MIN_SYNC_PARTICIPANTS, 342);

        // 341 signers is one short and must be refused.
        let mut bits = vec![0u8; 64];
        for i in 0..341 {
            bits[i / 8] |= 1 << (i % 8);
        }
        let agg = SyncAggregate {
            sync_committee_bits: bits.clone(),
            ..Default::default()
        };
        assert_eq!(agg.participants(), 341);
        assert!(matches!(
            agg.check_participation(),
            Err(BeaconError::InsufficientParticipation {
                got: 341,
                needed: 342
            })
        ));

        bits[341 / 8] |= 1 << (341 % 8);
        let agg = SyncAggregate {
            sync_committee_bits: bits,
            ..Default::default()
        };
        assert_eq!(agg.check_participation().unwrap(), 342);
    }

    #[test]
    fn domain_binds_fork_and_chain() {
        let gvr = [1u8; 32];
        let a = compute_domain(&[0, 0, 0, 0], &gvr);
        let b = compute_domain(&[1, 0, 0, 0], &gvr); // different fork
        let c = compute_domain(&[0, 0, 0, 0], &[2u8; 32]); // different chain
        assert_ne!(a, b, "a fork change must change the domain");
        assert_ne!(a, c, "a different genesis must change the domain");
        assert_eq!(&a[..4], &DOMAIN_SYNC_COMMITTEE);
    }

    #[test]
    fn shipped_bls_verifier_refuses_everything() {
        // A build with no real BLS must be unable to mint an anchor.
        let err = RejectingBls.verify_aggregate(&[0u8; 32], &[0xff; 64], &[0u8; 96]);
        assert!(matches!(err, Err(BeaconError::BadSignature(_))));
    }

    #[test]
    fn anchor_store_only_moves_forward() {
        let mut store = AnchorStore::new(4);
        let a1 = Anchor {
            slot: 100,
            block_number: 1,
            block_hash: [1u8; 32],
            state_root: [0u8; 32],
        };
        let a2 = Anchor {
            slot: 200,
            block_number: 2,
            block_hash: [2u8; 32],
            state_root: [0u8; 32],
        };
        store.insert(a1).unwrap();
        store.insert(a2).unwrap();
        assert_eq!(store.tip().unwrap().slot, 200);

        // Replaying an older update must not roll the anchor back.
        assert!(matches!(store.insert(a1), Err(BeaconError::NotNewer)));
        assert!(store.is_anchored(&[1u8; 32]));
        assert!(!store.is_anchored(&[9u8; 32]));
    }

    #[test]
    fn anchor_store_bounds_its_history() {
        let mut store = AnchorStore::new(2);
        for slot in 1..=5u64 {
            store
                .insert(Anchor {
                    slot,
                    block_number: slot,
                    block_hash: [slot as u8; 32],
                    state_root: [0u8; 32],
                })
                .unwrap();
        }
        assert_eq!(store.len(), 2);
        assert!(!store.is_anchored(&[1u8; 32]), "old anchors are evicted");
        assert!(store.is_anchored(&[5u8; 32]));
    }
}

/// A light client that **follows** Ethereum's sync committees on its own.
///
/// Seeded once from a trusted bootstrap, it then derives each period's
/// committee from the chain: the committee it already trusts signs an update,
/// and that update's beacon state commits to the *next* committee. No operator
/// ever supplies keys again — which is the difference between a light client
/// and a configuration file.
///
/// The store deliberately keeps only what it needs: the committee for the
/// current period, optionally the next one, and the latest anchor.
#[derive(Debug, Clone)]
pub struct LightClientStore {
    /// Period whose committee is in `current_committee`.
    period: u64,
    current_committee: SyncCommittee,
    /// Committee for `period + 1`, once an update has proven it.
    next_committee: Option<SyncCommittee>,
    /// Latest verified anchor, if any.
    anchor: Option<Anchor>,
}

impl LightClientStore {
    /// Seed from a trusted bootstrap.
    ///
    /// `header` and `branch` come from `/eth/v1/beacon/light_client/bootstrap`;
    /// the branch proves the committee against the header's state root, so a
    /// bootstrap cannot smuggle in a committee that the beacon state does not
    /// commit to. The *header* itself is the trust assumption — obtain it from
    /// a checkpoint you believe (this is standard weak subjectivity).
    pub fn from_bootstrap(
        header: &BeaconBlockHeader,
        committee: SyncCommittee,
        branch: &[Node],
    ) -> Result<Self, BeaconError> {
        let (depth, index) = ssz::gindex_parts(CURRENT_SYNC_COMMITTEE_GINDEX);
        if !verify_merkle_branch(
            &committee.hash_tree_root(),
            branch,
            depth,
            index,
            &header.state_root,
        ) {
            return Err(BeaconError::BadCurrentCommitteeBranch);
        }
        Ok(Self {
            period: period_of(header.slot),
            current_committee: committee,
            next_committee: None,
            anchor: None,
        })
    }

    pub fn period(&self) -> u64 {
        self.period
    }
    pub fn current_committee(&self) -> &SyncCommittee {
        &self.current_committee
    }
    pub fn next_committee(&self) -> Option<&SyncCommittee> {
        self.next_committee.as_ref()
    }
    pub fn anchor(&self) -> Option<&Anchor> {
        self.anchor.as_ref()
    }

    /// Apply a light-client update: verify it, learn the next committee if the
    /// update carries one, and rotate forward when the update is from the next
    /// period.
    ///
    /// Returns the anchor the update establishes.
    pub fn apply_update<V, F>(
        &mut self,
        update: &LightClientUpdate,
        fork_version: &[u8; 4],
        genesis_validators_root: &Node,
        make_verifier: F,
    ) -> Result<Anchor, BeaconError>
    where
        V: SyncCommitteeVerifier,
        F: Fn(&SyncCommittee) -> V,
    {
        // Which committee signed? Only the current period's, or the next one's
        // if we have already learned it. Anything else is a period we cannot
        // check, and guessing is how a light client gets walked onto a fork.
        let signing_period = period_of(update.signature_slot);
        let committee = if signing_period == self.period {
            &self.current_committee
        } else if signing_period == self.period + 1 {
            self.next_committee
                .as_ref()
                .ok_or(BeaconError::UnknownSigningPeriod {
                    got: signing_period,
                    current: self.period,
                    next: None,
                })?
        } else {
            return Err(BeaconError::UnknownSigningPeriod {
                got: signing_period,
                current: self.period,
                next: self.next_committee.as_ref().map(|_| self.period + 1),
            });
        };

        // Full verification (participation, branches, BLS) with that committee.
        let anchor = verify_update(
            update,
            fork_version,
            genesis_validators_root,
            &make_verifier(committee),
        )?;

        // Learn the next committee *after* the signature is verified — the
        // branch hangs off a state root we only trust because it was signed.
        let learned = match update.next_sync_committee {
            Some(_) => Some(update.verify_next_sync_committee()?.clone()),
            None => None,
        };

        // Rotate if this update came from the following period.
        if signing_period == self.period + 1 {
            let next = self
                .next_committee
                .take()
                .expect("checked above when selecting the committee");
            self.current_committee = next;
            self.period += 1;
        }
        if let Some(c) = learned {
            self.next_committee = Some(c);
        }

        // Anchors only move forward.
        if let Some(prev) = &self.anchor {
            if anchor.slot <= prev.slot {
                return Err(BeaconError::NotNewer);
            }
        }
        self.anchor = Some(anchor);
        Ok(anchor)
    }
}
