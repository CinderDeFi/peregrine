//! The Stoop commit rule — skip / undecided cascade (partial-synchrony,
//! crash-fault-live).
//!
//! # Model
//! Anchors (leaders) are scheduled one per round: `leader(r) = r mod n`
//! (round-robin bootstrap; production weights by stake × proven capacity).
//! Consensus over an *uncertified* DAG: a block's parent links ARE its
//! votes — there are no separate vote messages.
//!
//! ## Certificate abstraction
//! For an anchor `L` at round `r`:
//! * a round `r+1` block **votes** for `L` iff `L ∈ parents(block)`;
//! * a round `r+2` block is a **certificate** for `L` iff a *stake quorum*
//!   (`> 2/3`) of its parents are votes for `L`.
//!
//! ## Direct decision (a pure function of the current DAG)
//! * **Commit** `L` iff certificate stake ≥ quorum.
//! * **Skip** `L` iff non-voter stake at `r+1` ≥ quorum. Once a quorum of
//!   `r+1` blocks omit `L`, voter stake can never reach a quorum (their
//!   sum is bounded by `total − quorum < quorum`), so no certificate can
//!   ever form — skipping is safe in *every* honest view. This also covers
//!   a crashed or late anchor (absent `L` ⇒ every `r+1` block is a
//!   non-voter).
//! * **Undecided** otherwise (not enough of the DAG has arrived yet).
//!
//! Both thresholds are **monotonic**: certificates and non-voters only
//! accumulate as more blocks arrive, so a decision, once made, never flips.
//! Commit and Skip are mutually exclusive (a certificate quorum forces
//! voter stake ≥ quorum, hence non-voter stake < quorum).
//!
//! ## Indirect decision (the cascade — this is what survives crashes)
//! An Undecided `L(r)` is resolved by the nearest **directly-committed**
//! anchor `A` at round `r' ≥ r+3`:
//! * **Commit** `L` iff `A`'s causal history contains a certificate for `L`;
//! * **Skip** `L` otherwise.
//!
//! Why `r+3` and not `r+1`? `A`'s causal history is guaranteed to hold a
//! full stake quorum at every round strictly below `r'` (union of parent
//! quorums). The certificate layer for `L` lives at `r+2`, so we need
//! `r+2 < r'`, i.e. `r' ≥ r+3`, for `A`'s history to contain a quorum of
//! `r+2` blocks. Given that, quorum intersection guarantees: **if any node
//! directly commits `L`, then every directly-committed `A` at `r' ≥ r+3`
//! has a certificate for `L` in its history** — so no node can indirectly
//! skip a leader another node committed. That is the agreement backbone.
//!
//! Liveness: after GST, some honest anchor at a round `≥ r+3` is eventually
//! directly committed, which deterministically resolves every earlier
//! Undecided anchor. A crashed validator's anchor rounds are skipped and
//! never stall the frontier.
//!
//! ## Ordering
//! Committing `L` linearizes its still-uncommitted causal history by
//! `(round, author)` (see [`Dag::causal_history_ordered`]). Skipped rounds
//! lose nothing: their vertices are swept in by the next committed anchor
//! whose history reaches them, in the same deterministic order on every
//! node.

use crate::dag::Dag;
use peregrine_core::{Hash, Round, ValidatorId};
use std::collections::HashSet;

/// Per-anchor decision. `Undecided` is a barrier: commit processing stops
/// at the first Undecided anchor and resumes when more of the DAG arrives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Commit,
    Skip,
    Undecided,
}

/// Receives totally-ordered committed vertices. Implemented by the node's
/// execution/data pipeline.
pub trait CommitObserver {
    fn on_commit(&mut self, round: Round, anchor: Hash, ordered: &[Hash], dag: &Dag);
}

/// Tracks commit progress over a DAG.
pub struct Committer {
    /// Next anchor round to attempt to decide.
    next_anchor_round: Round,
    /// Everything already emitted, so linearization never re-emits.
    committed: HashSet<Hash>,
    /// Committed anchors (metrics).
    pub commits: u64,
    /// Skipped anchors (metrics).
    pub skips: u64,
    /// How far ahead the indirect rule may scan for a deciding anchor.
    /// Purely a work bound; correctness does not depend on its value.
    indirect_scan_limit: Round,
}

impl Committer {
    pub fn new() -> Self {
        Self {
            next_anchor_round: 1,
            committed: HashSet::new(),
            commits: 0,
            skips: 0,
            indirect_scan_limit: 512,
        }
    }

    /// Round-robin anchor schedule.
    pub fn anchor_for_round(dag: &Dag, round: Round) -> ValidatorId {
        ValidatorId((round % dag.committee().size() as u64) as u16)
    }

    /// The last anchor round that has been decided (committed or skipped).
    pub fn last_decided_round(&self) -> Round {
        self.next_anchor_round.saturating_sub(1)
    }

    /// Advance commits as far as the DAG currently allows. Idempotent and
    /// safe to call after every insertion.
    pub fn try_commit<O: CommitObserver>(&mut self, dag: &Dag, observer: &mut O) {
        loop {
            let r = self.next_anchor_round;

            let decision = match self.direct_decision(dag, r) {
                Decision::Undecided => self.indirect_decision(dag, r),
                decided => decided,
            };

            match decision {
                Decision::Commit => {
                    self.commit_anchor(dag, r, observer);
                    self.next_anchor_round += 1;
                }
                Decision::Skip => {
                    tracing::debug!(round = r, "anchor skipped");
                    self.skips += 1;
                    self.next_anchor_round += 1;
                }
                // Barrier: cannot decide r yet — stop and wait for more DAG.
                Decision::Undecided => return,
            }
        }
    }

    /// Linearize and emit a committed anchor's uncommitted causal history.
    fn commit_anchor<O: CommitObserver>(&mut self, dag: &Dag, r: Round, observer: &mut O) {
        let anchor = Self::anchor_for_round(dag, r);
        let anchor_hash = dag
            .round_vertices(r)
            .and_then(|m| m.get(&anchor))
            .copied()
            .expect("a committed anchor is always present in the DAG");
        let ordered = dag.causal_history_ordered(&anchor_hash, &self.committed);
        for h in &ordered {
            self.committed.insert(*h);
        }
        self.commits += 1;
        observer.on_commit(r, anchor_hash, &ordered, dag);
    }

    // ── decision rules ──────────────────────────────────────────────────

    /// The direct rule: decide `L(r)` from certificates at `r+2` and
    /// non-votes at `r+1`, or return Undecided.
    fn direct_decision(&self, dag: &Dag, r: Round) -> Decision {
        let quorum = dag.committee().quorum_threshold();
        let anchor_hash = dag
            .round_vertices(r)
            .and_then(|m| m.get(&Self::anchor_for_round(dag, r)))
            .copied();

        // Commit test: a stake quorum of r+2 certificates for the anchor.
        if let Some(anchor) = anchor_hash {
            let cert_stake = self.certificate_stake(dag, &anchor, r);
            if cert_stake >= quorum {
                return Decision::Commit;
            }
        }

        // Skip test: a stake quorum of r+1 blocks that do NOT vote for the
        // anchor (absent anchor ⇒ all present r+1 blocks are non-voters).
        // Requires r+1 to actually hold a quorum, so we never skip before
        // the deciding round exists.
        if dag.round_stake(r + 1) >= quorum {
            let non_voter_stake = self.non_voter_stake(dag, anchor_hash.as_ref(), r);
            if non_voter_stake >= quorum {
                return Decision::Skip;
            }
        }

        Decision::Undecided
    }

    /// The indirect rule: resolve an Undecided `L(r)` via the nearest
    /// directly-committed anchor at round `≥ r+3`.
    fn indirect_decision(&self, dag: &Dag, r: Round) -> Decision {
        let anchor_hash = dag
            .round_vertices(r)
            .and_then(|m| m.get(&Self::anchor_for_round(dag, r)))
            .copied();

        let highest = dag.highest_round();
        let scan_end = (r + 3 + self.indirect_scan_limit).min(highest);
        let mut r2 = r + 3;
        while r2 <= scan_end {
            if self.direct_decision(dag, r2) == Decision::Commit {
                let decider = dag
                    .round_vertices(r2)
                    .and_then(|m| m.get(&Self::anchor_for_round(dag, r2)))
                    .copied()
                    .expect("directly-committed anchor is present");
                // Commit L iff the decider's causal history certifies L.
                return match anchor_hash {
                    Some(l) if self.history_certifies(dag, &decider, &l, r) => Decision::Commit,
                    _ => Decision::Skip,
                };
            }
            r2 += 1;
        }
        Decision::Undecided
    }

    // ── certificate helpers ─────────────────────────────────────────────

    /// Stake of round `r+2` blocks that are certificates for `anchor`
    /// (their parents include a quorum of `r+1` votes for the anchor).
    fn certificate_stake(&self, dag: &Dag, anchor: &Hash, r: Round) -> u64 {
        let certs: Vec<ValidatorId> = match dag.round_vertices(r + 2) {
            Some(blocks) => blocks
                .iter()
                .filter(|(_, c)| self.is_certificate(dag, anchor, r, c))
                .map(|(a, _)| *a)
                .collect(),
            None => return 0,
        };
        dag.committee().stake_of(certs.iter())
    }

    /// Is `c` (a round `r+2` block) a certificate for `anchor` (round `r`)?
    fn is_certificate(&self, dag: &Dag, anchor: &Hash, r: Round, c: &Hash) -> bool {
        let quorum = dag.committee().quorum_threshold();
        let Some(parents) = dag.parents(c) else {
            return false;
        };
        // Authors of parents that are r+1 votes for the anchor.
        let mut voters: Vec<ValidatorId> = Vec::new();
        for p in parents {
            if dag.round_of(p) == Some(r + 1) && self.votes_for(dag, anchor, p) {
                if let Some(a) = dag.author_of(p) {
                    voters.push(a);
                }
            }
        }
        voters.sort();
        voters.dedup();
        dag.committee().stake_of(voters.iter()) >= quorum
    }

    /// Does round `r+1` block `voter` directly vote for `anchor`?
    fn votes_for(&self, dag: &Dag, anchor: &Hash, voter: &Hash) -> bool {
        dag.parents(voter)
            .map(|ps| ps.contains(anchor))
            .unwrap_or(false)
    }

    /// Stake of round `r+1` blocks that do NOT vote for the anchor.
    fn non_voter_stake(&self, dag: &Dag, anchor: Option<&Hash>, r: Round) -> u64 {
        let non_voters: Vec<ValidatorId> = match dag.round_vertices(r + 1) {
            Some(blocks) => blocks
                .iter()
                .filter(|(_, h)| match anchor {
                    Some(a) => !self.votes_for(dag, a, h),
                    None => true, // absent anchor ⇒ nobody can vote for it
                })
                .map(|(a, _)| *a)
                .collect(),
            None => return 0,
        };
        dag.committee().stake_of(non_voters.iter())
    }

    /// Does `decider`'s causal history contain a certificate for the anchor
    /// `l` (round `r`)? Scans round `r+2` blocks reachable from `decider`.
    fn history_certifies(&self, dag: &Dag, decider: &Hash, l: &Hash, r: Round) -> bool {
        let Some(candidates) = dag.round_vertices(r + 2) else {
            return false;
        };
        for c in candidates.values() {
            if (c == decider || dag.reaches(decider, c)) && self.is_certificate(dag, l, r, c) {
                return true;
            }
        }
        false
    }
}

impl Default for Committer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vertex::{Payload, Vertex};
    use peregrine_core::{Committee, Keypair, ValidatorId, ValidatorInfo};
    use std::collections::HashMap;

    /// Deterministic DAG builder for adversarial scenarios. Every vertex is
    /// placed explicitly, so tests control exactly who references whom.
    struct Harness {
        keys: Vec<Keypair>,
        dag: Dag,
        placed: HashMap<(Round, u16), Hash>,
    }

    impl Harness {
        fn new(n: u16) -> Self {
            let mut rng = rand::rngs::OsRng;
            let keys: Vec<Keypair> = (0..n).map(|_| Keypair::generate(&mut rng)).collect();
            let committee = Committee::new(
                keys.iter()
                    .enumerate()
                    .map(|(i, kp)| ValidatorInfo {
                        id: ValidatorId(i as u16),
                        public_key: kp.public(),
                        stake: 100,
                    })
                    .collect(),
            );
            Self {
                keys,
                dag: Dag::new(committee, vec![]),
                placed: HashMap::new(),
            }
        }

        fn hash(&self, round: Round, author: u16) -> Hash {
            *self
                .placed
                .get(&(round, author))
                .expect("vertex was placed")
        }

        fn parent_hashes(&self, round: Round, authors: &[u16]) -> Vec<Hash> {
            authors.iter().map(|a| self.hash(round, *a)).collect()
        }

        /// Add author's vertex at `round` referencing `parent_authors` at
        /// `round-1` (empty for genesis). Returns Ok(hash) or the DagError.
        fn add(
            &mut self,
            author: u16,
            round: Round,
            parent_authors: &[u16],
        ) -> Result<Hash, crate::dag::DagError> {
            let parents = if round == 0 {
                vec![]
            } else {
                self.parent_hashes(round - 1, parent_authors)
            };
            let v = Vertex::new_signed(
                &self.keys[author as usize],
                ValidatorId(author),
                round,
                parents,
                Payload::default(),
            );
            let h = v.hash();
            let res = self.dag.insert(v);
            if res.is_ok() {
                self.placed.insert((round, author), h);
            }
            res
        }

        /// Convenience: place `authors` at `round`, each referencing exactly
        /// `parent_authors` from the previous round.
        fn round(&mut self, round: Round, authors: &[u16], parent_authors: &[u16]) {
            for a in authors {
                self.add(*a, round, parent_authors)
                    .expect("valid placement");
            }
        }
    }

    #[derive(Default)]
    struct Rec {
        commits: Vec<(Round, Hash)>,
        ordered: Vec<Hash>,
    }

    impl CommitObserver for Rec {
        fn on_commit(&mut self, round: Round, anchor: Hash, ordered: &[Hash], _dag: &Dag) {
            self.commits.push((round, anchor));
            self.ordered.extend_from_slice(ordered);
        }
    }

    const ALL: &[u16] = &[0, 1, 2, 3];

    /// Baseline: 4 honest validators, full rounds ⇒ every eligible anchor
    /// is directly committed and every vertex is linearized exactly once.
    #[test]
    fn all_honest_commits_every_anchor() {
        let mut h = Harness::new(4);
        h.round(0, ALL, &[]);
        for r in 1..=5 {
            h.round(r, ALL, ALL);
        }
        let mut c = Committer::new();
        let mut rec = Rec::default();
        c.try_commit(&h.dag, &mut rec);

        // r+2 present for anchors of rounds 1,2,3.
        assert_eq!(c.commits, 3, "anchors 1,2,3 commit directly");
        assert_eq!(c.skips, 0);
        assert_eq!(
            rec.commits.iter().map(|(r, _)| *r).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        // No duplicates in the linearization.
        let unique: HashSet<_> = rec.ordered.iter().collect();
        assert_eq!(unique.len(), rec.ordered.len(), "each vertex emitted once");
    }

    /// Crash fault: validator 2 never proposes. Its anchor rounds must be
    /// skipped while others commit — liveness is preserved.
    #[test]
    fn crashed_validator_skips_its_anchors() {
        let live = &[0u16, 1, 3];
        let mut h = Harness::new(4);
        h.round(0, live, &[]);
        for r in 1..=6 {
            h.round(r, live, live);
        }
        let mut c = Committer::new();
        let mut rec = Rec::default();
        c.try_commit(&h.dag, &mut rec);

        // leader(2) == v2 (crashed) ⇒ round 2 anchor is skipped.
        assert!(c.skips >= 1, "crashed leader's anchor skipped");
        assert!(
            !rec.commits.iter().any(|(r, _)| *r == 2),
            "round-2 anchor not committed"
        );
        // Liveness: rounds led by live validators still commit and advance.
        assert!(
            c.commits >= 2,
            "live anchors keep committing past the crash"
        );
        assert!(rec.commits.iter().any(|(r, _)| *r == 1));
        assert!(rec.commits.iter().any(|(r, _)| *r == 3));
        // No data loss: round-2 vertices from live validators are linearized
        // by the round-3 anchor's causal history.
        for a in live {
            assert!(
                rec.ordered.contains(&h.hash(2, *a)),
                "v{a}@r2 linearized despite skip"
            );
        }
    }

    /// A late anchor whose block exists but arrived after the next round was
    /// built without referencing it must be skipped, not stall the chain.
    #[test]
    fn late_anchor_is_skipped() {
        let mut h = Harness::new(4);
        h.round(0, ALL, &[]);
        h.round(1, ALL, ALL);
        // Anchor v2@r2 exists…
        h.round(2, ALL, ALL);
        // …but round 3 is built WITHOUT referencing v2 (it was late):
        // everyone parents {0,1,3} only ⇒ zero votes for v2.
        h.round(3, ALL, &[0, 1, 3]);
        h.round(4, ALL, ALL);
        h.round(5, ALL, ALL);

        let mut c = Committer::new();
        let mut rec = Rec::default();
        c.try_commit(&h.dag, &mut rec);

        // Non-voters at r3 = all 4 (400) ≥ quorum ⇒ direct skip of anchor 2.
        assert!(
            !rec.commits.iter().any(|(r, _)| *r == 2),
            "late anchor 2 skipped"
        );
        assert!(
            rec.commits.iter().any(|(r, _)| *r == 1),
            "earlier anchor still commits"
        );
        assert!(c.skips >= 1);
    }

    /// Equivocation: a second, different vertex by the same author at the
    /// same round is rejected and the author is flagged. Consensus over the
    /// honest blocks is unaffected.
    #[test]
    fn equivocator_is_rejected_and_safe() {
        let mut h = Harness::new(4);
        h.round(0, ALL, &[]);
        h.round(1, ALL, ALL);

        // v2 tries to equivocate at round 1 with a different parent set.
        let parents = h.parent_hashes(0, &[0, 1, 3]);
        let evil = Vertex::new_signed(&h.keys[2], ValidatorId(2), 1, parents, {
            let mut p = Payload::default();
            p.items
                .push(crate::vertex::PayloadItem(b"double-spend".to_vec()));
            p
        });
        let err = h.dag.insert(evil).expect_err("equivocation rejected");
        assert!(matches!(
            err,
            crate::dag::DagError::Equivocation(ValidatorId(2), 1)
        ));
        assert!(h.dag.equivocators().contains(&ValidatorId(2)));

        // Consensus still makes progress on the honest DAG.
        for r in 2..=4 {
            h.round(r, ALL, ALL);
        }
        let mut c = Committer::new();
        let mut rec = Rec::default();
        c.try_commit(&h.dag, &mut rec);
        assert!(
            c.commits >= 1,
            "honest anchors commit despite the equivocation attempt"
        );
    }

    /// Partition / delayed messages: with only 2 votes present the anchor is
    /// Undecided (barrier). After the delayed blocks heal the partition, the
    /// same anchor commits — no divergence, no premature decision.
    #[test]
    fn delayed_messages_resolve_after_heal() {
        let mut h = Harness::new(4);
        h.round(0, ALL, &[]);
        h.round(1, ALL, ALL);
        // Partition: only v0,v1 land at round 2 (200 < quorum), so round 3
        // cannot even form. Anchor 1 is Undecided.
        h.round(2, &[0, 1], ALL);

        let mut c = Committer::new();
        let mut rec = Rec::default();
        c.try_commit(&h.dag, &mut rec);
        assert_eq!(c.commits, 0, "anchor undecided under partition — no commit");
        assert_eq!(c.skips, 0, "and not wrongly skipped");

        // Heal: the delayed round-2 blocks arrive, then rounds 3,4 fill in.
        h.add(2, 2, ALL).unwrap();
        h.add(3, 2, ALL).unwrap();
        h.round(3, ALL, ALL);
        h.round(4, ALL, ALL);

        c.try_commit(&h.dag, &mut rec);
        assert!(
            rec.commits.iter().any(|(r, _)| *r == 1),
            "anchor 1 commits after heal"
        );
    }

    /// The indirect cascade: an anchor that is Undecided by the direct rule
    /// (a quorum of votes exists but only one certificate is present) is
    /// later committed via a downstream directly-committed anchor whose
    /// causal history contains a certificate for it.
    #[test]
    fn undecided_anchor_committed_indirectly() {
        let mut h = Harness::new(4);
        h.round(0, ALL, &[]);
        h.round(1, ALL, ALL); // anchor L = v1@r1

        // Round 2 votes: v0,v1,v2 reference v1 (votes); v3 omits v1.
        h.add(0, 2, ALL).unwrap();
        h.add(1, 2, ALL).unwrap();
        h.add(2, 2, ALL).unwrap();
        h.add(3, 2, &[0, 2, 3]).unwrap(); // non-voter for L

        // Round 3: exactly ONE certificate for L (v0 references the three
        // voters v0,v1,v2). The others reference only two voters ⇒ not certs.
        h.add(0, 3, &[0, 1, 2]).unwrap(); // cert (3 votes)
        h.add(1, 3, &[0, 1, 3]).unwrap(); // votes {0,1} → not a cert
        h.add(2, 3, &[0, 2, 3]).unwrap(); // votes {0,2} → not a cert
        h.add(3, 3, &[1, 2, 3]).unwrap(); // votes {1,2} → not a cert

        // Phase 1: cert stake = 100 < quorum, non-voter = 100 < quorum.
        let mut c = Committer::new();
        let mut rec = Rec::default();
        c.try_commit(&h.dag, &mut rec);
        assert_eq!(
            c.commits, 0,
            "anchor L is Undecided — one cert is not a quorum"
        );

        // Build a clean downstream so a later anchor commits directly and
        // its history reaches the single certificate v0@r3.
        h.round(4, ALL, ALL);
        h.round(5, ALL, ALL);
        h.round(6, ALL, ALL);

        // Phase 2: anchor v0@r4 commits directly; its history contains the
        // certificate v0@r3 for L ⇒ L is committed indirectly.
        c.try_commit(&h.dag, &mut rec);
        assert!(
            rec.commits.iter().any(|(r, _)| *r == 1),
            "Undecided anchor L committed via the indirect cascade"
        );
    }
}
