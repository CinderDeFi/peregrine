//! The local DAG store: validated vertices indexed by hash and by round,
//! with causal-history traversal and equivocation detection.
//!
//! Concurrency note: bootstrap uses a plain struct guarded by the caller
//! (each simulated validator owns its DAG). The production path is a
//! sharded, lock-free store living inside the commit tile.

use crate::vertex::Vertex;
use peregrine_core::{Committee, Hash, Round, ValidatorId};
use std::collections::{BTreeMap, HashMap, HashSet};

#[derive(Debug, thiserror::Error)]
pub enum DagError {
    #[error("vertex {0:?} has missing parent {1:?}")]
    MissingParent(Hash, Hash),
    #[error("parents of vertex {0:?} do not form a stake quorum")]
    InsufficientParentQuorum(Hash),
    #[error("vertex {vertex:?} has parent {parent:?} at round {parent_round}, expected {expected_round} (DAG must be layered)")]
    NonLayeredParent {
        vertex: Hash,
        parent: Hash,
        parent_round: Round,
        expected_round: Round,
    },
    #[error("vertex verification failed: {0}")]
    InvalidVertex(String),
    #[error("unknown author {0:?}")]
    UnknownAuthor(ValidatorId),
    #[error("equivocation: {0:?} produced two vertices at round {1}")]
    Equivocation(ValidatorId, Round),
}

/// The per-node DAG.
pub struct Dag {
    committee: Committee,
    /// All vertices by identity hash.
    vertices: HashMap<Hash, Vertex>,
    /// Round -> author -> vertex hash. BTreeMap keeps rounds ordered for
    /// commit traversal and pruning.
    by_round: BTreeMap<Round, HashMap<ValidatorId, Hash>>,
    /// Detected equivocators (kept so we surface, and later slash).
    equivocators: HashSet<ValidatorId>,
}

impl Dag {
    /// Create a DAG seeded with the genesis vertices (round 0, no parents).
    pub fn new(committee: Committee, genesis: Vec<Vertex>) -> Self {
        let mut dag = Self {
            committee,
            vertices: HashMap::new(),
            by_round: BTreeMap::new(),
            equivocators: HashSet::new(),
        };
        for v in genesis {
            let h = v.hash();
            dag.by_round
                .entry(0)
                .or_default()
                .insert(v.header.author, h);
            dag.vertices.insert(h, v);
        }
        dag
    }

    pub fn committee(&self) -> &Committee {
        &self.committee
    }

    /// Validate and insert a vertex.
    ///
    /// Checks, in order:
    /// 1. author is known and the signature verifies,
    /// 2. all parents are present locally (round `r-1`),
    /// 3. parents represent a stake quorum of round `r-1`,
    /// 4. the author has not already produced a different vertex this round
    ///    (equivocation → recorded, insert rejected).
    pub fn insert(&mut self, vertex: Vertex) -> Result<Hash, DagError> {
        let h = vertex.hash();
        if self.vertices.contains_key(&h) {
            return Ok(h); // idempotent
        }

        let author = vertex.header.author;
        let info = self
            .committee
            .validator(author)
            .ok_or(DagError::UnknownAuthor(author))?;
        vertex
            .verify(&info.public_key)
            .map_err(|e| DagError::InvalidVertex(e.to_string()))?;

        let round = vertex.header.round;
        if round > 0 {
            // Parents must exist and form a quorum of the previous round.
            let mut parent_authors: Vec<ValidatorId> = Vec::new();
            for p in &vertex.header.parents {
                let pv = self.vertices.get(p).ok_or(DagError::MissingParent(h, *p))?;
                // AUDIT H-1: the DAG must be layered — every parent of a round-`r`
                // vertex sits at round `r-1`. This is load-bearing: the commit
                // rule's safety argument (see `committer.rs`) assumes it when it
                // reasons that an anchor's causal history holds a stake quorum at
                // *every* round below it, and `Dag::reaches` assumes parents
                // strictly decrease in round. A `debug_assert` here compiled the
                // check out of release builds, letting a Byzantine author submit a
                // signed vertex with cross-round parents. It is now a hard error.
                if pv.header.round != round - 1 {
                    return Err(DagError::NonLayeredParent {
                        vertex: h,
                        parent: *p,
                        parent_round: pv.header.round,
                        expected_round: round - 1,
                    });
                }
                parent_authors.push(pv.header.author);
            }
            parent_authors.sort();
            parent_authors.dedup();
            let stake = self.committee.stake_of(parent_authors.iter());
            if stake < self.committee.quorum_threshold() {
                return Err(DagError::InsufficientParentQuorum(h));
            }
        }

        // Equivocation check: one vertex per author per round.
        let slot = self.by_round.entry(round).or_default();
        if let Some(existing) = slot.get(&author) {
            if *existing != h {
                self.equivocators.insert(author);
                return Err(DagError::Equivocation(author, round));
            }
        }
        slot.insert(author, h);
        self.vertices.insert(h, vertex);
        Ok(h)
    }

    pub fn get(&self, hash: &Hash) -> Option<&Vertex> {
        self.vertices.get(hash)
    }

    /// All vertices at a round (author -> hash).
    pub fn round_vertices(&self, round: Round) -> Option<&HashMap<ValidatorId, Hash>> {
        self.by_round.get(&round)
    }

    /// Total stake of authors that have produced a vertex at `round`.
    pub fn round_stake(&self, round: Round) -> u64 {
        match self.by_round.get(&round) {
            Some(m) => self.committee.stake_of(m.keys()),
            None => 0,
        }
    }

    /// True if `ancestor` is in the causal history of `descendant`
    /// (or equal). Bounded BFS over parent links.
    pub fn reaches(&self, descendant: &Hash, ancestor: &Hash) -> bool {
        if descendant == ancestor {
            return true;
        }
        let target_round = match self.vertices.get(ancestor) {
            Some(v) => v.header.round,
            None => return false,
        };
        let mut stack = vec![*descendant];
        let mut seen = HashSet::new();
        while let Some(h) = stack.pop() {
            if !seen.insert(h) {
                continue;
            }
            if let Some(v) = self.vertices.get(&h) {
                if v.header.round <= target_round {
                    continue; // can't reach an equal-or-higher round via parents
                }
                for p in &v.header.parents {
                    if p == ancestor {
                        return true;
                    }
                    stack.push(*p);
                }
            }
        }
        false
    }

    /// Deterministic linearization of the causal history of `tip` that is
    /// not already in `committed`. Order: (round, author) ascending — every
    /// correct node computes the identical sequence, which is what turns a
    /// partially-ordered DAG into a totally-ordered ledger.
    pub fn causal_history_ordered(&self, tip: &Hash, committed: &HashSet<Hash>) -> Vec<Hash> {
        let mut out: Vec<(Round, ValidatorId, Hash)> = Vec::new();
        let mut stack = vec![*tip];
        let mut seen = HashSet::new();
        while let Some(h) = stack.pop() {
            if committed.contains(&h) || !seen.insert(h) {
                continue;
            }
            if let Some(v) = self.vertices.get(&h) {
                out.push((v.header.round, v.header.author, h));
                for p in &v.header.parents {
                    stack.push(*p);
                }
            }
        }
        out.sort();
        out.into_iter().map(|(_, _, h)| h).collect()
    }

    /// Direct parents of a vertex, if present. Used by the commit rule to
    /// test *direct* votes (an `r+1` block votes for an anchor iff the
    /// anchor is one of its parents).
    pub fn parents(&self, h: &Hash) -> Option<&[Hash]> {
        self.vertices.get(h).map(|v| v.header.parents.as_slice())
    }

    pub fn author_of(&self, h: &Hash) -> Option<ValidatorId> {
        self.vertices.get(h).map(|v| v.header.author)
    }

    pub fn round_of(&self, h: &Hash) -> Option<Round> {
        self.vertices.get(h).map(|v| v.header.round)
    }

    pub fn contains(&self, h: &Hash) -> bool {
        self.vertices.contains_key(h)
    }

    /// Highest round for which we hold at least one vertex.
    pub fn highest_round(&self) -> Round {
        self.by_round.keys().next_back().copied().unwrap_or(0)
    }

    /// The highest-round vertex authored by `id` that we currently hold.
    ///
    /// A node's *own* tip is what it re-announces when the mesh has gone quiet
    /// (see the restart-liveness backstop in `validator.rs`): peers that are
    /// waiting on exactly that vertex learn it, and peers that are further
    /// behind discover the gap through its parents. Walking rounds downward
    /// stops at the first hit, which for our own tip is the top of the DAG.
    pub fn latest_by(&self, id: ValidatorId) -> Option<&Vertex> {
        self.by_round
            .iter()
            .rev()
            .find_map(|(_, authors)| authors.get(&id))
            .and_then(|h| self.vertices.get(h))
    }

    /// True if we already hold a vertex authored by `id` at `round`. The
    /// proposal path checks this so a node never authors a *second* vertex for
    /// a round it has re-learned one of its own vertices for.
    pub fn has_vertex_by(&self, id: ValidatorId, round: Round) -> bool {
        self.by_round
            .get(&round)
            .map(|authors| authors.contains_key(&id))
            .unwrap_or(false)
    }

    /// Parent hashes of `vertex` that we do NOT yet hold locally — the set a
    /// validator asks its peers for during ancestor fetch.
    pub fn missing_parents(&self, vertex: &Vertex) -> Vec<Hash> {
        vertex
            .header
            .parents
            .iter()
            .filter(|p| !self.vertices.contains_key(p))
            .copied()
            .collect()
    }

    pub fn equivocators(&self) -> &HashSet<ValidatorId> {
        &self.equivocators
    }

    /// Every vertex currently held, cloned — the durable form a node persists
    /// so it can rebuild an identical DAG after a restart. Re-inserting these
    /// in round order (via [`insert`](Self::insert)) reconstructs both indexes
    /// and re-runs validation, so a corrupt vertex can never enter on reload.
    pub fn all_vertices(&self) -> Vec<Vertex> {
        self.vertices.values().cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.vertices.len()
    }

    pub fn is_empty(&self) -> bool {
        self.vertices.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vertex::{Payload, Vertex};
    use peregrine_core::{Keypair, ValidatorInfo};

    fn committee(keys: &[Keypair]) -> Committee {
        Committee::new(
            keys.iter()
                .enumerate()
                .map(|(i, kp)| ValidatorInfo {
                    id: ValidatorId(i as u16),
                    public_key: kp.public(),
                    stake: 100,
                })
                .collect(),
        )
    }

    /// AUDIT H-1: a signed vertex whose parents skip a round must be rejected in
    /// **every** build, not only in debug. Before the fix this was a
    /// `debug_assert` and the vertex was accepted in release.
    #[test]
    fn a_vertex_with_a_non_layered_parent_is_rejected() {
        let mut rng = rand::rngs::OsRng;
        let keys: Vec<Keypair> = (0..4).map(|_| Keypair::generate(&mut rng)).collect();
        let mut dag = Dag::new(committee(&keys), vec![]);

        // Round 0: a full genesis quorum.
        let mut r0: Vec<Hash> = Vec::new();
        for (i, kp) in keys.iter().enumerate() {
            let v = Vertex::new_signed(kp, ValidatorId(i as u16), 0, vec![], Payload::default());
            r0.push(dag.insert(v).expect("genesis inserts"));
        }

        // A round-*2* vertex whose parents are the round-0 genesis quorum — a
        // real stake quorum, correctly signed, but from the wrong round. It must
        // be refused because it is not layered onto round 1.
        let evil = Vertex::new_signed(&keys[0], ValidatorId(0), 2, r0.clone(), Payload::default());
        let err = dag
            .insert(evil)
            .expect_err("non-layered parent must be rejected");
        assert!(
            matches!(
                err,
                DagError::NonLayeredParent {
                    parent_round: 0,
                    expected_round: 1,
                    ..
                }
            ),
            "expected NonLayeredParent, got {err:?}"
        );
    }

    /// The two accessors the restart path leans on: `latest_by` finds the vertex
    /// a stalled node re-announces, and `has_vertex_by` is the guard that stops
    /// it authoring a second vertex for a round it re-learned one of its own at
    /// (self-equivocation after an ungraceful stop).
    #[test]
    fn own_tip_lookup_and_duplicate_round_guard() {
        let mut rng = rand::rngs::OsRng;
        let keys: Vec<Keypair> = (0..4).map(|_| Keypair::generate(&mut rng)).collect();
        let mut dag = Dag::new(committee(&keys), vec![]);
        let me = ValidatorId(1);

        assert!(dag.latest_by(me).is_none(), "no vertices yet");
        assert!(!dag.has_vertex_by(me, 0));

        let mut r0: Vec<Hash> = Vec::new();
        for (i, kp) in keys.iter().enumerate() {
            let v = Vertex::new_signed(kp, ValidatorId(i as u16), 0, vec![], Payload::default());
            r0.push(dag.insert(v).expect("genesis"));
        }
        assert_eq!(dag.latest_by(me).expect("tip").header.round, 0);
        assert!(dag.has_vertex_by(me, 0));
        assert!(!dag.has_vertex_by(me, 1));

        // Only *some* authors advance to round 1 — `latest_by` must report each
        // author's own highest round, not the DAG's.
        for (i, kp) in keys.iter().enumerate().take(3) {
            let v =
                Vertex::new_signed(kp, ValidatorId(i as u16), 1, r0.clone(), Payload::default());
            dag.insert(v).expect("round 1");
        }
        assert_eq!(dag.latest_by(me).expect("tip").header.round, 1);
        assert_eq!(dag.latest_by(me).expect("tip").header.author, me);
        assert!(dag.has_vertex_by(me, 1));
        assert_eq!(
            dag.latest_by(ValidatorId(3)).expect("tip").header.round,
            0,
            "an author that did not advance still reports its own tip"
        );
    }

    /// The honest, layered path still works: round-1 parents for a round-2 vertex.
    #[test]
    fn a_correctly_layered_vertex_is_accepted() {
        let mut rng = rand::rngs::OsRng;
        let keys: Vec<Keypair> = (0..4).map(|_| Keypair::generate(&mut rng)).collect();
        let mut dag = Dag::new(committee(&keys), vec![]);

        let mut r0: Vec<Hash> = Vec::new();
        for (i, kp) in keys.iter().enumerate() {
            let v = Vertex::new_signed(kp, ValidatorId(i as u16), 0, vec![], Payload::default());
            r0.push(dag.insert(v).expect("genesis"));
        }
        let mut r1: Vec<Hash> = Vec::new();
        for (i, kp) in keys.iter().enumerate() {
            let v =
                Vertex::new_signed(kp, ValidatorId(i as u16), 1, r0.clone(), Payload::default());
            r1.push(dag.insert(v).expect("round 1 layers onto round 0"));
        }
        let v2 = Vertex::new_signed(&keys[0], ValidatorId(0), 2, r1.clone(), Payload::default());
        assert!(
            dag.insert(v2).is_ok(),
            "a layered round-2 vertex is accepted"
        );
    }
}
