//! # peregrine-consensus — Stoop BFT (bootstrap edition)
//!
//! Uncertified-DAG consensus in the Mysticeti lineage (design doc §4.2).
//!
//! ## What is real in this bootstrap
//! * The DAG structure itself: signed vertices, parent quorum rule,
//!   round advancement, causal-history traversal.
//! * **Implicit voting**: a vertex at round `r+1` *votes for* every vertex
//!   in its causal history — there are no separate vote messages.
//! * A working commit rule (see [`committer`]) with deterministic total
//!   ordering of committed payloads.
//!
//! * The **skip / undecided cascade** commit rule ([`committer`]):
//!   certificate-based direct decisions with an indirect fallback so a
//!   crashed or partitioned leader is skipped rather than stalling the
//!   frontier. Crash-fault-live under partial synchrony.
//!
//! ## What is deliberately simplified (and where it goes next)
//! * Leader schedule is `round % committee_size` — production uses
//!   stake × proven-capacity weighted selection.
//! * Anchors are one-per-round with sequential decisions; production
//!   pipelines multiple commit slots per round.
//! * Equivocation is detected and surfaced, not yet slashed.

pub mod committer;
pub mod dag;
pub mod vertex;

pub use committer::{CommitObserver, Committer, Decision};
pub use dag::{Dag, DagError};
pub use vertex::{Payload, PayloadItem, Vertex, VertexHeader};
