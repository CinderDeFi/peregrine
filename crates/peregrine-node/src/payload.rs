//! Wire encoding of consensus payload items.
//!
//! Consensus orders opaque bytes ([`peregrine_consensus::PayloadItem`]);
//! this module defines what those bytes *mean* to the node: either a
//! Slipstream shred or a Talon transaction. One enum, one codec, so the
//! execution pipeline has a single decode point.

use peregrine_data::streams::StreamShred;
use peregrine_interop::VerifiedClaim;
use peregrine_vm::Instr;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum WirePayload {
    /// A signed high-frequency data record riding consensus dissemination.
    Shred(StreamShred),
    /// A user transaction: a Talon program to execute.
    TalonTx { program: Vec<Instr> },
    /// A proof-carrying claim about another chain's state.
    ///
    /// Anyone may submit one — it needs no signature, because it carries its
    /// own proof. Every validator independently verifies it during commit and
    /// only then materializes it into `sys.eth_state`, so acceptance is a
    /// deterministic function of the payload and the node's pinned
    /// configuration.
    ForeignClaim(Box<VerifiedClaim>),
}

impl WirePayload {
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("payload serialize")
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        bincode::deserialize(bytes).ok()
    }
}
