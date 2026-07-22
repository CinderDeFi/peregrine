//! Wire encoding of consensus payload items.
//!
//! Consensus orders opaque bytes ([`peregrine_consensus::PayloadItem`]);
//! this module defines what those bytes *mean* to the node: either a
//! Slipstream shred or a Talon transaction. One enum, one codec, so the
//! execution pipeline has a single decode point.

use peregrine_core::{Hash, Signature};
use peregrine_data::sessions::{SignedAction, SignedGrant};
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
    /// A principal delegates to a session key (see [`peregrine_data::sessions`]).
    ///
    /// Boxed because a grant carries two public keys plus a scope list, and an
    /// unboxed variant would make every payload as large as the biggest one.
    OpenSession(Box<SignedGrant>),
    /// A principal revokes one of its sessions. Signed by the **principal**,
    /// never the session key — a compromised session must not be able to
    /// manipulate its own revocation.
    RevokeSession {
        session_id: Hash,
        /// Principal's signature over `REVOKE_DOMAIN || session_id`.
        signature: Signature,
    },
    /// An action authorised by a session key.
    SessionAction(Box<SignedAction>),
}

impl WirePayload {
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("payload serialize")
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        bincode::deserialize(bytes).ok()
    }
}
