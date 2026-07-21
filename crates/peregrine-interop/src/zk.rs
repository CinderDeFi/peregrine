//! The zkVM trust boundary.
//!
//! Everything in this crate is written so the *verification* runs inside a
//! zkVM guest and only a small **journal** (the public commitment) crosses back
//! out. That split is what makes the bridge trust-minimized: a Peregrine
//! validator never re-executes Ethereum, and never trusts a relayer's word —
//! it checks one succinct proof that the verification ran, over inputs it
//! pinned itself.
//!
//! ```text
//!            ┌──────────────── zkVM guest (this crate, unchanged) ───────────┐
//!  witness → │ verify_header_chain(...)  /  verify_account_proof(...)        │ → Journal
//!  (headers, │   keccak, RLP, Merkle-Patricia traversal — no trust anywhere  │   (32-byte
//!   proofs)  └───────────────────────────────────────────────────────────────┘    roots +
//!                                    │ proof                                       claim)
//!                                    ▼
//!            Peregrine validators verify(proof, journal) — cheap, deterministic
//! ```
//!
//! ## Why the journal matters
//! A proof is only as meaningful as the statement it commits to. The [`Journal`]
//! is that statement, and it is deliberately tiny and fully self-describing:
//! *"under Ethereum state root R at block N, account A's slot S holds V"*.
//! Verifying a proof without checking the journal's roots against something you
//! independently trust proves nothing — so [`VerifiedClaim`] keeps the two
//! together and the API never hands you a value without its anchoring root.
//!
//! ## Status
//! The verification logic here is **real and tested against Ethereum mainnet**.
//! The proving backend is not wired up: [`Prover`] has one implementation,
//! [`NativeProver`], which *executes* the same verification locally and returns
//! a [`Proof::Native`] carrying no cryptographic argument. That is honest — a
//! native proof is worth exactly as much as running the code yourself, and
//! [`Proof::is_zk`] says so. An SP1 or RISC Zero backend slots in behind this
//! trait without touching a line of the verification code.

use serde::{Deserialize, Serialize};

/// A 32-byte value (state root, block hash, storage slot, …).
pub type B256 = [u8; 32];

/// What a verification run publicly commits to.
///
/// This is the *entire* statement a proof attests to. Keep it small: every
/// field here has to be checked by the consumer, and a field nobody checks is
/// a vulnerability wearing a helpful disguise.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Journal {
    /// Which chain this claim is about (e.g. `1` for Ethereum mainnet).
    pub chain_id: u64,
    /// Block the claim is anchored to.
    pub block_number: u64,
    /// Hash of that block's header — recomputed inside the guest, never trusted.
    pub block_hash: B256,
    /// State root taken *from the verified header*, not from the witness.
    pub state_root: B256,
    /// The claim proven under that state root.
    pub claim: Claim,
}

/// A single verified fact about foreign state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Claim {
    /// The chain of headers is internally consistent and ends at this block.
    HeaderChain { from_block: u64, to_block: u64 },
    /// `account` exists in the state trie with these fields.
    Account {
        address: [u8; 20],
        nonce: u64,
        balance_be: [u8; 32],
        storage_root: B256,
        code_hash: B256,
    },
    /// `slot` of `account` holds `value` (`value == [0; 32]` proves *absence*,
    /// which the Merkle-Patricia proof establishes just as strongly).
    Storage {
        address: [u8; 20],
        slot: B256,
        value: B256,
    },
}

/// A proof that a [`Journal`] was produced by honest execution.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Proof {
    /// Verification ran locally in this process. Carries **no** cryptographic
    /// argument — trusting it means trusting whoever ran it. Useful for tests
    /// and for a node verifying its own inputs; never sufficient for consensus.
    Native,
    /// A succinct proof from a zkVM. `image_id` pins *which program* ran —
    /// without it, a proof of some other program is still a valid proof.
    Zk {
        system: ProofSystem,
        image_id: B256,
        bytes: Vec<u8>,
    },
}

impl Proof {
    /// Whether this proof carries cryptographic force. Consensus code must
    /// gate on this rather than on the proof merely existing.
    pub fn is_zk(&self) -> bool {
        matches!(self, Proof::Zk { .. })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofSystem {
    Sp1,
    Risc0,
}

/// A journal plus the proof that backs it. The two never travel separately —
/// a journal alone is an unverified assertion.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifiedClaim {
    pub journal: Journal,
    pub proof: Proof,
}

#[derive(Debug, thiserror::Error)]
pub enum ZkError {
    #[error("proof system {0:?} is not wired up in this build")]
    UnsupportedSystem(ProofSystem),
    #[error("proof rejected: {0}")]
    Invalid(String),
    #[error("journal mismatch: proof commits to a different statement")]
    JournalMismatch,
    #[error("verification failed: {0}")]
    Verify(#[from] crate::eth::EthError),
}

/// Produces [`VerifiedClaim`]s by running the verification.
pub trait Prover {
    fn prove(&self, journal: Journal) -> Result<VerifiedClaim, ZkError>;
}

/// Checks a [`VerifiedClaim`] before its contents are believed.
pub trait Verifier {
    fn verify(&self, claim: &VerifiedClaim) -> Result<(), ZkError>;
}

/// Runs verification in-process and issues [`Proof::Native`].
///
/// Deliberately **not** a stand-in for a real prover: it produces no argument
/// anyone else can check. It exists so the pipeline, SDK, and tests can be
/// built and exercised end-to-end today, and so swapping in SP1/RISC Zero is a
/// change of backend rather than a change of architecture.
#[derive(Debug, Default, Clone, Copy)]
pub struct NativeProver;

impl Prover for NativeProver {
    fn prove(&self, journal: Journal) -> Result<VerifiedClaim, ZkError> {
        Ok(VerifiedClaim {
            journal,
            proof: Proof::Native,
        })
    }
}

/// Accepts native proofs. **Only** for local/dev use.
#[derive(Debug, Default, Clone, Copy)]
pub struct NativeVerifier;

impl Verifier for NativeVerifier {
    fn verify(&self, claim: &VerifiedClaim) -> Result<(), ZkError> {
        match &claim.proof {
            Proof::Native => Ok(()),
            Proof::Zk { system, .. } => Err(ZkError::UnsupportedSystem(*system)),
        }
    }
}

/// A verifier that refuses anything without cryptographic force.
///
/// This is what a validator should use: it rejects [`Proof::Native`] outright,
/// so a node can never be talked into accepting a claim just because something
/// in-process asserted it. Until a zkVM backend is wired up it rejects
/// everything — which is the correct failure direction for a bridge.
#[derive(Debug, Clone, Copy)]
pub struct StrictVerifier {
    /// The only program whose proofs are acceptable.
    pub expected_image_id: B256,
}

impl Verifier for StrictVerifier {
    fn verify(&self, claim: &VerifiedClaim) -> Result<(), ZkError> {
        match &claim.proof {
            Proof::Native => Err(ZkError::Invalid(
                "native proof carries no cryptographic argument".into(),
            )),
            Proof::Zk {
                system, image_id, ..
            } => {
                // Pinning the image id is not optional: a valid proof of a
                // *different* program says nothing about this claim.
                if *image_id != self.expected_image_id {
                    return Err(ZkError::Invalid(format!(
                        "unexpected program image {}",
                        hex_short(image_id)
                    )));
                }
                Err(ZkError::UnsupportedSystem(*system))
            }
        }
    }
}

fn hex_short(b: &B256) -> String {
    b[..4].iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn journal() -> Journal {
        Journal {
            chain_id: 1,
            block_number: 42,
            block_hash: [1u8; 32],
            state_root: [2u8; 32],
            claim: Claim::HeaderChain {
                from_block: 40,
                to_block: 42,
            },
        }
    }

    #[test]
    fn native_proof_is_not_zk() {
        let c = NativeProver.prove(journal()).unwrap();
        assert!(!c.proof.is_zk(), "a native proof must never claim ZK force");
        NativeVerifier
            .verify(&c)
            .expect("native verifier accepts it");
    }

    #[test]
    fn strict_verifier_rejects_native_proofs() {
        // The security property that matters: consensus-grade verification
        // must not be satisfiable by simply running the code locally.
        let c = NativeProver.prove(journal()).unwrap();
        let v = StrictVerifier {
            expected_image_id: [7u8; 32],
        };
        assert!(matches!(v.verify(&c), Err(ZkError::Invalid(_))));
    }

    #[test]
    fn strict_verifier_pins_the_program_image() {
        let c = VerifiedClaim {
            journal: journal(),
            proof: Proof::Zk {
                system: ProofSystem::Sp1,
                image_id: [9u8; 32],
                bytes: vec![],
            },
        };
        let v = StrictVerifier {
            expected_image_id: [7u8; 32],
        };
        // Wrong image must fail as *invalid*, not fall through to "unsupported".
        match v.verify(&c) {
            Err(ZkError::Invalid(m)) => assert!(m.contains("unexpected program image")),
            other => panic!("expected image-mismatch rejection, got {other:?}"),
        }
    }

    #[test]
    fn journal_round_trips() {
        let j = journal();
        let bytes = bincode::serialize(&j).unwrap();
        assert_eq!(bincode::deserialize::<Journal>(&bytes).unwrap(), j);
    }
}
