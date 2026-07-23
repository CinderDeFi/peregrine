//! # Institutional compliance hooks
//!
//! Optional, minimal-trust KYC/AML attestations. An **attester** — a KYC
//! provider, a bank's compliance desk, a regulator — signs a statement about a
//! subject account, and that statement is committed to a well-known table so
//! anyone can prove it against the store root.
//!
//! ```text
//!   attester ──signs──▶ Attestation { subject, status, scheme, expires_round }
//!                            │  submitted, signature verified on commit
//!                            ▼
//!   sys.compliance[ subject ‖ attester ] = flag(status, scheme, expires)
//! ```
//!
//! ## No global authority — you choose whom to trust
//!
//! There is deliberately **no privileged, chain-wide KYC oracle.** The chain
//! records *signed* attestations; it does not judge which attesters are
//! legitimate. An institution that "requires compliance" requires a valid
//! attestation **from an attester it has chosen**, which is why the table is
//! keyed by `(subject, attester)`: requiring attester *X* is reading *X*'s cell
//! for the subject, and a different attester's say-so simply lands in a
//! different cell that the institution never consults.
//!
//! ## Time is rounds, never wall-clock
//!
//! Like sessions ([`crate::sessions`]), expiry is a committed [`Round`], not a
//! timestamp — the only clock every validator agrees on. A wall-clock expiry
//! would lapse at a different point in the committed order on each validator and
//! fork the chain.
//!
//! ## Two ways to enforce
//!
//! * **Off-chain** — a verifier holding only the store root runs
//!   [`CompliancePolicy::gate`] against a [`ProvenRead`] of the cell. Minimal
//!   trust: the root, plus the attester it chose.
//! * **On-chain** — the data plane consults committed state during commit via
//!   [`CompliancePolicy::require_compliant`], so a gated transfer or claim is
//!   refused deterministically on every validator.

use crate::tables::{ProvenRead, TableId};
use peregrine_core::{crypto, PublicKey, Round, Signature};
use serde::{Deserialize, Serialize};

/// Domain tag for an attestation signature — never mistakable for a session
/// grant, a stream record, or any other signed object.
pub const ATTEST_DOMAIN: &[u8] = b"peregrine.compliance.attest.v1";

/// The well-known table holding compliance flags, readable and provable like
/// any other Peregrine table.
pub fn compliance_table() -> TableId {
    TableId::named("sys.compliance")
}

/// The cell address for a `(subject, attester)` pair. Binding the attester into
/// the key is what makes "require attester X" a local read rather than a trust
/// decision the chain has to make.
pub fn cell_key(subject: &PublicKey, attester: &PublicKey) -> Vec<u8> {
    let mut k = Vec::with_capacity(64);
    k.extend_from_slice(&subject.0);
    k.extend_from_slice(&attester.0);
    k
}

/// A KYC/AML verdict. `Verified` is the only status that passes a gate; the
/// others exist so a rejection or a pending review is *stated* rather than
/// looking like an absent attestation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComplianceStatus {
    Unverified,
    Pending,
    Verified,
    Rejected,
}

impl ComplianceStatus {
    /// Only `Verified` clears a compliance gate.
    pub fn is_compliant(self) -> bool {
        matches!(self, ComplianceStatus::Verified)
    }

    pub fn code(self) -> u8 {
        match self {
            ComplianceStatus::Unverified => 0,
            ComplianceStatus::Pending => 1,
            ComplianceStatus::Verified => 2,
            ComplianceStatus::Rejected => 3,
        }
    }

    pub fn from_code(c: u8) -> Option<Self> {
        Some(match c {
            0 => ComplianceStatus::Unverified,
            1 => ComplianceStatus::Pending,
            2 => ComplianceStatus::Verified,
            3 => ComplianceStatus::Rejected,
            _ => return None,
        })
    }
}

/// An attester's signed statement about a subject account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceAttestation {
    /// The account being attested.
    pub subject: PublicKey,
    /// The attester making the statement (also the signer).
    pub attester: PublicKey,
    pub status: ComplianceStatus,
    /// An opaque scheme code so one attester can run several programmes
    /// (e.g. a retail KYC tier vs an institutional AML tier) without them being
    /// interchangeable. `0` means "unspecified".
    pub scheme: u16,
    /// First round at which the attestation is valid.
    pub issued_round: Round,
    /// Last round at which it is valid, **inclusive**.
    pub expires_round: Round,
}

impl ComplianceAttestation {
    pub fn signing_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("attestation serialize")
    }

    /// The compact on-chain flag: `status ‖ scheme ‖ expires_round`. 11 bytes,
    /// so it fits the 32-byte value budget a light client / EVM row allows, and
    /// carries exactly what an on-chain gate needs to decide.
    pub fn flag_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(11);
        v.push(self.status.code());
        v.extend_from_slice(&self.scheme.to_le_bytes());
        v.extend_from_slice(&self.expires_round.to_le_bytes());
        v
    }

    /// Validity window check (independent of status): `issued ≤ now ≤ expires`.
    pub fn valid_at(&self, now: Round) -> Result<(), ComplianceError> {
        if now < self.issued_round {
            return Err(ComplianceError::NotYetValid {
                issued: self.issued_round,
                now,
            });
        }
        if now > self.expires_round {
            return Err(ComplianceError::Expired {
                expires: self.expires_round,
                now,
            });
        }
        Ok(())
    }
}

/// A decoded on-chain flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Flag {
    pub status: ComplianceStatus,
    pub scheme: u16,
    pub expires_round: Round,
}

/// Decode a flag written by [`ComplianceAttestation::flag_bytes`].
pub fn decode_flag(bytes: &[u8]) -> Result<Flag, ComplianceError> {
    if bytes.len() != 11 {
        return Err(ComplianceError::MalformedFlag);
    }
    let status = ComplianceStatus::from_code(bytes[0]).ok_or(ComplianceError::MalformedFlag)?;
    let scheme = u16::from_le_bytes([bytes[1], bytes[2]]);
    let expires_round = u64::from_le_bytes(bytes[3..11].try_into().unwrap());
    Ok(Flag {
        status,
        scheme,
        expires_round,
    })
}

/// An attestation plus the attester's signature over it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedAttestation {
    pub attestation: ComplianceAttestation,
    pub signature: Signature,
}

impl SignedAttestation {
    /// Sign an attestation with the attester's key.
    pub fn new(attester_key: &peregrine_core::Keypair, attestation: ComplianceAttestation) -> Self {
        debug_assert_eq!(
            attester_key.public(),
            attestation.attester,
            "attestation.attester must be the signing key"
        );
        let signature = attester_key.sign(ATTEST_DOMAIN, &attestation.signing_bytes());
        Self {
            attestation,
            signature,
        }
    }

    /// Check the named attester really signed this attestation. The signature
    /// is checked against `attestation.attester`, so a statement cannot be
    /// attributed to an attester who did not make it.
    pub fn verify(&self) -> bool {
        crypto::verify(
            &self.attestation.attester,
            ATTEST_DOMAIN,
            &self.attestation.signing_bytes(),
            &self.signature,
        )
        .is_ok()
    }
}

/// A requirement an institution places on a subject before accepting a transfer
/// or claim: a valid, unexpired `Verified` attestation from a specific attester,
/// optionally under a specific scheme.
#[derive(Clone, Debug)]
pub struct CompliancePolicy {
    /// The attester whose say-so this institution trusts.
    pub attester: PublicKey,
    /// If set, the attestation must be under this scheme code.
    pub scheme: Option<u16>,
}

impl CompliancePolicy {
    pub fn new(attester: PublicKey) -> Self {
        Self {
            attester,
            scheme: None,
        }
    }

    pub fn with_scheme(mut self, scheme: u16) -> Self {
        self.scheme = Some(scheme);
        self
    }

    /// **On-chain enforcement.** Decide from the committed flag bytes alone
    /// whether `subject` is compliant at `now`. `flag` is the value stored at
    /// `sys.compliance[cell_key(subject, self.attester)]`, or `None` if the cell
    /// is absent — and absence is *not* compliance, it is a hard refusal.
    pub fn require_compliant(
        &self,
        flag: Option<&[u8]>,
        now: Round,
    ) -> Result<(), ComplianceError> {
        let bytes = flag.ok_or(ComplianceError::NoAttestation)?;
        let flag = decode_flag(bytes)?;
        if !flag.status.is_compliant() {
            return Err(ComplianceError::NotCompliant {
                status: flag.status,
            });
        }
        if now > flag.expires_round {
            return Err(ComplianceError::Expired {
                expires: flag.expires_round,
                now,
            });
        }
        if let Some(want) = self.scheme {
            if flag.scheme != want {
                return Err(ComplianceError::SchemeMismatch {
                    want,
                    got: flag.scheme,
                });
            }
        }
        Ok(())
    }

    /// **Off-chain enforcement.** Verify a proven read of the compliance cell
    /// against the store root, confirm it is the right cell for `subject` under
    /// this policy's attester, and then apply [`require_compliant`] to its
    /// value. A verifier trusting only `store_root` (and its chosen attester)
    /// can decide compliance with this alone.
    pub fn gate(
        &self,
        subject: &PublicKey,
        read: &ProvenRead,
        store_root: &peregrine_core::Hash,
        now: Round,
    ) -> Result<(), ComplianceError> {
        if read.table != compliance_table() || read.key != cell_key(subject, &self.attester) {
            return Err(ComplianceError::WrongCell);
        }
        if !read.verify(store_root) {
            return Err(ComplianceError::BadRead);
        }
        self.require_compliant(Some(&read.value), now)
    }
}

/// Verify a **presented** signed attestation end to end: the attester's
/// signature, its validity window at `now` (`issued ≤ now ≤ expires`), and that
/// its status is `Verified`.
///
/// Use this when a subject hands you the full signed attestation off-chain. Use
/// [`CompliancePolicy::gate`] instead when you only hold the committed flag plus
/// a proof of it — that path is flag-based, so it enforces status and expiry but
/// not the issue round, which the flag does not carry.
pub fn check_attestation(signed: &SignedAttestation, now: Round) -> Result<(), ComplianceError> {
    if !signed.verify() {
        return Err(ComplianceError::BadSignature);
    }
    signed.attestation.valid_at(now)?;
    if !signed.attestation.status.is_compliant() {
        return Err(ComplianceError::NotCompliant {
            status: signed.attestation.status,
        });
    }
    Ok(())
}

/// Why a compliance check failed. Each is a distinct, legible reason.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ComplianceError {
    #[error("attestation signature is not from the named attester")]
    BadSignature,
    #[error("no attestation on record for this subject and attester")]
    NoAttestation,
    #[error("attestation status is {status:?}, not Verified")]
    NotCompliant { status: ComplianceStatus },
    #[error("attestation not yet valid (issued round {issued}, now {now})")]
    NotYetValid { issued: Round, now: Round },
    #[error("attestation expired at round {expires}, now {now}")]
    Expired { expires: Round, now: Round },
    #[error("required scheme {want}, attestation is scheme {got}")]
    SchemeMismatch { want: u16, got: u16 },
    #[error("on-chain flag is malformed")]
    MalformedFlag,
    #[error("proof is not of the expected compliance cell")]
    WrongCell,
    #[error("proof does not verify against the store root")]
    BadRead,
}

/// Fluent construction of an attestation.
pub struct AttestationBuilder {
    status: ComplianceStatus,
    scheme: u16,
    issued_round: Round,
    expires_round: Round,
}

impl AttestationBuilder {
    /// A verified attestation valid over `[issued, expires]` (rounds).
    pub fn verified(issued_round: Round, expires_round: Round) -> Self {
        Self {
            status: ComplianceStatus::Verified,
            scheme: 0,
            issued_round,
            expires_round,
        }
    }

    pub fn status(mut self, status: ComplianceStatus) -> Self {
        self.status = status;
        self
    }

    pub fn scheme(mut self, scheme: u16) -> Self {
        self.scheme = scheme;
        self
    }

    /// Sign the attestation, with `attester_key` attesting `subject`.
    pub fn sign(
        self,
        attester_key: &peregrine_core::Keypair,
        subject: &PublicKey,
    ) -> SignedAttestation {
        SignedAttestation::new(
            attester_key,
            ComplianceAttestation {
                subject: *subject,
                attester: attester_key.public(),
                status: self.status,
                scheme: self.scheme,
                issued_round: self.issued_round,
                expires_round: self.expires_round,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tables::TableStore;
    use peregrine_core::{Hash, Keypair};

    fn keys() -> (Keypair, Keypair, Keypair) {
        let mut rng = rand::rngs::OsRng;
        (
            Keypair::generate(&mut rng), // subject
            Keypair::generate(&mut rng), // attester
            Keypair::generate(&mut rng), // impostor
        )
    }

    #[test]
    fn an_attestation_verifies_only_against_its_attester() {
        let (subject, attester, impostor) = keys();
        let signed = AttestationBuilder::verified(1, 100).sign(&attester, &subject.public());
        assert!(signed.verify());

        // Re-signed by someone else claiming to be the attester.
        let mut forged = signed.clone();
        forged.signature = impostor.sign(ATTEST_DOMAIN, &forged.attestation.signing_bytes());
        assert!(!forged.verify(), "only the named attester may attest");
    }

    #[test]
    fn changing_any_field_invalidates_the_signature() {
        let (subject, attester, _) = keys();
        let signed = AttestationBuilder::verified(1, 100).sign(&attester, &subject.public());
        let mut tampered = signed.clone();
        tampered.attestation.status = ComplianceStatus::Rejected;
        assert!(!tampered.verify());
        let mut extended = signed;
        extended.attestation.expires_round = 999_999;
        assert!(!extended.verify());
    }

    #[test]
    fn flag_round_trips() {
        let (subject, attester, _) = keys();
        let att = AttestationBuilder::verified(3, 4242)
            .scheme(7)
            .sign(&attester, &subject.public())
            .attestation;
        let flag = decode_flag(&att.flag_bytes()).unwrap();
        assert_eq!(flag.status, ComplianceStatus::Verified);
        assert_eq!(flag.scheme, 7);
        assert_eq!(flag.expires_round, 4242);
        assert_eq!(decode_flag(&[]), Err(ComplianceError::MalformedFlag));
        assert_eq!(
            decode_flag(&[9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(ComplianceError::MalformedFlag)
        );
    }

    #[test]
    fn require_compliant_enforces_status_and_expiry() {
        let policy = CompliancePolicy::new(keys().1.public());
        // Absent → refused, not a silent pass.
        assert_eq!(
            policy.require_compliant(None, 1),
            Err(ComplianceError::NoAttestation)
        );

        let verified = ComplianceAttestation {
            subject: keys().0.public(),
            attester: policy.attester,
            status: ComplianceStatus::Verified,
            scheme: 0,
            issued_round: 1,
            expires_round: 100,
        };
        assert!(policy
            .require_compliant(Some(&verified.flag_bytes()), 100)
            .is_ok());
        assert_eq!(
            policy.require_compliant(Some(&verified.flag_bytes()), 101),
            Err(ComplianceError::Expired {
                expires: 100,
                now: 101
            })
        );

        let rejected = ComplianceAttestation {
            status: ComplianceStatus::Rejected,
            ..verified.clone()
        };
        assert_eq!(
            policy.require_compliant(Some(&rejected.flag_bytes()), 50),
            Err(ComplianceError::NotCompliant {
                status: ComplianceStatus::Rejected
            })
        );
    }

    #[test]
    fn scheme_is_enforced_when_required() {
        let policy = CompliancePolicy::new(keys().1.public()).with_scheme(2);
        let att = ComplianceAttestation {
            subject: keys().0.public(),
            attester: policy.attester,
            status: ComplianceStatus::Verified,
            scheme: 5,
            issued_round: 1,
            expires_round: 100,
        };
        assert_eq!(
            policy.require_compliant(Some(&att.flag_bytes()), 10),
            Err(ComplianceError::SchemeMismatch { want: 2, got: 5 })
        );
    }

    #[test]
    fn check_attestation_enforces_signature_window_and_status() {
        let (subject, attester, _) = keys();
        let good = AttestationBuilder::verified(10, 20).sign(&attester, &subject.public());
        assert!(check_attestation(&good, 15).is_ok());
        assert_eq!(
            check_attestation(&good, 9),
            Err(ComplianceError::NotYetValid { issued: 10, now: 9 })
        );
        assert_eq!(
            check_attestation(&good, 21),
            Err(ComplianceError::Expired {
                expires: 20,
                now: 21
            })
        );
        let pending = AttestationBuilder::verified(1, 100)
            .status(ComplianceStatus::Pending)
            .sign(&attester, &subject.public());
        assert_eq!(
            check_attestation(&pending, 50),
            Err(ComplianceError::NotCompliant {
                status: ComplianceStatus::Pending
            })
        );
    }

    #[test]
    fn gate_verifies_a_proven_read_of_the_right_cell() {
        let (subject, attester, other) = keys();
        let signed = AttestationBuilder::verified(1, 500).sign(&attester, &subject.public());

        // Materialize the flag into the compliance table, as the node would.
        let mut store = TableStore::new();
        store.insert(
            compliance_table(),
            cell_key(&subject.public(), &attester.public()),
            signed.attestation.flag_bytes(),
        );
        let root = store.store_root();
        let read = store
            .prove_read(
                compliance_table(),
                &cell_key(&subject.public(), &attester.public()),
            )
            .unwrap();

        let policy = CompliancePolicy::new(attester.public());
        assert!(policy.gate(&subject.public(), &read, &root, 250).is_ok());

        // Wrong store root is refused.
        assert_eq!(
            policy.gate(&subject.public(), &read, &Hash::ZERO, 250),
            Err(ComplianceError::BadRead)
        );
        // A policy naming a different attester consults a different cell.
        let wrong = CompliancePolicy::new(other.public());
        assert_eq!(
            wrong.gate(&subject.public(), &read, &root, 250),
            Err(ComplianceError::WrongCell)
        );
    }
}
