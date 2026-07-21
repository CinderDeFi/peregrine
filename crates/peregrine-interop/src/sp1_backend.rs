//! SP1 proving and verification (enabled by the `sp1` feature).
//!
//! Targets **SP1 v6**. Two halves:
//!
//! * [`Sp1Prover`] runs the guest program over a [`Witness`] and returns a
//!   [`VerifiedClaim`] carrying a real [`Proof::Zk`];
//! * [`Sp1Verifier`] checks such a proof — and is the piece that has to be
//!   right, because it is what a validator runs.
//!
//! # Why the verifier does four things, not one
//!
//! Verifying the SP1 proof itself is necessary but nowhere near sufficient.
//! Each of these has been a real bridge bug somewhere:
//!
//! 1. **The proof is cryptographically valid** — the obvious one.
//! 2. **The verifying key matches the pinned image id.** A proof of *some other
//!    program* is still a perfectly valid proof. Without pinning, an attacker
//!    supplies a proof of `fn main() { commit(whatever_i_want) }` and it
//!    verifies. This is the single most important check here.
//! 3. **The public values decode to the journal being asserted.** The proof
//!    commits to the guest's public values; if the caller is allowed to pass a
//!    journal *alongside* an unrelated proof, the proof is decorative.
//! 4. **The claim is about the chain we expect.** A proof about a testnet is
//!    valid and useless.
//!
//! Anchoring — deciding that `journal.block_hash` is really Ethereum's
//! canonical block — is deliberately *not* done here. This crate cannot know
//! what you trust. See the README.
//!
//! # Loading the ELF
//!
//! The guest ELF is loaded **at runtime** (env `PEREGRINE_ETH_GUEST_ELF`, or
//! the conventional build path) rather than via SP1's `include_elf!`. That
//! keeps `--features sp1` compilable on a machine where the guest has not been
//! built, so the security tests below can run without the Linux-only guest
//! toolchain. The trade-off is that a missing ELF is a runtime error instead of
//! a compile error — acceptable, because the *vkey pin* (check 2) is what
//! actually binds us to the right program, not how the bytes were loaded.

// Only `ZkError` is needed when the `sp1` feature is off; everything else is
// scoped to the backend module so a default build has no unused imports.
use crate::zk::ZkError;

/// Name of the guest package, used to locate its compiled ELF.
pub const GUEST_PACKAGE: &str = "peregrine-eth-guest";
/// Overrides where the guest ELF is read from.
pub const GUEST_ELF_ENV: &str = "PEREGRINE_ETH_GUEST_ELF";

/// Locate the guest ELF: `$PEREGRINE_ETH_GUEST_ELF`, else SP1's conventional
/// build output path under the workspace target directory.
pub fn guest_elf_path() -> std::path::PathBuf {
    if let Some(p) = std::env::var_os(GUEST_ELF_ENV) {
        return std::path::PathBuf::from(p);
    }
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/elf-compilation/riscv32im-succinct-zkvm-elf/release")
        .join(GUEST_PACKAGE)
}

/// Read the guest ELF from disk.
pub fn load_guest_elf() -> Result<Vec<u8>, ZkError> {
    let path = guest_elf_path();
    std::fs::read(&path).map_err(|e| {
        ZkError::Invalid(format!(
            "guest ELF not found at {} ({e}). Build it with \
             `cd crates/peregrine-eth-guest && cargo prove build`, or set {GUEST_ELF_ENV}.",
            path.display()
        ))
    })
}

#[cfg(feature = "sp1")]
mod imp {
    use super::*;
    use crate::witness::{decode_journal, encode_journal, Witness};
    use crate::zk::{Journal, Proof, ProofSystem, Prover, VerifiedClaim, Verifier, B256};
    use sp1_sdk::{ProverClient, SP1Stdin};

    /// Proof shape to generate.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub enum Sp1Mode {
        /// STARK, recursively compressed. **No trusted setup.** Larger to
        /// verify than Groth16 but the cleanest trust story — prefer this for
        /// verification inside Peregrine.
        #[default]
        Compressed,
        /// Groth16-wrapped, for cheap verification on an EVM chain. Small and
        /// fast, but inherits a **circuit-specific trusted setup** — see the
        /// security notes in the README before using it.
        Groth16,
    }

    /// Generates real SP1 proofs.
    pub struct Sp1Prover {
        elf: Vec<u8>,
        mode: Sp1Mode,
    }

    impl Sp1Prover {
        /// Load the guest ELF and prepare a prover.
        pub fn new(mode: Sp1Mode) -> Result<Self, ZkError> {
            Ok(Self {
                elf: load_guest_elf()?,
                mode,
            })
        }

        /// The verifying-key hash for the loaded guest — the value to pin.
        ///
        /// Print it with `peregrine interop image-id` and paste it into your
        /// configuration; a node should never learn its expected image id from
        /// the same party that supplies proofs.
        pub fn image_id(&self) -> Result<B256, ZkError> {
            let client = ProverClient::from_env();
            let (_, vk) = client.setup(&self.elf);
            vkey_to_image_id(&vk)
        }

        /// Prove a witness. The journal is whatever the *guest* committed, not
        /// anything we computed here.
        pub fn prove_witness(&self, witness: &Witness) -> Result<VerifiedClaim, ZkError> {
            let client = ProverClient::from_env();
            let (pk, vk) = client.setup(&self.elf);

            let mut stdin = SP1Stdin::new();
            stdin.write(witness);

            let builder = client.prove(&pk, &stdin);
            let proof = match self.mode {
                Sp1Mode::Compressed => builder.compressed().run(),
                Sp1Mode::Groth16 => builder.groth16().run(),
            }
            .map_err(|e| ZkError::Invalid(format!("proving failed: {e}")))?;

            // Read the statement back out of the proof rather than trusting our
            // own local computation of it.
            let journal =
                decode_journal(proof.public_values.as_slice()).map_err(ZkError::Invalid)?;
            let bytes = bincode::serialize(&proof)
                .map_err(|e| ZkError::Invalid(format!("serialize proof: {e}")))?;

            Ok(VerifiedClaim {
                journal,
                proof: Proof::Zk {
                    system: ProofSystem::Sp1,
                    image_id: vkey_to_image_id(&vk)?,
                    bytes,
                },
            })
        }
    }

    impl Prover for Sp1Prover {
        /// Present for trait completeness; proving needs a witness, so this
        /// path is intentionally unavailable rather than silently downgrading
        /// to a native (non-cryptographic) proof.
        fn prove(&self, _journal: Journal) -> Result<VerifiedClaim, ZkError> {
            Err(ZkError::Invalid(
                "SP1 proving requires a Witness; use Sp1Prover::prove_witness".into(),
            ))
        }
    }

    /// Verifies SP1 proofs against a pinned program image.
    pub struct Sp1Verifier {
        elf: Vec<u8>,
        expected_image_id: B256,
        expected_chain_id: u64,
    }

    impl Sp1Verifier {
        pub fn new(expected_image_id: B256, expected_chain_id: u64) -> Result<Self, ZkError> {
            Ok(Self {
                elf: load_guest_elf()?,
                expected_image_id,
                expected_chain_id,
            })
        }
    }

    impl Verifier for Sp1Verifier {
        fn verify(&self, claim: &VerifiedClaim) -> Result<(), ZkError> {
            let Proof::Zk {
                system,
                image_id,
                bytes,
            } = &claim.proof
            else {
                return Err(ZkError::Invalid(
                    "native proof carries no cryptographic argument".into(),
                ));
            };
            if *system != ProofSystem::Sp1 {
                return Err(ZkError::UnsupportedSystem(*system));
            }
            // (2) Pin the program *before* spending time on cryptography.
            if *image_id != self.expected_image_id {
                return Err(ZkError::Invalid(
                    "program image id does not match the pinned value".into(),
                ));
            }
            // (4) Right chain.
            if claim.journal.chain_id != self.expected_chain_id {
                return Err(ZkError::Invalid(format!(
                    "claim is for chain {}, expected {}",
                    claim.journal.chain_id, self.expected_chain_id
                )));
            }

            let proof: sp1_sdk::SP1ProofWithPublicValues = bincode::deserialize(bytes)
                .map_err(|e| ZkError::Invalid(format!("malformed proof bytes: {e}")))?;

            // (3) The proof's public values must be exactly the journal being
            // asserted — otherwise the proof is attached to a different claim.
            if proof.public_values.as_slice() != encode_journal(&claim.journal).as_slice() {
                return Err(ZkError::JournalMismatch);
            }

            // (1) And finally the cryptography.
            let client = ProverClient::from_env();
            let (_, vk) = client.setup(&self.elf);
            if vkey_to_image_id(&vk)? != self.expected_image_id {
                return Err(ZkError::Invalid(
                    "local guest ELF does not match the pinned image id".into(),
                ));
            }
            client
                .verify(&proof, &vk)
                .map_err(|e| ZkError::Invalid(format!("SP1 proof rejected: {e}")))
        }
    }

    /// SP1's verifying-key hash, as 32 bytes — our `image_id`.
    fn vkey_to_image_id(vk: &sp1_sdk::SP1VerifyingKey) -> Result<B256, ZkError> {
        let s = vk.bytes32();
        let hex = s.trim_start_matches("0x");
        let raw = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
            .collect::<Result<Vec<u8>, _>>()
            .map_err(|e| ZkError::Invalid(format!("bad vkey hex: {e}")))?;
        if raw.len() != 32 {
            return Err(ZkError::Invalid(format!(
                "vkey hash is {} bytes",
                raw.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&raw);
        Ok(out)
    }
}

#[cfg(feature = "sp1")]
pub use imp::{Sp1Mode, Sp1Prover, Sp1Verifier};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elf_path_is_overridable() {
        // A node operator must be able to point at a reviewed ELF explicitly
        // rather than whatever happens to be in the build directory.
        std::env::set_var(GUEST_ELF_ENV, "/tmp/some/guest.elf");
        assert_eq!(
            guest_elf_path(),
            std::path::PathBuf::from("/tmp/some/guest.elf")
        );
        std::env::remove_var(GUEST_ELF_ENV);
        assert!(guest_elf_path().ends_with(GUEST_PACKAGE));
    }

    #[test]
    fn missing_elf_is_an_actionable_error() {
        std::env::set_var(GUEST_ELF_ENV, "/definitely/not/here.elf");
        let err = load_guest_elf().unwrap_err().to_string();
        std::env::remove_var(GUEST_ELF_ENV);
        assert!(
            err.contains("cargo prove build"),
            "error should say how to fix it: {err}"
        );
    }
}
