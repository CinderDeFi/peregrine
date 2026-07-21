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

/// Which guest program to load.
///
/// There are two, one per direction, and they are **not** interchangeable: each
/// proves a different statement and has its own verifying-key hash. Confusing
/// them would yield a valid proof of the wrong thing, which is why the choice
/// is an enum rather than a stringly-typed path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Guest {
    /// Ethereum → Peregrine: verifies Ethereum headers and state proofs.
    Eth,
    /// Peregrine → Ethereum: verifies a quorum-signed checkpoint and a state
    /// inclusion proof, committing an ABI-encoded journal for the EVM.
    State,
}

impl Guest {
    /// Cargo package name of the guest crate.
    pub fn package(self) -> &'static str {
        match self {
            Guest::Eth => "peregrine-eth-guest",
            Guest::State => "peregrine-state-guest",
        }
    }

    /// Environment variable that overrides where its ELF is read from.
    pub fn elf_env(self) -> &'static str {
        match self {
            Guest::Eth => "PEREGRINE_ETH_GUEST_ELF",
            Guest::State => "PEREGRINE_STATE_GUEST_ELF",
        }
    }

    /// Locate the ELF: the override env var, else SP1's conventional build
    /// output path under the guest crate's own target directory.
    pub fn elf_path(self) -> std::path::PathBuf {
        if let Some(p) = std::env::var_os(self.elf_env()) {
            return std::path::PathBuf::from(p);
        }
        // Each guest is its own workspace, so its artefacts land under its own
        // `target/`, not the root one.
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join(self.package())
            .join("target/elf-compilation/riscv64im-succinct-zkvm-elf/release")
            .join(self.package())
    }

    /// Read the ELF from disk.
    pub fn load_elf(self) -> Result<Vec<u8>, ZkError> {
        let path = self.elf_path();
        std::fs::read(&path).map_err(|e| {
            ZkError::Invalid(format!(
                "guest ELF not found at {} ({e}). Build it with `cd crates/{} && \
                 cargo prove build`, or set {}.",
                path.display(),
                self.package(),
                self.elf_env()
            ))
        })
    }
}

/// Name of the Ethereum guest package. Retained for callers written before
/// there were two guests.
pub const GUEST_PACKAGE: &str = "peregrine-eth-guest";
/// Overrides where the Ethereum guest ELF is read from.
pub const GUEST_ELF_ENV: &str = "PEREGRINE_ETH_GUEST_ELF";

/// Locate the Ethereum guest ELF.
pub fn guest_elf_path() -> std::path::PathBuf {
    Guest::Eth.elf_path()
}

/// Read the Ethereum guest ELF from disk.
pub fn load_guest_elf() -> Result<Vec<u8>, ZkError> {
    Guest::Eth.load_elf()
}

#[cfg(feature = "sp1")]
mod imp {
    use super::*;
    use crate::witness::{decode_journal, encode_journal, Witness};
    use crate::zk::{Journal, Proof, ProofSystem, Prover, VerifiedClaim, Verifier, B256};
    // SP1 v6's default `ProverClient` is async. The blocking client keeps proof
    // verification off the async runtime, which matters because a validator
    // verifies claims inside its synchronous commit path.
    use sp1_sdk::blocking::{ProveRequest, Prover as _, ProverClient};
    use sp1_sdk::{Elf, HashableKey, ProvingKey as _, SP1ProofMode, SP1Stdin, SP1VerifyingKey};

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

    impl Sp1Mode {
        fn to_proof_mode(self) -> SP1ProofMode {
            match self {
                Sp1Mode::Compressed => SP1ProofMode::Compressed,
                Sp1Mode::Groth16 => SP1ProofMode::Groth16,
            }
        }
    }

    /// Generates real SP1 proofs.
    pub struct Sp1Prover {
        elf: Vec<u8>,
        mode: Sp1Mode,
    }

    impl Sp1Prover {
        /// Load the **Ethereum** guest ELF and prepare a prover.
        pub fn new(mode: Sp1Mode) -> Result<Self, ZkError> {
            Self::for_guest(Guest::Eth, mode)
        }

        /// Load a named guest's ELF and prepare a prover.
        pub fn for_guest(guest: Guest, mode: Sp1Mode) -> Result<Self, ZkError> {
            Ok(Self {
                elf: guest.load_elf()?,
                mode,
            })
        }

        /// The verifying-key hash for the loaded guest — the value to pin.
        ///
        /// A node should never learn its expected image id from the same party
        /// that supplies its proofs; derive it from your own build.
        pub fn image_id(&self) -> Result<B256, ZkError> {
            let client = ProverClient::from_env();
            let pk = client
                .setup(Elf::from(self.elf.as_slice()))
                .map_err(|e| ZkError::Invalid(format!("setup failed: {e}")))?;
            vkey_to_image_id(pk.verifying_key())
        }

        /// Prove a witness. The journal is whatever the *guest* committed, not
        /// anything we computed here.
        pub fn prove_witness(&self, witness: &Witness) -> Result<VerifiedClaim, ZkError> {
            let client = ProverClient::from_env();
            let pk = client
                .setup(Elf::from(self.elf.as_slice()))
                .map_err(|e| ZkError::Invalid(format!("setup failed: {e}")))?;

            let mut stdin = SP1Stdin::new();
            stdin.write(witness);

            let proof = client
                .prove(&pk, stdin)
                .mode(self.mode.to_proof_mode())
                .run()
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
                    image_id: vkey_to_image_id(pk.verifying_key())?,
                    bytes,
                },
            })
        }
    }

    /// A proof of Peregrine state, in the form an EVM contract consumes.
    ///
    /// Deliberately *not* a [`VerifiedClaim`]: that type carries an
    /// Ethereum-side `Journal` and is verified inside Peregrine. This one is
    /// verified by Solidity, so it carries the raw ABI-encoded public values
    /// and the raw proof bytes — exactly the two `bytes` arguments
    /// `verifyPeregrineState` takes, and nothing else.
    #[derive(Clone, Debug)]
    pub struct StateProof {
        /// The decoded statement, for inspection and assertions.
        pub journal: crate::state::StateJournal,
        /// ABI-encoded public values — `publicValues` on-chain.
        pub public_values: Vec<u8>,
        /// Proof bytes in the encoding SP1's on-chain verifier expects —
        /// `proofBytes` on-chain.
        pub proof_bytes: Vec<u8>,
        /// Verifying-key hash of the guest — `programVKey` on-chain.
        pub image_id: B256,
    }

    impl Sp1Prover {
        /// Prove a Peregrine state witness for on-chain verification.
        ///
        /// The mode matters here in a way it does not elsewhere: SP1's EVM
        /// verifier accepts **Groth16** (or PLONK), not a compressed STARK. A
        /// compressed proof is still a real proof — it just cannot be checked
        /// by the contract — so this refuses rather than producing bytes that
        /// would fail on-chain for reasons no one could diagnose from the
        /// revert.
        pub fn prove_state(
            &self,
            witness: &crate::state::StateWitness,
        ) -> Result<StateProof, ZkError> {
            if self.mode != Sp1Mode::Groth16 {
                return Err(ZkError::Invalid(
                    "on-chain verification needs Groth16; a Compressed proof cannot be \
                     verified by SP1's EVM verifier"
                        .into(),
                ));
            }

            let client = ProverClient::from_env();
            let pk = client
                .setup(Elf::from(self.elf.as_slice()))
                .map_err(|e| ZkError::Invalid(format!("setup failed: {e}")))?;

            let mut stdin = SP1Stdin::new();
            stdin.write(witness);

            let proof = client
                .prove(&pk, stdin)
                .mode(SP1ProofMode::Groth16)
                .run()
                .map_err(|e| ZkError::Invalid(format!("proving failed: {e}")))?;

            // Read the statement back out of the proof rather than trusting our
            // own local computation of it — the guest is the authority on what
            // was proved.
            let public_values = proof.public_values.as_slice().to_vec();
            let journal = crate::state::decode_state_journal(&public_values)
                .map_err(|e| ZkError::Invalid(e.to_string()))?;

            Ok(StateProof {
                journal,
                public_values,
                proof_bytes: proof.bytes(),
                image_id: vkey_to_image_id(pk.verifying_key())?,
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
    ///
    /// The verifying key is derived **once**, at construction. Deriving it is
    /// far more expensive than checking a proof against it, so doing it per
    /// call would put seconds of avoidable work on the commit path — and the
    /// ELF is fixed for the verifier's lifetime anyway.
    ///
    /// Construction also fails if the local ELF does not hash to the pinned
    /// image id, so a misconfigured node refuses to start rather than
    /// discovering the mismatch mid-consensus.
    pub struct Sp1Verifier {
        client: sp1_sdk::blocking::EnvProver,
        vk: SP1VerifyingKey,
        expected_image_id: B256,
        expected_chain_id: u64,
    }

    impl Sp1Verifier {
        pub fn new(expected_image_id: B256, expected_chain_id: u64) -> Result<Self, ZkError> {
            let elf = load_guest_elf()?;
            let client = ProverClient::from_env();
            let pk = client
                .setup(Elf::from(elf.as_slice()))
                .map_err(|e| ZkError::Invalid(format!("setup failed: {e}")))?;
            let vk = pk.verifying_key().clone();
            let actual = vkey_to_image_id(&vk)?;
            if actual != expected_image_id {
                return Err(ZkError::Invalid(format!(
                    "local guest ELF has image id 0x{} but 0x{} was pinned",
                    short_hex(&actual),
                    short_hex(&expected_image_id)
                )));
            }
            Ok(Self {
                client,
                vk,
                expected_image_id,
                expected_chain_id,
            })
        }

        /// The pinned program image this verifier accepts.
        pub fn image_id(&self) -> B256 {
            self.expected_image_id
        }
    }

    fn short_hex(b: &B256) -> String {
        b[..4].iter().map(|x| format!("{x:02x}")).collect()
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

            // (1) And finally the cryptography, against the key derived — and
            // checked against the pin — at construction time.
            self.client
                .verify(&proof, &self.vk, None)
                .map_err(|e| ZkError::Invalid(format!("SP1 proof rejected: {e}")))
        }
    }

    /// SP1's verifying-key hash, as 32 bytes — our `image_id`.
    fn vkey_to_image_id(vk: &SP1VerifyingKey) -> Result<B256, ZkError> {
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
pub use imp::{Sp1Mode, Sp1Prover, Sp1Verifier, StateProof};

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
