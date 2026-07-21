//! SP1 guest: prove Peregrine state **to Ethereum**.
//!
//! The mirror of `peregrine-eth-guest`, and the program whose verifying-key
//! hash [`PeregrineLightClient`] pins as `programVKey`.
//!
//! It does exactly three things:
//!
//! 1. read one untrusted [`StateWitness`] from the host,
//! 2. run the **same** verification the host runs natively
//!    ([`StateWitness::verify`]), and
//! 3. commit the resulting journal, ABI-encoded, as public values.
//!
//! The security argument rests on that shape:
//!
//! * **Nothing is committed unless verification succeeded.** A failing witness
//!   panics the guest, which produces no proof at all — there is no path that
//!   commits a journal without having earned it.
//! * **The journal is derived, never echoed.** The store root comes from the
//!   checkpoint whose signatures were just verified, and the value comes from
//!   an inclusion proof checked against *that* root. A relayer cannot choose
//!   what its "proof" attests to.
//! * **The committee is a public output, not a secret.** The guest is *told*
//!   which validator set to check against — it cannot know the real one. So a
//!   proof built against an attacker's committee is a valid proof of this
//!   program, and the only thing that distinguishes it is that the committee's
//!   digest is committed publicly for the contract to pin. Baking a committee
//!   into the ELF would also work, but it would hide the trust root inside a
//!   binary nobody reads.
//! * **The program is the statement.** Whoever verifies a proof of this ELF
//!   must pin its verifying-key hash; a proof of a *different* program is still
//!   a valid proof of something else entirely.
//!
//! Because the verification lives in `peregrine-interop` — a pure crate with no
//! zkVM dependency — the guest and the host provably execute the same logic,
//! and that logic is unit-tested on the host where testing is cheap
//! (`tests/state_journal.rs`).
//!
//! Build: `cd crates/peregrine-state-guest && cargo prove build`
//! (needs the Succinct toolchain: `curl -L https://sp1up.succinct.xyz | bash`)

#![no_main]

use peregrine_interop::state::{encode_state_journal, StateWitness};

sp1_zkvm::entrypoint!(main);

pub fn main() {
    // Untrusted input, supplied by whoever asked for the proof.
    let witness: StateWitness = sp1_zkvm::io::read();

    // Verify. On failure this panics, no proof is produced, and the host learns
    // only that the witness was bad — which is the correct outcome: an
    // unprovable claim must not become a provable one.
    let journal = witness
        .verify()
        .expect("witness failed verification — no journal is committed");

    // Commit the derived statement, ABI-encoded so the EVM contract can
    // `abi.decode` it directly. `encode_state_journal` is the same encoder the
    // host and the Solidity tests are pinned against, so the guest's public
    // values and the contract's `Journal` struct cannot drift apart.
    sp1_zkvm::io::commit_slice(&encode_state_journal(&journal));
}
