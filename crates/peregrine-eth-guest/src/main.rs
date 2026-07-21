//! SP1 guest: verify Ethereum state, commit a Peregrine interop `Journal`.
//!
//! This program is intentionally tiny. Everything it does is:
//!
//! 1. read one untrusted [`Witness`] from the host,
//! 2. run the **same** verification the host runs natively
//!    ([`Witness::verify`]), and
//! 3. commit the resulting [`Journal`] as public values.
//!
//! The whole security argument rests on that shape:
//!
//! * **Nothing is committed unless verification succeeded.** A failing witness
//!   panics the guest, which produces no proof at all — there is no path that
//!   commits a journal without having earned it.
//! * **The journal is derived, never echoed.** `Witness::verify` recomputes the
//!   block hash and reads the state root out of the header it hashed, so a
//!   relayer cannot pick the roots its "proof" attests to.
//! * **The program is the statement.** Whoever verifies a proof of this ELF
//!   must pin its verifying-key hash; a proof of a *different* program is still
//!   a valid proof of something else entirely.
//!
//! Because the verification lives in `peregrine-interop` — a pure crate with no
//! zkVM dependency — the guest and the host provably execute the same logic,
//! and that logic is unit-tested against real Ethereum mainnet data on the
//! host, where testing is cheap.
//!
//! Build: `cd crates/peregrine-eth-guest && cargo prove build`
//! (needs the Succinct toolchain: `curl -L https://sp1up.succinct.xyz | bash`)

#![no_main]

use peregrine_interop::witness::{encode_journal, Witness};

sp1_zkvm::entrypoint!(main);

pub fn main() {
    // Untrusted input, supplied by whoever asked for the proof.
    let witness: Witness = sp1_zkvm::io::read();

    // Verify. On failure this panics, the proof is never produced, and the
    // host learns only that the witness was bad — which is the correct
    // outcome: an unprovable claim must not become a provable one.
    let journal = witness
        .verify()
        .expect("witness failed verification — no journal is committed");

    // Commit the derived statement. `encode_journal` is the same encoding the
    // host verifier compares against, so public values and journal cannot
    // drift apart.
    sp1_zkvm::io::commit_slice(&encode_journal(&journal));
}
