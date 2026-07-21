# Contributing to Peregrine

Thanks for looking. This is an early-stage scaffold, so the most useful
contributions are the ones that make the foundations more correct, more
honest, or easier to build on.

## Getting set up

```bash
git clone https://github.com/peregrine-labs/peregrine
cd peregrine
cargo test                      # ~50 tests, all crates
cargo run -p peregrine-cli -- sim
```

You need a recent stable Rust (1.85+ is comfortable; the code itself compiles
on 1.75). For the TypeScript SDK you need Node ≥ 22.6 — it runs `.ts` directly
via type stripping, so there is no build step.

```bash
cd sdk/js && npm install && npm test
```

## Before you open a PR

CI runs exactly these, so run them locally first:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cd sdk/js && npm test
```

`make ci` runs the whole set if you have `make`.

## What we care about

**Correctness over features.** This is consensus and state-commitment code. A
subtly wrong commit rule or proof check is far worse than a missing feature.
New logic in `peregrine-consensus`, `peregrine-data`, or `peregrine-vm` should
arrive with tests that would fail without it — ideally including the
adversarial case, not just the happy path.

**Be honest about limitations.** The README has an "Honest limitations"
section, and it is deliberately long. If your change is a simplification, a
stub, or a bootstrap shortcut, say so there. We would much rather ship a
documented stub than an undocumented one. Comments explaining *why* something
is the way it is are worth more than comments restating what the code does.

**Respect the crate boundaries.** They are load-bearing:

| Crate | Rule |
| --- | --- |
| `peregrine-core` | pure types; no async, no I/O |
| `peregrine-consensus` | pure DAG/commit logic; no networking, no storage |
| `peregrine-data` | streams, tables, proofs, fees; no async, no I/O |
| `peregrine-vm` | deterministic interpreter; state only via the `Host` trait |
| `peregrine-node` | the only crate that touches sockets, disk, and tokio |
| `peregrine-sdk` | a client; must not depend on `peregrine-node` |
| `peregrine-cli` | argument parsing and config; logic lives in the libraries |

Keeping the pure crates dependency-free is what will let them move into the
future tile runtime, and what keeps consensus testable without a network.

⚠️ **`peregrine-interop` compiles into a RISC-V zkVM guest.** Anything it
depends on must build for `riscv*-succinct-zkvm-elf` — no tokio, no mio, no
networking, no `std::net`. That is why `peregrine-data`'s subscriber fan-out
sits behind a default-on `streams` feature and interop takes
`default-features = false`.

Two things that will bite you there:

* Cargo **silently ignores** `default-features = false` on an *inherited*
  workspace dependency unless the workspace entry sets it too. Declare the dep
  by path in the member instead — `peregrine-interop/Cargo.toml` does, with a
  comment saying why.
* A `pub use` of a gated module must carry the same `#[cfg]`, or the crate
  fails to compile with the feature off.

Check your change with:

```bash
cargo check -p peregrine-interop --no-default-features   # guest-shaped build
```

**Determinism is a hard requirement.** Anything on the commit path must
produce byte-identical state on every validator. No wall-clock reads, no
iteration over `HashMap` where order escapes, no floating point in anything
that touches money or state roots.

## Testing conventions

- Unit tests live next to the code in `#[cfg(test)] mod tests`.
- Cross-crate and end-to-end behaviour lives in `crates/peregrine-node/tests/`.
- Integration tests should assert on *observable* properties — converged store
  roots, verified proofs, committed counts — rather than internal state.
- If you touch the proof formats, regenerate the cross-language fixture and
  make sure the TypeScript verifier still agrees:

  ```bash
  cargo run -p peregrine-node --example gen_js_fixture
  cd sdk/js && npm test
  ```

## Timing-sensitive tests

Several tests drive a real network and are therefore timing-sensitive. If one
flakes, please don't just bump the sleep — find out what is actually slow.
Past examples that turned out to be real bugs:

- a validator couldn't catch up after a restart because a blocking `fsync` on
  the async runtime was starving message delivery;
- a single-validator devnet burned a whole core, because a lone node's own
  proposal self-delivers instantly and it re-proposes in a hot loop with no
  round-trip to pace it. (This is why `validators` must be ≥ 2.)

## Commit messages

Explain the *why*. "Fix restart flake by offloading the redb fsync with
`block_in_place`" is useful; "fix test" is not.

## Reporting bugs

Please include what you ran, what you expected, what happened, and the output.
For anything timing-related, mention your core count — several tests spin up
four validators plus a client.

## Security

Do **not** open a public issue for a security problem in the consensus, proof,
or crypto paths. Email the maintainers instead.

Note that this scaffold is explicitly not production software: the TLS is
self-signed with verification disabled, the RPC endpoint has no
authentication or rate limiting, and the VM has no state-rollback journal.
These are documented in the README, not bugs to report — but a way to *break*
the properties the README claims to hold very much is.
