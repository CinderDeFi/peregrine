# Security Policy

## Audit status

**Peregrine has never been audited.** It is a bootstrap scaffold, not
production software. Nothing in this repository should hold value.

| Area | Status |
| --- | --- |
| External audit | ❌ none |
| Formal verification | ❌ none |
| Testnet / mainnet deployment | ❌ never deployed |
| Bug bounty | ❌ not yet |
| Static analysis (Slither) | ✅ clean on the shipped contract — see [`contracts/SLITHER.md`](contracts/SLITHER.md) |
| EVM contract test suite | ✅ 48 Foundry tests incl. fuzzing + real Groth16 e2e — see [`contracts/AUDIT.md`](contracts/AUDIT.md) |
| Audit package | ✅ prepared — see [`AUDIT.md`](AUDIT.md) |
| Coverage-guided fuzzing (Rust) | ❌ none — property tests only |
| Test suite stability under load | ✅ four flaky tests fixed (three timing, one env-var race); full suite 0/10 under load (see [`AUDIT.md`](AUDIT.md#determinism-of-the-suite-itself)) |

**[`AUDIT.md`](AUDIT.md) is the entry point for reviewers**: scope, trust
boundaries, twenty-three named invariants, a threat model, a full test-coverage
map, and a ranked list of what to attack first. It exists to make an audit efficient, not to suggest one has
happened.

A clean static-analysis run is **not** an audit. Slither finds pattern-level
defects; it cannot tell you whether the right committee is pinned or whether
the Rust encoder agrees with `abi.decode`. Those are the things most likely to
be wrong, and they are covered by tests, not by tooling.

## Known-unsafe by design

These are deliberate bootstrap shortcuts, documented so nobody mistakes them
for oversights. Each is also called out in the README.

| Component | What is unsafe | Consequence |
| --- | --- | --- |
| **TLS** (validator mesh + RPC) | Self-signed certs, verification disabled | Transport is unauthenticated. Consensus still signature-checks every vertex, so blocks can't be forged — but bandwidth can be wasted. |
| **Client RPC** | Per-connection rate limiting only | Bounds one client; **not Sybil resistance** — many connections get many buckets. Needs stake- or key-weighted admission across connections before public exposure. |
| **TalonVM** | No state-rollback journal | A trapped transaction's partial writes persist (deterministically on every node). |
| **Equivocation** | Detected, not slashed | A double-proposing validator is surfaced but not punished. |
| **Wire format** | `bincode` | Not a canonical encoding; unsuitable for cross-implementation consensus. |
| **EVM contract** | Unaudited and undeployed | Compiled, tested (48 passing Foundry tests **including a real SP1 Groth16 proof verified on-chain by the vendored real verifier, ~418k gas**), Slither-clean. Unaudited and never deployed — do not put value behind it. |
| **Committee rotation (Peregrine → Ethereum)** | Not implemented | `committeeDigest` is immutable in the EVM client, so a Peregrine validator-set change requires deploying a new contract. **This is the weakest link in that direction.** |
| **Groth16 trusted setup** | Circuit-specific setup performed by Succinct | Unavoidable if you want EVM-affordable verification. Peregrine's own verification of Ethereum uses Compressed STARK, which has no trusted setup — the asymmetry is a property of the EVM, not of the protocol. |
| **SP1 backend** | Real proofs generated and verified, but the proving path is **unaudited** and has only been exercised on the header-chain witness | `Proof::Native` still carries **no** cryptographic argument; only `Proof::Zk` does. |

## The security properties that *are* real

Stated precisely, because "trust-minimized" is easy to claim and hard to earn:

* **Proofs, not promises.** Cross-chain facts are re-derived from cryptography
  the verifier checks itself. There is no multisig, no privileged key, and no
  trusted relayer anywhere in `peregrine-interop`.
* **Fail-closed everywhere.** A node that cannot verify a proof rejects the
  claim. A build without `--features bls` mints no anchors and therefore
  accepts nothing. `StrictVerifier` rejects `Proof::Native` outright.
* **Absence is not zero.** `LoadEthState` traps rather than returning `0` for
  unverified state, and refuses to truncate values wider than 64 bits. The EVM
  contract's `getVerifiedValue` reverts rather than returning zero.
* **Anchoring is mandatory.** A state claim is refused unless its block is
  anchored by a BLS-verified beacon update, and anchors move forward only.
* **Image pinning.** A valid proof of a *different program* is still a valid
  proof; the verifier pins the program's verifying-key hash before doing any
  cryptography. The EVM client pins three things — program, committee, and
  chain id — all immutable, because an upgradeable pin is an admin key that can
  redefine what every past and future proof meant.
* **Verify before decode.** The EVM client checks the proof *before* reading a
  single field of the public values. Decoding first and validating later is how
  verifiers end up acting on attacker-chosen data.
* **Equivocation stops the client.** Two different store roots proven for the
  same Peregrine round revert rather than being silently absorbed. Absorbing it
  would let an attacker who achieved it write state under a root of their
  choosing.

These are enforced by tests that run on every CI push — see
`tests/zk_security.rs`, `tests/foreign_claims.rs`,
`tests/bls_sync_committee.rs`, `tests/state_journal.rs`, and the Foundry suite
under `contracts/test/`.

## Consensus-critical configuration

⚠️ **`ClaimPolicy` and proof-verification capability are consensus rules, not
local preferences.** Validators that disagree about which proofs are acceptable
will disagree about state and **fork the chain**. Any change must be a
coordinated network upgrade.

## Reporting a vulnerability

**Do not open a public issue** for a security problem in the consensus, proof,
cryptography, or interop paths.

Email the maintainers with:

* what you found and where (file/function if you have it),
* how to reproduce it, and
* what an attacker gains.

Expect an acknowledgement within a few days. Since there is no bounty program
yet and nothing is deployed, please treat this as good-faith collaboration
rather than a payout process.

**Please do report** anything that breaks a property in *The security
properties that are real* above — that list is the claim, and a way to break it
is exactly what we want to hear about. Please **don't** report items in
*Known-unsafe by design*; those are documented trade-offs, not findings.

## Supported versions

Pre-1.0 and pre-release: only `main` is supported. There are no security
backports.
