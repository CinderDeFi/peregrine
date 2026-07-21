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

## Known-unsafe by design

These are deliberate bootstrap shortcuts, documented so nobody mistakes them
for oversights. Each is also called out in the README.

| Component | What is unsafe | Consequence |
| --- | --- | --- |
| **TLS** (validator mesh + RPC) | Self-signed certs, verification disabled | Transport is unauthenticated. Consensus still signature-checks every vertex, so blocks can't be forged — but bandwidth can be wasted. |
| **Client RPC** | No auth, quotas, or rate limits | Trivially DoS-able. Needs stake- or key-weighted admission control before public exposure. |
| **TalonVM** | No state-rollback journal | A trapped transaction's partial writes persist (deterministically on every node). |
| **Equivocation** | Detected, not slashed | A double-proposing validator is surfaced but not punished. |
| **Wire format** | `bincode` | Not a canonical encoding; unsuitable for cross-implementation consensus. |
| **EVM contract** | Unaudited, undeployed, never run against a real Groth16 proof | Do not deploy. |
| **SP1 backend** | Written but never compiled or executed | `Proof::Native` carries **no** cryptographic argument. |

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
  cryptography.

These are enforced by tests that run on every CI push — see
`tests/zk_security.rs`, `tests/foreign_claims.rs`, and
`tests/bls_sync_committee.rs`.

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
