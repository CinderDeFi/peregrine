# Peregrine — audit package

Everything a reviewer needs to scope, understand, and attack this system.
Written for someone who has never seen the repository.

> **Status: unaudited.** No third party has reviewed this code. It has never
> been deployed to any network and holds no value. This document exists to make
> an audit *efficient*, not to suggest one has happened.

For the EVM contract specifically, see [`contracts/AUDIT.md`](contracts/AUDIT.md),
which goes deeper on that one file. This document covers the whole system.

An internal security review was conducted; its findings and their resolutions
are in [§14](#14-internal-review--resolved-findings). This does not replace a
third-party audit.

---

## 1. What Peregrine is

A data-native Layer-1: signed high-frequency records ride **inside** consensus
dissemination rather than queueing behind blocks, commit to a deterministic
total order, and materialize into Merkle-verifiable tables. A light client
holding a 32-byte root can verify any point read for itself.

The design bet is that *reads should carry proofs*. Most chains ask you to
trust an RPC provider for state; here every read is verifiable against a root,
and every cross-chain fact is re-derived from cryptography the verifier checks
itself.

### Size

| | lines |
|---|---|
| Total Rust across crates | ~13,900 |
| **Consensus-critical subset** (see §3) | **~3,660** |
| EVM contract | 300 |
| TypeScript light client | ~400 |

An auditor who reads only §3's file list has seen everything that can fork the
chain or forge a proof.

---

## 2. Architecture in one pass

```
   clients ──RPC(QUIC)──▶ ingest queue ─┐
                                        ▼
   peers ──QUIC──▶ [ DAG: Stoop BFT, uncertified ] ──▶ committer
                                        │                  │
                          sig-verify tiles (parallel)      │ deterministic
                                        │                  │ total order
                                        ▼                  ▼
                              ExecutionPipeline ──▶ TableStore (sparse Merkle)
                                        │                  │
                                        │                  └─▶ store root (32B)
                                        └─▶ TalonVM (metered) ─▶ rows
```

| Component | Crate | Role |
|---|---|---|
| Consensus | `peregrine-consensus` | Uncertified DAG (Mysticeti lineage), skip/undecided cascade, commit rule |
| State | `peregrine-data` | Sparse Merkle trees (v1 dense, v2 path-compressed), tables, stream registry |
| Execution | `peregrine-vm`, `peregrine-node` | Metered stack VM; commit-time state transition |
| Interop | `peregrine-interop` | Ethereum verification, zkVM witness/journal, BLS beacon anchoring |
| Transport | `peregrine-node` | QUIC mesh + client RPC |
| Clients | `peregrine-sdk`, `sdk/js`, `contracts/` | Rust, TypeScript, and Solidity verifiers |

---

## 3. Scope

### In scope — consensus-critical

A bug here forks the chain, forges a proof, or corrupts state. **Start here.**

| File | Lines | Why it matters |
|---|---|---|
| `crates/peregrine-consensus/src/committer.rs` | 605 | The commit rule. Non-determinism here forks the chain. |
| `crates/peregrine-consensus/src/dag.rs` | 241 | Vertex admission, parent quorum, equivocation detection. |
| `crates/peregrine-consensus/src/vertex.rs` | 125 | Signature preimage and payload commitment. |
| `crates/peregrine-data/src/smt.rs` | 397 | v1 tree. Still live; roots are pinned by deployed verifiers. |
| `crates/peregrine-data/src/smt_v2.rs` | 629 | v2 path-compressed tree, **incl. non-inclusion soundness**. |
| `crates/peregrine-data/src/tables.rs` | 668 | Store root composition, proof construction, version migration. |
| `crates/peregrine-node/src/pipeline.rs` | 683 | The state transition, claim policy, Merkle upgrade activation. |
| `crates/peregrine-interop/src/state.rs` | 281 | The Peregrine→EVM statement, ABI encoding. |
| `crates/peregrine-data/src/sessions.rs` | 640 | **New.** Session-key policy: scope, budget, expiry, revocation, replay. Authorises spending. |
| `contracts/src/PeregrineLightClient.sol` | 300 | On-chain verifier. See `contracts/AUDIT.md`. |

Also in scope, lower density:

- `crates/peregrine-interop/src/{witness,zk,eth,beacon}.rs` — Ethereum→Peregrine
  verification and the zkVM boundary.
- `crates/peregrine-node/src/tiles.rs` — parallel signature verification;
  the property to check is that it cannot change a verdict.
- `sdk/js/src/{hash,verify}.ts` — the independent TypeScript verifier.
- `sdk/js/src/{bincode,sessions}.ts` — **new.** TypeScript reproduction of
  Rust's bincode encoding for session grants. A divergence here produces
  signatures that are rejected with no diagnosable cause; checked by byte
  equality against Rust fixtures, not merely by "it verified".
- `crates/peregrine-node/src/templates.rs` — RWA contract templates. Not
  consensus-critical (they compose existing opcodes), but they are what
  integrators will copy, so a mistake propagates.

### Out of scope

Stated so nobody spends time confirming what is already known-unsafe:

- **Dev TLS.** Self-signed certs, verification disabled. Transport is
  unauthenticated by design at this stage; consensus signature-checks every
  vertex independently, so an unauthenticated link cannot forge blocks — only
  waste bandwidth. Production binds validator identity into the certificate.
- **Economics.** Fee schedule and split exist but are unmodelled. No staking,
  slashing, delegation, or token.
- **DoS resistance beyond per-connection limits.** See §6.
- **`peregrine-cli`, `demos.rs`, `bench.rs`, `sim.rs`** — operator/demo surface,
  not consensus.
- **Vendored `contracts/lib/sp1-contracts`** — Succinct's verifier, audited by
  them, vendored unmodified at v6.1.0.

---

## 4. Trust model

### What a Peregrine node trusts

1. **A ⅔ stake quorum of the committee.** Standard BFT assumption. Below that,
   safety fails — as designed.
2. **BLAKE3 and ed25519.**
3. **For cross-chain claims:** SP1's proof system, the pinned guest program
   image, and a BLS-verified beacon anchor. All three are checked; none is
   assumed.

### What it does *not* trust

- Any RPC client. Submissions are unauthenticated by design; a proof is its own
  authorization.
- Any relayer. Foreign claims are verified by **every** validator at commit
  time, so acceptance is part of the state transition rather than something a
  relayer is trusted to have done.
- Any field of a witness before verification. Journals are **derived** by
  verification, never copied from input.
- The transport.

### What a *light client* trusts

Exactly one thing: the 32-byte store root, obtained honestly. Everything else
is verified locally. That is the property most worth attacking — if a proof can
be forged against a root, the whole design collapses.

---

## 5. Invariants

Each is enforced in code and has at least one test. A reviewer's most useful
question is "can I violate this?"

### Consensus

| # | Invariant | Where |
|---|---|---|
| C1 | One vertex per author per round; a second is equivocation, detected and refused. | `dag.rs` |
| C2 | A vertex is admitted only if its parents form a ⅔ stake quorum of the previous round. | `dag.rs` |
| C3 | Every vertex's signature is verified before it enters the DAG. | `dag.rs` |
| C4 | The commit rule is a pure function of the DAG — same DAG, same committed order, on every node. | `committer.rs` |
| C5 | A node's own proposal is inserted before broadcast, so its next round always links its previous vertex. | `validator.rs` |

### State

| # | Invariant | Where |
|---|---|---|
| S1 | The store root is a pure function of the rows. | `tables.rs` |
| S2 | Two validators applying the same committed order reach byte-identical roots. | `pipeline.rs`, `sim.rs` |
| S3 | Parallel signature verification changes *when* work happens, never what it decides. | `tiles.rs` |
| S4 | A Merkle version migration changes the commitment, never a row value. | `tables.rs` |
| S5 | All validators migrate at the same committed round. | `pipeline.rs` |
| S6 | A proof declares its tree version; one version's proof never verifies under the other. | `tables.rs`, `verify.ts` |

### Verification

| # | Invariant | Where |
|---|---|---|
| V1 | **Absence is not zero.** `LoadEthState` traps rather than returning 0 for unverified state; `getVerifiedValue` reverts rather than returning 0. | `pipeline.rs`, `.sol` |
| V2 | A foreign claim is refused unless its block is anchored by a BLS-verified beacon update. | `pipeline.rs` |
| V3 | A proof of a *different program* is refused — the guest image is pinned. | `sp1_backend.rs`, `.sol` |
| V4 | Verification strictly precedes decoding of any attacker-supplied journal. | `.sol` |
| V5 | Non-inclusion cannot be forged by presenting an unrelated leaf. | `smt_v2.rs`, `verify.ts` |
| V6 | A session key can only ever do **less** than its principal: scope is an allow-list, spend is capped per action and in total, and authority ends at a committed round. | `sessions.rs` |
| V7 | A refused session action changes no state — no debit, no nonce bump, no partial write. | `pipeline.rs` |
| V8 | Only a principal may revoke its session; revocation is immediate and terminal. | `pipeline.rs` |

**V5 is the newest and least battle-tested.** v2 non-inclusion has two shapes
(empty slot, or a different key occupying it), and the second requires checking
that the presented leaf is a *different* key **and** shares the queried key's
path prefix. Omit either and any leaf proves any key's absence.

---

## 6. Threat model

| Adversary | Capability | Mitigation | Residual risk |
|---|---|---|---|
| **Malicious relayer** | Submits arbitrary claims/proofs | Every validator verifies independently; image + chain + anchor pinned | None known — this is the best-covered path |
| **Byzantine validator (<⅓)** | Equivocates, withholds, proposes garbage | Equivocation detected; skip/undecided cascade preserves liveness | **Detected, not slashed.** No penalty exists. |
| **Byzantine validator (≥⅓)** | — | — | Safety fails. Standard, out of scope. |
| **Malicious node serving reads** | Returns wrong values/proofs | Light client verifies against the root | Client must obtain the root honestly — that is the whole trust surface |
| **Network attacker** | Reads/injects/drops traffic | Consensus signature-checks everything | Dev TLS means traffic is readable and peers unauthenticated |
| **Resource exhaustion** | Floods RPC | Per-connection token buckets, weighted by cost; size caps | **Not Sybil resistance.** Many connections get many buckets. |
| **Malicious publisher** | Signs bad data into a stream | Signature + sequence checks | **Garbage-in is not addressed.** No data-quality slashing. |
| **Compromised SP1 setup** | Forges Groth16 proofs | — | Inherited trusted setup; unavoidable for EVM-affordable verification |
| **Chain-split via config** | Validators disagree on a consensus parameter | Parameters documented as consensus-critical | Nothing *enforces* agreement. See §7. |

**V6–V8 are the newest surface in the system.** Session keys authorise
*spending*, so a policy bug there is directly monetisable — unlike most bugs
here, which merely break a proof. They are also the only place where expiry is
evaluated, and expiry measured in wall-clock time rather than committed rounds
would fork the chain. Worth attacking early.

### The attack I would try first

Forge a v2 non-inclusion proof (V5). It is the newest code, the logic has two
branches that are easy to conflate, and success would let a node deny that
committed state exists. Second: find a path where `pipeline.rs` applies a
foreign claim without an anchor (V2).

---

## 7. Consensus-critical configuration

⚠️ These are **protocol parameters, not local settings**. Validators that
disagree compute different state and fork. Nothing in the code enforces
agreement across nodes — that is a real gap and a deliberate one at this stage.

| Parameter | Where | Effect of disagreement |
|---|---|---|
| `ClaimPolicy` | `pipeline.rs` | Different validators accept different foreign claims |
| `merkle_v2_activation` | `pipeline.rs` | Different store roots from the activation round on |
| `MAX_CLAIMS_PER_COMMIT` | `pipeline.rs` | Divergent execution budgets |
| Committee + stakes | genesis | Different quorum arithmetic |
| Guest image ID | verifier config | Different proofs accepted |

---

## 8. Known limitations

Ranked by how much they should worry a reviewer.

1. **No audit.** This document is preparation for one.
2. **Committee rotation (Peregrine→Ethereum) is not implemented.** The EVM
   client pins a committee digest immutably, so a validator-set change requires
   a new deployment. Weakest link in that direction.
3. **Equivocation is detected, not slashed.** A misbehaving validator is
   surfaced and ignored; nothing is at stake.
4. **Groth16 trusted setup**, inherited from SP1 for the EVM direction.
   Peregrine's own verification of Ethereum uses Compressed STARK, which needs
   no setup — the asymmetry is a property of the EVM, not the protocol.
5. **RPC rate limiting is per-connection**, not Sybil-resistant.
6. **`bincode` wire format** is not canonical; unsuitable for cross-implementation
   consensus as-is.
7. **TalonVM has no state-rollback journal** — a trapped transaction's partial
   writes persist (deterministically on every node, so not a fork, but wrong).
8. **Unbounded outbound queues** — a permanently slow peer can grow memory.
9. **The whole snapshot is rewritten per flush**; fine at bootstrap sizes.
10. **No completeness in range proofs** — membership of listed rows is proven,
    but not that no other key exists in range.
11. **Grains are not conserved** (audit M-1). `sys.balances` is a credit-only
    total, not a ledger: payments credit the payee with no matching debit, and
    there is no funding primitive, so `budget_grains` is an emission cap rather
    than backed value. Do not build value logic on `sys.balances`.

---

## 9. Prior analysis

| Tool | Target | Result |
|---|---|---|
| Slither 0.11.5 | `PeregrineLightClient.sol` | **0 findings** across 101 detectors. Dispositions in [`contracts/SLITHER.md`](contracts/SLITHER.md). |
| `cargo clippy -D warnings` | whole workspace | clean |
| `cargo fmt --check` | whole workspace | clean |
| Flaky-test soak (per-binary + full-suite) | integration tests | 3 flakes found & fixed; see §10 |
| MythX / Certora / formal | — | **not run** |

A clean Slither run means "no known pattern-level defects" and nothing more.
It cannot tell you whether the right committee is pinned, whether the Rust
encoder agrees with `abi.decode`, or whether a non-inclusion proof is sound —
which are the things most likely to be wrong here.

**Fuzzing status:** Solidity tests run 512-run Foundry fuzzing. Rust has
property-style tests but **no coverage-guided fuzzing** (no `cargo-fuzz`
targets). The SMT and the committer are the obvious candidates and would be a
high-value addition.

---

## 10. Test suite

| Suite | Count | Command |
|---|---|---|
| Rust | 222 | `cargo test --workspace` |
| Solidity (Foundry) | 41 | `cd contracts && forge test` |
| TypeScript | 60 | `cd sdk/js && npm test` |

Tests worth reading first, because they encode the properties above:

- `crates/peregrine-node/tests/tiled_determinism.rs` — S3
- `crates/peregrine-node/tests/merkle_migration.rs` — S4, S5, S6
- `crates/peregrine-data/src/smt_v2.rs` (tests module) — V5
- `crates/peregrine-interop/tests/zk_security.rs` — V3
- `crates/peregrine-node/tests/agent_sessions.rs` — V6, V7, V8
- `contracts/test/PeregrineLightClient.t.sol` — V1, V4
- `sdk/js/test/verify.test.ts` — cross-language agreement, both tree versions

### Determinism of the suite itself

An audit is worth little if the suite it rests on is unreliable, so the flaky
tests were hunted rather than tolerated. **Four** tests were fixed — of two
*different* kinds (three timing, one shared-state), and the last only
reproducible by running the whole suite at once:

| Test | Symptom | Root cause | Fix |
|---|---|---|---|
| `restart_recovery` | `v2 diverged after restart`, ~1 in 6 under load | Fixed 6 s drain; the restarted node was still catching up when the test shut down. **Lag, not a fork.** | Polls every validator's `Query::StoreRoot` until all four agree, then asserts |
| `quic_network` | `EADDRINUSE` on rebind, ~1 in 5 under load | Fixed 200 ms sleep before rebinding the same UDP port; the OS had not released it | Retries the bind until it succeeds |
| `crash_liveness` | `committed nothing`, intermittent under load | Fixed 3 s sleep before asserting the survivors committed | Polls until the survivors' root moves past its pre-commit baseline |
| `sp1_backend::elf_path…` | `assertion failed: …ends_with(GUEST_PACKAGE)`, ~1 in 4 **only in the full suite** | Two tests fought over the process-global `PEREGRINE_ETH_GUEST_ELF`; one asserted on its *absence* while the other set it | Split the pure path logic out and test it with an explicit argument — no global env touched |

Two lessons a reviewer should take from this:

* **The first three were the same mistake — a `sleep` encoding a guess about
  machine speed.** A loaded CI box is not the machine the guess was made on.
  Every one now waits on the actual condition and times out only on a genuine
  failure, printing enough state to tell lag from a fork.
* **The env-var race was invisible to per-test soaking.** It only appears when
  multiple tests share a process, which is exactly the full-suite run. It was a
  latent bug from the day those tests were written, masked until the suite grew
  busy enough to interleave them. It is fixed structurally (no test mutates
  global env) rather than by serialising, because a mutex would have hidden the
  design smell instead of removing it.

The `restart_recovery` distinction matters most: a diverged root *looks* like a
consensus fork, the most serious possible finding. It was not one — a genuinely
forked node never converges, whereas this one always does once given time. The
rewritten test proves that difference rather than hiding it.

Reproduce the hunt with the two soak harnesses — one loops a single binary
under CPU load, the other loops the whole suite (which is what caught the env
race):

```powershell
scripts/soak.ps1 -Runs 10 -Load 28 -TestName restart_recovery
scripts/soak_full.ps1 -Runs 10
```

Measured after the fixes, on a 32-thread machine:

| Test | Before | After |
|---|---|---|
| `restart_recovery` | 1/6 failed | **0/10** |
| `quic_network` | 1/5 failed | **0/8** |
| `crash_liveness` | intermittent | **fixed; poll-based** |
| `sp1_backend::elf_path…` | 1/4 in full suite | **hermetic; cannot race** |
| full workspace suite | 2/8 failed | **0/10** |

The full-suite figure is the one that matters: `soak_full.ps1` looping
`cargo test --workspace` went from 2 failures in 8 runs (the env race and a
`crash_liveness` timing flake) to **0 in 10** after the fixes, on the same
machine.

⚠️ Absence of failure in a soak is evidence, not proof. These are concurrent
network tests; a rarer race could still exist below the detection floor of
these runs. The honest claim is "the four reproducible flakes are gone", not
"there are no races".

### Test coverage map

Which tests actually establish each invariant, so a reviewer can check the
claim rather than take it on trust. An invariant with no test is listed as
such rather than omitted.

| # | Invariant | Covering tests |
|---|---|---|
| C1 | one vertex per author per round | `peregrine-consensus` unit tests (`dag.rs`) |
| C2 | parents form a stake quorum | `peregrine-consensus` unit tests (`dag.rs`) |
| C3 | every vertex signature verified before insert | `peregrine-consensus` unit tests (`vertex.rs`, `dag.rs`) |
| C4 | commit rule is a pure function of the DAG | `committer.rs` unit tests; `sim.rs` cross-validator root equality |
| C5 | self-parent linked before broadcast | `crash_liveness.rs`, `restart_recovery.rs` |
| S1 | store root is a pure function of rows | `tables.rs` unit tests |
| S2 | same committed order → identical roots | `sim.rs`; `restart_recovery.rs`; `agent_sessions.rs::two_nodes_applying_the_same_actions_agree` |
| S3 | tiles change timing, never verdicts | `tiled_determinism.rs` (0/1/4/8 tiles) |
| S4 | migration changes commitment, not rows | `merkle_migration.rs::migration_preserves_every_row` |
| S5 | all validators migrate at the same round | `merkle_migration.rs::activation_is_keyed_to_the_committed_round` |
| S6 | proofs declare their tree version; no cross-version acceptance | `merkle_migration.rs`; `sdk/js/test/verify.test.ts` |
| V1 | absence is not zero | `pipeline.rs` tests; `templates.rs::an_unproven_balance_traps_instead_of_reading_zero`; `PeregrineLightClient.t.sol::test_UnprovenValueReverts` |
| V2 | claims require a BLS-verified anchor | `foreign_claims.rs`; `zk_commit_path.rs` (slow, SP1) |
| V3 | guest image is pinned | `zk_security.rs`; `PeregrineProofE2E.t.sol` (passes against a real proof, ~418k gas) |
| V4 | verification precedes decoding | `PeregrineLightClient.t.sol::test_ProofIsCheckedBeforeJournalIsRead` |
| V5 | non-inclusion cannot be forged | `smt_v2.rs` tests; `sdk/js/test/verify.test.ts` (v2 soundness block) |
| V6 | a session key can only do less than its principal | `sessions.rs` unit tests; `agent_sessions.rs` |
| V7 | a refused session action changes no state | `agent_sessions.rs::a_refused_action_changes_no_state` |
| V8 | only a principal may revoke | `agent_sessions.rs::only_the_principal_can_revoke` |
| — | **cross-language encoding** (Rust ⇄ TS) | `sdk/js/test/verify.test.ts`, `sdk/js/test/sessions.test.ts` — byte equality against Rust fixtures, regenerated in CI |

**Gaps a reviewer should know about:**

* **V3's on-chain half now executes end to end.** `PeregrineProofE2E.t.sol`
  verifies a real SP1 Groth16 proof of Peregrine state through the vendored real
  verifier (~418k gas, verify + record). Regenerating the proof needs the SP1
  toolchain and Docker; when the committed fixture is absent the Foundry suite
  skips it loudly rather than faking a pass.
* **No coverage-guided fuzzing in Rust.** Solidity has 512-run Foundry fuzzing;
  Rust has property-style tests only. `smt_v2` and `committer` are the obvious
  `cargo-fuzz` targets.
* **No test asserts liveness under ≥⅓ Byzantine validators** — only crash
  faults (`crash_liveness.rs`).
* **Economic properties are untested** because they are unmodelled.

### Reproducing everything

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings

cd contracts && git submodule update --init --recursive && forge test -vv

cd sdk/js && npm install && npm test

# Cross-language: regenerate fixtures from Rust, verify in TypeScript
cargo run -p peregrine-node --example gen_js_fixture && cd sdk/js && npm test
```

Two slow, high-assurance checks are **not** in the default suite and require
the SP1 toolchain (Linux/WSL2) plus Docker:

```bash
# A real ZK proof verified inside the commit path (~213 s to prove)
cargo test -p peregrine-node --features sp1 --test zk_commit_path -- --nocapture

# Regenerate the real Groth16 proof fixture verified by SP1's on-chain verifier
cargo test -p peregrine-interop --features sp1 --test state_groth16 -- --ignored
```

The second produces the fixture that `PeregrineProofE2E.t.sol` checks; that e2e
**passes** — a real proof of Peregrine state is accepted by the vendored real
verifier for ~418k gas, closing the last link between the prover and the on-chain
verifier. Regenerating the proof needs the SP1 toolchain and Docker, and needs
the WSL VM to have enough memory (proving peaks above 23 GB — an under-provisioned
VM OOM-kills it mid-STARK). When the committed fixture is absent the Foundry
suite skips that test loudly rather than letting it look like a pass.

---

## 11. What an audit should prioritise

If budget is limited, in this order:

1. **v2 non-inclusion soundness** (V5) — newest, subtlest, highest impact.
2. **The commit rule's determinism** (C4) — a non-deterministic edge case
   forks the chain and would be invisible in testing.
3. **The foreign-claim path** (V2, V3) — anchoring, image pinning, and the
   budget reset, in `pipeline.rs::apply_foreign_claim`.
4. **Cross-language encoding** — the guest hand-writes nine 32-byte words that
   Solidity `abi.decode`s. A silent disagreement shifts every field.
5. **The migration** (S4–S6) — a chain mid-upgrade is the least-exercised state
   the system can be in.

## 12. Security checklist

A reviewer's quick pass over the categories that catch most real findings. ✅
means addressed and tested; ⚠️ means a documented, deliberate gap.

**Cryptography & proofs**
- ✅ Domain separation on every signature (vertex, checkpoint, stream, and the
  three session domains are disjoint).
- ✅ Journals are *derived* by verification, never copied from a witness.
- ✅ Guest image pinning; a proof of another program is refused.
- ✅ ZK verification is part of the state transition (every validator), not a
  relayer's claim.
- ⚠️ Groth16 inherits a trusted setup (EVM direction only).

**State & determinism**
- ✅ Store root is a pure function of rows; validated cross-validator.
- ✅ Parallel signature verification cannot change a verdict.
- ✅ Merkle migration is round-gated and preserves every row.
- ✅ No wall-clock time anywhere in consensus state (session TTL is in rounds).
- ✅ `BTreeMap` for all consensus-visible iteration; no `HashMap` ordering
  leaks into a root.

**Access & authority**
- ✅ Session keys are scoped, budget-capped, expiring, and revocable.
- ✅ A refused action changes no state.
- ✅ Only a principal may revoke its session.
- ✅ RPC submissions are unauthenticated by design; the proof is the
  authorization.
- ⚠️ RPC rate limiting is per-connection, not Sybil-resistant.

**Failure & absence**
- ✅ Unverified foreign state traps; unproven on-chain reads revert. Never zero.
- ✅ A trapped VM transaction is still metered (no free computation).
- ⚠️ A trapped transaction's partial writes persist (no rollback journal) —
  deterministic on every node, so not a fork, but a wrong intermediate state.

**Operational**
- ✅ Restart recovery reloads state and rejoins without forking (now tested
  deterministically under load).
- ✅ Snapshot writes are atomic (single redb transaction).
- ⚠️ Whole snapshot rewritten per flush; fine at bootstrap sizes.
- ⚠️ Unbounded outbound queues; a slow peer can grow memory.
- ⚠️ Dev TLS: transport unauthenticated, consensus signature-checked.

**Consensus configuration** (§7)
- ⚠️ Nothing *enforces* that validators agree on consensus parameters
  (`ClaimPolicy`, `merkle_v2_activation`, committee). Disagreement forks.

## 13. Contact

Security issues: see [`SECURITY.md`](SECURITY.md). Please do not open a public
issue for a vulnerability.

---

## 14. Internal review — resolved findings

An internal security and correctness review was conducted over the
consensus-critical surface, the concurrency paths, and the cross-chain crypto.
No CRITICAL issues were found. Every finding below has been addressed; each fix
carries an `AUDIT <id>` comment at its site.

### HIGH

**H-1 — Parent-round consensus invariant was a `debug_assert` (release-unchecked).**
`Dag::insert` (`crates/peregrine-consensus/src/dag.rs`) enforced "every parent
of a round-`r` vertex is at round `r-1`" only in debug builds. The commit rule's
safety argument depends on the DAG being layered (an anchor's causal history
holds a stake quorum at every round below it; `Dag::reaches` assumes parents
strictly decrease in round), so in a release build a Byzantine author could have
submitted a correctly-signed vertex with cross-round parents.
**Resolved:** promoted to a hard `DagError::NonLayeredParent`, returned in every
build. Regression tests `a_vertex_with_a_non_layered_parent_is_rejected` and
`a_correctly_layered_vertex_is_accepted` added. *No end-to-end fork was
demonstrated — the direct commit rule filters votes/certs by exact round — but
the invariant is load-bearing and the fix is free.*

### MEDIUM

**M-1 — Session payments credit without debiting (grains not conserved).**
`Pay` and per-record subscription charges `credit` the payee with no matching
debit, so `sys.balances` is a credit-only total, not a conserved ledger.
**Resolution: documented, not "fixed" by adding a debit — deliberately.** The
scaffold has **no funding primitive** (no genesis allocation, faucet, or mint),
so every account starts at zero; a conservative debit-and-refuse model would
make the *first* payment impossible for everyone and break the working
agent/RWA demos. Implementing a real conserved ledger is future economic work
that must begin with a funding source. The behaviour is now called out
prominently at `balances_table()`, `ExecutionPipeline::credit`, and in the
"Known limitations" section: `budget_grains` is a per-session emission *cap*,
`sys.balances` is not spendable value.

### LOW

**L-1 — Indirect-scan window used a fixed `r + 3 + 512` offset.**
An Undecided anchor whose deciding commit first appeared beyond the fixed
window could be stranded (remote liveness hazard). **Resolved:** the indirect
scan now runs to the DAG frontier (`highest_round`), which already bounds the
work; the fixed-offset field was removed.

**L-2 — Non-saturating `+=` on the subscription payment sum.**
`total += *paid` in `charge_subscribers` could wrap in release. **Resolved:**
`saturating_add`, matching the discipline used everywhere else in the fee path.

**L-3 — Tile collection blocked a tokio worker synchronously.**
The commit path blocks on crossbeam channels while sig-verify tiles work; on an
async worker this could starve the runtime. **Resolved:** the dispatch/collect
is wrapped in `block_in_place`, guarded so it is applied only on a multi-thread
runtime (it would panic off a runtime or on a current-thread one). Verdicts are
unchanged — this affects scheduling, never results.

### INFORMATIONAL

**I-1 — `read_frame` allocated up to 64 MiB before the 8 MiB RPC cap applied.**
**Resolved:** added `read_frame_capped(recv, max)`; the RPC server passes
`MAX_CLAIM_BYTES`, so the length prefix is checked against the tighter bound
before any allocation.

**I-2 — `check_participation` did not enforce the 64-byte bitvector length.**
The BLS verifier rejected wrong lengths (so there was no bypass), but the count
and the verifier could run over different-length inputs. **Resolved:**
`check_participation` now enforces exactly 512 bits.

**I-3 — `SmtV2::split` panics on a BLAKE3 collision.**
**Resolved as intentional, with rationale recorded in the code.** A collision is
~2^128 work (unreachable); the softer alternatives (no-op / drop a key) would
silently pick a winner that could differ across nodes → an invisible fork. A
deterministic halt is the correct response to an impossible-yet-catastrophic
invariant break.

**I-4 — Non-deterministic verdict if a sig-verify tile panicked mid-batch.**
`crypto::verify` does not panic on its length-validated inputs, but a future
change might, and a panicking tile would leave a scheduling-dependent job
unverified. **Resolved:** the tile runs each job inside `catch_unwind`; a
panicking job resolves deterministically to `false` (fail-closed) and the tile
survives.

### Verification

After the fixes: `cargo test --workspace` (222 tests), `cargo clippy --workspace
--all-targets -D warnings`, and `cargo fmt --check` are all clean, and the full
suite passes in an isolated run. The two consensus regression tests added for
H-1 are the net +2 over the previous count.
