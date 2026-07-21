# Peregrine — audit package

Everything a reviewer needs to scope, understand, and attack this system.
Written for someone who has never seen the repository.

> **Status: unaudited.** No third party has reviewed this code. It has never
> been deployed to any network and holds no value. This document exists to make
> an audit *efficient*, not to suggest one has happened.

For the EVM contract specifically, see [`contracts/AUDIT.md`](contracts/AUDIT.md),
which goes deeper on that one file. This document covers the whole system.

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
| `contracts/src/PeregrineLightClient.sol` | 300 | On-chain verifier. See `contracts/AUDIT.md`. |

Also in scope, lower density:

- `crates/peregrine-interop/src/{witness,zk,eth,beacon}.rs` — Ethereum→Peregrine
  verification and the zkVM boundary.
- `crates/peregrine-node/src/tiles.rs` — parallel signature verification;
  the property to check is that it cannot change a verdict.
- `sdk/js/src/{hash,verify}.ts` — the independent TypeScript verifier.

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

---

## 9. Prior analysis

| Tool | Target | Result |
|---|---|---|
| Slither 0.11.5 | `PeregrineLightClient.sol` | **0 findings** across 101 detectors. Dispositions in [`contracts/SLITHER.md`](contracts/SLITHER.md). |
| `cargo clippy -D warnings` | whole workspace | clean |
| `cargo fmt --check` | whole workspace | clean |
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
| Rust | 184 | `cargo test --workspace` |
| Solidity (Foundry) | 41 | `cd contracts && forge test` |
| TypeScript | 41 | `cd sdk/js && npm test` |

Tests worth reading first, because they encode the properties above:

- `crates/peregrine-node/tests/tiled_determinism.rs` — S3
- `crates/peregrine-node/tests/merkle_migration.rs` — S4, S5, S6
- `crates/peregrine-data/src/smt_v2.rs` (tests module) — V5
- `crates/peregrine-interop/tests/zk_security.rs` — V3
- `contracts/test/PeregrineLightClient.t.sol` — V1, V4
- `sdk/js/test/verify.test.ts` — cross-language agreement, both tree versions

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

# A real Groth16 proof verified by SP1's on-chain verifier — WRITTEN, NEVER RUN
cargo test -p peregrine-interop --features sp1 --test state_groth16 -- --ignored
```

⚠️ The second has **never been executed** — generating the proof needs Docker,
which was unavailable in the development environment. The Foundry suite skips
that test loudly rather than letting it look like a pass. **Running it is the
single highest-value thing a reviewer with a Docker host can do**, because it
is the only untested link between the prover and the on-chain verifier.

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

## 12. Contact

Security issues: see [`SECURITY.md`](SECURITY.md). Please do not open a public
issue for a vulnerability.
