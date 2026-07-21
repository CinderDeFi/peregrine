<p align="center">
  <b>PEREGRINE</b> · the data plane of the autonomous economy<br/>
  <i>fly fast. prove everything.</i>
</p>

# Peregrine — bootstrap scaffold (v0.1)

[![CI](https://github.com/peregrine-labs/peregrine/actions/workflows/ci.yml/badge.svg)](https://github.com/peregrine-labs/peregrine/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org)
[![Security policy](https://img.shields.io/badge/security-policy-red.svg)](SECURITY.md)
[![Audit: none](https://img.shields.io/badge/audit-none-critical.svg)](SECURITY.md#audit-status)
[![Website](https://img.shields.io/badge/website-peregrine--labs.github.io-blue.svg)](https://peregrine-labs.github.io/peregrine/)

**[peregrine-labs.github.io/peregrine](https://peregrine-labs.github.io/peregrine/)** — overview, benchmarks, and demo instructions.

📋 **Reviewing this code?** Start with **[AUDIT.md](AUDIT.md)** — scope, trust
boundaries, sixteen named invariants, a threat model, and a ranked list of what
to attack first. One page on the idea: **[docs/PITCH.md](docs/PITCH.md)**.

A data-native, real-time Layer-1. This repository is the **solo bootstrap
phase**: the minimal, honest skeleton of every core subsystem, wired
end-to-end and demonstrated by a local 4-validator network over real QUIC.

> ⚠️ **Unaudited, never deployed, holds no value.** This is a scaffold for
> reading and building on, not for running anything real. The
> [*Honest limitations*](#honest-limitations-of-this-bootstrap) section is long
> on purpose, and [SECURITY.md](SECURITY.md) lists what is deliberately unsafe.

**The wedge proven first: Streams + verifiable state.** Signed
high-frequency records ride *inside consensus dissemination*, are committed
to a deterministic total order, materialize into Merkle-verifiable tables,
and a light client holding only a 32-byte root verifies point reads.

## Quick start

Requires a recent stable Rust (1.85+ is comfortable). Then:

```bash
git clone https://github.com/peregrine-labs/peregrine && cd peregrine
cargo install --path crates/peregrine-cli    # or: cargo run -p peregrine-cli --

peregrine -q demo                            # ← start here: the whole tour
```

**`peregrine demo`** runs everything end to end in about ten seconds, against
real consensus over a real QUIC mesh:

```text
── act 1 · Streams ──────────────────────────────────────
4-validator devnet up on 127.0.0.1:54660 (real QUIC mesh)
published 25 signed price ticks to strm:218f8941
  → committed and materialized: tick #0 = 6150000 cents

── act 2 · TalonVM ──────────────────────────────────────
on-chain loop summed 1..=10 → 55 (metered: compute + data)

── act 3 · Light client ─────────────────────────────────
trusted store root : 86399705eb801dcf419154f0dcc1d74a2a7a55ded18909358438cd8742d4c7e5
  genuine proof           … ✓ as expected
  tampered value          … ✓ as expected
  proof vs. wrong root    … ✓ as expected

── act 4 · Ethereum interop ─────────────────────────────
a contract reads WETH.decimals() with nothing proven yet:
  → tx trapped, nothing written … ✓ as expected
     (LoadEthState refuses to return 0 for unverified state)
  → a claim with no ZK proof is rejected … ✓ as expected
  [demo-only: accepting an unproven claim so the rest can run]
  → contract read WETH.decimals() = 18
```

Act 4 is the one to watch: the default path **refuses**, because nothing has
been proven. The demo then shows the success path explicitly labelled insecure,
so the difference is impossible to miss.

### A worked example: tokenized real-world assets

```bash
peregrine -q sdk example rwa
```

A property-backed loan whose health depends on three things Peregrine can
prove and a bridge cannot: a **valuation** from a signed oracle stream, the
**collateral** posted as USDC on *Ethereum* (read through a verified state
proof), and a **TalonVM contract** that computes loan health from both.

```text
1. oracle valuation committed   : $500000.000000
2. registered on-chain          : rwa.registry[PROP-1729-BRIXTON]

3. verdict with UNVERIFIED collateral … ✓ as expected
   (the tx trapped — an unproven balance is not a balance)

   required collateral (30%)    : $150000.000000
   collateral $200000.000000  (well collateralised) → HEALTHY
   collateral $100000.000000  (short              ) → UNDER-COLLATERALISED

4. verdict proof verifies       … ✓ as expected
```

The contract is nine instructions:

```rust
Instr::LoadTable    { table: registry, key: property },  // valuation (oracle)
Instr::Push(30), Instr::Mul, Instr::Push(100), Instr::Div,  // required = 30%
Instr::LoadEthState { chain_id: 1, address: USDC, slot },  // collateral (proven)
Instr::Lt,                                                 // healthy?
Instr::StoreTable   { table: health, key: property },
Instr::Halt,
```

Step 3 is the point: `LoadEthState` **traps** when the Ethereum leg hasn't been
verified, so an under-collateralised loan cannot be marked healthy by
withholding data — missing data is an error, never a zero. A lender audits the
verdict with the 32-byte store root alone.

### Other entry points

```bash
peregrine devnet up    # a local network with a client RPC endpoint, until Ctrl-C
peregrine sim          # 5,000 ticks + a Talon tx; asserts identical store roots
peregrine bench        # sustained throughput + latency percentiles
peregrine --help       # every command
```

### Watch it live

In a second terminal, point `watch` at a running node:

```bash
peregrine watch --key contract.answers:meaning --key sys.eth_state:0x01…
```

```text
PEREGRINE · live   127.0.0.1:9000   poll #37
────────────────────────────────────────────────────────────
store root   c36395fb…f301f665
             changed since last poll
────────────────────────────────────────────────────────────
contract.answers:meaning  42                   ✓ proven
sys.eth_state:0x01…       18                   ✓ proven

every value above was verified against the root, locally
```

The dashboard is a **client**: it uses nothing but the public SDK, and every
value it shows is re-verified against the root in your own process before it is
printed. If a node lies, the line turns red — the dashboard cannot be used to
launder an unproven value into a pretty display.

### Write and read some state

```bash
peregrine node run &                                  # leave a node running
peregrine submit-tx contract.answers meaning 42       # a Talon tx that writes
peregrine read contract.answers meaning               # read it back, proof-checked
#   value  : 0x2a00000000000000
#   as u64 : 42
#   root   : 193c01a5…
#   proof  : ✓ verified locally
```

`read` never prints a value it hasn't verified against the store root — the
node's word alone isn't good enough.

### Build on it

```bash
peregrine sdk example publish-stream   # publish signed ticks
peregrine sdk example submit-tx        # run a Talon program
peregrine sdk example light-client     # verify, then try to forge

cd sdk/js && npm install && npm test   # TypeScript light client
```

Each example boots a real devnet and drives it **only through the public
SDK** — no in-process shortcuts. (They're also plain `cargo run --example`
targets if you prefer.)

### Develop

```bash
cargo test                                        # 184 tests, all crates
cargo test -p peregrine-interop --features bls    # + real BLS / mainnet fixtures
cd contracts && forge test                        # EVM verifier (41 Foundry tests)
cd sdk/js && npm install && npm test              # TypeScript light client (41 tests, v1+v2)
make ci                                           # everything CI runs
```

| Suite | Count | What it covers |
| --- | --- | --- |
| Rust (default) | 184 | consensus, data plane, VM, persistence, QUIC, SDK, CLI, tile pipeline, Merkle migration |
| Rust (`--features bls`) | 84 | real mainnet BLS signatures + committee rotation |
| Solidity (Foundry) | 41 (+7 skipped) | the EVM verifier: rules, fuzzing, version pinning, cross-language encoding; the real-Groth16 suite skips pending a proof fixture |
| TypeScript | 41 | light-client proofs for **both** Merkle versions, against Rust-generated fixtures |

New here? [CONTRIBUTING.md](CONTRIBUTING.md) covers setup and the crate-boundary
rules; [SECURITY.md](SECURITY.md) is blunt about what is and isn't safe;
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) applies to everyone.

## Repository layout

```
peregrine/
├── Cargo.toml                    # workspace: members, shared deps, profiles
├── crates/
│   ├── peregrine-core/           # pure types — no async, no I/O
│   │   ├── src/crypto.rs         #   BLAKE3 Hash, Ed25519 keys/sigs, domains
│   │   └── src/committee.rs      #   ValidatorId, stake, quorum math
│   ├── peregrine-consensus/      # Stoop BFT (uncertified DAG, Mysticeti lineage)
│   │   ├── src/vertex.rs         #   signed vertices; parents = implicit votes
│   │   ├── src/dag.rs            #   DAG store, quorum checks, equivocation,
│   │   │                         #   deterministic causal linearization
│   │   └── src/committer.rs      #   anchor schedule + commit/skip cascade
│   ├── peregrine-data/           # Slipstream data plane
│   │   ├── src/streams.rs        #   publishers, shreds, registry, fan-out
│   │   ├── src/merkle.rs         #   binary Merkle tree + inclusion proofs
│   │   ├── src/smt.rs            #   incremental sparse Merkle tree (256-deep)
│   │   ├── src/tables.rs         #   TableStore, store root, ProvenRead
│   │   └── src/fees.rs           #   dual meter (CU vs bytes), 50/30/20 split
│   ├── peregrine-vm/             # TalonVM stub
│   │   └── src/lib.rs            #   metered stack ISA (control flow), Host trait,
│   │                             #   call_evm surface, proven reads
│   ├── peregrine-sdk/            # Rust client SDK (+ the shared wire protocol)
│   │   ├── src/protocol.rs       #   RpcRequest/RpcResponse, framing
│   │   ├── src/client.rs         #   async Client over QUIC, SdkError
│   │   └── src/tls.rs            #   dev client TLS
│   ├── peregrine-node/           # wiring + simulation
│   │   ├── src/network.rs        #   Broadcaster/Inbox surface (+ in-process backend)
│   │   ├── src/quic.rs           #   real QUIC transport: framed streams, reconnect
│   │   ├── src/rpc.rs            #   client-facing QUIC RPC server (serves the SDK)
│   │   ├── src/devnet.rs         #   one-call local node + RPC, for examples/tests
│   │   ├── src/payload.rs        #   WirePayload: Shred | TalonTx
│   │   ├── src/pipeline.rs       #   committed order → streams → tables → fees
│   │   ├── src/store.rs          #   redb persistence: snapshot/restore DAG+state
│   │   ├── src/validator.rs      #   per-node event loop (propose/insert/commit)
│   │   ├── src/sim.rs            #   the demonstration (peregrine sim)
│   │   ├── src/bench.rs          #   throughput/latency harness (peregrine bench)
│   │   └── src/demos.rs          #   SDK walkthroughs (peregrine sdk example)
│   └── peregrine-cli/            # the `peregrine` binary
│       ├── src/main.rs           #   clap command tree
│       └── src/config.rs         #   TOML config: defaults, layering, validation
├── sdk/js/                       # TypeScript SDK
│   ├── src/hash.ts               #   BLAKE3 + domain tags (mirrors Rust, v1+v2)
│   ├── src/verify.ts             #   light-client proof verification, version-dispatched
│   ├── src/client.ts             #   typed client, pluggable transport
│   └── test/                     #   verifies real Rust-generated proofs
├── contracts/                    # EVM light client (Foundry) + AUDIT.md
└── website/                      # the public site: one self-contained HTML file
```

## Architecture in one paragraph

Consensus (`peregrine-consensus`) orders **opaque payload items** and knows
nothing about their meaning. The node (`peregrine-node`) defines the wire
payloads (stream shreds, Talon transactions), runs one event loop per
validator, and feeds the committed total order into a deterministic
execution pipeline: shreds are signature-checked, sequenced, fanned out to
subscribers, and materialized into the `sys.stream_ticks` table; Talon
programs execute against the table store through the VM's `Host` trait;
every byte and compute unit is metered on the dual meter and settled
50/30/20 (burn / validators / Data Endowment). Because every validator runs
the identical pipeline over the identical order, their 32-byte store roots
must match — the simulation asserts it.

## Persistence & restart recovery

Nodes survive restarts. `peregrine-node/src/store.rs` keeps one embedded
[redb](https://github.com/cberner/redb) database per validator with two
tables, each holding one bincode blob:

```text
  redb "dag"   → DagSnapshot   (every vertex held)
  redb "state" → StateSnapshot (every TableStore row)
```

* **Only rows are stored, never trees.** The sparse Merkle trees — and the
  store root a light client pins — are a pure function of the rows, so they
  rebuild on load. Fewer bytes, and no chance of a tree disagreeing with the
  rows it supposedly commits to.
* **The commit cursor is re-derived, not persisted.** On boot the DAG is
  rebuilt by re-inserting vertices in round order, then the (pure,
  deterministic) commit rule is replayed over it against a *null observer*, so
  the cursor fast-forwards without re-applying committed payloads.
* **Atomicity is load-bearing.** Both blobs are written in a single redb
  write transaction, guaranteeing the DAG and tables always agree on
  "committed through anchor N" — exactly what lets the restart path trust the
  restored tables against the re-derived cursor.
* **Flush policy** — persist every `N` commits (default 16) plus a guaranteed
  final flush on clean shutdown. The redb commit fsyncs inside
  `block_in_place`, so it never stalls message delivery or a peer's catch-up
  sync on the shared runtime. A gracefully-stopped node resumes at exactly
  `highest_own_round + 1`, so it never re-issues a round a peer already
  accepted from it (self-equivocation).

The `restart_recovery` test kills one of four validators, keeps the survivors
committing, restarts the dead node from disk, and asserts it re-syncs the gap
it missed and converges to the identical store root — including a Talon VM
write committed before the crash.

**Persistence limitations (bootstrap):** the full snapshot is rewritten each
flush (no incremental deltas — fine at bootstrap DAG sizes); after an
*ungraceful* crash the resume point may trail the last few broadcasts by up to
`N` commits (those rounds re-sync from peers; closing the tiny
self-equivocation window is a cheap per-proposal watermark left for
production); and stream-registry sequence counters plus fee/latency *metrics*
are not persisted and reset on restart — the consensus-critical **state
roots** are fully recovered, which is the property that matters.

## Networking & benchmarks

`peregrine-node/src/quic.rs` is a real QUIC transport ([quinn](https://github.com/quinn-rs/quinn))
that produces the *same* `Broadcaster`/`Inbox` surface the in-process backend
does, so the consensus loop is untouched — only the wiring changes.

* **Topology** — full directional mesh. Each node owns one endpoint that both
  accepts and dials. Outbound: one unbounded queue + one writer task per peer,
  writing length-prefixed bincode frames on a single ordered stream. Inbound:
  an accept loop spawns a reader per connection.
* **Reconnect is implicit.** A peer's writer task keeps redialing a dead
  address, so when a killed node rebinds to the same address both directions
  heal with no coordination. The writer *holds the un-acked frame and resends
  it after reconnect*, so a dropped link never silently loses a sync request —
  which, because the fetch layer dedups by hash, would otherwise strand
  recovery.

### Benchmark results

Measured with `peregrine bench` on a **13th-gen Intel i9-13900HX (24C/32T),
32 GB, Windows 11**, 4 validators over QUIC on loopback, release build,
8-second runs. Reproduce with e.g.
`peregrine bench --validators 4 --rate 5000 --duration 8`.

| Offered load | Committed throughput | p50 | p99 | keeps up? |
| --- | --- | --- | --- | --- |
| 1,000 rec/s | 800 rec/s | 2.1 ms | 33.6 ms | yes |
| 3,000 rec/s | 2,400 rec/s | 4.2 ms | 268 ms | yes |
| 5,000 rec/s | 4,578 rec/s | 4.2 ms | 1,074 ms | at the knee |
| flood (max) | 5,470 rec/s | 4,295 ms | 8,590 ms | no — ingest queueing |

* **Sub-5 ms p50 publish→commit** at sustainable load, well inside the
  design's ~300 ms target (loopback has no WAN RTT, so treat this as a floor,
  not a WAN finality claim).
* **Sustained ceiling ≈ 5.5k committed records/s under the original v1 tree.**
  The ceiling was **consensus/commit-side, not the transport**: per-record cost
  was dominated by ed25519 verification and a 256-deep sparse-Merkle update
  replayed on every validator, not by QUIC. Both have since been addressed —
  see the tiled pipeline and path compression below, which together move the
  ceiling to **~34k records/s**. The table above is the v1 baseline, kept
  because the before/after is the interesting part.
* This is a bootstrap number on one laptop with unbatched crypto and
  full-mesh fanout. The design's 250k+ TPS target assumes 64-core validators,
  hardware-batched signature verification, and Turbine-style stake-weighted
  fanout — none of which this scaffold implements yet.

### The tiled pipeline

Commit-side work is split into a **share-nothing tile pipeline**
([`tiles.rs`](crates/peregrine-node/src/tiles.rs)): pinned OS threads that own
their state, talk only over lock-free queues, and never touch the async
runtime. Signature verification runs there; the state transition stays serial.

**The design was chosen from a profile, not from architecture fashion.** Run it
yourself — `cargo run --release -p peregrine-node --example vertex_profile`:

| per committed record | cost | parallelisable |
| --- | --- | --- |
| ed25519 verify | 28 µs (25%) | ✅ tiles take this |
| sparse-Merkle insert | 77 µs (69%) | ❌ it *is* the state transition |
| other | 6 µs (6%) | — |

Only a quarter of the work is parallel, so Amdahl caps tiling alone at ~1.33×
— and that is almost exactly what it delivers (4,727 → 6,324 rec/s measured
with `PEREGRINE_TILES=0` vs `=8` on the same binary). Anyone claiming a large
speedup from "adding tiles" to a pipeline shaped like this is measuring
something else.

Measured, same machine, 4 validators, in-process:

| offered load | tiles off | tiles on (8) |
| --- | --- | --- |
| 6,000 rec/s | p50 **134 ms** | p50 **16.8 ms** |
| 8,000 rec/s | 5,577 rec/s, p50 1,074 ms | 6,170 rec/s, p50 537 ms |
| 10,000 rec/s | 5,127 rec/s *(degrading)* | 6,443 rec/s, p50 1,074 ms |

The headline is not peak throughput (+16%) but **where the knee moves**:
sustainable load at p50 < 50 ms goes from ~4,000 to ~6,000 rec/s, and latency
at 6,000 rec/s drops **8×**. Tiles buy headroom before saturation, which is
what a real-time chain actually needs.

`PEREGRINE_TILES=<n>` overrides the pool size (`0` disables it) so the same
binary can be A/B'd — comparing two builds would confound the tile effect with
everything else that differs between them.

**Determinism is the load-bearing property.** Tiles change *when* verification
happens, never what it decides: verdicts return indexed by input position and
are applied in committed order, so validators with different core counts commit
byte-identical state. Two validators disagreeing along hardware lines would
fork the chain, so this is tested directly — `tiled_determinism.rs` drives
identical batches through 0/1/4/8-tile pipelines and requires equal store
roots, including for the rejection paths.

### Two fixes that mattered more than the tiles

Both were found by profiling rather than by reading the code, and both are the
kind of thing an architecture diagram hides:

1. **Congestion collapse (a real bug).** The validator drained its ingest
   channel with an unbounded `while try_recv()`. Under sustained load that loop
   never terminated, so the node never reached the consensus work below it:
   round rate collapsed from ~4,000/s to ~44/s and publish→commit latency ran
   past **eight seconds**, while an unbounded buffer absorbed the backlog and
   hid the cause. The drain is now capped at one proposal's worth per wake, so
   pressure propagates back to the publisher through the bounded channel
   instead of turning into latency.

2. **The sparse-Merkle tree, the actual bottleneck.** A 256-deep update paid
   SipHash over a 34-byte key twice per level, for keys that are *already*
   uniformly-distributed hashes, and rebuilt a streaming hasher per level.
   Using a trivial hasher for node ids and a one-shot hash for interior nodes
   took the per-row cost from **77 µs → 62 µs** with **byte-identical roots** —
   verified by the existing SMT, light-client, and cross-language fixture tests.

### Path compression (Merkle v2) — the ceiling, removed

That 62 µs Merkle update was 67% of commit cost. It is now **2.0 µs — a 31×
reduction** — via a path-compressed tree
([`smt_v2.rs`](crates/peregrine-data/src/smt_v2.rs)).

**Why this could not preserve roots.** A v1 root is *defined* as a 256-level
fold, so a subtree holding one leaf still has a value produced by ~245 combines
against empty defaults. Any implementation yielding the same root must do that
work — "compression that preserves roots" saves memory and proof size but **not
insert cost**, which was the entire bottleneck. Getting O(log n) means changing
what a node hash *means*, and that changes every root. So this is a consensus
upgrade, versioned and round-gated, not a refactor.

v2 has three node kinds and no per-height defaults: a subtree containing one
leaf simply *is* that leaf. Insert descends only to the first bit where two keys
differ — expected O(log n), and proof depth drops from a fixed 256 to ~log₂(n).

End-to-end, same binary, 4 validators (`PEREGRINE_MERKLE_V2=0` vs `1`):

| offered load | v1 | v2 |
| --- | --- | --- |
| 10,000 rec/s | 5,853 rec/s, p50 **1,074 ms** | 9,593 rec/s, p50 **2.10 ms** |
| 20,000 rec/s | — (saturated) | 19,993 rec/s, p50 **4.19 ms**, p99 16.8 ms |
| flood | 6,911 rec/s | **34,154 rec/s** |

**Sustained ceiling: ~5.5k → ~34k records/s (6.2×).** At 10k/s the node went
from saturated-and-collapsing to keeping up with room to spare, and round rate
rose from 194 to 26,277 over the same window. Latency at load improved by
roughly **500×** because the system is no longer past its knee.

### Migrating a live chain

The upgrade is gated on a **committed round**, not wall-clock time, node start,
or an operator command:

```rust
ExecutionPipeline::new().with_merkle_v2_at(activation_round)
```

Every validator observes the same committed sequence, so every one migrates at
the same point in it and they agree on every root thereafter. Migration happens
*before* that round's payloads are applied, so the boundary is unambiguous:
everything committed at or after the activation round is authenticated under v2.

⚠️ **`merkle_v2_activation` is a consensus parameter.** Validators carrying
different activation rounds compute different roots for identical state and
**fork**. It belongs in genesis, and changes only by coordinated upgrade —
exactly like `ClaimPolicy`.

What the migration does and does not touch:

* **Rows are the authority and are untouched.** `get` returns identical bytes
  before and after; only the commitment changes. A migration that could alter a
  *value* would be a state transition wearing an upgrade's clothes.
* **Roots change, by design.** Light clients must re-pin. A v1 proof is refused
  against a v2 root and vice versa — tested in both directions.
* **Proofs are self-describing** (`RowProof::V1 | V2`). During a rollout both
  are in flight, and a proof that did not declare its rule would be verified
  under the wrong one. The JS fixture now carries `treeVersion` so the
  TypeScript verifier — which implements **v1 only** — can *refuse* a v2 proof
  rather than silently disagree with the chain.
* **Restart safety.** The trees are rebuilt from rows on load, so the snapshot
  records its version. Without that, a migrated node would come back computing
  v1 roots over v2 state and fork from the network it had just agreed with.
* **Idempotent.** A replayed activation is a no-op, so a node restarted mid
  upgrade cannot churn the root.

`crates/peregrine-node/tests/merkle_migration.rs` covers each of these,
including that a migrated store and a natively-v2 store are indistinguishable
(otherwise a rebuilt node would fork from a migrated one).

**Both verifiers now support v2.** The TypeScript light client verifies v1 and
v2, dispatching on the version tag and *refusing* an unknown one rather than
guessing — a silent fallback would verify a future v3 proof under the wrong
rule, the exact failure the tag exists to prevent. Fixtures are generated for
both versions, including v2's two structurally different non-inclusion shapes
(empty slot vs. a different key occupying it), because a verifier tested only
on inclusion would miss the path where a lax implementation lets any leaf deny
any key.

The EVM client gained a fourth pin, `treeVersion`. It verifies a zkVM proof
rather than Merkle paths, so path compression does not change its mechanics —
but it previously could not tell *which rule* a journal's `storeRoot` was
computed under, and a v1 root and a v2 root over identical state are different
32-byte values. The guest now commits the version, **derived from the proof it
actually verified** rather than taken as an input (a relayer that could declare
the version would simply claim whatever the consumer pins). A client pinned to
one version refuses the other in both directions.

`TableStore::new()` still defaults to v1 so nothing changes roots merely by
being recompiled; a chain that has migrated serves v2 and needs clients
deployed with `TREE_VERSION=2`.

**Networking limitations (bootstrap):** dev TLS (self-signed cert per node,
skip-verify client) — production binds the validator's ed25519 identity into
the certificate and pins it; this layer is transport-only, and every vertex is
still independently signature-checked by consensus, so an unauthenticated link
cannot forge blocks, only waste bandwidth. Full mesh, not Turbine-style
stake-weighted fanout. Unbounded outbound queues: a permanently-slow peer can
grow memory (a bounded, drop-oldest queue is the follow-up).

## Execution & metering (TalonVM)

`peregrine-vm` is the bootstrap stub of TalonVM — a small, deterministic,
**metered** stack machine standing in for the eventual RV64 RISC-V core while
locking in the interfaces the rest of the node programs against. Talon
transactions ride inside consensus vertices (`WirePayload::TalonTx`) and are
executed by the commit pipeline against the `TableStore`, identically on every
validator.

* **ISA** — `Push/Pop/Dup/Swap`, wrapping arithmetic (`Add/Sub/Mul/Div/Mod`,
  EVM-style divide-by-zero → 0), comparisons (`Lt/Gt/Eq`), **control flow**
  (`Jump`/`JumpIf` over instruction indices), and data-native host calls.
  Enough for real "compute → branch/loop → write → prove" programs — the sim
  runs a bounded loop that sums `1..=10` entirely on-chain and proves the
  result (`55`).
* **Dual metering** — every instruction charges compute units against a fixed
  budget; host data ops charge the data meter (priced ~1000× below compute).
  Metering lives in the interpreter, not the host, so costs are
  consensus-identical.
* **Bounded & safe by construction** — every instruction costs ≥1 CU, so any
  loop halts (out-of-compute); a jump-target check and a 1024-deep stack cap
  close the other unbounded paths. **Gas is charged even when a tx traps**:
  the meter is always returned and settled, so a program can't buy free
  computation by failing late (verified by a `gas_charged_on_trap` test).
* **Data-native host calls** — `table_insert`, `table_read`, `stream_emit`,
  and `table_read_proven`. The proven read returns the value **plus an
  inclusion proof** and is metered for the proof's bytes, making the cost of a
  verifiable/stateless read explicit.
* **EVM surface** — `Vm::call_evm` lowers a `(to, selector, args)` descriptor
  to an equivalent Talon program through the identical metering + host path.

**VM limitations (bootstrap):** flat 1-CU-per-instruction cost (not
cycle-accurate — that arrives with the RISC-V core); no state-rollback
journal, so a trapped tx's partial writes persist (deterministically on every
node); no inter-contract calls, gas refunds, or memory beyond the table host
calls; `call_evm` is a descriptor stub, not a bytecode interpreter.

## CLI & configuration

`peregrine` is the single entry point. `--help` works at every level.

| Command | What it does |
| --- | --- |
| `peregrine node run` | Run a local validator network + client RPC endpoint, until Ctrl-C |
| `peregrine sim` | The end-to-end demonstration |
| `peregrine bench` | Throughput and publish→commit latency percentiles |
| `peregrine submit-tx <table> <key> <value>` | Submit a Talon tx that writes a value |
| `peregrine read <table> <key>` | Proven read, verified locally before printing |
| `peregrine keygen [--out FILE]` | Generate an ed25519 keypair |
| `peregrine config init \| show` | Scaffold a config file / print the effective one |
| `peregrine sdk example <name>` | Runnable SDK walkthroughs |

Tables accept either a name (`contract.answers`, hashed exactly like
`TableId::named`) or a 32-byte hex id; keys are UTF-8 unless prefixed `hex:`.

### Configuration

Settings layer, lowest precedence first:

1. **built-in defaults** — the CLI works with no config file at all;
2. **file** — `--config <path>`, else `$PEREGRINE_CONFIG`, else
   `./peregrine.toml` if present;
3. **flags** — anything you pass explicitly.

Every table and key is optional: a partial file merges *over* the defaults
rather than replacing them.

```bash
peregrine config init     # writes a commented peregrine.toml
peregrine config show     # prints the effective config after layering
```

```toml
[node]
validators = 4                    # must be >= 2 (see below)
rpc_addr = "127.0.0.1:9000"
max_items_per_vertex = 512
stream = "devnet/demo"

[storage]
path = "./peregrine-data"         # omit to run purely in memory

[logging]
level = "info"                    # or e.g. "peregrine_node=debug,quinn=warn"

[sim]
validators = 4
ticks = 5000

[bench]
validators = 4
duration_secs = 5
rate = 0                          # 0 = flood as fast as possible
transport = "quic"                # or "inproc"
items_per_vertex = 512
```

Configuration is **validated before anything starts**. A typo'd key is an
error naming the key (not a silently ignored setting), and `validators = 1` is
rejected outright:

```
Error: node.validators = 1: need at least 2. A lone validator's own proposal
self-delivers instantly, so it re-proposes in a hot loop with nothing to pace
it. Use 4 for a fault-tolerant committee.
```

That isn't hypothetical — a single-validator devnet burned a full core in
testing before the check existed. `RUST_LOG` still overrides `logging.level`.

## SDKs — building on Peregrine

Two clients ship here: a Rust SDK that talks to a live node over QUIC, and a
TypeScript SDK whose job is to **verify** what a node tells you.

### Rust

```rust
use peregrine_sdk::{Client, Keypair, Publisher, TableId};

let client = Client::connect("127.0.0.1:9000".parse()?).await?;

// Publish a signed price tick — it rides inside consensus vertices.
let mut feed = Publisher::new("acme/BTC-USD", Keypair::generate(&mut rand::rngs::OsRng));
client.publish(feed.emit(61_500_00u64.to_le_bytes().to_vec())).await?;

// Read state with a proof, then verify it against the root — trusting 32 bytes.
let root = client.store_root().await?;
if let Some(read) = client.prove_read(TableId::named("contract.answers"), b"sum").await? {
    assert!(read.verify(&root));
}
```

`Client` covers `ping`, `publish`, `submit_tx`, `submit_claim`, `prove_read`,
and `store_root`, and re-exports the types you need so an app depends only on
`peregrine-sdk`.

### How a client request is served

```text
  SDK --QUIC bi-stream--> rpc.rs --+--> ingest_tx  (publish / submit tx)
                                   `--> Query{oneshot} --> validator loop
                                                           (owns the pipeline)
```

Writes ride the **same ingest queue** the sim uses, so a client submission is
indistinguishable from any other payload once it enters consensus. Reads
become a message answered *inside* the validator loop, keeping the pipeline
single-owner — committed state is never shared behind a lock. Each request
gets its own stream and task. The wire protocol lives in the SDK and the node
depends on it, so there is one source of truth for the contract.

### Submitting a foreign claim over RPC

A relayer hands Peregrine a proof-carrying claim about Ethereum state the same
way it submits anything else:

```bash
peregrine submit-claim ./claim.json          # a serialized VerifiedClaim
#   claim  : chain 1 block 25580559
#   proof  : ZK
#   queued for verification at 127.0.0.1:9000
peregrine read sys.eth_state 0x01…           # did consensus actually accept it?
```

```rust
client.submit_claim(claim).await?;            // queued, not believed
```

**A successful submission means "queued", never "accepted".** The RPC front
door checks only size and rate; the cryptography is checked later, by *every*
validator, inside the commit path — image ID, chain ID, journal binding, and a
BLS-verified anchor, in that order. That split is the point: an RPC endpoint
must never be the thing deciding what consensus believes, because then anyone
who can reach the endpoint decides. The only way to confirm a claim landed is
to read the state back and verify the proof yourself.

### Admission control

`rpc_limits.rs` weights requests by the work they impose downstream rather than
counting them, because a `Ping` and an 8 MB proof are not the same load:

| request | cost | why |
|---|---|---|
| `ping` | 1 | liveness only |
| `prove_read` / `store_root` | 4 | served from committed state |
| `publish` / `submit_tx` | 16 | enters the ingest queue |
| `submit_claim` | 256 | large on the wire, *and* expensive to verify on every validator |

Each connection gets a token bucket (default: 1024 burst, 128 tokens/sec —
roughly four claims of burst, refilling one every two seconds). A bucket
absorbs a legitimate batch while still bounding the sustained rate, which a
fixed window cannot do without either rejecting the batch or permitting double
the intended rate across a boundary. Claims are additionally capped at
`MAX_CLAIM_BYTES` (8 MB) and rejected **before** deserialization, so an
oversized frame costs a length check rather than an allocation.

Bearer auth is available (`RpcLimits::auth_token`) and compared in constant
time, but is **off by default** — a token baked into a public scaffold would be
worse than none, because it would look like protection.

⚠️ **This is not Sybil resistance.** Buckets are per connection, so an attacker
with many connections gets many buckets. It bounds what one client can push and
makes an accidental flood (a looping script) harmless; real protection needs
stake- or key-weighted admission across connections, which this scaffold does
not have. See [SECURITY.md](SECURITY.md).

### TypeScript — verify, don't trust

[`sdk/js`](sdk/js) is a complete reimplementation of Peregrine's proof
verification in TypeScript: the sparse-Merkle row path *and* the
binary-Merkle store path, with BLAKE3 and every domain tag matching Rust byte
for byte.

```ts
const client = PeregrineClient.http("http://localhost:8080/rpc");
// Fetches value + proof, re-derives the root locally, throws if it disagrees.
const row = await client.readVerified(tableId("contract.answers"), "73756d");
```

A light client that verifies *differently* from the chain is worse than none,
so correctness isn't asserted with hand-written vectors: the test suite runs
against **real proofs generated by the Rust node**
(`cargo run -p peregrine-node --example gen_js_fixture`), checking that
tampered values, wrong roots, corrupted paths, replayed keys, and truncated
paths all fail. It also asserts `tableId(name)` matches `TableId::named`.

**Transport limitation, stated plainly:** nodes speak QUIC, and browsers can't
open raw QUIC sockets (Node's support is still experimental), so the TS client
targets a JSON gateway through a swappable `Transport` — **and that gateway is
not implemented yet.** Use the Rust SDK to talk to a live node today. This is
deliberately not a security gap: because `readVerified` re-checks locally, a
gateway can withhold data but never forge it. Record signing and Talon
encoding in TS are also still to do.

## Interoperability — verify, never trust

Bridges get drained because they are secured by a multisig or a relayer's
promise. `peregrine-interop` takes the other route: **every cross-chain fact is
re-derived from cryptography the verifier checks itself.** There is no
committee to bribe, no relayer to trust, and no privileged key anywhere in the
crate — by construction, not by policy.

### Reading Ethereum from Peregrine

```rust
use peregrine_sdk::{verify_eth_storage, EthBlockHeader};

// The state root is read out of the header we hash ourselves — a witness
// cannot supply a root of its choosing alongside a matching proof.
let journal = verify_eth_storage(1, &header, &weth, &account_proof, &slot, &storage_proof)?;
assert_eq!(journal.block_hash, /* independently anchored */ anchor);
```

* **Headers** — `keccak256(rlp(header))` over all 21 canonical fields
  (through Prague/EIP-7685), plus parent-hash chain linkage.
* **State** — Merkle-Patricia Trie traversal for accounts and storage slots,
  from a state root down to a value.

**Tested against real Ethereum mainnet.** `crates/peregrine-interop/tests/fixtures/mainnet.json`
holds a genuine post-Prague block header and a real `eth_getProof` witness for
the WETH contract. The tests are strong because the data is real:

* the header test recomputes the block hash and compares it to the one
  **mainnet itself agreed on** — a single misordered or mis-width field could
  not match;
* the state tests walk a real trie from a real state root and recover WETH's
  real storage, including the independently-known `decimals() == 18`;
* corrupted nodes, **truncated witnesses**, wrong roots, and proofs replayed
  for a different account are all rejected. A truncated witness is an error,
  never silently read as "absent" — that confusion is a classic bridge bug.

### Reading Peregrine from Ethereum (the EVM contract)

[`contracts/PeregrineLightClient.sol`](contracts/) is the reciprocal side. It
verifies **no Merkle paths**: Peregrine commits state with BLAKE3, which has no
EVM precompile, so the whole statement — *a quorum signed a checkpoint
committing to root R, and `table[key] == value` under R* — is proven inside the
zkVM, and the contract verifies one succinct proof plus a pinned `programVKey`.
Gas is then constant regardless of proof depth.

Its `getVerifiedValue` **reverts** for an unproven key rather than returning
zero — the same trap `LoadEthState` avoids in the other direction.

#### The three pins

A proof only means something relative to what it is a proof *of*. Three
immutable values fix that, and all three are checked on every call:

| Pin | Answers | If wrong |
|---|---|---|
| `programVKey` | which program ran | a proof of a *different* program is accepted — still a valid proof, of something else |
| `committeeDigest` | whose signatures counted | a proof built against an attacker's validator set is accepted |
| `peregrineChainId` | which network | a testnet proof applies to mainnet |

None has a setter. An upgradeable pin is an admin key that can redefine what
every past and future proof meant, which would make the cryptography
decorative. The cost is that changing one means a new deployment.

#### Testing

```bash
cd contracts
git submodule update --init --recursive    # forge-std
forge build && forge test -vv              # 41 tests incl. 512-run fuzzing
```

Six invariants are stated in the contract's NatSpec and each has a test — most
importantly that **verification strictly precedes decoding** (the proof is
checked before a single field of the public values is read), that
**equivocation reverts** rather than being absorbed, and that a **contradiction
reverts** rather than silently overwriting. `contracts/AUDIT.md` maps each
invariant to its test.

Two things are cross-checked that neither language can verify alone:

- **The journal encoding.** The guest hand-writes eight 32-byte words; Solidity
  `abi.decode`s them. A silent disagreement would shift every field — a `round`
  read as a `chainId` — and nothing would fail loudly. A Rust-generated fixture
  is decoded, re-encoded, and compared byte-for-byte in Solidity.
- **A real Groth16 proof**, to be verified by SP1's own `SP1VerifierGroth16`
  (vendored at the circuit version SP1 v6 produces), doing the full BN254
  pairing on-chain with no mock in the path. ⚠️ This test is **written but not
  yet run** — generating the proof needs Docker, which was unavailable here, so
  it skips loudly rather than looking like a pass. Running it is the
  highest-value next step for this contract.

Static analysis: **Slither reports 0 findings** across 101 detectors on the
shipped contract ([`contracts/SLITHER.md`](contracts/SLITHER.md)). That is not
an audit — Slither finds patterns, and cannot tell you whether the right
committee is pinned.

⚠️ **Unaudited and undeployed.** Also: **committee rotation is not
implemented**, so a Peregrine validator-set change requires deploying a new
client. That is the weakest link in this direction. See
[`contracts/AUDIT.md`](contracts/AUDIT.md).

### Reading Peregrine from elsewhere (reciprocal)

A foreign chain checks two independent halves: a stake-weighted quorum of
Peregrine's committee signed a checkpoint committing to store root `R`
(`verify_checkpoint`), and the value is proven under `R` by Merkle inclusion
(`ProvenRead::verify`) — the second half needing no trust at all. Duplicate
signers, unknown validators, sub-quorum stake, and signatures over a different
root are each rejected by test.

### The zkVM boundary

Everything above is a **pure function over bytes** — no async, no I/O, no node
access — which is exactly what lets it compile unchanged as an SP1 or RISC Zero
guest. The guest verifies, and commits a small `Journal`:

> *under Ethereum state root R at block N, account A's slot S holds V*

Peregrine validators then check one succinct proof instead of re-executing
Ethereum.

### Anchoring — the beacon light client

A state proof only means something if the block it hangs off is really
Ethereum's. `peregrine-interop::beacon` establishes that:

```text
  sync committee (512 validators, BLS) ── signs ──▶ attested beacon header
                                                        │ state_root
                                     finality_branch ───┤
                                                        ▼
                                                finalized beacon header
                                                        │ body_root
                                    execution_branch ───┤
                                                        ▼
                                      execution payload header
                                                        │
                                                block_hash  ← the anchor
```

Verified against **real mainnet beacon data** (`tests/fixtures/beacon.json`, a
genuine finality update): SSZ `hash_tree_root` for both header types, both
Merkle branches, the ≥2/3 participation threshold, and the fork-domain
derivation. The SSZ test is self-checking in the strongest way available — the
beacon chain publishes the root **it** computed for the finalized header, and
ours must reproduce it byte for byte, so a single wrong field order,
endianness, or padding rule could not pass.

**BLS12-381 sync-committee verification is implemented** (`--features bls`,
using `blst` in Ethereum's `min_pk` mode: G1 keys, G2 signatures, DST
`BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`). The decisive test verifies a
**real mainnet aggregate signature** — 510 of 512 validators, sync-committee
period 1808 — and `real_update_with_real_committee_yields_a_real_anchor` runs
the whole chain on real data end to end, producing an `Anchor` from genuine
validator signatures.

Negative cases are covered too: a wrong fork version, a wrong genesis
validators root (testnet replay), a tampered header, altered participation
bits, a tampered signature, and a committee from the wrong period all fail.

```bash
cargo test -p peregrine-interop --features bls
```

**Rotation is autonomous.** `LightClientStore` is seeded *once* from a
bootstrap and then follows the chain by itself: the committee it already trusts
signs an update, and that update's beacon state commits to the *next* period's
committee (`next_sync_committee` + its Merkle branch). No operator ever supplies
keys again — which is the difference between a light client and a configuration
file. Tested against real mainnet rotation data, including the cross-check that
the committee learned by rotation equals an independently fetched one.

An update signed by a period the store doesn't know is **refused, not guessed**
— guessing is how a light client gets walked onto a fork.

⚠️ Without `--features bls` the shipped `RejectingBls` refuses everything, so
such a build **mints no anchors and therefore accepts no claims**. That is the
intended fail-closed default: `blst` compiles C/assembly and cannot build
inside a zkVM guest, so BLS is a host-level choice.

### On-chain verification

A proof-carrying claim rides consensus like any other payload
(`WirePayload::ForeignClaim`). It needs no signature — it carries its own
proof — and **every validator verifies it independently during commit**, so
acceptance is part of the state transition rather than something a relayer is
trusted to have done.

Proof verification happens **inside the commit path**, so accepting a claim is
part of the state transition. Two consequences the design has to respect:

* **It must be bounded.** Verifying a proof costs orders of magnitude more than
  anything else on the commit path, so a vertex stuffed with claims would be a
  consensus-halting DoS. At most `MAX_CLAIMS_PER_COMMIT` (4) are verified per
  commit batch, and each is charged `CU_VERIFY_CLAIM` on the compute meter
  **whether or not it is accepted** — an attacker must not get free
  proof-checking by submitting garbage. The cap is counted per batch and reset
  at the same point in the committed order on every validator, so it cannot
  itself cause a fork (`the_budget_is_deterministic_across_validators`).
* **The verifying key is derived once, at startup.** Deriving it dominates the
  cost of checking a proof against it, so `Sp1Verifier` does it in its
  constructor — which also means a node whose local guest ELF doesn't match the
  pinned image id **refuses to start** rather than discovering the mismatch
  mid-consensus.

A claim must clear **two** independent gates:

1. its proof must satisfy the node's `ClaimPolicy` (**defaults to
   `RejectAll`**; `ClaimPolicy::sp1(image_id, chain_id)` is what a production
   validator runs, and `ClaimPolicy::strict(..)` fails closed on builds without
   `--features sp1`), and
2. its `block_hash` must be in the node's `AnchorStore` — **anchoring is
   mandatory**. A perfect proof about a block nobody anchored is refused, which
   is what stops a relayer proving a self-consistent chain it invented. A node
   with no anchors accepts nothing.

Accepted storage lands in `sys.eth_state` (`chain_id ‖ address ‖ slot` →
32-byte word) — an ordinary table, so it joins the store root and **a light
client can prove an Ethereum-derived value against Peregrine's single 32-byte
root**.

### Using verified Ethereum state in a contract

`LoadEthState` is the host call. Its defining property is what it does when the
value *isn't* verified:

```rust
use peregrine_vm::Instr;

// Read WETH.decimals() from Ethereum, inside a Talon program.
let program = vec![
    Instr::LoadEthState { chain_id: 1, address: WETH, slot: decimals_slot },
    Instr::StoreTable { table: my_table, key: b"weth_decimals".to_vec() },
    Instr::Halt,
];
```

Unlike `LoadTable`, an unavailable value **traps** rather than pushing zero,
and a value wider than 64 bits **traps** rather than truncating. A contract
asking "what is this Ethereum balance?" must never be silently told *zero*
because the proof was missing, or handed a truncated number — a fact that has
not been verified is not a fact. Both are asserted by test
(`unverified_state_traps_instead_of_reading_zero`,
`oversized_values_refuse_to_truncate`).

### Proving (SP1)

The guest program is [`crates/peregrine-eth-guest`](crates/peregrine-eth-guest):
it reads an untrusted `Witness`, runs **the same `Witness::verify` the host
runs natively**, and commits the resulting `Journal`. One implementation, so
the proved statement and the natively-checked statement cannot drift apart. A
failing witness panics the guest, so no proof is produced — an unprovable claim
stays unprovable.

```bash
curl -L https://sp1up.succinct.xyz | bash && sp1up   # Linux/macOS (WSL2 on Windows)
cd crates/peregrine-eth-guest && cargo prove build   # → guest ELF
cargo test -p peregrine-interop --features sp1       # host proving/verification
```

**Real proofs have been generated and verified.** A compressed STARK proof of
Ethereum block verification, measured on a 13th-gen i9 (WSL2, CPU proving):

```text
mainnet block   : #25580559
program image id: 0x002409f0efd0de2be2bf9a091e1ae561b91ab682737d3f0cc3f7691ebaefece6
proving (compressed STARK — no trusted setup)…
proved in       : 171.3s
proof is ZK     : true
journal matches native verification: yes
verified in     : 19.3s   (includes one-time key derivation — see below)
wrong image id refused: true

PROVEN: Ethereum blocks 25580559..=25580559 verified inside a zkVM.
```

Three things are confirmed at once: the guest computes the right journal, the
host verifies it, and the two agree on the statement — the guest's committed
public values are byte-identical to the native verification's journal.

**And through the real commit path.** `tests/zk_commit_path.rs` proves an
Ethereum *storage* read (WETH's `decimals` slot, over a real mainnet MPT
witness) and pushes it through `ExecutionPipeline` exactly as consensus would:

```text
proving (MPT witness, compressed STARK)…
proved in                      : 213.0s
verified in commit path        : 52.4ms      ← what a validator actually pays
value materialized in sys.eth_state: 18
test result: ok. 3 passed
```

The asymmetry is the whole design: proving is minutes and happens **once**,
off-chain, by whoever wants the claim believed; verification is milliseconds
and happens on **every** validator, in consensus. 52 ms is affordable per
commit — which is why `MAX_CLAIMS_PER_COMMIT` is a small constant rather than
unbounded. (The verifying key is derived once at construction; deriving it per
call cost 19.3 s and would have made this unusable.)

The other two tests are the ones that matter for security: a valid proof
stapled to a different journal is refused, and a proof of a different program
is refused at verifier construction — so a misconfigured node fails at startup
rather than mid-consensus.

⚠️ **SP1 does not build on Windows** — `sp1-jit` (pulled in transitively by the
mandatory `sp1-prover`) uses POSIX shared memory, and there is no feature flag
to exclude it. Use Linux, macOS, or WSL2. Two blockers worth knowing about, both
fixable without root: `protoc` is required by `sp1-prover-types`' build script
(the conda-forge `protobuf` package does **not** ship the binary — take the
upstream release zip and set `PROTOC`), and a C toolchain is needed to link at
all (`micromamba install -c conda-forge c-compiler` works without `sudo`).

Every security rule below is *also* tested **without** SP1, deliberately:
generating a proof is environment-dependent, but the rules a validator enforces
when accepting one are pure logic and should be tested everywhere.

### Security notes (audit-oriented)

**1. Image-ID pinning is the load-bearing check.** A proof of a *different
program* is still a perfectly valid proof — without pinning, an attacker
supplies a proof of `fn main() { commit(anything_i_like) }` and it verifies.
`Sp1Verifier` compares the guest's verifying-key hash against a pinned value
*before* spending time on cryptography, and also checks the locally-loaded ELF
hashes to that same pin. Obtain the expected image id out of band — never from
the party supplying proofs.

**2. The journal must be bound to the proof.** The verifier requires the
proof's public values to equal the encoded journal being asserted; otherwise a
valid proof could be stapled to an unrelated claim and the proof becomes
decorative. Tested field-by-field (`journal_encoding_binds_every_field`).

**3. Trusted setup.** SP1 **Compressed (STARK) proofs need no trusted setup** —
that is the default mode here and the recommended one for verification inside
Peregrine. The **Groth16 wrapper** used for cheap EVM-side verification *does*
inherit a circuit-specific trusted setup performed by Succinct; PLONK relies on
a universal SRS ceremony. If you cannot accept that assumption, use
`Sp1Mode::Compressed` and pay the larger verification cost.

**4. Proof-verification capability is a consensus rule, not a local option.**
If some validators can verify SP1 proofs and others cannot, they will disagree
about whether a claim applies and **fork the state root**. `ClaimPolicy` must
be identical across the validator set, and changing it is a coordinated
upgrade.

**5. Anchoring is mandatory and now cryptographic.** A claim is refused unless
its block is in the `AnchorStore`, and anchors move forward only (a replayed
old update cannot roll one back). With `--features bls`, anchors are minted
only from updates carrying a valid ≥2/3 sync-committee signature, and the
client **follows committees autonomously** via `next_sync_committee` after a
single trusted bootstrap. The residual assumption is the usual weak-subjectivity
one: the bootstrap header must come from a checkpoint you believe. Without
`--features bls`, no anchor can be minted at all.

**7. Reciprocal direction takes a trusted setup; the forward direction does
not.** Peregrine verifying Ethereum uses SP1 **Compressed** (STARK, no trusted
setup). The EVM contract in [`contracts/`](contracts/) uses SP1 **Groth16**,
which carries a circuit-specific trusted setup, because nothing cheaper is
viable on L1 today. That asymmetry is a property of the EVM, not of the
protocol — and it is why the contract verifies a proof rather than Merkle
paths: Peregrine commits state with BLAKE3, which has no EVM precompile.

**6. Verification is metered.** Claims are charged on the data meter whether or
not they are accepted; unpriced verification is a denial-of-service vector.

### Status

| Property | Status |
| --- | --- |
| Header + MPT verification logic | **real, tested against mainnet** |
| Peregrine checkpoint quorum verification | **real, tested** |
| Image-ID pinning / journal binding / fail-closed | **real, tested** |
| On-chain claim verification + `sys.eth_state` | **real, tested** |
| Mandatory anchoring (`AnchorStore`, forward-only) | **real, tested** |
| `LoadEthState` host call (traps, never truncates) | **real, tested** |
| Beacon SSZ roots + finality/execution branches | **real, tested vs mainnet** |
| **BLS12-381 sync-committee signatures** | **real, verified against a live mainnet aggregate** |
| Trust in a relayer / multisig | **none, by construction** |
| SP1 guest + host backend | **real — builds and proves** |
| Real proof generation | **done: 171s prove, 19s verify, image pinning enforced** |
| **Sync-committee rotation** (`next_sync_committee`) | **real, tested vs mainnet — anchoring is autonomous** |
| EVM verifier contract (`contracts/`) | **compiles + 9 Foundry tests**; ⚠️ unaudited, undeployed, mock verifier |

Nothing in this repo has generated a real ZK proof. `Proof::Native` carries no
cryptographic argument — `is_zk()` returns `false` and `StrictVerifier` rejects
it outright — so a build without a working SP1 backend refuses every claim.
That is the correct failure direction for a bridge, and it is asserted by test
(`without_a_backend_strict_verification_fails_closed`).

## Contributing

Contributions are welcome — see **[CONTRIBUTING.md](CONTRIBUTING.md)** for
setup, conventions, and the crate-boundary rules.

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cd sdk/js && npm test
```

or just `make ci`, which runs exactly what GitHub Actions runs.

Three things we care about disproportionately:

* **Correctness over features** — new consensus, proof, or VM logic should
  arrive with a test that fails without it, including the adversarial case.
* **Honesty about limitations** — if your change is a stub or a shortcut, add
  it below. A documented stub beats an undocumented one.
* **Determinism** — anything on the commit path must produce byte-identical
  state on every validator. No wall-clock reads, no escaping `HashMap` order,
  no floating point near money or state roots.

## Honest limitations of this bootstrap

* **SDKs / RPC** — the client endpoint has **no auth, quotas, or rate limits**;
  a public deployment needs stake- or key-weighted admission control in front
  of ingest. Reads are served by *one* validator and reflect its committed
  frontier (read from several and compare roots if you need agreement). The
  **JSON gateway the TypeScript client targets is not implemented**, so
  browser clients can't reach a node yet.
* **Commit rule** is the full Stoop **skip / undecided cascade**:
  certificate-based direct decisions (`commit` on an `r+2` certificate
  quorum, `skip` once an `r+1` non-voter quorum makes a certificate
  impossible) with an indirect fallback that resolves an undecided anchor
  via the nearest directly-committed anchor at round `>= r+3`. A crashed or
  partitioned leader is skipped rather than stalling the frontier —
  crash-fault-live under partial synchrony, covered by adversarial unit
  tests plus an end-to-end crash-liveness test (one of four validators killed,
  the three survivors keep committing and agree). A bounded per-round
  leader-wait keeps the healthy path from needlessly skipping an anchor that
  is merely a little late. Still simplified: round-robin leader schedule (not
  stake/capacity-weighted), one anchor per round decided sequentially (not
  pipelined), and equivocation is surfaced but not yet slashed.
* **Merkle roots** are incrementally maintained: each table is an `smt`
  sparse Merkle tree keyed by `blake3(key)`, so a write only touches the
  `O(depth)` nodes on that key's path (empty subtrees collapse to per-height
  defaults and aren't stored). The store root is a small sorted tree over one
  `(table_id, table_root)` leaf per table. Point **inclusion**,
  **non-inclusion**, and basic **range** (membership) proofs all verify
  against the 32-byte store root. Still simplified: proofs carry the full
  256-sibling path (compress to `~log₂(n)` non-default siblings next); range
  proofs cover membership, not completeness; Verkle multiproofs later.
* **TalonVM** is a metered stack-machine stub — see
  [Execution & metering](#execution--metering-talonvm) for its ISA and limits;
  the RV64 RISC-V core replaces the interpreter behind the same contracts.
* **Wire format** is bincode (bootstrap convenience), to be replaced by a
  canonical encoding before any cross-implementation work.

## Toolchain note

Developed against a pinned dependency set that compiles on rustc 1.75.
On a current toolchain (1.85+), you can `cargo update` freely — nothing in
the code depends on the pins. CI builds on stable.

## License

Apache-2.0 — see [LICENSE](LICENSE).
