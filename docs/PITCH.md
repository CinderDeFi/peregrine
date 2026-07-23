# Peregrine — one page

**A data-native, real-time Layer-1. Signed records ride inside consensus,
materialize into Merkle-verifiable tables, and a light client holding 32 bytes
verifies any read for itself.**

> Status: an unaudited bootstrap scaffold. Never deployed, holds no value, no
> token. Every number below is measured and reproducible; see
> [AUDIT.md](../AUDIT.md) for what is deliberately unfinished.

---

## The problem

Blockchains are good at *ordering* and bad at *data*. Two consequences:

1. **Reads are trust-me.** Almost every app reads chain state through an RPC
   provider and believes what comes back. The chain's guarantees end at the
   node boundary; your users' guarantees end at whoever runs it.
2. **High-frequency data doesn't fit.** Price ticks, sensor readings, and
   telemetry queue behind blocks designed for financial settlement, then get
   pushed off-chain into exactly the oracles the chain was meant to replace.

Bridges make this worse. Most are multisigs wearing a cryptography costume, and
they are where the money actually gets stolen.

## The approach

**Verify, don't trust — at every boundary.**

- **Streams ride inside consensus.** Signed records travel in consensus
  vertices rather than queueing behind blocks, commit to a deterministic order,
  and materialize into queryable tables.
- **Every read carries a proof.** State lives in sparse Merkle trees. A client
  with a 32-byte root verifies a point read locally, in the browser, without
  trusting the node that served it.
- **Cross-chain facts are proven, not attested.** Ethereum state is verified
  inside a zkVM and re-checked by *every* validator at commit time. No
  multisig, no privileged key, no trusted relayer anywhere.
- **Absence is never zero.** A contract reading unverified foreign state
  **traps**; an on-chain read of an unproven key **reverts**. Missing data is
  an error, not a default — the failure mode behind a long list of real
  exploits.

## What is actually built

A working end-to-end system, demonstrable in ten seconds on a laptop:

| | |
|---|---|
| Consensus | Uncertified DAG (Mysticeti lineage), real QUIC mesh, restart recovery |
| State | Path-compressed sparse Merkle trees, versioned with a migration path |
| Execution | Metered stack VM — dual meter for compute **and** data bytes |
| Interop | Ethereum headers + MPT proofs verified in SP1; BLS beacon anchoring; reciprocal Solidity client |
| Clients | Rust SDK, TypeScript light client, EVM verifier contract |
| Tests | 283 Rust · 48 Solidity · 82 TypeScript |

```bash
peregrine demo     # streams, VM, light client, and interop — end to end
```

## Measured performance

4 validators, 13th-gen i9, release build. Reproduce with `peregrine bench`.

| Offered load | Committed | p50 publish→commit |
|---|---|---|
| 20,000 rec/s | 19,993 rec/s | **4.19 ms** |
| flood | ~34,000 rec/s | past the knee |

A real ZK proof of Ethereum state verifies **inside the commit path in 52 ms**
— proving takes minutes and happens once, off-chain; verification is
milliseconds and happens on every validator.

Two changes moved the ceiling from ~5.5k to ~34k records/s: tiling signature
verification onto pinned cores, and replacing a dense 256-level Merkle tree
with a path-compressed one (**62 µs → 2 µs per row**).

Loopback has no WAN round-trip, so treat latency as a floor, not a finality
claim.

## Why this is credible

Not because it is finished — it isn't — but because the work was **measured
rather than asserted**:

- The tiled pipeline delivers ~1.33×, exactly the Amdahl ceiling implied by its
  own profile. The larger win came from fixing the serial bottleneck, and the
  documentation says so.
- Ethereum verification is tested against **real mainnet data** — reproduced
  block hashes, real `eth_getProof` responses, a real 510/512 BLS aggregate.
- The TypeScript verifier is checked against Rust-generated fixtures in CI, so
  the two cannot silently drift.
- Slither reports 0 findings on the contract, and the docs state plainly that
  this means "no pattern-level defects" and nothing more.

## What it is not

- **Not third-party audited.** An internal security review was done (findings + resolutions in `AUDIT.md`); no external audit yet.
- **Not deployed.** No testnet, no mainnet, no token, nothing to buy.
- **Not economically complete.** Equivocation is detected but not slashed;
  fees exist but are unmodelled.
- **Not Sybil-resistant at the RPC layer.**

The full list is in [AUDIT.md §8](../AUDIT.md#8-known-limitations) and is
longer than this page.

## Where it goes

The near-term work is unglamorous and specific: run the Groth16 end-to-end test
against a real prover, get a third-party audit of the ~3,660 consensus-critical
lines, add coverage-guided fuzzing for the Merkle tree and committer, and
implement committee rotation so the EVM client can follow a live validator set.

---

**[github.com/peregrine-labs/peregrine](https://github.com/peregrine-labs/peregrine)**
· Apache-2.0 · [AUDIT.md](../AUDIT.md) · [SECURITY.md](../SECURITY.md)
