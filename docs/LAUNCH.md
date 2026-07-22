# Launch materials

Templates for announcing Peregrine. Copy, adjust, post.

---

## Ground rules

Read these before editing anything below. Peregrine's entire pitch is *verify,
don't trust* — launch copy that asks people to trust it undermines the product
more than any amount of reach could make up for.

**Always say:**
- unaudited
- never deployed, holds no value
- no token, nothing to buy
- benchmarks are loopback, single machine, and reproducible

**Never say:**
- "secure", "trustless", or "production-ready" without the unaudited caveat in
  the same breath
- "fastest", "N× faster than <chain>" — nothing here has been benchmarked
  against another chain, and a 4-validator loopback run is not comparable to a
  live network
- anything implying investment, presale, allowlist, airdrop, or future token
- "audited by" / "reviewed by" — nobody has
- a TPS number without the conditions attached

**If someone asks "when token":** there isn't one and none is planned. Say so
plainly rather than winking.

**If someone finds a bug:** point them at `SECURITY.md`, thank them publicly,
fix it. Do not argue in the replies.

The strongest thing this project has going for it is that the numbers are real
and the limitations are written down. Lead with that.

---

## Public launch thread (repo is public + demo)

> The headline "it's live, go run it" thread. Leads with the demo because the
> demo is the argument. Same ground rules apply. Nine posts; keep 1, 2, and 9 if
> trimming.

**1/**
Peregrine is public.

A Layer-1 where every read carries a proof you check yourself — no RPC provider
to trust, no bridge multisig, no oracle.

Don't take my word for any of it. Clone it and run the ten-second demo 👇

Unaudited scaffold, no token. <URL>

**2/**
```
git clone <URL> && cd peregrine
cargo install --path crates/peregrine-cli
peregrine -q demo
```

That stands up a **4-validator devnet over a real QUIC mesh** and runs four acts
end to end in ~10 seconds. Real consensus, no faucet, no config.

**3/**
What the demo shows, in order:

· signed price ticks committed and materialized
· a metered on-chain VM loop (1..=10 → 55)
· a light client accepting a genuine proof and *rejecting* a tampered one
· a contract that **traps** on unverified Ethereum state instead of reading zero

**4/**
The idea under it: signed high-frequency records ride *inside* consensus
dissemination instead of queueing behind blocks.

They commit to a deterministic order and materialize into Merkle-verifiable
tables. A client holding 32 bytes verifies any read — in a browser.

**5/**
The numbers, measured on 4 validators on one laptop:

· 19,993 records/s at p50 **4.19 ms**
· ~34,000 records/s sustained ceiling

Loopback, so treat latency as a floor, not a finality claim. Reproduce:
`peregrine bench`

**6/**
Cross-chain is where money actually gets stolen, so there are no multisigs.

Ethereum state is verified inside a zkVM and re-checked by *every* validator at
commit time — a real proof verifies in the commit path in **52 ms**. The reverse
direction is a real on-chain Groth16 verifier doing the full BN254 pairing.

**7/**
The rule I care most about: **absence is never zero.**

A contract reading unverified foreign state traps. An on-chain read of an
unproven key reverts. Missing data is an error, not a default — that confusion is
behind a long list of real exploits.

**8/**
Checked against reality, not vibes: real mainnet block hashes, real `eth_getProof`
responses, a real 510/512 BLS aggregate. The Rust, TypeScript, and Solidity
verifiers are diffed byte-for-byte against the same fixtures in CI.

Internal review found a real bug (a consensus check compiled out of release). Fixed, written up.

**9/**
What it is NOT: audited, deployed, or economically complete. No token, nothing
to buy.

The limitations list is longer than the pitch, and it's public.

Demo + code: <URL>
Audit package: AUDIT.md

Apache-2.0. I'd rather hear what's wrong with it than what's good.

---

## Milestone announcement thread (feature-complete)

> Use this for the "the loop is closed" moment. The general thread below is the
> evergreen intro. Same ground rules apply — every line here is true as written;
> do not embellish. Tweet **3/** is true as of this release:
> `PeregrineProofE2E.t.sol` passes against a real proof (≈418k gas), so the
> claim that the proof is verified on-chain is earned, not aspirational.

**1/**
Peregrine just closed the loop, end to end.

A Layer-1 where every read carries a proof — and where *both* directions of the
Ethereum bridge now meet real cryptography, no mock in the path.

Still unaudited, still no token. What "feature-complete scaffold" means 👇

**2/**
Ethereum → Peregrine:

A real SP1 proof of Ethereum state is verified *inside the commit path* — on
every validator, in ~52 ms. Proving takes minutes and happens once, off-chain;
verification is milliseconds and happens on-chain, every time.

No multisig anywhere near it.

**3/**
Peregrine → Ethereum:

The EVM light client uses SP1's **real on-chain Groth16 verifier** (vendored at
the exact circuit version), doing the full BN254 pairing. A genuine proof of
Peregrine state, from the real prover, is verified on-chain for **~418k gas** —
no mock in the path. The end-to-end test is in the repo.

**4/**
The part I'm most careful about: this is the scaffold reaching
feature-completeness, NOT a production launch.

It has not been third-party audited. It has never been deployed. It holds no
value and there is no token.

The limitations list is longer than the pitch, and it's public.

**5/**
Before this milestone I ran an internal security review of the ~3,660
consensus-critical lines.

It found a real one: a consensus round-structure check that was a `debug_assert`
— compiled out of release builds. Plus five lower-severity items.

All fixed, all written up with resolutions in AUDIT.md.

**6/**
Everything is checked against reality, not vibes:

· Ethereum verification tested against real mainnet data (block hashes,
  eth_getProof, a real 510/512 BLS aggregate)
· the TypeScript + Solidity verifiers checked byte-for-byte against
  Rust-generated fixtures in CI

**7/**
What's next is unglamorous and specific: a third-party audit, committee rotation
so the EVM client can follow a live validator set, and coverage-guided fuzzing
of the Merkle tree and the committer.

Code, AUDIT.md, and the honest-limitations list: <URL>

Apache-2.0. I'd rather hear what's wrong with it than what's good.

---

## X / Twitter thread

> Replace `<URL>` with the repo link. Nine posts; trim from the middle if you
> want it shorter, but keep 1, 2, and 9.

**1/**
Most blockchains are good at ordering and bad at data.

So apps read state through an RPC provider and just… believe it.

I spent 20 weeks building Peregrine: a Layer-1 where every read carries a proof
you check yourself.

Unaudited scaffold, no token. Code + numbers 👇

**2/**
The core idea: signed high-frequency records ride *inside* consensus
dissemination instead of queueing behind blocks.

They commit to a deterministic order and materialize into Merkle-verifiable
tables.

A light client holding 32 bytes can verify any read. In a browser.

**3/**
Measured on 4 validators, one laptop:

· 19,993 records/s committed at p50 **4.19 ms**
· ~34,000 records/s sustained ceiling

Loopback, so treat latency as a floor not a finality claim.

Reproduce it: `peregrine bench`

**4/**
Getting there meant two fixes, and I want to be honest about which mattered.

Tiling signature verification onto pinned cores: **1.33×**. Exactly the Amdahl
ceiling its own profile predicted.

The real win was the Merkle tree: **62 µs → 2 µs per row.**

**5/**
That second one changed every state root, so it couldn't just be shipped.

It's a versioned consensus upgrade, gated on a committed round so every
validator switches at the same point. Rows are untouched; only the commitment
changes.

Old proofs are refused against new roots. Both directions tested.

**6/**
Cross-chain is where money actually gets stolen, so there are no multisigs
here.

Ethereum state is verified inside a zkVM and re-checked by *every* validator at
commit time.

A real proof verifies **in the commit path in 52 ms**. Proving takes minutes,
once, off-chain.

**7/**
The rule I care most about: **absence is never zero.**

A contract reading unverified foreign state *traps*. An on-chain read of an
unproven key *reverts*.

Missing data is an error, not a default. That confusion is behind a long list
of real exploits.

**8/**
Tested against real mainnet data, not hand-written vectors: reproduced block
hashes, real `eth_getProof` responses, a real 510/512 BLS aggregate signature.

The TypeScript verifier is checked against Rust-generated fixtures in CI so the
two can't silently drift.

**9/**
What it is NOT: audited, deployed, or economically complete. No token, nothing
to buy.

The limitations list is longer than the pitch, and it's public.

Audit package: AUDIT.md
Code: <URL>

Apache-2.0. Reviews and bug reports very welcome.

---

## Short version (one post)

> For when a thread is too much.

I built Peregrine — a Layer-1 where every read carries a proof you verify
yourself, and cross-chain state is proven in a zkVM instead of attested by a
multisig.

20k records/s at 4 ms p50 (loopback, reproducible).

Unaudited scaffold, no token. <URL>

---

## Hacker News / Lobsters

**Title:** Peregrine: a Layer-1 where every read carries a proof (Rust,
unaudited scaffold)

**Body:**

I spent twenty weeks building a data-native Layer-1 and I'd value technical
criticism.

The premise: blockchains order transactions well and handle data badly, so
apps end up reading state through an RPC provider they simply trust. Peregrine
puts signed high-frequency records *inside* consensus dissemination, commits
them to a deterministic order, and materializes them into sparse Merkle trees —
so a client holding a 32-byte root verifies any point read locally.

Some things that might interest this crowd:

- **The performance work was profile-driven and the write-up says where it
  disappointed.** A share-nothing tile pipeline for signature verification
  delivers ~1.33×, which is exactly the Amdahl ceiling implied by its own
  profile (only 25% of commit cost was parallelisable). The larger win was
  replacing a dense 256-level sparse Merkle tree with a path-compressed one:
  62 µs → 2 µs per row, moving the sustained ceiling from ~5.5k to ~34k
  records/s.
- **That Merkle change couldn't preserve roots**, which makes it a consensus
  upgrade rather than an optimisation. It's versioned and gated on a committed
  round so every validator migrates at the same point in the same sequence.
- **Cross-chain state is verified in a zkVM at commit time**, by every
  validator, with the guest image pinned. A real SP1 proof verifies inside the
  commit path in 52 ms.
- **Ethereum verification is tested against real mainnet data** — reproduced
  block hashes, real `eth_getProof` responses, a real 510/512 BLS aggregate.

It is an unaudited scaffold: never deployed, holds no value, no token. There's
an AUDIT.md with the scope, twenty-three named invariants, a threat model, and a
ranked list of what I'd attack first. The known-limitations section is longer
than the pitch.

Apache-2.0. Happy to answer questions, and I'd rather hear what's wrong with it
than what's good.

---

## Repo description (GitHub "About")

> A data-native, real-time Layer-1. Signed records ride inside consensus and
> materialize into Merkle-verifiable tables — every read carries a proof.
> Unaudited scaffold, no token.

**Topics:** `blockchain` `rust` `consensus` `zero-knowledge` `merkle-tree`
`layer-1` `light-client` `bft`

---

## Talking points for questions

**"Is this production ready?"**
No. It's unaudited and has never been deployed. It's a complete, working
scaffold of every subsystem — the point is that the architecture is
demonstrable end to end, not that you should run it.

**"How does it compare to <chain>?"**
I haven't benchmarked against other chains and won't quote a comparison I
can't reproduce. The numbers here are 4 validators on loopback on one laptop.

**"Why no token?"**
There's nothing to fund yet. Adding a token to an unaudited prototype would be
the least interesting thing about it.

**"What's the weakest part?"**
Committee rotation for the Ethereum→Peregrine direction isn't implemented, so
the EVM client pins a validator set immutably. And equivocation is detected but
not slashed — a misbehaving validator is ignored, not punished. Both are in
AUDIT.md.

**"Did you write this with AI?"**
Yes, in collaboration with Claude, across twenty weekly sessions. The design
decisions, the profiling that drove them, and the honesty about what didn't
work are all documented in the repo — including the week where the headline
optimisation only delivered 1.33× and I said so.
