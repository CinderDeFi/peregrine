# PEREGRINE
## A Data-Native, Real-Time Layer-1 for the Autonomous Economy
### Founding Design Document & Investment Thesis — July 2026

---

# 1. Executive Summary

**Peregrine** is a new Layer-1 blockchain built around a single conviction: **the next decade of on-chain value is not transactions — it's data in motion.** Every winning category of 2025–2026 (perp DEXs, RWA, stablecoin rails, AI agents, DePIN) is, underneath, a high-frequency data problem wearing a finance costume. Yet every major chain still treats data as an afterthought: expensive to write, impossible to query, priced with the same gas meter as a token swap.

Peregrine is architected as **two fused planes on one validator set**:

1. **The Execution Plane** — a DAG-based BFT consensus ("Stoop") delivering ~300ms finality, with a dual-path parallel execution engine (declared-access scheduling with optimistic fallback) targeting **250k+ TPS sustained, 1M+ TPS burst**, on a RISC-V virtual machine (TalonVM) with full EVM compatibility via transpilation.
2. **The Data Plane** — the genuinely new part. Native columnar state tables, **verifiable SQL-class queries with light-client proofs**, protocol-level pub/sub data streams with sub-block ingestion for oracle/sensor/agent traffic, and tiered storage economics (hot state bonds → warm blob market → cold erasure-coded archival) that make writing a data point cost ~1/1000th of a transaction.

The native token, **$WING**, uses a fixed 10B genesis supply, decaying tail inflation (4% → 1%), a three-way fee split (burn / validators / a perpetual **Data Endowment** that subsidizes archival storage forever), and a deliberately **high-float, transparent-unlock TGE** designed as a direct repudiation of the low-float/high-FDV playbook that is currently destroying trust in new L1 launches.

**The wedge:** real-time on-chain markets (perp DEX / HFT-grade DeFi), the AI-agent machine economy, and DePIN/oracle data — three verticals where sub-second finality *and* cheap verifiable data are simultaneously required, and where no incumbent delivers both.

**The ask this document supports:** a $60–100M raise to fund 3 years of protocol engineering, a Firedancer-class client team, and an ecosystem war chest — launching testnet mid-2027 and mainnet in early 2028, into what history suggests will be the early innings of the next cycle.

---

# 2. Market Analysis (Mid-2026)

## 2.1 Where We Actually Are

Mid-2026 is a drawdown-and-rebuild market, not a euphoria market — and that is precisely when foundational L1s should be built (Solana was built through 2019–2020; Monad through 2023–2024).

**Macro state of play:**

- Total crypto market cap sits near **$2.2–2.3T, down roughly 45–50% from the October 2025 peak**. BTC trades in the low-$60Ks after touching ~$58K (a 20-month low); ETH has bled to the $1,700s after an unprecedented three consecutive red quarters.
- Spot BTC ETFs posted their **worst-ever monthly outflow (~$4B in June 2026)** before flipping back to inflows in July; institutional structure remains intact but the "ETF perpetual bid" thesis is dead. Capital rotated hard into AI equities.
- Regulatory: the **GENIUS Act (stablecoins, 2025)** is law; the **CLARITY Act (market structure)** is in active hearings as of July 2026. A privacy-coin crackdown is pushing volume from CEXs to non-custodial venues. Net-net: the US is, for the first time, a *plannable* jurisdiction for a compliant L1 — a structural change no prior new chain launched into.

## 2.2 Narratives & Capital Flows

| Narrative | 2026 Status | Signal for a New L1 |
|---|---|---|
| **Stablecoins / Stablechains** | ~$311B supply (Apr 2026), +50% since early 2025; GENIUS Act tailwind; dedicated "stablechains" emerging | Payments throughput + compliance hooks are table stakes; fee-in-stablecoin UX is now expected |
| **Perp DEXs** | The breakout winner. Hyperliquid + Aster dominate; sub-second execution + self-custody beat CEXs post-privacy-crackdown | **Latency and matching-quality are the moat.** An L1 that gives every team Hyperliquid-grade infra is a category |
| **RWA / Tokenization** | Moving from pilots to scale; institution-led; needs auditability, data trails, selective disclosure | Institutions demand **queryable, provable state** — exactly what no chain offers natively |
| **AI × Crypto / Agents** | The strongest secular flow; agent payment standards (x402-style, Machine Payments Protocol on Monad) emerging; AI equities are *absorbing* crypto capital | Agents need: micro-fees, session keys, machine-verifiable data feeds, and millions of tiny writes/reads — a **data-plane problem** |
| **DePIN** | Resilient through the drawdown; fundamentally a sensor-data ingestion business | Same data-plane problem, larger scale |
| **Memecoins** | Collapsed from ~$150B peak to ~$34B (Apr 2026). Narrative fatigue is real | Do **not** build a chain whose demand thesis is speculation velocity |
| **Privacy / ZK** | Regulatory pressure on privacy *coins*, but ZK *proofs* (light clients, query proofs, compliance-preserving disclosure) are being institutionalized | ZK as infrastructure, not as anonymity — the correct 2026 posture |

**The meta-lesson of this cycle:** capital now punishes chains whose only utility is trading their own token, and punishes **low-float/high-FDV launches** brutally (Monad's 30%+ 2026 unlock schedule drew public fire from Arthur Hayes and traded down accordingly). "Quality and utility" is not a slogan this time; it's the observed rotation.

## 2.3 Performance Gaps in Existing High-Speed Chains

| Chain | Real Sustained Perf (2026) | Finality | Core Gap |
|---|---|---|---|
| **Solana (+ Firedancer)** | ~3,000–5,000 TPS real-world; Firedancer cut median finality ~50%, ~400ms baseline | ~400ms–2s (optimistic vs full) | Validator count fell from 3,000+ (2022) to ~1,900 as hardware costs ($10–15K/yr) rose → creeping stake concentration; state/indexing still off-chain (Geyser plugins, third-party indexers); congestion-era fee UX scars |
| **Sui** | High burst ceiling; Mysticeti consensus is genuinely fast (~sub-500ms) | Sub-second | Move ecosystem still niche; data querying = external indexers; owned-object model brilliant but under-exploited for data |
| **Aptos** | Solid Block-STM parallelism | ~1s | Struggling for a differentiated demand narrative; drawdown hit hard |
| **Sei (v2 / Giga)** | Parallelized EVM; Giga targets 200K+ TPS | Sub-second target | Targets are targets; oracle-native design is the right instinct but data layer is thin |
| **Monad** | Launched Nov 2025; ~10,000 TPS claimed, 800ms finality, strong uptime record; MPP agent payments live | ~800ms | Tokenomics overhang (unlock schedule) crushed sentiment; data layer is vanilla EVM; 10K TPS is an order of magnitude below the frontier |
| **MegaETH (L2)** | Mainnet Jan 2026; 10ms blocks, ~35K TPS sustained in stress tests, 47K peaks; $506M raised | Real-time blocks, **but** optimistic settlement to Ethereum | Centralized sequencer trade-off; settlement/DA inherits Ethereum's costs and latency; it proved *demand* for real-time chains while conceding decentralization |
| **Hyperliquid (app-L1)** | Best-in-class order-book UX; category-defining | Sub-second | Purpose-built, not general; proves the demand curve for latency but can't host the long tail |

**Synthesis of gaps — the white space:**

1. **The 10K-TPS plateau.** The "new" chains (Monad, MegaETH-sustained) cluster at 10–35K TPS. Nobody ships verified 100K+ sustained on a decentralized validator set. The claim space is crowded; the *delivery* space is empty.
2. **Data is homeless.** Every chain outsources indexing/querying (The Graph, Dune, Goldsky, Geyser). Results are **unverifiable** — the entire industry reads chain state through trusted middlemen. For RWA/institutions and for AI agents (which cannot "eyeball" a block explorer), this is untenable.
3. **One gas meter for two economies.** Writing an oracle tick, a sensor reading, or an agent heartbeat is priced like a financial transaction. Data-heavy apps are economically exiled to off-chain systems, then awkwardly re-anchored.
4. **MEV & fairness remain unsolved at the base layer**, pushing serious trading venues (Hyperliquid) to build their own chains.
5. **Decentralization is quietly eroding under hardware pressure** (Solana's validator decline). The frontier needs performance *per watt and per dollar of hardware*, not just performance.
6. **Launch credibility is a technical requirement now.** Post-Monad-unlock backlash, tokenomics *is* architecture: float, emissions, and independent benchmarks determine whether anyone shows up.

## 2.4 What Users, Developers, and Institutions Actually Want (2026–2027)

- **Users:** CEX-feel (instant, gasless-feeling, passkey login), self-custody by default, no bridge anxiety.
- **Developers:** Rust *and* Solidity, real tooling day one, no bespoke indexer stack, predictable fees, app-controlled ordering for market venues.
- **Institutions:** provable state (audit queries with cryptographic answers), selective disclosure, GENIUS/CLARITY-compatible compliance hooks, credible neutrality, and a validator set they can join.
- **Agents (the new user class):** machine payments in the sub-cent range, session-scoped keys with spend limits, verifiable data reads, and streaming ingestion — millions of writes per hour, priced in dust.

Peregrine is designed to be the first chain where all four constituencies get their first-choice platform simultaneously.

---

# 3. Network Name & Vision

## 3.1 Name

**PEREGRINE** — after the peregrine falcon, the fastest organism on Earth (240+ mph in a hunting dive, called a *stoop*). The name carries three brand loads: raw speed, precision targeting, and long-range travel (peregrine = "wanderer" — the interoperability wink). Sub-brand naming falls out naturally: **Stoop** consensus, **TalonVM**, **Slipstream** data plane, **$WING** token, **Windtunnel** testnet, **Falconry** SDK, **The Aerie** governance forum.

## 3.2 Vision Statement

> **"The data plane of the autonomous economy."**
>
> Within ten years, most economic actors on the internet will be software. They will trade, sense, negotiate, and settle millions of times per second — and they cannot trust a screenshot, an API key, or an indexer. Peregrine is the first Layer-1 where *both* halves of that economy — the value and the data — are native, verifiable, and priced correctly. Not a faster ledger. A **real-time, queryable, provable world-state**.

## 3.3 Positioning in One Line Per Audience

- **To traders/apps:** Hyperliquid-grade latency, as a public platform, for every venue.
- **To AI teams:** the settlement + sensory layer for agents — pay, read, and prove at machine speed and machine cost.
- **To institutions:** the first chain you can audit with a SQL query and a proof instead of a service provider.
- **To crypto natives:** the anti-low-float launch — high float, honest emissions, benchmarks published before token.

---

# 4. Core Architecture & Technical Deep Dive

## 4.1 System Overview

Peregrine is a **vertically integrated L1 with two fused planes** sharing one validator set and one security budget. It is *modular internally* (clean plane separation, swappable components) but *monolithic externally* (one chain, one token, no bridge between your app and its data).

```
                        ┌──────────────────────────────────────────────┐
                        │                 PEREGRINE L1                 │
                        │                                              │
  Users ──passkeys──▶   │  ┌──────────────── EXECUTION PLANE ───────┐  │
  Agents ──sessions─▶   │  │  TalonVM (RISC-V) + EVM transpiler     │  │
  Apps  ──intents──▶    │  │  Duplex Scheduler (declared ∥ optimistic│ │
                        │  │  Owned-object fast path (~120ms)        │ │
                        │  └───────────────▲───────────▲────────────┘  │
                        │                  │           │               │
                        │        ┌─────────┴──┐   ┌────┴───────────┐   │
                        │        │ STOOP BFT  │   │  SLIPSTREAM    │   │
                        │        │ uncertified│   │  DATA PLANE    │   │
                        │        │ DAG, 300ms │   │ streams·tables │   │
                        │        │ finality   │   │ ·queries·DA    │   │
                        │        └─────────▲──┘   └────▲───────────┘   │
                        │                  │           │               │
                        │  ┌───────────────┴───────────┴────────────┐  │
                        │  │      VALIDATOR SET (one stake, DVT)     │ │
                        │  │  Tile-based client · kernel-bypass net  │ │
                        │  └─────────────────────────────────────────┘ │
                        └──────────────┬───────────────┬───────────────┘
                                       │               │
                              ZK light clients   Cold Archival Ring
                              (ETH, SOL, BTC,    (erasure-coded storage
                               IBC, intents)      nodes, Data Endowment)
```

## 4.2 Consensus: **Stoop BFT**

**Family:** uncertified-DAG BFT (the Mysticeti/Mahi-Mahi lineage), chosen because certified DAGs (Narwhal/Bullshark) pay an extra certification round-trip, and classical leader-based chains (HotStuff/MonadBFT) bottleneck dissemination on one proposer.

**Design:**

- **Multi-proposer by construction.** Every validator proposes blocks every round into a structured DAG; there is no single leader to DDoS, bribe, or wait on. Bandwidth of the *whole set* is the throughput ceiling, not one machine's NIC.
- **Two-message-delay commit.** Blocks commit via implicit DAG voting patterns in **3 network hops (~250–400ms global finality)**, pipelined so a commit lands every ~40–60ms.
- **Uncertified + equivocation-slashing.** No availability certificates; equivocation is detected in-DAG and slashed at 100% of the offending block's proposer bond, keeping the fast path clean.
- **Bandwidth-weighted proposing.** Validators earn proposal slots proportional to stake × proven serving capacity (measured in-protocol), which rewards good infrastructure without a hardware arms race — capacity proofs are throughput-serving audits, not PoW.
- **Epochless dynamic membership** with 1-block validator entry/exit finality, enabling DVT clusters to rotate keys without downtime.

**Why not just fork Mysticeti?** Two upgrades matter: (a) Stoop integrates the **data plane's stream shreds directly into DAG blocks** — oracle ticks ride consensus dissemination for free rather than as transactions; (b) commit rule is tuned for **asymmetric block sizes** (huge data blocks + small tx blocks coexist without stalling the commit frontier).

## 4.3 Execution: The **Duplex Scheduler** + Object Lanes

Three execution paths, chosen automatically per transaction:

1. **Fast Path (owned objects, no consensus ordering needed):** Sui-style — transfers, agent micropayments, and single-owner state mutate with only Byzantine-consistent broadcast: **~120ms end-to-end**, and these *never* consume the shared-state throughput budget. Target: the overwhelming majority of agent/payment traffic.
2. **Declared Path (shared state, access lists):** transactions that declare read/write sets (Sealevel-style) are scheduled conflict-free across cores *before* execution — deterministic, no re-execution waste. The SDK auto-generates access lists; declared txs get a ~20% fee discount, making declaration the economically dominant strategy.
3. **Optimistic Path (undeclared/dynamic):** Block-STM-style optimistic concurrency for everything else, with the scheduler feeding it *hints* from historical conflict graphs (a learned conflict predictor per contract), cutting abort rates versus vanilla Block-STM.

**State model:** object-DAG (every account, table, and stream is an object with an owner and a version), backed by a **binary Merkle/Verkle hybrid commitment** so witnesses stay small and query proofs (below) stay cheap. Stateless validation supported: proposers ship witnesses; validators need not hold full state to verify.

**Performance budget (honest math, not marketing):**

| Component | Target |
|---|---|
| Consensus ordering ceiling | >1M small tx/s (DAG dissemination-bound) |
| Shared-state parallel execution, 64-core validators | 150–300K TPS sustained (ERC-20-transfer-class mix) |
| Owned-object fast path (additive) | 500K–1M+ ops/s |
| **Combined sustained real-world target** | **250K+ TPS** |
| Finality | **~300ms consensus path / ~120ms fast path** |
| Median fee | <$0.0005 tx · <$0.000001 per data record |

We will publish reproducible third-party benchmarks (see Risks) *before* any token event. In 2026, unverified TPS claims are negative marketing.

## 4.4 Virtual Machine: **TalonVM** (RISC-V core, polyglot surface)

- **ISA:** RV64IMC + vector extensions. RISC-V is where the frontier converged in 2025–2026 (PolkaVM shipped it; Ethereum's own long-term roadmap discussions point there): it JIT/AOT-compiles to near-native speed, has a formal-verification ecosystem, and lets ZK-proving of execution reuse standard RISC-V zkVMs (SP1/RISC Zero lineage) instead of bespoke circuits.
- **Front-ends:** Rust (primary), **Solidity via EVM-bytecode → Talon transpilation** (full compatibility mode with EVM gas semantics for drop-in ports), and Move-inspired resource types available as a Rust library (linear ownership enforced by the object model itself, so asset-safety guarantees don't require a new language).
- **Data-native syscalls:** `stream_emit`, `table_insert`, `view_read_proven`, `blob_put` are VM primitives, not contract patterns — this is what makes data ops 1000× cheaper than storage-slot writes.
- **Metering:** dual meters — *compute gas* and *data bytes* — settle independently (see fee design). Deterministic, cycle-accurate metering from the RISC-V core.

## 4.5 The **Slipstream Data Plane** (the actual moat)

Four native primitives:

### a) Streams (high-frequency ingestion)
Protocol-level pub/sub channels. A registered publisher (oracle, DePIN gateway, exchange, agent swarm) emits fixed-schema records that are **shredded into consensus dissemination directly** — sub-block ingestion at 10–20ms cadence, sequenced and timestamped by the DAG. Priced **per byte at data-plane rates** (~1000× below execution gas). Contracts subscribe; the latest tick is readable in-VM with zero oracle-contract ceremony. This obsoletes the push-oracle tax: Pyth/Chainlink/RedStone become *publishers on Peregrine rails* rather than parallel infrastructures.

### b) Tables (structured on-chain state)
First-class **columnar tables** as objects: typed schemas, secondary indexes maintained by validators deterministically, row-level ownership. An RWA registry, an order-book, an agent-reputation ledger — these are tables, not hand-rolled mappings.

### c) Verifiable Queries (**StateSQL**)
The industry's missing primitive. A read-node executes a bounded SQL-class query (filters, joins on indexed columns, aggregates, time-windows) over tables/streams and returns results **with a succinct proof against the state root** — Verkle multiproofs for point/range reads, incrementally-maintained authenticated views for standing queries, and an optional zk-proved mode (RISC-V zkVM re-execution of the query plan) for institution-grade audits. Result: *any* light client — a phone, a smart contract on Ethereum, an AI agent — can consume Peregrine state **without trusting an indexer**. Dune-class analytics with cryptographic answers.

### d) Tiered Storage & DA
- **Hot** (in-state): refundable **storage bonds** in $WING — deposit scales with bytes; delete and reclaim. No silent state bloat, no confiscatory rent.
- **Warm** (blob market): 2D erasure-coded blobs with data-availability sampling by light nodes; independent fee lane (EIP-4844-style pricing, dramatically larger capacity).
- **Cold** (Archival Ring): a permissionless storage-node network holding erasure-coded history, paid *forever* from the on-chain **Data Endowment** (funded by the fee split, §5) with random Proof-of-Retrievability audits. Solves "who pays for eternity" without Arweave-style upfront-pricing fragility.

## 4.6 Networking & Client Engineering

- **Tile architecture** (the correct lesson from Firedancer): the client is a set of pinned, share-nothing tiles (net, sig-verify, dedup, exec, commit, stream) communicating over lock-free queues; written in **Rust with zero-copy discipline**, kernel-bypass networking (AF_XDP/DPDK), QUIC transport, Turbine-style stake-weighted fanout for shreds.
- **Two independent client implementations funded from genesis** (Rust reference + a Zig or C++ second client) — client monoculture is a lesson already paid for by others.
- **Validator hardware target:** 32–64 core / 512GB / 2×25GbE — roughly $6–8K/yr, deliberately *below* Solana's drifting floor, because the DAG spreads bandwidth load across all proposers. Performance-per-dollar-of-hardware is a governance-tracked metric, not an accident.

## 4.7 MEV, Fairness & Spam

- **Threshold-encrypted mempool (default):** transactions encrypt to a committee key; contents decrypt only post-ordering. Sandwiching requires corrupting the committee, not just watching the wire.
- **App-Defined Sequencing (ADS):** an application (e.g., a perp DEX) can own a **sequencing lane** and choose its ordering policy — FCFS with latency equalization (Hyperliquid-style), frequent batch auctions, or priority auctions **with proceeds routed to the app/its LPs**, not extracted by validators. MEV becomes an application revenue choice instead of validator leakage.
- **Local fee markets** per object/table: a hot NFT mint or one congested market pays surge pricing; the rest of the chain stays at base fee. Global fee spikes are an architecture bug, not a market feature.
- **Spam/Sybil:** fee floor denominated in real cost + per-account rate elasticity + stake-weighted ingress QoS; fast-path (owned-object) spam self-limits because it only burns the sender's own object lane.

## 4.8 Security & Decentralization

- **Economic security:** delegated PoS; 200 genesis validators → 1,000+ target; slashing for equivocation (severe) and data-withholding (proportional); **no native restaking of $WING** at L1 (systemic-leverage refusal is a feature institutions ask about now).
- **DVT-native:** validator keys shardable across operators (Obol/SSV-style) in-protocol, lowering solo-operator risk and raising the cost of coercing any single machine.
- **Governance:** minimal-viable on-chain governance (parameters + treasury + upgrade activation), stake-weighted with delegation and a **security council with veto-only powers that sunsets in year 4**. Protocol upgrades require dual-client releases.
- **Interoperability trust model:** **ZK light clients** for Ethereum and Solana verified on Peregrine (and a Peregrine light client provable *on* them via the RISC-V zkVM), IBC for Cosmos-lineage chains, plus an **intent/solver bridging layer** for UX. No multisig canonical bridge — ever. The bridge-hack era ends by construction.

## 4.9 Account & Agent Layer

- **Native account abstraction:** every account is a programmable object. Passkey/WebAuthn signers, social recovery, multisig, and policy modules are standard library, not ERC-4337 scaffolding.
- **Session keys & spend policies:** first-class — an agent or game grants a scoped key (contracts × budget × TTL). Revocation is one fast-path op.
- **Gas sponsorship:** protocol-level paymasters; apps sponsor users; **fees payable in whitelisted stablecoins** with validators auto-swapped into $WING via an enshrined fee-conversion auction (demand for $WING preserved; UX in dollars).
- **Machine payments:** native x402-compatible HTTP-payment flows and streaming micropayments (pay-per-token, pay-per-tick) settled on the fast path — the agent-economy rails Monad's MPP gestured at, made a base-layer primitive.

---

# 5. Tokenomics — **$WING**

## 5.1 Design Philosophy

$WING is engineered for sustainable utility and broad adoption, not speculative velocity. Every emission and burn mechanism is tied to measurable on-chain work. The token powers security, data permanence, sequencing rights, and governance while keeping fees extremely low for users and developers worldwide.

Key commitments, published before TGE:

1. **Utility-first demand** — $WING is required for gas, storage, publishing, and premium features.
2. **High float, transparent unlocks** — credibility is a competitive advantage in 2026; ≥35% circulating at TGE with an immutable on-chain unlock calendar (a structural, not rhetorical, rejection of the low-float/high-FDV playbook).
3. **Usage-driven scarcity** — burns and bonds grow with real activity (RWAs, agents, DePIN, perps, stablecoins).
4. **Global accessibility** — stablecoin payments, gas sponsorship, and compliance-optional primitives lower barriers for institutions and everyday users.

## 5.2 Supply & Emissions

- **Genesis supply:** 10,000,000,000 $WING (fixed).
- **Tail inflation:** starts at **4.0%/yr**, decaying 15%/yr to a **1.0% terminal floor** (~year 9). 85% → stakers/validators; 15% → the Data Endowment.
- **Fee flows (both meters — compute gas and data bytes), a 50/30/20 split:**
  - **50% burned** (EIP-1559-style base-fee burn; at scale, targets net-deflation),
  - **30% to validators/delegators** (real yield on top of issuance),
  - **20% to the Data Endowment** (perpetual funding of archival storage + DA sampling incentives).
- **Additional burns:** sequencing-lane auction revenue, publisher-bond slashings, and forfeited storage bonds.
- **Storage bonds:** refundable $WING locked proportional to hot-state bytes — a usage-driven supply sink that grows with genuine adoption while giving users direct control over costs.

At scale, the combination of burns and bonds is expected to produce net deflationary pressure tied directly to network usage.

## 5.3 Utility & Demand Levers

| Mechanism | Description | Demand Driver |
|---|---|---|
| **Gas & Data Fees** | Dual-meter system (compute units vs. data bytes). Data operations ~1/1000th the cost of traditional transactions. | Extremely low fees for agents, DePIN, RWAs, and high-frequency apps. |
| **Stablecoin Payments** | Fees payable in USDC/USDT. Enshrined conversion auction buys $WING on-chain. | Global accessibility; no need for users to hold $WING. |
| **Gas Sponsorship** | Apps and projects can sponsor user fees programmatically. | Mass-adoption barrier removal (consumer and enterprise apps). |
| **Sequencing Lanes** | Apps bond $WING to own custom ordering (FCFS, auctions, etc.). Revenue shared to burn/endowment. | Attracts serious trading venues (perps, order books). |
| **Stream Publishing** | Oracles, DePIN nodes, and agents bond $WING; slashed for bad data. | Recurring demand from data providers. |
| **Staking** | Delegated PoS with performance-weighted rewards (uptime, latency, bandwidth). | Network security + yield for holders. |
| **Governance** | Time-locked, weighted voting with delegation. | Long-term alignment. |
| **Data Endowment** | 20% of fees fund permanent archival storage and public goods. | Solves "who pays for history" sustainably. |

## 5.4 Allocation & Launch Structure (10B Total)

| Bucket | % | Vesting / Notes |
|---|---|---|
| **Community & Ecosystem** | 40% | Usage-weighted airdrops, incentivized testnet, grants, liquidity programs. KPI-gated tranches. |
| **Public Sale** | 10% | Broad-access, fully unlocked at TGE. |
| **Investors** | 17% | 1-year cliff, 3-year linear. No single fund >4%. |
| **Core Team & Founders** | 18% | 1-year cliff, 4-year linear. 25% performance-gated (uptime + decentralization milestones). |
| **Foundation Treasury** | 10% | On-chain, transparent, capped drawdown. |
| **Liquidity & Market Ops** | 5% | Transparent MM agreements with caps. |

**Float at TGE:** ~35–40%. Full unlock schedule published on-chain and immutable. This is a deliberate rejection of low-float/high-FDV launches.

**Insider guidance (explicit).** Keep total insiders (team + investors) ≤35% — in this market that is the credibility line. Individual founders 3–6% each; total founders ≤10% inside the 18%. No advisor allocation above 0.25% individually; total advisors ≤1.5%. Founder allocations vest against *network* milestones, not time alone, and team sells only via pre-announced 10b5-1-style programs after cliff — surprise insider selling is how chains die twice.

## 5.5 Economic Security & Risk Mitigation

- **No native L1 restaking** — avoids systemic leverage risk.
- **Local fee markets** — congestion in one app does not affect the entire chain.
- **Spam resistance** — per-byte floors, rate limits, and publisher bonds.
- **MEV design** — app-defined sequencing routes value to applications/LPs rather than validators.
- **Validator incentives** — bandwidth-weighted proposing rewards good infrastructure without a hardware arms race.

## 5.6 Path to Global Adoption

Peregrine economics are optimized for real usage across RWAs, AI agents, DePIN, perps, stablecoins, and consumer apps. By making data cheap and verifiable, fees predictable, and onboarding friction minimal (stablecoins + sponsorship), the chain becomes default infrastructure for the machine economy and tokenized real-world assets.

The flywheel is simple: **more usage → more fees burned + bonds locked → stronger scarcity and security → more adoption.**

---

# 6. Differentiators & Killer Features

| # | Feature | Why nobody else has it | Who it wins |
|---|---|---|---|
| 1 | **Verifiable queries (StateSQL)** | Requires commitment scheme + deterministic views + zkVM designed together from genesis; unbolt-on-able | Institutions, auditors, AI agents, cross-chain consumers |
| 2 | **Dual-meter economy (compute vs data)** | Incumbent fee markets are single-meter by ossification | DePIN, oracles, gaming, agents — every data-heavy app priced out elsewhere |
| 3 | **Streams in consensus dissemination** | Needs DAG consensus + data plane co-design | Perp DEXs, oracle networks, HFT DeFi |
| 4 | **App-Defined Sequencing with MEV-to-app routing** | L1s treat ordering as validator property; we treat it as app property | Every serious trading venue currently forced to build its own chain |
| 5 | **Owned-object fast path at ~120ms** | Sui pioneered it; we fuse it with EVM compatibility and machine payments | Payments, agents, consumer apps |
| 6 | **RISC-V TalonVM with EVM transpilation** | Rides the industry's own convergence direction; zk-provable by construction | Solidity's installed base *and* the performance frontier |
| 7 | **ZK-only interop, no multisig bridge, ever** | Discipline, not technology | Everyone burned 2021–2025 |
| 8 | **Data Endowment** | Permanent storage economics solved at fee-split level | Archives, RWA provenance, compliance |
| 9 | **High-float honest launch + pre-token independent benchmarks** | Cultural, and therefore rare | The entire post-2025 market psychology |
| 10 | **Performance-per-dollar validator targeting + DVT-native** | Counters the Solana hardware-centralization drift with measurable governance targets | Long-term credible neutrality |

**Energy/regulatory posture:** PoS at ~watts-per-transaction orders below PoW; US-plannable under GENIUS/CLARITY trajectory; compliance-*optional* primitives (selective-disclosure proofs on tables, attested publisher identities) that institutions can adopt per-app without imposing surveillance on the base layer.

---

# 7. Risks & Mitigations

| Risk | Severity | Mitigation |
|---|---|---|
| **Performance claims fail in production** (the graveyard is full) | High | Public, reproducible benchmark harness from testnet day 1; third-party verification (e.g., an academic lab + Jump-class engineering audit) *before* TGE; market conservative numbers (250K) while engineering for 1M |
| **Complexity risk** — DAG + duplex execution + data plane is a lot of novel surface | High | Phase the novelty: launch with Streams+Tables+bonds; ship StateSQL-zk mode and ADS lanes in upgrades; two clients; formal verification of Stoop's commit rule; $10M+ audit/bug-bounty budget |
| **EVM gravity** — devs default to where users are | High | Transpiled EVM compatibility (drop-in ports) + 10× cheaper data as the reason to move; wedge verticals that *cannot* be served elsewhere (real-time venues, agents) rather than fighting for generic DeFi TVL |
| **Bear-market timing** — mid-2026 capital is scarce and picky | Medium | This is the historically correct *build* window; raise now, launch into the recovery; keep 3-yr runway at current-market valuations, not peak-market assumptions |
| **Tokenomics backlash / unlock overhang** | Medium | The §5 structure *is* the mitigation; publish immutable unlock schedule; float ≥35% |
| **Validator centralization drift** | Medium | Hardware-cost governance target, DVT, bandwidth-weighted (not raw-stake) proposing, delegation caps on top validators for issuance boosts |
| **Data-plane abuse / garbage-data spam** | Medium | Publisher bonds + quality slashing; per-byte pricing floors; TTL defaults; DA sampling makes withholding detectable |
| **Regulatory reversal** (CLARITY stalls; token = security risk) | Medium | Offshore-foundation + US-entity dual structure; token utility genuinely consumptive (fees, bonds, storage); no yield marketed as profit-from-others'-efforts; counsel-reviewed public sale structure (Reg A+/Reg S paths) |
| **Oracle/incumbent channel conflict** (Pyth/Chainlink see Streams as a threat) | Low-Med | Position Streams as *distribution rails* with publisher revenue share — make incumbents the first, best-paid publishers |
| **Team execution risk** — this needs a Firedancer-class team | High | The raise is sized to hire one: 25–35 protocol engineers, incl. HFT/kernel-networking veterans; milestone-gated tranches with investors |

---

# 8. Phased Roadmap

**Phase 0 — Foundation (Q3 2026 – Q1 2027)**
Raise $60–100M (seed + Series A). Core team to 20+. Stoop whitepaper + formal spec; TalonVM prototype; benchmark harness open-sourced. Devnet with Streams + fast path.

**Phase 1 — Windtunnel Testnet (Q2–Q4 2027)**
Public incentivized testnet: usage-weighted (run venues, publish streams, break things) — not click-farm points. Duplex scheduler + Tables live; EVM transpiler beta; 100+ external validators; independent benchmark publication; two audits; second client alpha. Target: 3–5 flagship launch partners built-in-private (one perp DEX, one oracle network as native publisher, one agent platform, one DePIN, one RWA registry).

**Phase 2 — Mainnet Ascent (Q1–Q2 2028)**
Mainnet with 200 validators, conservative caps raised weekly against live telemetry. TGE (structure per §5) *after* mainnet stability, not before. StateSQL (proof mode) live; stablecoin fee payment; canonical ZK light client to Ethereum. Liquidity: day-one native USDC/USDT commitments negotiated in Phase 1; $25M ecosystem liquidity program (transparent, capped, decaying).

**Phase 3 — The Hunt (H2 2028 – 2029)**
ADS lanes GA; zk-query mode; Solana light client; agent-payments standard push (open spec, multi-chain). Growth: 1,000-validator program, university validator grants, "Falconry" hackathon circuit in the wedge verticals, institutional pilot program (audit-by-query with a Big-4 partner). North-star metrics published quarterly: sustained TPS under real load, data records/day, verified-query volume, validator Nakamoto coefficient, % fees from non-speculative apps.

---

# 9. Conclusion & Recommendation

The mid-2026 market has finished teaching its lessons: speculation-velocity chains mean-revert; low-float launches get repriced; 10K TPS is now table stakes, not frontier; and every durable narrative — perps, RWA, stablecoins, agents, DePIN — is bottlenecked on the same missing primitive: **fast, cheap, *verifiable* data fused with fast, cheap, final settlement.**

No incumbent can retrofit this. Solana's data layer lives in Geyser plugins and third-party indexers; Monad and MegaETH are vanilla-EVM state machines with faster engines; Sui has the right state model but not the data economy; Hyperliquid proved the demand curve but only for itself.

**Recommendation:** build Peregrine now, in the drawdown, with the discipline this document specifies — benchmarks before token, float before hype, endowment before permanence promises — and launch into the 2027–2028 recovery as the first chain designed for the economy that is actually arriving: one where most users are machines, most value is data, and trust is a proof, not a brand.

*Fly fast. Prove everything.* 🦅

---

*Appendix pointers (available on request): Stoop commit-rule sketch and safety argument; Duplex scheduler conflict-predictor design; StateSQL proof-system selection matrix (Verkle multiproof vs. IVC vs. zkVM re-execution cost curves); validator P&L model at 200/500/1,000 nodes; fee-market simulations for the dual-meter economy.*
