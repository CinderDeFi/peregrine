# Running a Peregrine testnet

Everything you need to stand up a public Peregrine testnet: a **genesis**, a
**faucet**, validator and RPC nodes, and the parameters wallets and SDKs connect
with.

> **Scope, honestly.** This is a bootstrap scaffold. A `peregrine node run`
> launches the whole validator committee in one process over a real QUIC mesh —
> ideal for a single-host testnet or CI. Running validators on *separate* hosts
> means distributing the same `genesis.toml`, giving each operator only their own
> `validator-i.key`, and wiring the mesh addresses — the identities, chain id,
> faucet, and allocations all come from the shared genesis. The pieces below are
> the same either way. It is **unaudited** and holds no real value.

---

## Live testnet (running, verified 2026-07-23)

A **single operator** runs a **three-validator** `peregrine-testnet` across three
hosts, with one HTTP gateway fronting validator 0's RPC. This is a coordinated
test network, **not a decentralized production chain**. It is **unaudited**, has
**never been mainnet**, and holds **no real value** — addresses, balances, and
store roots here are disposable and may be reset. No TPS, audit, or token-economics
claims apply; there is nothing to buy.

The fuller operator runbook (ports, systemd units, restart procedure, health
checks, security posture) lives in **[docs/LIVE_TESTNET.md](LIVE_TESTNET.md)**;
this section is the connection summary.

**Chain**

| Parameter | Value |
|---|---|
| network name | `peregrine-testnet` |
| chain id | `1` |
| committee | 3 validators, equal stake 100 (quorum is > ⅔ stake, i.e. all three; one down stalls the tip until it returns) |
| gateway (HTTP/JSON RPC) | `http://37.27.182.133:8081/rpc` |
| explorer | open the explorer (see [`explorer/README.md`](../explorer/README.md)) with `?gateway=http://37.27.182.133:8081/rpc` |
| genesis on nodes | `/opt/peregrine/testnet/genesis.toml` |
| keys on nodes | `/opt/peregrine/testnet/keys/` — `validator-0..2.key`, `faucet.key`, mode `0600` |

**Hosts** — peers are listed in committee-index order, skipping self (see
[the distributed guidance](#running-a-distributed-testnet--one-identity-per-server)
below). Storage paths are under `/opt/peregrine/testnet/`.

| Role | Host | `--identity` | `--listen` | `--peers` | `--storage` | node RPC | gateway |
|---|---|---|---|---|---|---|---|
| val-1 | `37.27.182.133` | 0 | `0.0.0.0:9001` | `77.42.24.213:9001`, `77.42.22.144:9001` | `…/data-0` | `0.0.0.0:8080` | `0.0.0.0:8081` → node `127.0.0.1:8080` |
| val-2 | `77.42.24.213` | 1 | `0.0.0.0:9001` | `37.27.182.133:9001`, `77.42.22.144:9001` | `…/data-1` | `0.0.0.0:8080` | — |
| val-3 | `77.42.22.144` | 2 | `0.0.0.0:9001` | `37.27.182.133:9001`, `77.42.24.213:9001` | `…/data-2` | `0.0.0.0:8080` | — |
| rpc-1 | `95.216.154.162` | — | — | — | — | — | build / genesis host (optional ops box; not a validator) |

**Faucet** — authority public key from `peregrine genesis show`:

| Field | Value |
|---|---|
| authority pubkey | `5cd621cc5b0c710703cf0bf19a5873ce6e53bcff0f61327ee1cb29302b1b50d0` |
| per request | `1000` grains (largest single drip) |
| cooldown | `100` rounds between drips, per recipient |
| lifetime cap | `10000` grains, per recipient |
| genesis allocations | `0` — every balance comes from the faucet |

### Verified working (2026-07-23)

- All three validators running; tip rounds advancing. Brief `no consensus
  progress` / `consensus progress resumed` log chatter is observed and recovers
  on its own — expected when a peer is momentarily busy or a link blips, not a
  fault.
- Gateway live at `http://37.27.182.133:8081/rpc`; the explorer queries it via
  `?gateway=http://37.27.182.133:8081/rpc`.
- Proven reads verify locally in the client — e.g. `contract.answers` / `meaning`
  reads back `42` with its proof `✓`.
- Faucet drip works end to end (below).

The gateway is **HTTP/JSON in front of the QUIC RPC** — read-only and
CORS-permissive, a **dev posture** suitable for a testnet, not a hardened public
endpoint. Wallets, the explorer, and SDK readers use the gateway URL and never
touch the node RPC or the faucet key.

### Faucet drip + read (operator, on a validator host)

Run these on a node host, addressing the local node RPC at `127.0.0.1:8080`. The
drip is signed by the faucet key and **takes no `--genesis` flag**; the recipient
public key is the positional argument:

```bash
# Drip 1000 grains to a recipient (recipient 64-hex pubkey is positional):
peregrine faucet drip \
  --rpc-addr 127.0.0.1:8080 \
  --faucet-key /opt/peregrine/testnet/keys/faucet.key \
  <RECIPIENT_64_HEX>

# Read the recipient's balance back. `read` takes table then key positionally;
# the pubkey key is hex, so prefix it with `hex:`.
peregrine read \
  --rpc-addr 127.0.0.1:8080 \
  sys.balances hex:<RECIPIENT_64_HEX>
```

Confirmed example: recipient
`b19c978f325f96d786ce0e5edfa0c206674213cbd1c433f456ba11fe5274a4f2` received
`1000` grains, proof `✓`. The on-chain per-recipient cooldown and lifetime cap
still apply, so confirm issuance by **reading the balance** rather than trusting
the drip's "queued" acknowledgement.

---

## Quick start (one host)

```bash
# 1. Generate a genesis + validator/faucet keys (chain id is yours to pick).
peregrine genesis new --validators 4 --chain-id 424242 --network peregrine-testnet-1

# 2. Run the network from that genesis.
peregrine node run --genesis genesis.toml --keys-dir testnet-keys --rpc-addr 127.0.0.1:9000

# 3. (new terminal) Serve a public HTTP RPC for browsers/SDKs, and a faucet.
peregrine gateway      --node 127.0.0.1:9000 --bind 127.0.0.1:8080
peregrine faucet serve --node 127.0.0.1:9000 --faucet-key testnet-keys/faucet.key

# 4. Get tokens and start building.
peregrine faucet drip <your-64-hex-pubkey>          # as the operator, or:
curl -X POST localhost:8088/drip -d '{"address":"<hex>"}' -H 'content-type: application/json'
```

`scripts/testnet-local.sh` wraps steps 1–2.

---

## Network parameters & chain id

| Parameter | Where | Notes |
|---|---|---|
| **chain id** | `genesis.chain_id` | A non-zero `u64`. Carried in every committed checkpoint and **pinned by the EVM light client**, so a proof of this chain can't pass as another's. Publish it. |
| **network name** | `genesis.network` | Human-readable label, e.g. `peregrine-testnet-1`. |
| **validator set** | `[[validators]]` | Public keys + stake. The committee and its ⅔-stake quorum come from here. |
| **max_items_per_vertex** | `[params]` | Payload items per proposal (default 512). |
| **merkle_v2_activation_round** | `[params]` | Optional; a coordinated Merkle-rule upgrade round. Every validator must carry the same value. |
| **faucet** | `[faucet]` | Authority key + per-request / cooldown / lifetime limits. |
| **allocations** | `[[allocations]]` | Accounts credited with grains at genesis. |

Give wallets and SDK users the **chain id**, the **gateway URL** (HTTP RPC), and
the **faucet URL**.

---

## Generating a genesis

```bash
peregrine genesis new \
  --validators 4 --chain-id 424242 --network peregrine-testnet-1 \
  --out genesis.toml --keys-dir testnet-keys
peregrine genesis show genesis.toml
```

It writes:

* `genesis.toml` — the shared file (only **public** keys). Distribute this.
* `testnet-keys/validator-{0..N}.key` — validator secrets, `0600`. Each validator
  operator gets **only their own**.
* `testnet-keys/faucet.key` — the faucet authority secret. Guard this: it is the
  only key that can drip.

A generated genesis looks like:

```toml
chain_id = 424242
network  = "peregrine-testnet-1"

[params]
max_items_per_vertex = 512

[[validators]]
public_key = "…64 hex…"
stake = 100
# …one block per validator…

[faucet]
authority = "…64 hex…"
per_request = 1000       # largest single drip
cooldown_rounds = 100    # a recipient must wait this many rounds between drips
lifetime_cap = 10000     # a recipient may ever receive at most this much

# Optional: pre-fund accounts at genesis.
# [[allocations]]
# account = "…64 hex…"
# grains  = 1000000
```

Edit the faucet limits and add allocations before launch; re-run
`genesis show` to check.

---

## Running validators & an RPC node

```bash
# All validators on one host (single-host testnet / CI):
peregrine node run --genesis genesis.toml --keys-dir testnet-keys \
  --rpc-addr 0.0.0.0:9000 --storage ./data

# Persist state: --storage writes a redb file per validator, so a restart
# reloads committed state. Omit for in-memory (state lost on exit).
```

The node prints its RPC address and, on shutdown (Ctrl-C), a per-validator commit
summary. Point the SDK's QUIC client at `--rpc-addr`.

This is the **local all-in-one** mode: `--genesis` without `--identity` runs the
whole committee in one process (every validator key local). Good for a
single-host testnet or CI. For a real distributed network, run one identity per
server:

### Running a distributed testnet — one identity per server

Each physical server runs **one** member of the committee. They share the same
`genesis.toml`, but every server holds **only its own** validator key and knows
the mesh addresses of the others.

```bash
# On server 0 (its key is validator-0.key; peers are validators 1 and 2):
peregrine node run \
  --genesis genesis.toml --keys-dir keys \
  --identity 0 \
  --listen   0.0.0.0:9001 \
  --peers    5.6.7.8:9001,9.10.11.12:9001 \
  --rpc-addr 0.0.0.0:9000 --storage ./data

# On server 1 (identity 1, its peers are validators 0 and 2):
peregrine node run --genesis genesis.toml --keys-dir keys \
  --identity 1 --listen 0.0.0.0:9001 --peers 1.2.3.4:9001,9.10.11.12:9001 \
  --rpc-addr 0.0.0.0:9000 --storage ./data

# …and identity 2, with peers 0 and 2's neighbours, likewise.
```

Rules that matter:

* **`--identity <i>`** is the 0-based index into `genesis.validators`. The
  process loads **only** `validator-{i}.key` and **fails closed** if that key
  doesn't match the genesis public key at index `i`, if `i` is out of range, or
  if a key is missing — so a server can never join under a borrowed identity.
* **`--peers`** lists the *other* validators' `--listen` addresses **in
  genesis-index order, skipping this identity** (identity 0 lists validators 1,
  2, …; identity 1 lists 0, 2, …). Order matters — ancestor-sync requests are
  addressed by committee index. Provide exactly `N-1` addresses.
* **`--listen`** is this node's QUIC mesh address (what its peers dial). It can
  differ from `--rpc-addr`, the client-facing RPC (bind that `0.0.0.0` to serve
  publicly, or keep it local and expose only the gateway).
* **Storage is per-identity:** each node writes its own `validator-{i}.redb`
  under `--storage`, so nothing is shared. Start order doesn't matter — peers
  redial with backoff and the mesh heals as each server comes up, which is also
  what makes restarts non-disruptive.

That's the whole deployment: **one `genesis.toml`, three key files, three start
commands.** No peer-discovery protocol — the peer list is explicit, which is the
honest choice for a coordinated testnet.

### Restarting validators (never wipe)

**Stop the nodes and start them again with the same `--storage` — that is the
whole procedure.** Wiping storage is not a recovery step; if a restart doesn't
resume, that is a bug worth reporting, not a reason to reach for `rm -rf`.

Restarting the *entire* committee is supported, in any order, with any gap
between servers. Each node reloads its DAG and table state, re-announces its own
tip so peers that were waiting on it can move, and keeps redialing until the
mesh is back. Expect rounds to resume within a few seconds of the last server
coming up.

To verify a restart actually worked, on each host:

```bash
# 1. Before stopping: note the value and the store root.
peregrine read demo.table hello --rpc-addr 127.0.0.1:9000

# 2. Stop both nodes (Ctrl-C, or `systemctl stop peregrine`). A graceful stop
#    flushes a final snapshot; expect "shutting down…" and a commit summary.

# 3. Start both again with the *same* flags — same --storage, same --listen,
#    same --peers. Each log should show, at info:
#      restored from disk   … resume_round=<n> dag=<n> commits=<n>
#      dialing mesh peer    … peer=<other-ip>:9001
#      outbound QUIC session established   peer=<other-ip>:9001
#      inbound QUIC session accepted       peer=<other-ip>:<port>
#    While the second host is still down the first logs, twice a second:
#      no consensus progress — re-announcing tip and re-requesting ancestors
#    plus, once each dial has actually timed out (tens of seconds if the
#    packets are being dropped rather than refused):
#      peer unreachable — still redialing   peer=… failed_dials=…
#    Both stop once the peer is up; a "consensus progress resumed" line
#    confirms it. A real run looks like this:
#      10:48:44  restored from disk  id=v0 resume_round=10922 dag=21843
#      10:48:44  no consensus progress …  tip_round=10921 attempt=1
#      10:48:49  inbound QUIC session accepted  peer=…
#      10:48:50  outbound QUIC session established  peer=…
#      10:48:50  consensus progress resumed  id=v0 round=10924 after_announces=11

# 4. Commit something new and read it back on BOTH hosts.
peregrine submit-tx demo.table hello 12345 --rpc-addr 127.0.0.1:9000
peregrine read      demo.table hello       --rpc-addr 127.0.0.1:9000   # host A
peregrine read      demo.table hello       --rpc-addr 127.0.0.1:9000   # host B
```

Both hosts must return the same value **and** the same store root, with the
proof verifying. If `submit-tx` never commits, the log lines above tell you
which half is wrong: no `outbound QUIC session established` is a network or
firewall problem (check `--peers` addresses, committee-index order, and that
UDP `9001` is open in *both* directions); sessions established but a repeating
`no consensus progress` line is a consensus problem.

The `restart_mesh` integration test runs this exact sequence — stop both,
restart one, restart the other late, commit — against a 2-validator committee.

> The dev transport still uses self-signed TLS with verification skipped; every
> vertex is independently signature-checked by consensus, so an unauthenticated
> link can waste bandwidth but cannot forge blocks. Binding validator identity
> into the certificate is a production follow-up.

### A public HTTP RPC (for browsers, wallets, the explorer)

Browsers can't speak the node's QUIC RPC directly, so front it with the gateway:

```bash
peregrine gateway --node 127.0.0.1:9000 --bind 0.0.0.0:8080
```

It's read-only and CORS-permissive. The TypeScript SDK and the explorer connect
to `http://<host>:8080/rpc`. **Every value it serves is re-verified against the
store root in the client**, so the gateway can withhold data but not forge it —
which is what makes it safe to run one publicly.

---

## The faucet

`sys.balances` is otherwise credit-only, so the faucet is how testnet accounts
get grains. **Its limits are enforced on-chain**, on every validator, so no node
can hand out more than genesis allows:

* per **request**: an amount cap;
* per **recipient**: a cooldown between drips and a lifetime cap.

Only the genesis **faucet authority** can sign a drip, so nobody can credit
themselves.

```bash
# Operator, one-off:
peregrine faucet drip <recipient-hex> --amount 1000 --faucet-key testnet-keys/faucet.key

# Web faucet (soft per-IP rate limit on top of the hard on-chain caps):
peregrine faucet serve --node 127.0.0.1:9000 --faucet-key testnet-keys/faucet.key \
  --bind 0.0.0.0:8088 --amount 1000 --per-ip-cooldown-secs 60
# POST /drip {"address":"<64 hex>"}   ·   GET /health
```

**Security:** the faucet key is the whole trust boundary — keep it off the public
RPC host, rotate it by shipping a new genesis. The on-chain per-recipient
cooldown and lifetime cap mean that even a compromised web layer cannot let one
address drain the supply.

---

## Connecting SDKs & wallets

```rust
// Rust: connect to a validator's QUIC RPC.
let client = peregrine_sdk::Client::connect("testnet-host:9000".parse()?).await?;
let balance = client.balance_of(&my_pubkey).await?;   // verified vs the store root
```

```ts
// TypeScript: connect to the gateway's HTTP RPC.
import { PeregrineClient } from "@peregrine/sdk";
const client = PeregrineClient.http("https://testnet-host:8080/rpc");
```

The explorer connects the same way — open it with
`?gateway=https://testnet-host:8080/rpc` (see [`explorer/README.md`](../explorer/README.md)).

---

## Health checks & monitoring

| Check | How |
|---|---|
| Gateway up + node reachable | `GET /health` on the gateway → `{"ok":true}` |
| Faucet up + node reachable | `GET /health` on the faucet |
| Node liveness | an SDK `ping()`, or the gateway health (it pings the node) |
| Commit progress | store root advances (`storeRoot` via the SDK/gateway); poll and alert if it stalls |
| Per-validator stats | printed on `node run` shutdown; `PipelineMetrics` counts commits, records, txs, faucet drips |

A simple monitor polls the gateway `/health` and the store root every few
seconds and alerts if either stops changing.

---

## Load-testing a running network (client mode)

`peregrine bench` has two modes. By default it spins up its *own* loopback
committee — useful, but its latency has no WAN round-trip. **Client mode**
(`--against <host:port>`) instead drives an **already-running** committee over
the SDK's QUIC RPC, exactly as an app would, so the numbers include real network
RTT and the node's live load. It never starts a validator.

```bash
# Local baseline (unchanged): bench spins up its own 4-validator loopback mesh.
peregrine bench --validators 4 --rate 5000 --duration 8

# Client mode, same host as a node (loopback). Rate under the per-connection
# budget (~8 submits/s × 8 connections ≈ 64/s) so rejects stay ~0:
peregrine bench --against 127.0.0.1:8080 --rate 40 --duration 20 --concurrency 8

# Client mode from ANOTHER host (e.g. the ops box rpc-1 → val-1), real WAN RTT:
peregrine bench --against 37.27.182.133:8080 --rate 40 --duration 20 --concurrency 8

# Spread load across all three validators (more connections → more headroom):
peregrine bench --against 37.27.182.133:8080 \
                --against 77.42.24.213:8080 \
                --against 77.42.22.144:8080 \
                --rate 80 --duration 20 --concurrency 12
```

**What it does.** A **global rate pacer** hands submit permits out at `--rate`
across all `--concurrency` connections, so *attempted* submits track the offered
rate (a small burst, never a 100× overshoot); `--rate 0` means unpaced/ack-bound.
Each connection submits Talon **table writes** (`submit_tx`) — the permissionless
path (`sys.balances` is credit-only, so no balance, fee, or genesis-registered
key is needed). Every write goes to a unique key and is **confirmed** on a
**separate read connection** (so confirming reads never spend the submit
connection's rate budget) by proving that key, with a 1 ms→20 ms adaptive
backoff. A rejected submit is counted and **not** retried.

**Reading the table.**

| Row | Meaning |
|---|---|
| offered rate | your `--rate` target (writes/s), or `max` |
| attempted | submit calls the client made (≈ offered × window when the node keeps up) |
| accepted / achieved | of those, how many the node took into its ingest queue, and that rate |
| confirmed committed | of the accepted writes, how many became provable (100% when healthy) |
| publish→confirm p50/p99/max | **submit → the client first proves the write committed.** Exact percentiles from raw samples; client-observed, so it includes the confirming read's round-trip — an *upper bound* on in-consensus publish→commit, and the number an app feels |
| errors | `rejected` (node refused — over the per-connection RPC budget), `disconnect` (transport fault), `confirm-timeout` (accepted but never observed within 20 s) |

**Interpreting attempted vs accepted vs rejected.** The RPC limiter is *per
connection* (a submit costs 16 tokens, refill 128/s ⇒ ~8 submits/s sustained per
connection, plus a burst). Keep `--rate` under `~8 × --concurrency` and rejects
stay near zero. Many rejects means you asked for more than the connections'
budget — raise `--concurrency` to spread the load over more buckets (an operator
can also raise the node's RPC limits; the public testnet keeps the defaults).

**Loopback-vs-WAN recipe.** Run the local baseline and client-mode-against-`127.0.0.1:8080`
on a validator host, then client-mode from a *different* host against the same
node, same `--rate`/`--concurrency`. The p50/p99 gap between the last two is your
real client↔committee RTT; the accepted-rate gap shows what the WAN path costs.
Raise `--concurrency` (not just `--rate`) for throughput — each connection's
submit is ack-synchronous, so aggregate throughput scales with connections.

**Safety.** Duration defaults to a short **10 s** so a bare `--against` command
cannot accidentally hammer a live node; ask for longer runs explicitly with
`--duration`. Client mode uses an **ephemeral client** — no validator or faucet
keys are involved. An unreachable node fails immediately with a clear message
rather than a run full of disconnect counts.

> This is a **public, unaudited testnet with no real value.** These are
> engineering measurements — always report the validator count, where the client
> ran (same host vs external), the transport, and the offered-vs-achieved rate
> alongside any p50/p99. Never a bare "N TPS" or a superlative.

---

## Security checklist before going public

- [ ] The **faucet key** lives only where the faucet runs, not on the RPC host.
- [ ] Faucet `per_request` / `cooldown_rounds` / `lifetime_cap` are set for your
      expected traffic (they are the hard cap on issuance).
- [ ] Validators run with `--storage` so a restart resumes rather than forks.
- [ ] The public **chain id** is documented and distinct from any other network.
- [ ] It is stated everywhere that this is an **unaudited** testnet with no real
      value — see [`SECURITY.md`](../SECURITY.md).
