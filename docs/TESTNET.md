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

## Security checklist before going public

- [ ] The **faucet key** lives only where the faucet runs, not on the RPC host.
- [ ] Faucet `per_request` / `cooldown_rounds` / `lifetime_cap` are set for your
      expected traffic (they are the hard cap on issuance).
- [ ] Validators run with `--storage` so a restart resumes rather than forks.
- [ ] The public **chain id** is documented and distinct from any other network.
- [ ] It is stated everywhere that this is an **unaudited** testnet with no real
      value — see [`SECURITY.md`](../SECURITY.md).
