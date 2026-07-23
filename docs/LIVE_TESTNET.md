# The public Peregrine testnet

Connection parameters, host layout, and operator runbook for the running
`peregrine-testnet` deployment: three validators on three machines, meshed over
QUIC, with one public HTTP gateway.

> **Status, honestly.** This network is **unaudited**. No third party has
> reviewed the code (see [AUDIT.md](../AUDIT.md)). It carries **no real value**,
> there is **no token and nothing to buy**, and it **will be reset** — treat
> every address, balance, and store root as disposable. It is a testnet for
> exercising the software on real hosts across a real network, and that is the
> only claim being made for it. Nothing here is "secure" or "production-ready".

For standing up your *own* network, see [TESTNET.md](TESTNET.md); this file
documents the one that is already running.

---

## Network parameters

| Parameter | Value |
| --- | --- |
| Network name | `peregrine-testnet` |
| Chain id | `1` |
| Validators | 3, equal stake 100 each (total stake 300) |
| Quorum threshold | 201 of 300 stake — see [Quorum & liveness](#quorum--liveness) |
| `max_items_per_vertex` | 512 |
| Faucet | enabled — max 1000 per drip, 100-round cooldown, 10000 lifetime cap per recipient |
| Genesis allocations | 0 (every balance comes from the faucet) |
| Public read endpoint | `http://37.27.182.133:8081` |

Every client needs the same `genesis.toml` the validators run. Confirm what a
file contains before trusting it:

```bash
peregrine genesis show --path genesis.toml
```

---

## Hosts

| Host | Identity | Mesh address | Role |
| --- | --- | --- | --- |
| Val-1 | `--identity 0` | `37.27.182.133:9001` | validator + HTTP gateway |
| Val-2 | `--identity 1` | `77.42.24.213:9001` | validator |
| Val-3 | `--identity 2` | `77.42.22.144:9001` | validator |

`--identity <i>` is the 0-based index into `genesis.validators`. Each host holds
**only its own** `validator-{i}.key` and fails closed if that key does not match
the genesis public key at index `i`.

### Ports

| Port | Proto | Purpose | Exposure |
| --- | --- | --- | --- |
| 9001 | UDP | validator mesh (QUIC) | open between the three hosts, **both directions** |
| 8080 | UDP | node RPC (QUIC), for CLI/SDK clients | bound to `127.0.0.1` on Val-1; the gateway is what fronts it |
| 8081 | TCP | HTTP gateway | public, Val-1 only |
| 22 | TCP | SSH | operators only |

Mesh reachability must be symmetric. A one-way firewall rule produces a mesh
that looks half-connected and a tip that never advances; `nc -zvu <host> 9001`
from *both* ends is the check.

### Peer lists

`--peers` takes the *other* validators' mesh addresses **in genesis-index order,
skipping this identity**. Order is load-bearing — ancestor-sync requests are
addressed by committee index.

| Identity | `--peers` |
| --- | --- |
| 0 (Val-1) | `77.42.24.213:9001,77.42.22.144:9001` |
| 1 (Val-2) | `37.27.182.133:9001,77.42.22.144:9001` |
| 2 (Val-3) | `37.27.182.133:9001,77.42.24.213:9001` |

---

## Validator set

| Index | Host | Address | Stake | Public key |
| --- | --- | --- | --- | --- |
| 0 | Val-1 | `37.27.182.133` | 100 | `881c6fe263b4074801c8d68fdf2c880fb9a8463bec37ff78a390e82bbd216b1c` |
| 1 | Val-2 | `77.42.24.213` | 100 | `62b499a74aec42c167ae25ca7a9158009e8a7e0303f7e07444406866a76436dd` |
| 2 | Val-3 | `77.42.22.144` | 100 | `e99b85acb82af697db13972a4f264d32bd5e7a93f6a78c62a487ef94b147375c` |

### Faucet

| Field | Value |
| --- | --- |
| Authority public key | `5cd621cc5b0c710703cf0bf19a5873ce6e53bcff0f61327ee1cb29302b1b50d0` |
| Max per request | 1000 (largest single drip) |
| Cooldown | 100 committed rounds between drips, per recipient |
| Lifetime cap | 10000 total, per recipient |

The cooldown is counted in **rounds, not wall-clock time** — it advances only
while the chain is committing, so a stalled tip also stalls the cooldown.

Verify these against the genesis your node loaded rather than trusting this
page:

```bash
peregrine genesis show --path genesis.toml
```

> The `genesis.toml` checked into this workspace is a **different, local** key
> set — it does not contain the keys above. Do not use it to connect to this
> network.

Only ever publish public keys. Secret keys live in `--keys-dir` on their own
host and belong in no document, repository, or issue.

---

## Connecting

### HTTP gateway (browsers, wallets, the explorer)

Browsers cannot speak the node's QUIC RPC, so Val-1 fronts its local node RPC
(`127.0.0.1:8080`) with the gateway on `:8081`.

The gateway is **read-only by design**: `ping`, `storeRoot`, `proveRead`.
Submitting anything is signing work, and signing belongs in the CLI or a native
SDK client, not behind a shared HTTP endpoint.

**Health**

```bash
curl http://37.27.182.133:8081/health
# {"ok":true}
```

Returns HTTP 200 with `{"ok":true}` when the gateway can reach its node, and
HTTP 502 with `{"ok":false,"error":"…"}` when it cannot. A 502 here means the
*node* is down, not the gateway.

**RPC** — one endpoint, `POST /rpc`, body `{"kind":"…"}`:

| Request | Response |
| --- | --- |
| `{"kind":"ping"}` | `{"kind":"pong"}` |
| `{"kind":"storeRoot"}` | `{"kind":"root","root":"<64-hex>"}` |
| `{"kind":"proveRead","table":"<64-hex>","key":"<hex>"}` | `{"kind":"proof","read":{…}}`, or `read: null` if absent |
| anything else | `{"kind":"error","message":"…"}` |

```bash
curl -s http://37.27.182.133:8081/rpc \
  -H 'content-type: application/json' \
  -d '{"kind":"storeRoot"}'
```

`table` is the **32-byte hex table id**, not a name: the id is
`BLAKE3(table_name)`. The TypeScript SDK exposes `tableId("demo.table")` for
this; the Rust equivalent is `TableId::named`. (The `peregrine read` CLI accepts
either a name or a hex id — the gateway takes hex only.)

Write kinds (`publish`, `submitTx`, `submitClaim`, `openSession`, …) are
rejected with an explicit error telling you to use the CLI or an SDK client.

**Verify, don't trust.** A `proveRead` response carries an inclusion proof.
Check it against the store root in your own client rather than believing the
gateway — that is the entire point of shipping proofs. The gateway operator can
withhold an answer, but cannot forge one you actually verify.

### Native QUIC (CLI and SDK)

Reads and writes over the node's QUIC RPC:

```bash
peregrine read       demo.table hello        --rpc-addr 127.0.0.1:8080
peregrine submit-tx  demo.table hello 12345  --rpc-addr 127.0.0.1:8080
```

`read` and `submit-tx` take their table/key/value **positionally**; only
`--rpc-addr` is a flag.

Because 8080 is bound to loopback on Val-1, these run **on the host** (or over an
SSH tunnel). Publishing the QUIC RPC is a deliberate choice, not a default: open
UDP 8080 only if you intend to accept transactions from the internet, and
understand that it is an unauthenticated write path into an unaudited node.

---

## Quorum & liveness

`quorum_threshold = (total_stake * 2) / 3 + 1`. With three validators at stake
100 each:

```
(300 * 2) / 3 + 1  =  201
```

Two validators are 200 stake, which is **less than 201**. So on this network the
quorum is **all three validators**, and it therefore tolerates **zero**
failures:

| Validators up | Stake | ≥ 201? | Behaviour |
| --- | --- | --- | --- |
| 3 | 300 | yes | rounds advance |
| 2 | 200 | no | tip freezes; RPC stays up and serves the last committed state |
| 1 | 100 | no | tip freezes |

This is expected, not a bug: a committee that survives one failure needs **four**
validators (quorum 267 of 400, reachable by any three). Three is the smallest
set that exercises real multi-host meshing, and the deliberate trade is that any
single host going down stalls the tip until it returns.

A frozen tip is **not** a fork or data loss. Committed state stays readable and
proofs keep verifying; only new commits stop. When the missing validator comes
back, rounds resume from where they stopped — no wipe, no re-genesis.

---

## Operations

### systemd

| Unit | Host | Purpose |
| --- | --- | --- |
| `peregrine` | Val-1 (verified), Val-2, Val-3 | the validator process |
| `peregrine-gateway` | Val-1 | the HTTP gateway on `:8081` |

Both units on Val-1 were confirmed in the 2026-07-23 run below. Val-2 and Val-3
run the validator unit under the same name.

```bash
systemctl status  peregrine peregrine-gateway
journalctl -u peregrine -f
```

### Restarting — never wipe

**Stop the unit and start it again with the same `--storage`. That is the whole
procedure.** Wiping storage is not a recovery step. Restarting the entire
committee is supported, in any order, with any gap between hosts: each node
reloads its DAG and table state, re-announces its own tip so peers waiting on it
can move, and keeps redialing until the mesh is back.

The detailed runbook — including the exact `info` log lines to expect and how to
tell a network problem from a consensus problem — is in
[TESTNET.md § Restarting validators](TESTNET.md#restarting-validators-never-wipe).
The short version:

```bash
# on each host
systemctl stop peregrine
systemctl start peregrine
journalctl -u peregrine -n 50
```

Expect, at `info`:

```
restored from disk                 id=v0 resume_round=… dag=… commits=…
dialing mesh peer                  peer=…:9001
outbound QUIC session established  peer=…:9001
inbound QUIC session accepted      peer=…
consensus progress resumed         id=v0 round=… after_announces=…
```

While a peer is still down you will see `no consensus progress — re-announcing
tip and re-requesting ancestors` twice a second. That line stopping, and
`consensus progress resumed` appearing, is the signal that the mesh healed.

### Health checklist

```bash
# 1. Gateway reaches its node.
curl -s http://37.27.182.133:8081/health

# 2. The tip is moving: two storeRoot calls a few seconds apart should differ
#    while transactions are being committed.
curl -s http://37.27.182.133:8081/rpc -H 'content-type: application/json' \
     -d '{"kind":"storeRoot"}'

# 3. Mesh reachability, from each host to each other host, both directions.
nc -zvu 77.42.24.213 9001
```

If the tip is frozen: check all three validators are up before anything else —
on a 3-of-3 quorum that is by far the most likely cause.

---

## Verification log

Recorded on **2026-07-23**, on the live hosts:

| Check | Result |
| --- | --- |
| Committee formed, rounds advancing | tip reached round **≥ 133625** |
| Kill one validator | tip **froze** — expected at 3-of-3 quorum |
| Restart that validator | rounds **resumed**, 133625 → **133900+** |
| Restart required a storage wipe? | **no** |
| systemd units on Val-1 | `peregrine`, `peregrine-gateway` both active |

That sequence is the live counterpart of the `restart_mesh` integration test,
which pins the same behaviour in CI against a 2-validator committee.

---

## What this does not prove

Being live is not the same as being ready. Specifically:

- **Unaudited.** No external review of consensus, the VM, the proof paths, or
  the node. See [AUDIT.md](../AUDIT.md) for the invariants and threat model, and
  [SECURITY.md](../SECURITY.md) for what is and is not covered.
- **Dev TLS on the mesh.** The QUIC transport uses self-signed certificates with
  verification skipped. Every vertex is still independently signature-checked by
  consensus, so an unauthenticated link can waste bandwidth but cannot forge
  blocks. Binding validator identity into the certificate is a production
  follow-up.
- **Three validators is not fault tolerance.** See above — the quorum is all
  three by construction.
- **Static committee.** No validator rotation, no staking, no slashing. The peer
  list is explicit, with no discovery protocol.
- **Expect resets.** Chain state here is disposable and will be wiped when the
  genesis changes. Do not build anything that assumes an address, balance, or
  store root survives.

---

## Related documents

| Document | What it covers |
| --- | --- |
| [TESTNET.md](TESTNET.md) | Standing up your own testnet; genesis, keys, faucet, the restart runbook |
| [DESIGN.md](DESIGN.md) | Architecture and the consensus/execution design |
| [../README.md](../README.md) | Project overview, persistence and networking internals |
| [../AUDIT.md](../AUDIT.md) | Invariants, threat model, audit status |
| [../SECURITY.md](../SECURITY.md) | Reporting a vulnerability; what is in scope |
