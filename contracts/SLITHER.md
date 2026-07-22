# Static analysis — Slither

Tool output for `PeregrineLightClient`, with a disposition for every finding
including the ones deliberately not changed.

```
slither 0.11.5
solc   0.8.28  (--optimize --optimize-runs 200)
date   2026-07-21 (re-run; contract unchanged in findings after the treeVersion pin was added)
```

## Reproducing

```bash
pipx install slither-analyzer solc-select   # or: pip install --user
solc-select install 0.8.28 && solc-select use 0.8.28

cd contracts
slither src/PeregrineLightClient.sol \
  --solc-args "--optimize --optimize-runs 200" \
  --exclude-dependencies
```

`--exclude-dependencies` is not a way to hide findings: it excludes `lib/`
(forge-std), which is test tooling and is not deployed. The shipped contract is
`src/PeregrineLightClient.sol` and nothing else.

## Result — the deployed contract

```
INFO:Slither:src/PeregrineLightClient.sol analyzed (2 contracts with 101 detectors), 0 result(s) found
```

`--print human-summary`:

```
Total number of contracts in source files: 2
Source lines of code (SLOC) in source files: 138
Number of  assembly lines: 0
Number of optimization issues: 0
Number of informational issues: 0
Number of low issues: 0
Number of medium issues: 0
Number of high issues: 0
```

**Clean is not the same as correct.** Slither finds patterns; it cannot know
whether pinning the right committee digest matters, whether the equivocation
rule should stop or pick a side, or whether the Rust encoder agrees with
`abi.decode`. Those are the things most likely to be wrong here, and they are
covered by tests and by [`AUDIT.md`](AUDIT.md), not by this tool. Treat a clean
run as "no known pattern-level defects", nothing more.

## Findings addressed

### 1. `pragma` — different Solidity versions used *(fixed)*

Slither flagged `src/` pinned to `^0.8.24` while `script/` used `^0.8.28`.

Minor, but real: two pragmas mean two possible compilers, and the bytecode you
audit may not be the bytecode you deploy. All first-party files are now
`^0.8.28`, matching `solc_version` in `foundry.toml`. forge-std still declares
`>=0.8.13 <0.9.0`; that is a library constraint, not a second compiler.

## Findings not addressed, with reasons

### 2. `unused-state` on `Deploy` *(won't fix — not ours)*

Nine constants inherited from forge-std's `CommonBase`/`ScriptBase`
(`CONSOLE`, `CREATE2_FACTORY`, `DEFAULT_SENDER`, …) are unused by `Deploy`.

They belong to forge-std's base contracts, are unused by design in a script
this small, and are never deployed — `Deploy` is a Foundry script, not part of
the on-chain system. Nothing to fix.

## Detectors worth understanding for this contract

These did *not* fire, but a reviewer should know why, because each would be a
real problem in a slightly different design.

| Detector | Why it does not apply |
|---|---|
| `reentrancy-*` | The only external call is a `view` on an immutable, code-checked address, made before any state write. No value transfer, no callback surface. |
| `abi-encodePacked-collision` | `_slot` packs three `bytes32` values. Fixed-width operands make the concatenation unambiguous; no collision is reachable. It would **not** be safe if any operand were dynamic — that is the invariant to preserve. |
| `arbitrary-send` / `unchecked-transfer` | No ether, no tokens. The contract has no `receive`/`fallback`, so ether sent to it reverts (tested). |
| `unprotected-upgrade` / `suicidal` | No proxy, no `selfdestruct`, no owner, no admin function. |
| `uninitialized-state` | All four configuration values are `immutable` and set in the constructor, which validates each one. |
| `tx-origin` / `timestamp` | Neither is read. Nothing here depends on the caller's identity or on block time. |
| `assembly` | Zero assembly lines. |
| `solc-version` | `^0.8.28` is well above 0.8.20, where `PUSH0` starts being emitted. ⚠️ Deploying to a chain without Shanghai requires setting `evm_version` in `foundry.toml`; `cancun` is configured, which targets mainnet and its equivalents. |

## What static analysis does not cover here

Listed so the gap is explicit rather than implied:

- **Cross-language encoding.** That the Rust guest's eight hand-written words
  are what Solidity's `abi.decode` expects. Covered by
  `test/PeregrineJournalAbi.t.sol` against a Rust-generated fixture.
- **The proven statement.** Slither analyses the verifier, not the guest. If the
  guest proves the wrong thing, this contract will faithfully record it.
- **Trusted setup.** Groth16's setup is a property of SP1's verifier, off-limits
  to any Solidity analyser.
- **Economic and liveness properties.** Nothing forces proofs to be submitted;
  a stale root is genuinely proven but old.
