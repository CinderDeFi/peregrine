# EVM contracts — reading Peregrine from Ethereum

The reciprocal of Peregrine's beacon light client: this is how an Ethereum
contract learns Peregrine state without trusting a bridge operator.

> **Status: compiled and tested, but unaudited and undeployed.** `forge build`
> and `forge test` pass (9 tests, solc 0.8.24). It has **not** been run against
> a real SP1 Groth16 proof — the tests use a mock verifier, because the real
> one only ever reverts-or-returns and that is the branch the contract's rules
> hinge on. Not audited; do not put value behind it.

## Layout

```
contracts/
├── foundry.toml                      # no libs: zero submodules by design
├── src/PeregrineLightClient.sol
├── test/PeregrineLightClient.t.sol   # 9 tests, no forge-std
└── script/Deploy.s.sol
```

```bash
forge build
forge test            # 9 passing
forge test --gas-report
```

Measured gas: `verifyPeregrineState` ~29k–123k (mean ~73k, dominated by
storage writes; the real Groth16 verification adds ~250k on top),
`getVerifiedValue` ~5k.

The tests deliberately avoid `forge-std` so the project builds from a clean
checkout with no `git submodule` or package manager. Revert expectations use
low-level `call` instead of cheatcodes.

## Design: prove off-chain, verify on-chain

Peregrine commits state with **BLAKE3** sparse-Merkle trees, and the EVM has no
BLAKE3 precompile. Verifying a Peregrine inclusion proof directly in Solidity
would cost hundreds of thousands of gas — a 256-deep SMT path makes it worse.

So the contract verifies **no Merkle paths at all**. The entire statement is
proven inside the zkVM:

```text
  guest program proves:
     a stake-weighted quorum signed a checkpoint committing to store root R
     AND  table[key] == value  under R
  ────────────────────────────────────────────────────────────────────────
  contract verifies: one SP1 proof + reads the committed journal
```

Gas is constant regardless of proof depth, and no BLAKE3 ever runs on-chain.
The guest is the same `peregrine-interop` verification code used everywhere
else (`verify_checkpoint` + `ProvenRead::verify`), which is why the two sides
cannot drift apart.

## Deployment story

1. **Build the guest** for the Peregrine-state direction and record its
   verifying-key hash:
   ```bash
   cd crates/peregrine-eth-guest && cargo prove build   # (Linux/macOS/WSL2)
   ```
2. **Deploy**, pinning the vkey and the SP1 verifier gateway for your network:
   ```solidity
   new PeregrineLightClient(SP1_VERIFIER_GATEWAY, PROGRAM_VKEY, PEREGRINE_CHAIN_ID);
   ```
   `programVKey` is `immutable` deliberately — an upgradeable vkey is an admin
   key that can swap in a program committing anything.
3. **Relay**: anyone generates a Groth16 proof off-chain and calls
   `verifyPeregrineState(publicValues, proofBytes)`. Relayers are permissionless
   and untrusted; a wrong proof simply reverts.

## Trust assumptions

| Assumption | Notes |
| --- | --- |
| SP1 Groth16 verifier | **Circuit-specific trusted setup** by Succinct. Unavoidable for cheap L1 verification today. |
| Pinned `programVKey` | A proof of a *different* program is still a valid proof — pinning is what makes a proof mean what you think. |
| Peregrine validator set | The guest checks a quorum against a committee fixed at its compile time. **Committee rotation is not implemented** — the weakest link in this direction. |

Note the asymmetry: Peregrine verifying *Ethereum* uses SP1 **Compressed**
(STARK, **no trusted setup**). Only this direction takes the Groth16 setup, and
only because the EVM leaves no cheaper option. That is a property of the EVM,
not of the protocol.

## Not yet done

* Committee rotation, so the guest can follow Peregrine's validator set from a
  single trusted genesis instead of a compile-time constant.
* A Foundry/Hardhat project with tests against a real proof.
* Gas benchmarking (expected ~250–300k for a Groth16 verification plus storage).
