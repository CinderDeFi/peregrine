# scripts

Reproduction tooling for the flaky-test investigation (see
[`AUDIT.md` §10](../AUDIT.md#determinism-of-the-suite-itself)). Windows
PowerShell, because that is where the flakes were found.

## Why two harnesses

Concurrency bugs hide at two different scales, and each script targets one:

- **`soak.ps1`** loops a *single* test binary while N background processes burn
  CPU. This finds timing flakes — a test whose fixed `sleep` is too short when
  the cores are contended.

  ```powershell
  scripts/soak.ps1 -Runs 10 -Load 28 -TestName restart_recovery
  ```

- **`soak_full.ps1`** loops the *whole* `cargo test --workspace` and keeps the
  log of any run that fails. This is the only way to find bugs that need
  multiple tests in one process — the env-var race in `sp1_backend` was
  invisible to per-binary soaking because it only happens when two tests
  interleave their access to a shared global.

  ```powershell
  scripts/soak_full.ps1 -Runs 10
  ```

A clean soak is evidence, not proof: it says "no failure in N runs", which
bounds the flake rate but never reaches zero. The claim these support is "the
three reproducible flakes are fixed", not "there are no races".
