---
name: Bug report
about: Something behaves differently than documented
labels: bug
---

**⚠️ Not for security issues.** If this is a vulnerability in consensus,
proofs, cryptography, or interop, please follow [SECURITY.md](../../SECURITY.md)
instead of opening a public issue.

### What you ran

```bash
# e.g. peregrine demo, or cargo test -p peregrine-interop --features bls
```

### What you expected / what happened

Paste the actual output. For a failing test, the full assertion message.

### Environment

- OS + arch:
- `rustc --version`:
- Core count (several tests spin up 4 validators + a client):

### Timing-sensitive?

Several tests drive a real network. If it fails intermittently, say so — and
please don't just increase the sleep in a PR; past flakes turned out to be real
bugs (a blocking `fsync` starving message delivery, and a single-validator
devnet hot-looping).
