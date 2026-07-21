---
name: Feature request
about: Suggest something to build
labels: enhancement
---

### What problem does this solve?

### Which crate would it touch?

The crate boundaries are load-bearing (see [CONTRIBUTING.md](../../CONTRIBUTING.md)) —
`core`/`consensus`/`data`/`vm` are pure, and only `peregrine-node` may touch
sockets, disk, or tokio.

### Is this already a documented limitation?

The README's *Honest limitations* section is long on purpose. If your request is
already listed there, say so — that's useful signal about what to prioritise.
