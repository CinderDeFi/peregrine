/**
 * A `Transport` that serves bundled, real Rust-generated proofs — so the
 * explorer works with no backend (e.g. on GitHub Pages) and still verifies
 * every value for real. It cycles through the committed snapshots so the head
 * visibly moves; each snapshot's proofs verify against that snapshot's root.
 *
 * Kept backend-free (no DOM, no fetch) so it can be unit-tested under Node.
 */
export class DemoTransport {
  #data;
  #poll = 0;
  #snapIdx = 0;
  #advanceEvery;

  constructor(data, { advanceEvery = 6 } = {}) {
    this.#data = data;
    this.#advanceEvery = advanceEvery;
  }

  get snapshot() {
    return this.#data.snapshots[this.#snapIdx % this.#data.snapshots.length];
  }

  async request(req) {
    switch (req.kind) {
      case "ping":
        return { kind: "pong" };
      case "storeRoot": {
        this.#poll += 1;
        if (this.#data.snapshots.length > 1 && this.#poll % this.#advanceEvery === 0) {
          this.#snapIdx += 1; // simulate a new committed frontier
        }
        return { kind: "root", root: this.snapshot.storeRoot };
      }
      case "proveRead": {
        const hit = this.snapshot.reads.find(
          (r) => r.table === req.table && r.key === req.key,
        );
        return { kind: "proof", read: hit ?? null };
      }
      default:
        return { kind: "error", message: `demo transport does not support ${req.kind}` };
    }
  }
}
