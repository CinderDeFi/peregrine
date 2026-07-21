/**
 * Cross-language proof verification.
 *
 * The fixture holds **real proofs produced by the Rust node**
 * (`cargo run -p peregrine-node --example gen_js_fixture`). If the TypeScript
 * verifier disagrees with Rust on a single domain tag, byte order, or bit
 * index, these tests fail — which is the whole point: a light client that
 * verifies differently from the chain is worse than none.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { fromHex, readU64LE, toHex } from "../src/hash.ts";
import {
  provenReadFromJson,
  verifyProvenRead,
  verifySmt,
  type ProvenReadJson,
} from "../src/verify.ts";

const here = dirname(fileURLToPath(import.meta.url));
const fixture = JSON.parse(
  readFileSync(join(here, "fixtures", "proven-read.json"), "utf8"),
) as { storeRoot: string; reads: ProvenReadJson[] };

const storeRoot = fromHex(fixture.storeRoot);

describe("light-client proof verification", () => {
  it("loads real Rust-generated proofs", () => {
    assert.equal(storeRoot.length, 32);
    assert.ok(fixture.reads.length >= 4, "fixture should cover several keys");
  });

  it("verifies every genuine proof against the store root", () => {
    for (const j of fixture.reads) {
      const read = provenReadFromJson(j);
      assert.ok(
        verifyProvenRead(read, storeRoot),
        `proof for key ${j.key} in table ${j.table} should verify`,
      );
    }
  });

  it("rejects a tampered value", () => {
    for (const j of fixture.reads) {
      const read = provenReadFromJson(j);
      read.value = fromHex("deadbeefdeadbeef");
      assert.equal(verifyProvenRead(read, storeRoot), false);
    }
  });

  it("rejects a genuine proof against the wrong root", () => {
    const read = provenReadFromJson(fixture.reads[0]);
    assert.equal(verifyProvenRead(read, new Uint8Array(32)), false);
  });

  it("rejects a corrupted sparse-Merkle path", () => {
    const read = provenReadFromJson(fixture.reads[0]);
    read.rowProof.siblings[0] = new Uint8Array(32);
    assert.equal(verifyProvenRead(read, storeRoot), false);
  });

  it("rejects a corrupted store path", () => {
    const read = provenReadFromJson(fixture.reads[0]);
    read.storeProof.siblings[0] = new Uint8Array(32);
    assert.equal(verifyProvenRead(read, storeRoot), false);
  });

  it("rejects a proof replayed for a different key", () => {
    const read = provenReadFromJson(fixture.reads[0]);
    read.key = fromHex("00112233");
    assert.equal(verifyProvenRead(read, storeRoot), false);
  });

  it("rejects a truncated sparse-Merkle path", () => {
    const read = provenReadFromJson(fixture.reads[0]);
    read.rowProof.siblings = read.rowProof.siblings.slice(0, 100);
    assert.equal(verifyProvenRead(read, storeRoot), false);
  });

  it("will not let an inclusion proof claim absence", () => {
    const read = provenReadFromJson(fixture.reads[0]);
    // Same path, but claiming the slot is empty must not reconstruct the root.
    assert.equal(verifySmt(read.key, null, read.rowProof, read.tableRoot), false);
  });

  it("decodes committed values (u64 little-endian)", () => {
    // contract.answers["sum"] == 55 — the on-chain loop result.
    const sum = fixture.reads.find((r) => toHex(fromHex(r.key)) === toHex(new TextEncoder().encode("sum")));
    assert.ok(sum, "fixture contains the 'sum' key");
    assert.equal(readU64LE(fromHex(sum!.value)), 55n);
  });
});
