/**
 * Cross-language proof verification, for **both tree versions**.
 *
 * The fixture holds **real proofs produced by the Rust node**
 * (`cargo run -p peregrine-node --example gen_js_fixture`). If the TypeScript
 * verifier disagrees with Rust on a single domain tag, byte order, or bit
 * index, these tests fail — which is the whole point: a light client that
 * verifies differently from the chain is worse than none.
 *
 * Every case runs against v1 *and* v2. During a chain's migration both are in
 * flight simultaneously, so testing only the new one would leave the old path
 * to rot exactly when it is still load-bearing.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { fromHex, readU64LE, toHex } from "../src/hash.ts";
import {
  parseTreeVersion,
  provenReadFromJson,
  verifyProvenRead,
  verifyRowProof,
  type ProvenReadJson,
  type TreeVersion,
} from "../src/verify.ts";

interface VersionFixture {
  treeVersion: TreeVersion;
  storeRoot: string;
  reads: ProvenReadJson[];
  absent: ProvenReadJson[];
}

const here = dirname(fileURLToPath(import.meta.url));
const fixture = JSON.parse(
  readFileSync(join(here, "fixtures", "proven-read.json"), "utf8"),
) as { v1: VersionFixture; v2: VersionFixture };

const versions: TreeVersion[] = ["v1", "v2"];

describe("cross-version invariants", () => {
  it("commits the same rows to different roots", () => {
    // If these matched, the version tag would be decorative and a stale proof
    // would verify against a migrated chain.
    assert.notEqual(fixture.v1.storeRoot, fixture.v2.storeRoot);
  });

  it("path compression makes v2 proofs far shallower", () => {
    const v1Depth = fixture.v1.reads[0].rowProof.siblings.length;
    const v2Depth = fixture.v2.reads[0].rowProof.siblings.length;
    assert.equal(v1Depth, 256, "v1 paths are a fixed 256");
    assert.ok(v2Depth < 32, `v2 path should be ~log2(n), got ${v2Depth}`);
  });

  it("refuses an unknown tree version rather than guessing", () => {
    assert.throws(() => parseTreeVersion("v3"), /unsupported Merkle tree version/);
    assert.throws(() => parseTreeVersion("nonsense"), /unsupported/);
    // Missing means v1 — fixtures predating the tag really are v1.
    assert.equal(parseTreeVersion(undefined), "v1");
  });

  it("will not verify one version's proof under the other's rule", () => {
    for (const v of versions) {
      const other: TreeVersion = v === "v1" ? "v2" : "v1";
      const f = fixture[v];
      const read = provenReadFromJson(f.reads[0]);
      assert.equal(
        verifyRowProof(other, read.key, read.value, read.rowProof, read.tableRoot),
        false,
        `a ${v} proof must not verify as ${other}`,
      );
    }
  });
});

for (const v of versions) {
  describe(`light-client proof verification (${v})`, () => {
    const f = fixture[v];
    const storeRoot = fromHex(f.storeRoot);

    it("loads real Rust-generated proofs", () => {
      assert.equal(storeRoot.length, 32);
      assert.ok(f.reads.length >= 4, "fixture should cover several keys");
      assert.equal(f.treeVersion, v);
    });

    it("verifies every genuine proof against the store root", () => {
      for (const j of f.reads) {
        const read = provenReadFromJson(j);
        assert.equal(read.treeVersion, v);
        assert.ok(
          verifyProvenRead(read, storeRoot),
          `proof for key ${j.key} in table ${j.table} should verify`,
        );
      }
    });

    it("verifies genuine absence proofs", () => {
      assert.ok(f.absent.length > 0, "fixture should cover absent keys");
      for (const j of f.absent) {
        const read = provenReadFromJson(j);
        assert.equal(read.value, null);
        assert.ok(
          verifyProvenRead(read, storeRoot),
          `absence proof for key ${j.key} should verify`,
        );
      }
    });

    it("rejects a tampered value", () => {
      for (const j of f.reads) {
        const read = provenReadFromJson(j);
        read.value = fromHex("deadbeefdeadbeef");
        assert.equal(verifyProvenRead(read, storeRoot), false);
      }
    });

    it("rejects a genuine proof against the wrong root", () => {
      const read = provenReadFromJson(f.reads[0]);
      assert.equal(verifyProvenRead(read, new Uint8Array(32)), false);
    });

    it("rejects a corrupted sparse-Merkle path", () => {
      const read = provenReadFromJson(f.reads[0]);
      read.rowProof.siblings[0] = new Uint8Array(32);
      assert.equal(verifyProvenRead(read, storeRoot), false);
    });

    it("rejects a corrupted store path", () => {
      const read = provenReadFromJson(f.reads[0]);
      read.storeProof.siblings[0] = new Uint8Array(32);
      assert.equal(verifyProvenRead(read, storeRoot), false);
    });

    it("rejects a proof replayed for a different key", () => {
      const read = provenReadFromJson(f.reads[0]);
      read.key = fromHex("00112233");
      assert.equal(verifyProvenRead(read, storeRoot), false);
    });

    it("rejects a truncated sparse-Merkle path", () => {
      const read = provenReadFromJson(f.reads[0]);
      read.rowProof.siblings = read.rowProof.siblings.slice(0, 1);
      assert.equal(verifyProvenRead(read, storeRoot), false);
    });

    it("will not let an inclusion proof claim absence", () => {
      const read = provenReadFromJson(f.reads[0]);
      // Same path, but claiming the slot is empty must not reconstruct the root.
      assert.equal(
        verifyRowProof(v, read.key, null, read.rowProof, read.tableRoot),
        false,
      );
    });

    it("will not let an absence proof claim a value", () => {
      const read = provenReadFromJson(f.absent[0]);
      assert.equal(
        verifyRowProof(v, read.key, fromHex("2a00000000000000"), read.rowProof, read.tableRoot),
        false,
      );
    });

    it("decodes committed values (u64 little-endian)", () => {
      const sumKey = toHex(new TextEncoder().encode("sum"));
      const sum = f.reads.find((r) => toHex(fromHex(r.key)) === sumKey);
      assert.ok(sum, "fixture contains the 'sum' key");
      assert.equal(readU64LE(fromHex(sum!.value!)), 55n);
    });
  });
}

// ── v2-specific soundness ───────────────────────────────────────────────────

describe("v2 non-inclusion soundness", () => {
  const f = fixture.v2;
  const storeRoot = fromHex(f.storeRoot);

  it("exercises the occupied-slot shape, not just empty slots", () => {
    // v2 absence comes in two shapes and the occupied one is where a lax
    // verifier breaks. If the fixture stopped covering it, these tests would
    // pass while proving nothing about that path.
    const occupied = f.absent.filter((a) => a.rowProof.otherLeaf);
    assert.ok(
      occupied.length > 0,
      "fixture must include an absence proof whose slot holds another key",
    );
  });

  it("refuses an unrelated leaf as evidence of absence", () => {
    const occupied = f.absent.find((a) => a.rowProof.otherLeaf)!;
    const read = provenReadFromJson(occupied);

    // Substitute a key that is definitely *not* the one occupying the slot.
    // (Picking another fixture read would be fragile: the slot is often
    // occupied by one of them, in which case the "forgery" is the genuine
    // proof and the test would assert the wrong thing.)
    const genuine = read.rowProof.otherLeaf!;
    const forgedKey = new Uint8Array(genuine.key.length + 1);
    forgedKey.set(genuine.key);
    forgedKey[genuine.key.length] = 0xff;

    read.rowProof.otherLeaf = { key: forgedKey, value: genuine.value };
    // Refused either by the shared-prefix check (the forged key lands
    // elsewhere) or by the climb (its leaf hash differs). Both are correct.
    assert.equal(verifyProvenRead(read, storeRoot), false);
  });

  it("refuses a key presented as evidence of its own absence", () => {
    const occupied = f.absent.find((a) => a.rowProof.otherLeaf)!;
    const read = provenReadFromJson(occupied);
    read.rowProof.otherLeaf = { key: read.key, value: fromHex("00") };
    assert.equal(verifyProvenRead(read, storeRoot), false);
  });

  it("refuses an inclusion proof that carries an otherLeaf", () => {
    const read = provenReadFromJson(f.reads[0]);
    read.rowProof.otherLeaf = { key: fromHex("aabb"), value: fromHex("ccdd") };
    assert.equal(verifyProvenRead(read, storeRoot), false);
  });

  it("refuses a tampered otherLeaf value", () => {
    const occupied = f.absent.find((a) => a.rowProof.otherLeaf)!;
    const read = provenReadFromJson(occupied);
    read.rowProof.otherLeaf!.value = fromHex("ffffffffffffffff");
    assert.equal(verifyProvenRead(read, storeRoot), false);
  });
});
