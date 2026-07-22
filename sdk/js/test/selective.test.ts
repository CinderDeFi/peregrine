/**
 * Selective disclosure + compliance, checked against **real Rust-produced
 * fixtures** (`cargo run -p peregrine-node --example gen_selective_fixtures`).
 * If the TypeScript verifier disagrees with Rust on a domain tag, byte order, or
 * the flag layout, these fail — the same drift-guard as `verify.test.ts`.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fromHex } from "../src/hash.ts";
import { selectiveDisclosureFromJson, verifySelectiveDisclosure } from "../src/disclosure.ts";
import {
  ComplianceStatus,
  decodeFlag,
  gate,
  requireCompliant,
  type CompliancePolicy,
} from "../src/compliance.ts";
import { provenReadFromJson } from "../src/verify.ts";

const fx = JSON.parse(readFileSync(new URL("./fixtures/selective.json", import.meta.url), "utf8"));
const ZERO = new Uint8Array(32);

describe("selective disclosure (v1 fixture)", () => {
  const d = fx.disclosure;
  const root = fromHex(d.storeRoot);

  it("verifies a genuine disclosure against the store root", () => {
    const disc = selectiveDisclosureFromJson(d);
    assert.ok(verifySelectiveDisclosure(disc, root));
    assert.deepEqual(
      disc.reveals.map((r) => r.index).sort(),
      [1, 3],
    );
  });

  it("does not leak the hidden fields", () => {
    const blob = JSON.stringify(d.reveals);
    for (const i of d.hiddenIndices) {
      assert.ok(!blob.includes(d.allFields[i]), `hidden field ${i} must not appear`);
    }
  });

  it("rejects a tampered revealed field", () => {
    const disc = selectiveDisclosureFromJson(d);
    disc.reveals[0].value = fromHex("deadbeef");
    assert.ok(!verifySelectiveDisclosure(disc, root));
  });

  it("rejects a field claimed at the wrong index", () => {
    const disc = selectiveDisclosureFromJson(d);
    disc.reveals[0].index = 2; // a hidden index, keeping index-1's path
    assert.ok(!verifySelectiveDisclosure(disc, root));
  });

  it("does not verify against the wrong root", () => {
    assert.ok(!verifySelectiveDisclosure(selectiveDisclosureFromJson(d), ZERO));
  });
});

describe("compliance gate (v1 fixture)", () => {
  const c = fx.compliance;
  const root = fromHex(c.storeRoot);
  const subject = fromHex(c.subject);
  const read = () => provenReadFromJson(c.read);
  const policy: CompliancePolicy = { attester: fromHex(c.attester), scheme: c.scheme };

  it("accepts a Verified, in-window flag from the trusted attester", () => {
    assert.ok(gate(policy, subject, read(), root, c.nowRound).ok);
  });

  it("refuses once the attestation has expired", () => {
    const r = gate(policy, subject, read(), root, c.expiredNowRound);
    assert.ok(!r.ok);
  });

  it("refuses a proof for a different attester's cell", () => {
    const r = gate({ attester: fromHex(c.otherAttester) }, subject, read(), root, c.nowRound);
    assert.ok(!r.ok);
  });

  it("refuses against the wrong store root", () => {
    assert.ok(!gate(policy, subject, read(), ZERO, c.nowRound).ok);
  });

  it("decodes the flag the same way Rust encodes it", () => {
    const f = decodeFlag(fromHex(c.flag));
    assert.ok(f);
    assert.equal(f.status, ComplianceStatus.Verified);
    assert.equal(f.scheme, c.scheme);
  });

  it("treats an absent flag as a hard refusal, not a pass", () => {
    assert.ok(!requireCompliant(null, 1).ok);
  });
});
