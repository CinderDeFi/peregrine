/**
 * Headless test of the explorer's non-DOM logic: the DemoTransport, driven
 * through the real PeregrineClient, verifying every catalog entry across every
 * committed snapshot — and proving that a tampered value is rejected.
 *
 * Run: node explorer/test-explorer.mjs
 */
import assert from "node:assert";
import { readFileSync } from "node:fs";
import {
  PeregrineClient,
  verifyProvenRead,
  provenReadFromJson,
  fromHex,
  toHex,
  verifySelectiveDisclosure,
  selectiveDisclosureFromJson,
  gate,
  decodeFlag,
  ComplianceStatus,
} from "./vendor/peregrine-sdk.js";
import { DemoTransport } from "./demo-transport.js";

const here = new URL(".", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1");
const data = JSON.parse(readFileSync(new URL("./demo-data.json", import.meta.url), "utf8"));

let checks = 0;
const ok = (cond, msg) => { assert.ok(cond, msg); checks++; };

// 1. Every snapshot's every read verifies against that snapshot's own root.
for (const snap of data.snapshots) {
  const root = fromHex(snap.storeRoot);
  ok(snap.reads.length > 0, `snapshot ${snap.treeVersion} has reads`);
  for (const r of snap.reads) {
    const read = provenReadFromJson(r);
    ok(verifyProvenRead(read, root), `real proof verifies (${snap.treeVersion} ${r.key.slice(0, 8)})`);
    // Against the *other* snapshot's root it must NOT verify.
    const other = data.snapshots.find((s) => s !== snap);
    if (other) ok(!verifyProvenRead(read, fromHex(other.storeRoot)), "proof refused against a foreign root");
  }
}

// 2. Drive it exactly as the page does: through the client + transport.
const transport = new DemoTransport(data, { advanceEvery: 1000 }); // pin snapshot 0
const client = new PeregrineClient(transport);
await client.ping();
const root = await client.storeRoot();
ok(toHex(root).length === 64, "storeRoot is 32 bytes");

for (const entry of data.catalog) {
  const read = await client.proveRead(entry.table, entry.key);
  if (entry.label.startsWith("absent:")) {
    ok(read === null, `absent key reads back null (${entry.label})`);
  } else {
    ok(read !== null, `present key resolves (${entry.label})`);
    ok(verifyProvenRead(read, root), `client-verified (${entry.label})`);
    // Tamper: flip the first value byte; verification MUST reject it.
    const bad = provenReadFromJson({
      table: toHex(read.table), key: toHex(read.key),
      value: (parseInt(toHex(read.value).slice(0, 2), 16) ^ 0xff).toString(16).padStart(2, "0") + toHex(read.value).slice(2),
      tableRoot: toHex(read.tableRoot), treeVersion: read.treeVersion,
      rowProof: { siblings: read.rowProof.siblings.map(toHex), ...(read.rowProof.otherLeaf ? { otherLeaf: { key: toHex(read.rowProof.otherLeaf.key), value: toHex(read.rowProof.otherLeaf.value) } } : {}) },
      storeProof: { leafIndex: read.storeProof.leafIndex, siblings: read.storeProof.siblings.map(toHex) },
    });
    ok(!verifyProvenRead(bad, root), `tampered value rejected (${entry.label})`);
  }
}

// 3. The head advances: with advanceEvery=2, root changes after 2 polls.
const t2 = new DemoTransport(data, { advanceEvery: 2 });
const c2 = new PeregrineClient(t2);
const r0 = toHex(await c2.storeRoot());
await c2.storeRoot();
const r2 = toHex(await c2.storeRoot());
ok(r0 !== r2, "the simulated head advances to a new committed root");

// 4. Selective disclosure + compliance embedded in the demo data verify for real.
if (data.disclosure) {
  const d = data.disclosure;
  const disc = selectiveDisclosureFromJson(d);
  ok(verifySelectiveDisclosure(disc, fromHex(d.storeRoot)), "demo disclosure verifies");
  ok(!verifySelectiveDisclosure(disc, new Uint8Array(32)), "disclosure refused vs wrong root");
  // hidden fields never appear in the reveal payload
  const blob = JSON.stringify(d.reveals);
  for (const i of d.hiddenIndices) ok(!blob.includes(d.allFields[i]), `hidden field ${i} not leaked`);
}
if (data.compliance) {
  const c = data.compliance;
  const read = provenReadFromJson(c.read);
  const root = fromHex(c.storeRoot);
  const policy = { attester: fromHex(c.attester), scheme: c.scheme };
  ok(gate(policy, fromHex(c.subject), read, root, c.nowRound).ok, "demo compliance gate passes");
  ok(!gate(policy, fromHex(c.subject), read, root, c.expiredNowRound).ok, "gate refuses when expired");
  ok(!gate({ attester: fromHex(c.otherAttester) }, fromHex(c.subject), read, root, c.nowRound).ok, "gate refuses wrong attester");
  ok(decodeFlag(read.value)?.status === ComplianceStatus.Verified, "flag decodes to Verified");
}

console.log(`explorer logic: ${checks} checks passed`);
void here;
