/**
 * Verify a Peregrine state proof in pure JavaScript.
 *
 * The proofs below were produced by the Rust node; nothing here trusts the
 * node that served them — only the 32-byte store root.
 *
 * Run: `npm run example`  (from sdk/js)
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { fromHex, readU64LE, toHex } from "../src/hash.ts";
import { provenReadFromJson, verifyProvenRead, type ProvenReadJson } from "../src/verify.ts";
import { tableId } from "../src/client.ts";

const here = dirname(fileURLToPath(import.meta.url));
const fixture = JSON.parse(
  readFileSync(join(here, "..", "test", "fixtures", "proven-read.json"), "utf8"),
) as { storeRoot: string; reads: ProvenReadJson[] };

const root = fromHex(fixture.storeRoot);
console.log(`trusted store root: ${fixture.storeRoot}\n`);

// Table ids are derived from their names, identically to the Rust SDK.
console.log(`tableId("contract.answers") = ${toHex(tableId("contract.answers"))}\n`);

for (const j of fixture.reads.slice(0, 3)) {
  const read = provenReadFromJson(j);
  const ok = verifyProvenRead(read, root);
  console.log(`key ${j.key.slice(0, 24)}…  value=${readU64LE(read.value)}  verified=${ok}`);
}

// Now forge one and watch it fail.
const forged = provenReadFromJson(fixture.reads[0]);
forged.value = fromHex("ffffffffffffffff");
console.log(`\nforged value verified = ${verifyProvenRead(forged, root)}  (must be false)`);

// And a genuine proof against the wrong root.
console.log(
  `genuine proof, wrong root = ${verifyProvenRead(
    provenReadFromJson(fixture.reads[0]),
    new Uint8Array(32),
  )}  (must be false)`,
);
