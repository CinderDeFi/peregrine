/**
 * Client behaviour, driven through a stub transport.
 *
 * The point of these tests is the security property: `readVerified` must
 * *refuse* anything that doesn't reconstruct the trusted root, even though the
 * "node" on the other end is telling it the value is fine.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { fromHex, readU64LE, toHex } from "../src/hash.ts";
import {
  PeregrineClient,
  PeregrineError,
  ProofVerificationError,
  tableId,
  type RpcRequest,
  type RpcResponse,
  type Transport,
} from "../src/client.ts";
import type { ProvenReadJson } from "../src/verify.ts";

const here = dirname(fileURLToPath(import.meta.url));
const fixture = JSON.parse(
  readFileSync(join(here, "fixtures", "proven-read.json"), "utf8"),
) as { storeRoot: string; reads: ProvenReadJson[] };

/** A transport that replays canned responses and records what it was asked. */
class StubTransport implements Transport {
  seen: RpcRequest[] = [];
  // Explicit field, not a TS parameter property (unsupported by Node's
  // strip-only TypeScript mode, which never emits code).
  readonly #handler: (req: RpcRequest) => RpcResponse;

  constructor(handler: (req: RpcRequest) => RpcResponse) {
    this.#handler = handler;
  }

  async request(req: RpcRequest): Promise<RpcResponse> {
    this.seen.push(req);
    return this.#handler(req);
  }
}

const sumRead = fixture.reads.find(
  (r) => r.key === toHex(new TextEncoder().encode("sum")),
)!;

function serving(read: ProvenReadJson | null): StubTransport {
  return new StubTransport((req) => {
    switch (req.kind) {
      case "ping":
        return { kind: "pong" };
      case "storeRoot":
        return { kind: "root", root: fixture.storeRoot };
      case "proveRead":
        return { kind: "proof", read };
      default:
        return { kind: "accepted" };
    }
  });
}

describe("PeregrineClient", () => {
  it("derives table ids exactly like the Rust TableId::named", () => {
    // The fixture's tables were created by name on the Rust side.
    const names = ["contract.answers", "sys.stream_ticks"];
    const fixtureTables = new Set(fixture.reads.map((r) => r.table));
    for (const n of names) {
      assert.ok(fixtureTables.has(toHex(tableId(n))), `table id for ${n} should match Rust`);
    }
  });

  it("pings and reads the store root", async () => {
    const client = new PeregrineClient(serving(sumRead));
    await client.ping();
    assert.equal(toHex(await client.storeRoot()), fixture.storeRoot);
  });

  it("returns a verified value when the proof is genuine", async () => {
    const client = new PeregrineClient(serving(sumRead));
    const got = await client.readVerified(tableId("contract.answers"), sumRead.key);
    assert.ok(got);
    assert.equal(readU64LE(got!.value), 55n);
  });

  it("refuses a forged value even though the node claims it is fine", async () => {
    const forged = { ...sumRead, value: toHex(new TextEncoder().encode("beefbeef")) };
    const client = new PeregrineClient(serving(forged));
    await assert.rejects(
      () => client.readVerified(tableId("contract.answers"), sumRead.key),
      ProofVerificationError,
    );
  });

  it("refuses a genuine proof when verified against a different root", async () => {
    const client = new PeregrineClient(serving(sumRead));
    await assert.rejects(
      () => client.readVerified(tableId("contract.answers"), sumRead.key, new Uint8Array(32)),
      ProofVerificationError,
    );
  });

  it("returns null for an absent key", async () => {
    const client = new PeregrineClient(serving(null));
    assert.equal(await client.readVerified(tableId("contract.answers"), "00"), null);
  });

  it("surfaces node-reported errors", async () => {
    const client = new PeregrineClient(
      new StubTransport(() => ({ kind: "error", message: "validator stopped" })),
    );
    await assert.rejects(() => client.ping(), PeregrineError);
  });

  it("sends hex-encoded table and key", async () => {
    const stub = serving(sumRead);
    const client = new PeregrineClient(stub);
    await client.proveRead(tableId("contract.answers"), fromHex(sumRead.key));
    const req = stub.seen.at(-1)!;
    assert.equal(req.kind, "proveRead");
    assert.equal((req as { table: string }).table, toHex(tableId("contract.answers")));
  });
});
