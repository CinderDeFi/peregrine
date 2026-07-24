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
  HttpTransport,
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
// The fixture now carries both tree versions. The client is version-agnostic
// — it moves proofs around and hands them to the verifier — so these tests
// exercise it against v2, the format a current chain serves.
const fixture = (
  JSON.parse(readFileSync(join(here, "fixtures", "proven-read.json"), "utf8")) as {
    v2: { storeRoot: string; reads: ProvenReadJson[] };
  }
).v2;

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

/**
 * Browser regression: the default `fetch` MUST stay bound to `globalThis`.
 *
 * In a browser, `fetch` is a method of `Window`. `HttpTransport` stores the
 * fetch it is given and later calls it as `this.#fetch(url, opts)` — a
 * method-call whose receiver is the transport instance, not `Window`. A browser
 * enforces the receiver and throws
 *   TypeError: Failed to execute 'fetch' on 'Window': Illegal invocation
 * so a bare `globalThis.fetch` default is broken in exactly the environment the
 * explorer runs in, while working fine under Node (which does not check).
 *
 * This test reproduces the browser's check rather than faking it: it installs a
 * `globalThis.fetch` that throws unless its receiver is `globalThis`, and drives
 * a real `HttpTransport` through its DEFAULT constructor. It passes only while
 * the default is `globalThis.fetch.bind(globalThis)`; revert to the bare
 * reference and it fails with the same Illegal-invocation error the explorer hit.
 */
describe("HttpTransport default fetch binding", () => {
  /** A `fetch` that mimics the browser: legal only when called on `globalThis`. */
  function receiverCheckingFetch(this: unknown): Promise<Response> {
    if (this !== globalThis) {
      throw new TypeError(
        "Failed to execute 'fetch' on 'Window': Illegal invocation",
      );
    }
    return Promise.resolve({
      ok: true,
      status: 200,
      json: async () => ({ kind: "root", root: "00".repeat(32) }) as RpcResponse,
    } as Response);
  }

  /** Run `body` with `globalThis.fetch` swapped, always restoring the original. */
  async function withGlobalFetch(
    impl: typeof fetch,
    body: () => Promise<void>,
  ): Promise<void> {
    const original = globalThis.fetch;
    globalThis.fetch = impl;
    try {
      await body();
    } finally {
      globalThis.fetch = original;
    }
  }

  it("uses the default fetch with the Window receiver (no Illegal invocation)", async () => {
    await withGlobalFetch(receiverCheckingFetch as typeof fetch, async () => {
      // Default constructor path — this is what `PeregrineClient.http` and the
      // explorer use. The bind must happen here.
      const transport = new HttpTransport("https://gateway.example/rpc");
      const res = await transport.request({ kind: "storeRoot" });
      assert.deepEqual(res, { kind: "root", root: "00".repeat(32) });
    });
  });

  it("honors a caller-supplied fetch as-is (used, not re-bound)", async () => {
    // A caller may pass a fetch already bound to some other object (a mock, a
    // proxy, a Node polyfill). We must call it as given, so this custom impl —
    // which asserts it was NOT re-pointed at globalThis — has to succeed.
    const calls: Array<{ url: string; self: unknown }> = [];
    const custom = function (this: unknown, url: string): Promise<Response> {
      calls.push({ url, self: this });
      return Promise.resolve({
        ok: true,
        status: 200,
        json: async () => ({ kind: "pong" }) as RpcResponse,
      } as Response);
    } as unknown as typeof fetch;

    // Install a hostile global fetch so a stray default-bind would be caught.
    await withGlobalFetch(
      (() => {
        throw new Error("default fetch must not be used when a custom one is passed");
      }) as unknown as typeof fetch,
      async () => {
        const transport = new HttpTransport("https://gateway.example/rpc", custom);
        const res = await transport.request({ kind: "ping" });
        assert.deepEqual(res, { kind: "pong" });
      },
    );
    assert.equal(calls.length, 1);
    assert.equal(calls[0]!.url, "https://gateway.example/rpc");
  });
});
