/**
 * The TypeScript client.
 *
 * ## Transport, honestly
 * Peregrine nodes speak **QUIC**. Browsers cannot open raw QUIC sockets, and
 * Node's QUIC support is still experimental, so this client does not pretend
 * to dial a validator directly. Instead it targets a small **JSON gateway**
 * that fronts a node's RPC endpoint, and the transport is an interface you can
 * swap:
 *
 * * {@link HttpTransport} — `POST` the JSON request shapes below to a gateway.
 * * your own — implement {@link Transport} over WebTransport, a websocket, a
 *   mock, or an in-process bridge.
 *
 * **The transport is not the trust boundary.** Whatever delivers the bytes,
 * {@link PeregrineClient.readVerified} re-verifies every value against the
 * store root locally, so a hostile gateway can withhold data but cannot forge
 * it. That check is the same arithmetic the Rust node does — see `verify.ts`.
 */
import { digest, fromHex, toHex, type Bytes } from "./hash.ts";
import {
  provenReadFromJson,
  verifyProvenRead,
  type ProvenRead,
  type ProvenReadJson,
} from "./verify.ts";

/** Derive a table id from its name — mirrors Rust `TableId::named`. */
export function tableId(name: string): Bytes {
  return digest(new TextEncoder().encode(name));
}

/** Requests, as JSON. Mirrors the Rust `RpcRequest`. */
export type RpcRequest =
  | { kind: "ping" }
  | { kind: "publish"; shred: unknown }
  | { kind: "submitTx"; program: unknown[] }
  | { kind: "proveRead"; table: string; key: string }
  | { kind: "storeRoot" };

/** Responses, as JSON. Mirrors the Rust `RpcResponse`. */
export type RpcResponse =
  | { kind: "pong" }
  | { kind: "accepted" }
  | { kind: "proof"; read: ProvenReadJson | null }
  | { kind: "root"; root: string }
  | { kind: "error"; message: string };

/** Pluggable request/response transport. */
export interface Transport {
  request(req: RpcRequest): Promise<RpcResponse>;
}

/** Error carrying a node-reported message. */
export class PeregrineError extends Error {}

/** Thrown when a served value fails local proof verification. */
export class ProofVerificationError extends PeregrineError {
  constructor(message = "proof failed to verify against the store root") {
    super(message);
  }
}

/** A `fetch`-based transport for a JSON gateway. */
export class HttpTransport implements Transport {
  // Native #private fields, not TS parameter properties: this package runs
  // straight off .ts source under Node's type stripping, which only removes
  // types and cannot emit the assignments a parameter property implies.
  readonly #url: string;
  readonly #fetch: typeof fetch;

  // The default MUST stay bound to `globalThis`. In a browser, `fetch` is a
  // method of `Window`; stored as a bare reference and later called as
  // `this.#fetch(...)`, it loses its `Window` receiver and throws
  // `TypeError: Failed to execute 'fetch' on 'Window': Illegal invocation`.
  // Binding at the default fixes every request path (preferred over a `.call`
  // at each call site). A caller-supplied `fetchImpl` is used as-is — it is the
  // caller's responsibility to pass something already callable, and re-binding
  // it here would defeat a deliberately-bound or wrapped implementation.
  constructor(
    url: string,
    fetchImpl: typeof fetch = globalThis.fetch.bind(globalThis),
  ) {
    this.#url = url;
    this.#fetch = fetchImpl;
  }

  async request(req: RpcRequest): Promise<RpcResponse> {
    const res = await this.#fetch(this.#url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(req),
    });
    if (!res.ok) throw new PeregrineError(`gateway HTTP ${res.status}`);
    return (await res.json()) as RpcResponse;
  }
}

function asHex(v: Bytes | string): string {
  return typeof v === "string" ? v : toHex(v);
}

/**
 * High-level client. Method names and semantics deliberately mirror the Rust
 * SDK so the two read the same.
 */
export class PeregrineClient {
  readonly #transport: Transport;

  constructor(transport: Transport) {
    this.#transport = transport;
  }

  /** Convenience constructor for a JSON gateway URL. */
  static http(url: string): PeregrineClient {
    return new PeregrineClient(new HttpTransport(url));
  }

  async #call(req: RpcRequest): Promise<RpcResponse> {
    const res = await this.#transport.request(req);
    if (res.kind === "error") throw new PeregrineError(res.message);
    return res;
  }

  /** Liveness check. */
  async ping(): Promise<void> {
    const res = await this.#call({ kind: "ping" });
    if (res.kind !== "pong") throw new PeregrineError("unexpected response to ping");
  }

  /** The node's current 32-byte store root. */
  async storeRoot(): Promise<Bytes> {
    const res = await this.#call({ kind: "storeRoot" });
    if (res.kind !== "root") throw new PeregrineError("unexpected response to storeRoot");
    return fromHex(res.root);
  }

  /** Publish a signed stream record (sign it with your publisher key). */
  async publish(shred: unknown): Promise<void> {
    const res = await this.#call({ kind: "publish", shred });
    if (res.kind !== "accepted") throw new PeregrineError("publish not accepted");
  }

  /** Submit a Talon program. */
  async submitTx(program: unknown[]): Promise<void> {
    const res = await this.#call({ kind: "submitTx", program });
    if (res.kind !== "accepted") throw new PeregrineError("tx not accepted");
  }

  /**
   * Fetch a value with its inclusion proof — **unverified**. Prefer
   * {@link readVerified} unless you are verifying against a root yourself.
   */
  async proveRead(table: Bytes | string, key: Bytes | string): Promise<ProvenRead | null> {
    const res = await this.#call({ kind: "proveRead", table: asHex(table), key: asHex(key) });
    if (res.kind !== "proof") throw new PeregrineError("unexpected response to proveRead");
    return res.read === null ? null : provenReadFromJson(res.read);
  }

  /**
   * Read a value and **verify it locally** against the store root, throwing
   * {@link ProofVerificationError} if it does not check out. This is the call
   * applications should use: it makes trusting the gateway impossible.
   *
   * Pass a `root` you already trust (from consensus or a checkpoint) to avoid
   * taking the node's word for the root as well.
   */
  async readVerified(
    table: Bytes | string,
    key: Bytes | string,
    root?: Bytes,
  ): Promise<{ value: Bytes; root: Bytes } | null> {
    const read = await this.proveRead(table, key);
    if (read === null) return null;
    const against = root ?? (await this.storeRoot());
    if (!verifyProvenRead(read, against)) throw new ProofVerificationError();
    return { value: read.value, root: against };
  }
}
