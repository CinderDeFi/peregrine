/**
 * Just enough **bincode** to sign Peregrine messages from TypeScript.
 *
 * Session grants and actions are signed over their `bincode` encoding. A
 * signature is only valid if the bytes underneath it match what Rust would
 * produce, and the failure mode is nasty: a wrong length prefix yields a
 * perfectly well-formed signature that every validator rejects, with no
 * indication of *why*. So this file is deliberately small, explicit, and
 * checked against Rust-generated fixtures byte-for-byte in
 * `test/sessions.test.ts`.
 *
 * ## The encoding rules that matter here
 *
 * These are bincode 1.3 with its **default** configuration, which is what
 * `bincode::serialize` uses:
 *
 * | Rust type | bytes |
 * |---|---|
 * | `u32`, `u64` | fixed width, **little-endian** (not varint) |
 * | `[u8; 32]` | 32 raw bytes, **no** length prefix |
 * | `Vec<T>` | `u64` LE length, then each element |
 * | `struct` | fields in declaration order, no tags, no padding |
 * | `enum` | `u32` LE variant index, then the variant's fields |
 *
 * Two of those are the usual mistakes: arrays are *not* length-prefixed while
 * vectors are, and the enum tag is `u32` rather than a single byte.
 *
 * This is not a general bincode implementation and should not become one —
 * it covers exactly the shapes Peregrine signs.
 */
import type { Bytes } from "./hash.ts";

/** Accumulates bytes; every writer appends in Rust field order. */
export class BincodeWriter {
  #parts: Bytes[] = [];
  #len = 0;

  /** Raw bytes, with no length prefix — for `[u8; N]` fields. */
  fixedBytes(b: Bytes): this {
    this.#parts.push(b);
    this.#len += b.length;
    return this;
  }

  /** A `[u8; 32]`: hashes, public keys, table and stream ids. */
  hash32(b: Bytes): this {
    if (b.length !== 32) {
      throw new Error(`expected 32 bytes, got ${b.length}`);
    }
    return this.fixedBytes(b);
  }

  u32(n: number): this {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, n, true);
    return this.fixedBytes(b);
  }

  /**
   * A `u64`, little-endian. Takes `bigint | number` because JS numbers lose
   * precision above 2^53 and budgets are `u64` on the Rust side — passing a
   * plain number is fine for realistic values and safe because `BigInt()`
   * rejects a non-integer.
   */
  u64(n: bigint | number): this {
    const b = new Uint8Array(8);
    new DataView(b.buffer).setBigUint64(0, BigInt(n), true);
    return this.fixedBytes(b);
  }

  /** A `Vec<T>`: `u64` LE length, then each element via `write`. */
  vec<T>(items: readonly T[], write: (w: BincodeWriter, item: T) => void): this {
    this.u64(items.length);
    for (const item of items) write(this, item);
    return this;
  }

  /** A `Vec<u8>`: length prefix then the raw bytes. */
  byteVec(b: Bytes): this {
    return this.u64(b.length).fixedBytes(b);
  }

  /** An enum variant tag. `u32`, not a byte. */
  variant(index: number): this {
    return this.u32(index);
  }

  finish(): Bytes {
    const out = new Uint8Array(this.#len);
    let off = 0;
    for (const p of this.#parts) {
      out.set(p, off);
      off += p.length;
    }
    return out;
  }
}

/** Convenience: build and finish in one expression. */
export function encode(write: (w: BincodeWriter) => void): Bytes {
  const w = new BincodeWriter();
  write(w);
  return w.finish();
}

/**
 * The mirror of {@link BincodeWriter}: reads Rust's bincode back. Used to decode
 * committed `SessionState` so an agent can read its own remaining budget. Same
 * encoding rules as the writer; throws if it runs off the end of the buffer.
 */
export class BincodeReader {
  #view: DataView;
  #bytes: Bytes;
  #off = 0;

  constructor(bytes: Bytes) {
    this.#bytes = bytes;
    this.#view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }

  #need(n: number): void {
    if (this.#off + n > this.#bytes.length) throw new Error("bincode: unexpected end of input");
  }

  /** `n` raw bytes (a `[u8; N]` field). */
  fixedBytes(n: number): Bytes {
    this.#need(n);
    const out = this.#bytes.subarray(this.#off, this.#off + n);
    this.#off += n;
    return out;
  }

  hash32(): Bytes {
    return this.fixedBytes(32);
  }

  u32(): number {
    this.#need(4);
    const v = this.#view.getUint32(this.#off, true);
    this.#off += 4;
    return v;
  }

  u64(): bigint {
    this.#need(8);
    const v = this.#view.getBigUint64(this.#off, true);
    this.#off += 8;
    return v;
  }

  bool(): boolean {
    this.#need(1);
    const b = this.#view.getUint8(this.#off);
    this.#off += 1;
    return b !== 0;
  }

  /** A `Vec<T>`: `u64` length, then each element via `read`. */
  vec<T>(read: (r: BincodeReader) => T): T[] {
    const n = Number(this.u64());
    const out: T[] = new Array(n);
    for (let i = 0; i < n; i++) out[i] = read(this);
    return out;
  }

  /** A `Vec<u8>`. */
  byteVec(): Bytes {
    return this.fixedBytes(Number(this.u64()));
  }

  /** An enum variant tag (`u32`). */
  variant(): number {
    return this.u32();
  }

  /** Bytes left unread — should be 0 after decoding a whole value. */
  remaining(): number {
    return this.#bytes.length - this.#off;
  }
}
