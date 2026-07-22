/**
 * Oracle & verifiable data feeds — the consumer side, in TypeScript.
 *
 * A feed's latest value is committed table state, so reading it is an ordinary
 * proven read verified against the store root. This module decodes the
 * `sys.feed_latest` cell into a {@link FeedValue}, checks freshness, and (for a
 * JS publisher) encodes observations. Mirrors `peregrine-data::feeds`.
 */
import { type Bytes } from "./hash.ts";
import { tableId } from "./client.ts";
import { verifyProvenRead, type ProvenRead } from "./verify.ts";

const FEED_ENC_V1 = 1;

/** What a feed measures. Values match the Rust codes. */
export const FeedKind = { Price: 0, Rwa: 1, Generic: 2 } as const;
export type FeedKind = (typeof FeedKind)[keyof typeof FeedKind];
const KIND_NAMES = ["Price", "Rwa", "Generic"] as const;
export function feedKindName(k: number): string {
  return KIND_NAMES[k] ?? `kind(${k})`;
}

/** How multiple sources are combined. */
export const Aggregation = { Single: 0, Median: 1 } as const;
export type Aggregation = (typeof Aggregation)[keyof typeof Aggregation];

/** The `sys.feed_latest` table id. */
export function feedLatestTable(): Bytes {
  return tableId("sys.feed_latest");
}

export interface FeedValue {
  /** Fixed-point integer; the real value is `value * 10^-decimals`. */
  value: bigint;
  decimals: number;
  kind: FeedKind;
  aggregation: Aggregation;
  /** Number of fresh sources that contributed. */
  nSources: number;
  /** Committed round this value was last recomputed at. */
  updatedRound: bigint;
}

/** Decode a `sys.feed_latest` cell; `null` if malformed or an unknown version. */
export function decodeFeedValue(bytes: Bytes): FeedValue | null {
  if (bytes.length !== 21 || bytes[0] !== FEED_ENC_V1) return null;
  if (bytes[1] > 2 || bytes[3] > 1) return null;
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return {
    kind: bytes[1] as FeedKind,
    decimals: bytes[2],
    aggregation: bytes[3] as Aggregation,
    nSources: bytes[4],
    value: dv.getBigUint64(5, true),
    updatedRound: dv.getBigUint64(13, true),
  };
}

/**
 * Verify a proven read of a feed's latest cell against the store root and decode
 * it. Returns `null` if the proof does not verify or the cell is malformed — a
 * value only comes back if it is genuinely in committed state under `storeRoot`.
 */
export function readFeedValue(read: ProvenRead, storeRoot: Bytes): FeedValue | null {
  if (!verifyProvenRead(read, storeRoot)) return null;
  if (read.value === null) return null;
  return decodeFeedValue(read.value);
}

/** How many committed rounds old `fv` is at `now`. */
export function staleness(fv: FeedValue, now: bigint | number): bigint {
  const n = BigInt(now);
  return n > fv.updatedRound ? n - fv.updatedRound : 0n;
}

/** Whether `fv` is fresh enough at `now` for a `maxStaleness` bound. */
export function isFresh(fv: FeedValue, now: bigint | number, maxStaleness: bigint | number): boolean {
  return staleness(fv, now) <= BigInt(maxStaleness);
}

/** The value as a JS number, applying `decimals`. Display only — keep on-chain
 *  logic in the integer domain. */
export function feedValueAsNumber(fv: FeedValue): number {
  return Number(fv.value) / 10 ** fv.decimals;
}

// ── publishing (optional, for a JS data source) ──────────────────────────────

export interface FeedObservation {
  value: bigint;
  timestampNs: bigint;
}

/** Encode an observation for a stream record payload. */
export function encodeObservation(o: FeedObservation): Bytes {
  const b = new Uint8Array(17);
  b[0] = FEED_ENC_V1;
  const dv = new DataView(b.buffer);
  dv.setBigUint64(1, o.value, true);
  dv.setBigUint64(9, o.timestampNs, true);
  return b;
}

/** Decode an observation payload; `null` if malformed. */
export function decodeObservation(bytes: Bytes): FeedObservation | null {
  if (bytes.length !== 17 || bytes[0] !== FEED_ENC_V1) return null;
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return { value: dv.getBigUint64(1, true), timestampNs: dv.getBigUint64(9, true) };
}
