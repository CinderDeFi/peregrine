/**
 * Compliance checks — decide whether an account is KYC/AML-compliant using only
 * the store root and an attester you choose. Mirrors
 * `peregrine-data::compliance`.
 *
 * The **gate** is flag-based: it verifies a proven read of the compliance cell
 * against the store root, then reads the compact on-chain flag (status, scheme,
 * expiry). No signature is checked here — the attester's signature was verified
 * on-chain when the flag was materialized, so a verifier holding only the root
 * trusts the committed flag, not the gateway that delivered it.
 */
import { bytesEqual, concat, type Bytes } from "./hash.ts";
import { tableId } from "./client.ts";
import { verifyProvenRead, type ProvenRead } from "./verify.ts";

/**
 * KYC/AML verdict. Only `Verified` clears a gate. Values match the Rust codes.
 *
 * A `const` object rather than a TS `enum`: this package runs straight off `.ts`
 * source under Node's type-stripping, which cannot emit an enum's runtime table.
 */
export const ComplianceStatus = {
  Unverified: 0,
  Pending: 1,
  Verified: 2,
  Rejected: 3,
} as const;
export type ComplianceStatus = (typeof ComplianceStatus)[keyof typeof ComplianceStatus];

const STATUS_NAMES = ["Unverified", "Pending", "Verified", "Rejected"] as const;

/** Human-readable name for a status code. */
export function statusName(code: number): string {
  return STATUS_NAMES[code] ?? `status(${code})`;
}

/** The well-known compliance table id. */
export function complianceTable(): Bytes {
  return tableId("sys.compliance");
}

/** The cell address for a `(subject, attester)` pair: `subject ‖ attester`. */
export function cellKey(subject: Bytes, attester: Bytes): Bytes {
  return concat(subject, attester);
}

export interface Flag {
  status: ComplianceStatus;
  scheme: number;
  expiresRound: number;
}

/** Decode the 11-byte on-chain flag, or `null` if malformed. */
export function decodeFlag(bytes: Bytes): Flag | null {
  if (bytes.length !== 11) return null;
  if (bytes[0] > 3) return null;
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return {
    status: bytes[0] as Flag["status"],
    scheme: dv.getUint16(1, true),
    expiresRound: Number(dv.getBigUint64(3, true)),
  };
}

/** A compliance verdict — `ok`, or a legible reason it failed. */
export type ComplianceResult = { ok: true } | { ok: false; reason: string };

export interface CompliancePolicy {
  /** The attester whose say-so is trusted. */
  attester: Bytes;
  /** If set, the attestation must be under this scheme code. */
  scheme?: number;
}

/**
 * On-chain-style enforcement from the committed flag alone. `flag` is the value
 * at `sys.compliance[cellKey(subject, attester)]`, or `null` if absent — and
 * absence is a hard refusal, never a silent pass.
 */
export function requireCompliant(
  flag: Bytes | null,
  nowRound: number,
  scheme?: number,
): ComplianceResult {
  if (flag === null) return { ok: false, reason: "no attestation on record" };
  const f = decodeFlag(flag);
  if (!f) return { ok: false, reason: "malformed flag" };
  if (f.status !== ComplianceStatus.Verified) {
    return { ok: false, reason: `status is ${statusName(f.status)}, not Verified` };
  }
  if (nowRound > f.expiresRound) {
    return { ok: false, reason: `expired at round ${f.expiresRound}` };
  }
  if (scheme !== undefined && f.scheme !== scheme) {
    return { ok: false, reason: `required scheme ${scheme}, attestation is ${f.scheme}` };
  }
  return { ok: true };
}

/**
 * Off-chain enforcement: verify a proven read of the compliance cell against the
 * store root, confirm it is the right cell for `subject` under `policy.attester`,
 * and apply {@link requireCompliant} to its value. A verifier trusting only the
 * root (and its chosen attester) can decide compliance with this alone.
 */
export function gate(
  policy: CompliancePolicy,
  subject: Bytes,
  read: ProvenRead,
  storeRoot: Bytes,
  nowRound: number,
): ComplianceResult {
  if (!bytesEqual(read.table, complianceTable())) {
    return { ok: false, reason: "proof is not of the compliance table" };
  }
  if (!bytesEqual(read.key, cellKey(subject, policy.attester))) {
    return { ok: false, reason: "proof is not of this subject/attester cell" };
  }
  if (!verifyProvenRead(read, storeRoot)) {
    return { ok: false, reason: "proof does not verify against the store root" };
  }
  return requireCompliant(read.value, nowRound, policy.scheme);
}
