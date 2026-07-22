/**
 * Selective disclosure — verify one field (or a range) of a row while the rest
 * stays hidden, against the 32-byte store root.
 *
 * Mirrors `peregrine-data::disclosure`. A disclosable row stores a **Merkle root
 * over its fields** as its on-chain value; a disclosure carries an ordinary
 * proven read of that root plus a Merkle path per revealed field. This module
 * contains no new cryptography: it reuses the same `verifyMerkle` /
 * `verifyProvenRead` a light client already trusts.
 */
import { concat, fromHex, type Bytes } from "./hash.ts";
import {
  provenReadFromJson,
  verifyMerkle,
  verifyProvenRead,
  type MerkleProof,
  type ProvenRead,
  type ProvenReadJson,
} from "./verify.ts";

/** Domain tag for a field leaf — matches the Rust `FIELD_LEAF_DOMAIN`. */
const FIELD_LEAF_DOMAIN = new TextEncoder().encode("peregrine.disclosure.field.v1");

function u32le(n: number): Bytes {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, true);
  return b;
}

/** The bytes hashed into the field tree for `(index, arity, field)`. */
export function fieldLeafBytes(index: number, arity: number, value: Bytes): Bytes {
  return concat(FIELD_LEAF_DOMAIN, u32le(index), u32le(arity), value);
}

export interface FieldReveal {
  index: number;
  value: Bytes;
  proof: MerkleProof;
}

export interface SelectiveDisclosure {
  read: ProvenRead;
  arity: number;
  reveals: FieldReveal[];
}

/** JSON (hex) wire form, as produced by the Rust fixture generator / SDK. */
export interface SelectiveDisclosureJson {
  read: ProvenReadJson;
  arity: number;
  reveals: { index: number; value: string; proof: { leafIndex: number; siblings: string[] } }[];
}

export function selectiveDisclosureFromJson(j: SelectiveDisclosureJson): SelectiveDisclosure {
  return {
    read: provenReadFromJson(j.read),
    arity: j.arity,
    reveals: j.reveals.map((r) => ({
      index: r.index,
      value: fromHex(r.value),
      proof: { leafIndex: r.proof.leafIndex, siblings: r.proof.siblings.map(fromHex) },
    })),
  };
}

/**
 * Verify a selective disclosure against a trusted store root:
 *
 * 1. the field commitment (`read.value`, 32 bytes) is genuinely the committed
 *    value of the row; and
 * 2. every revealed field sits in that commitment at its claimed index, under
 *    the claimed arity.
 *
 * Reveals nothing about hidden fields, and cannot be made to accept a tampered
 * field, a wrong index, or a foreign root.
 */
export function verifySelectiveDisclosure(disc: SelectiveDisclosure, storeRoot: Bytes): boolean {
  // (1) the on-chain value must be a 32-byte field root, committed under root.
  if (disc.read.value === null || disc.read.value.length !== 32) return false;
  const fieldRoot = disc.read.value;
  if (!verifyProvenRead(disc.read, storeRoot)) return false;
  // (2) each revealed field is in that field root, index- and arity-bound.
  for (const r of disc.reveals) {
    if (r.proof.leafIndex !== r.index) return false;
    if (r.index >= disc.arity) return false;
    if (!verifyMerkle(fieldLeafBytes(r.index, disc.arity, r.value), r.proof, fieldRoot)) {
      return false;
    }
  }
  return true;
}
