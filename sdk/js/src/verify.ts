/**
 * Light-client proof verification, in pure TypeScript.
 *
 * This is the part of the SDK that matters most: it lets a browser or edge
 * runtime confirm a value really is in Peregrine's committed state **without
 * trusting the node that served it**. The only input that must be obtained
 * honestly is the 32-byte store root.
 *
 * A `ProvenRead` chains two proofs:
 *
 *   1. a **sparse-Merkle** path proving `(key, value)` sits in its table, under
 *      that table's root — the same path proves *absence* when `value` is null;
 *   2. a **binary-Merkle** path proving `(table, tableRoot)` is in the store,
 *      under the store root.
 *
 * Verify both and the value is as authoritative as the root you started with.
 */
import {
  bit,
  bytesEqual,
  combine,
  concat,
  digest,
  fromHex,
  merkleLeafHash,
  SMT_DEPTH,
  smtEmptyLeaf,
  smtLeafHash,
  type Bytes,
} from "./hash.ts";

/** Sparse-Merkle path for one key; siblings are leaf-adjacent first. */
export interface SmtProof {
  siblings: Bytes[];
}

/** Binary-Merkle inclusion path for one store leaf. */
export interface MerkleProof {
  leafIndex: number;
  siblings: Bytes[];
}

/** A verifiable point read, mirroring the Rust `ProvenRead`. */
export interface ProvenRead {
  table: Bytes;
  key: Bytes;
  value: Bytes;
  tableRoot: Bytes;
  rowProof: SmtProof;
  storeProof: MerkleProof;
}

/**
 * Climb a sparse-Merkle path from a leaf to the implied table root.
 * Returns null if the path isn't exactly `SMT_DEPTH` siblings.
 */
function smtClimb(key: Bytes, leaf: Bytes, proof: SmtProof): Bytes | null {
  if (proof.siblings.length !== SMT_DEPTH) return null;
  const pos = digest(key); // the key's fixed slot = blake3(key)
  let acc = leaf;
  // siblings[0] sits at depth DEPTH-1, ... siblings[DEPTH-1] at depth 0.
  for (let k = 0; k < proof.siblings.length; k++) {
    const depth = SMT_DEPTH - 1 - k;
    const sib = proof.siblings[k];
    acc = bit(pos, depth) === 0 ? combine(acc, sib) : combine(sib, acc);
  }
  return acc;
}

/**
 * Verify a sparse-Merkle proof against `root`.
 * Pass `value` to check **inclusion**, or `null` to check **absence**.
 */
export function verifySmt(
  key: Bytes,
  value: Bytes | null,
  proof: SmtProof,
  root: Bytes,
): boolean {
  const leaf = value === null ? smtEmptyLeaf() : smtLeafHash(key, value);
  const implied = smtClimb(key, leaf, proof);
  return implied !== null && bytesEqual(implied, root);
}

/** Recompute the binary-Merkle root implied by `leafBytes` under `proof`. */
function merkleImpliedRoot(leafBytes: Bytes, proof: MerkleProof): Bytes {
  let acc = merkleLeafHash(leafBytes);
  let index = proof.leafIndex;
  for (const sib of proof.siblings) {
    acc = index % 2 === 0 ? combine(acc, sib) : combine(sib, acc);
    index = Math.floor(index / 2);
  }
  return acc;
}

/** Verify a binary-Merkle inclusion proof of `leafBytes` under `root`. */
export function verifyMerkle(leafBytes: Bytes, proof: MerkleProof, root: Bytes): boolean {
  return bytesEqual(merkleImpliedRoot(leafBytes, proof), root);
}

/** The store's leaf encoding for a table: `tableId || tableRoot`. */
function storeLeafBytes(table: Bytes, tableRoot: Bytes): Bytes {
  return concat(table, tableRoot);
}

/**
 * Verify a proven read against a trusted 32-byte store root.
 *
 * This is the entire trust surface of a Peregrine light client for point
 * reads: if this returns true, the value is in committed state under `root`.
 */
export function verifyProvenRead(read: ProvenRead, storeRoot: Bytes): boolean {
  // 1. the row sits in its table
  if (!verifySmt(read.key, read.value, read.rowProof, read.tableRoot)) return false;
  // 2. the table (at that root) sits in the store
  return verifyMerkle(storeLeafBytes(read.table, read.tableRoot), read.storeProof, storeRoot);
}

// ── JSON decoding (hex wire form) ───────────────────────────────────────────

/** A `ProvenRead` as delivered over the wire / in fixtures: hex strings. */
export interface ProvenReadJson {
  table: string;
  key: string;
  value: string;
  tableRoot: string;
  rowProof: { siblings: string[] };
  storeProof: { leafIndex: number; siblings: string[] };
}

/** Decode the hex wire form into byte arrays ready for verification. */
export function provenReadFromJson(j: ProvenReadJson): ProvenRead {
  return {
    table: fromHex(j.table),
    key: fromHex(j.key),
    value: fromHex(j.value),
    tableRoot: fromHex(j.tableRoot),
    rowProof: { siblings: j.rowProof.siblings.map(fromHex) },
    storeProof: {
      leafIndex: j.storeProof.leafIndex,
      siblings: j.storeProof.siblings.map(fromHex),
    },
  };
}
