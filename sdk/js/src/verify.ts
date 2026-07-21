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
 *
 * ## Two tree versions
 *
 * Peregrine's row trees were path-compressed in the v2 upgrade. v2 commits the
 * **same rows to different roots**, so a proof declares which rule it follows
 * and this module dispatches on that tag. During a chain's migration both are
 * in flight simultaneously; a verifier that assumed one would silently
 * disagree with consensus. Only the per-table row trees changed — the
 * store-level binary Merkle tree is identical in both.
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
  SMT_V2_MAX_DEPTH,
  smtEmptyLeaf,
  smtLeafHash,
  smtV2Empty,
  smtV2LeafHash,
  smtV2Node,
  type Bytes,
} from "./hash.ts";

/** Which sparse-Merkle rule a proof follows. */
export type TreeVersion = "v1" | "v2";

/** Sparse-Merkle path for one key; siblings are leaf-adjacent first. */
export interface SmtProof {
  siblings: Bytes[];
  /**
   * v2 only, and only for non-inclusion where a *different* key occupies the
   * queried slot: that key and value, so the verifier can recompute the leaf
   * hash itself instead of trusting a supplied digest.
   */
  otherLeaf?: { key: Bytes; value: Bytes };
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
  /** `null` asserts **absence** rather than a value. */
  value: Bytes | null;
  tableRoot: Bytes;
  treeVersion: TreeVersion;
  rowProof: SmtProof;
  storeProof: MerkleProof;
}

// ── v1: dense 256-level tree ────────────────────────────────────────────────

/**
 * Climb a v1 sparse-Merkle path from a leaf to the implied table root.
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
 * Verify a v1 sparse-Merkle proof against `root`.
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

// ── v2: path-compressed tree ────────────────────────────────────────────────

/**
 * Climb a **v2** path from a starting hash at the proof's depth to a root.
 *
 * The proof's length *is* its depth: a v2 path stops at the first bit that
 * separates this key from everything else in the tree, so it is ~log2(n) deep
 * rather than a fixed 256.
 */
function smtV2Climb(key: Bytes, start: Bytes, proof: SmtProof): Bytes | null {
  if (proof.siblings.length > SMT_V2_MAX_DEPTH) return null;
  const pos = digest(key);
  const depth = proof.siblings.length;
  let acc = start;
  for (let k = 0; k < depth; k++) {
    // siblings[0] sits at depth-1, siblings[depth-1] at 0.
    const d = depth - 1 - k;
    const sib = proof.siblings[k];
    acc = bit(pos, d) === 0 ? smtV2Node(acc, sib) : smtV2Node(sib, acc);
  }
  return acc;
}

/** Do two positions agree on their first `n` bits? */
function sharesPrefix(a: Bytes, b: Bytes, n: number): boolean {
  for (let i = 0; i < n; i++) if (bit(a, i) !== bit(b, i)) return false;
  return true;
}

/**
 * Verify a **v2** sparse-Merkle proof against `root`.
 *
 * Non-inclusion has two shapes and both must be handled, or the proof is
 * worthless:
 *
 *  * the slot is empty — climb from the empty constant;
 *  * a *different* key occupies it — climb from that key's leaf hash.
 *
 * The second case is where a lax verifier breaks. Accepting any leaf would let
 * a prover deny membership of anything, so we require that the presented leaf
 * is a **different** key *and* that its position really does share the queried
 * key's path for the full proof depth.
 */
export function verifySmtV2(
  key: Bytes,
  value: Bytes | null,
  proof: SmtProof,
  root: Bytes,
): boolean {
  let start: Bytes;
  if (value !== null) {
    // Inclusion. A proof carrying `otherLeaf` is malformed here — refuse it
    // rather than ignore a field whose presence we cannot account for.
    if (proof.otherLeaf) return false;
    start = smtV2LeafHash(key, value);
  } else if (!proof.otherLeaf) {
    start = smtV2Empty();
  } else {
    const { key: otherKey, value: otherValue } = proof.otherLeaf;
    if (bytesEqual(otherKey, key)) return false; // no key proves its own absence
    if (!sharesPrefix(digest(key), digest(otherKey), proof.siblings.length)) return false;
    start = smtV2LeafHash(otherKey, otherValue);
  }
  const implied = smtV2Climb(key, start, proof);
  return implied !== null && bytesEqual(implied, root);
}

/**
 * Verify a row proof under whichever rule it declares.
 *
 * Unknown versions are **refused**, never guessed at: a verifier that fell back
 * to a default would quietly disagree with the chain the first time the rules
 * moved on without it.
 */
export function verifyRowProof(
  version: TreeVersion,
  key: Bytes,
  value: Bytes | null,
  proof: SmtProof,
  root: Bytes,
): boolean {
  if (version === "v1") return verifySmt(key, value, proof, root);
  if (version === "v2") return verifySmtV2(key, value, proof, root);
  return false;
}

// ── store-level binary Merkle (unchanged by the v2 upgrade) ─────────────────

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
  // 1. the row sits in its table, under the rule the proof declares
  if (!verifyRowProof(read.treeVersion, read.key, read.value, read.rowProof, read.tableRoot)) {
    return false;
  }
  // 2. the table (at that root) sits in the store
  return verifyMerkle(storeLeafBytes(read.table, read.tableRoot), read.storeProof, storeRoot);
}

// ── JSON decoding (hex wire form) ───────────────────────────────────────────

/** A `ProvenRead` as delivered over the wire / in fixtures: hex strings. */
export interface ProvenReadJson {
  table: string;
  key: string;
  /** Absent or null for a non-inclusion proof. */
  value?: string | null;
  tableRoot: string;
  /** Defaults to `"v1"` for fixtures produced before versioning existed. */
  treeVersion?: string;
  rowProof: {
    siblings: string[];
    otherLeaf?: { key: string; value: string } | null;
  };
  storeProof: { leafIndex: number; siblings: string[] };
}

/**
 * Parse a declared tree version, rejecting anything unrecognised.
 *
 * Throwing is deliberate. A silent fallback to v1 would make a future v3 proof
 * verify under the wrong rule — the exact failure the version tag exists to
 * prevent.
 */
export function parseTreeVersion(s: string | undefined): TreeVersion {
  if (s === undefined || s === "v1") return "v1";
  if (s === "v2") return "v2";
  throw new Error(
    `unsupported Merkle tree version ${JSON.stringify(s)} — this verifier ` +
      `understands v1 and v2. Refusing rather than guessing: verifying under ` +
      `the wrong rule would disagree with the chain.`,
  );
}

/** Decode the hex wire form into byte arrays ready for verification. */
export function provenReadFromJson(j: ProvenReadJson): ProvenRead {
  const other = j.rowProof.otherLeaf;
  return {
    table: fromHex(j.table),
    key: fromHex(j.key),
    value: j.value === undefined || j.value === null ? null : fromHex(j.value),
    tableRoot: fromHex(j.tableRoot),
    treeVersion: parseTreeVersion(j.treeVersion),
    rowProof: {
      siblings: j.rowProof.siblings.map(fromHex),
      ...(other ? { otherLeaf: { key: fromHex(other.key), value: fromHex(other.value) } } : {}),
    },
    storeProof: {
      leafIndex: j.storeProof.leafIndex,
      siblings: j.storeProof.siblings.map(fromHex),
    },
  };
}
