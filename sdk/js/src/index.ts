/**
 * @peregrine/sdk — TypeScript client and light-client proof verifier.
 *
 * ```ts
 * import { PeregrineClient, tableId } from "@peregrine/sdk";
 *
 * const client = PeregrineClient.http("http://localhost:8080/rpc");
 * // Reads are verified locally against the store root — a hostile gateway
 * // can withhold data, but it cannot forge it.
 * const row = await client.readVerified(tableId("contract.answers"), "73756d");
 * ```
 */
export {
  HttpTransport,
  PeregrineClient,
  PeregrineError,
  ProofVerificationError,
  tableId,
  type RpcRequest,
  type RpcResponse,
  type Transport,
} from "./client.ts";

export {
  provenReadFromJson,
  verifyMerkle,
  verifyProvenRead,
  verifySmt,
  type MerkleProof,
  type ProvenRead,
  type ProvenReadJson,
  type SmtProof,
} from "./verify.ts";

export {
  bytesEqual,
  combine,
  digest,
  fromHex,
  readU64LE,
  SMT_DEPTH,
  toHex,
  type Bytes,
} from "./hash.ts";
