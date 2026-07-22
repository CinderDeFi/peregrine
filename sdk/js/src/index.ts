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

export {
  ACTION_DOMAIN,
  encodeAction,
  encodeGrant,
  GRANT_DOMAIN,
  id32FromHex,
  publicKeyOf,
  REVOKE_DOMAIN,
  SessionBuilder,
  SessionSigner,
  sessionId,
  signAction,
  signGrant,
  signRevocation,
  type Action,
  type Id32,
  type Scope,
  type SessionAction,
  type SessionGrant,
  type SignedAction,
  type SignedGrant,
} from "./sessions.ts";

export { BincodeWriter, encode as bincodeEncode } from "./bincode.ts";
