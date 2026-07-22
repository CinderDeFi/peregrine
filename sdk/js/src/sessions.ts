/**
 * Session keys and micropayments, from TypeScript.
 *
 * An autonomous agent needs to act continuously without holding a key that can
 * drain its owner. A **session grant** is a bounded delegation: the principal
 * signs it once, and Peregrine's consensus — not the agent's good behaviour —
 * enforces every bound.
 *
 * ```ts
 * const grant = new SessionBuilder(expiresAtRound)   // a round, not a clock
 *   .allowTable(tableId("agent.notes"))              // everything starts closed
 *   .allowStream(streamId)
 *   .budget(50n)                                     // total it may ever spend
 *   .maxPerAction(5n)                                // and never this at once
 *   .sign(principalSecretKey);
 *
 * await client.openSession(grant);
 * ```
 *
 * ## Expiry is a round number, not a timestamp
 *
 * `expiresAtRound` is a consensus round, not a clock reading. Every validator
 * agrees on the committed round; none agree on the time. A wall-clock TTL would
 * expire a session at a different point in the committed order on each node and
 * fork the chain, so there is deliberately no "expires in 10 minutes" helper —
 * read the current round from the chain and add to it.
 *
 * ## Why the encoding is tested so hard
 *
 * Signatures cover the **bincode** encoding of the grant. If TypeScript encodes
 * one length prefix differently from Rust, it produces a valid-looking
 * signature that every validator rejects, with nothing in the error to say why.
 * `test/sessions.test.ts` therefore checks the bytes *and* the resulting
 * signatures against Rust-generated fixtures. ed25519 is deterministic, so a
 * matching signature proves the encoding beneath it is right.
 */
import { ed25519 } from "@noble/curves/ed25519.js";
import { blake3 } from "@noble/hashes/blake3";
import { encode, BincodeWriter } from "./bincode.ts";
import { concat, fromHex, type Bytes } from "./hash.ts";

const enc = new TextEncoder();

/** Domain tags — mirrors of the Rust constants. A grant signature must never
 *  be mistakable for an action signature, or a principal signing one could be
 *  tricked into having signed the other. */
export const GRANT_DOMAIN = enc.encode("peregrine.session.grant.v1");
export const ACTION_DOMAIN = enc.encode("peregrine.session.action.v1");
export const REVOKE_DOMAIN = enc.encode("peregrine.session.revoke.v1");

/** A 32-byte table or stream identifier. */
export type Id32 = Bytes;

// `tableId(name)` lives in `client.ts` — one definition, so the two cannot
// drift apart into subtly different ids.

/** What a session key may do. An allow-list: everything starts denied. */
export interface Scope {
  tables: Id32[];
  streams: Id32[];
  maxSpendPerAction: bigint;
}

export interface SessionGrant {
  principal: Bytes;
  sessionKey: Bytes;
  scope: Scope;
  budgetGrains: bigint;
  expiresAtRound: bigint;
  grantNonce: bigint;
}

/** Encode a grant exactly as Rust's `SessionGrant::signing_bytes()` does. */
export function encodeGrant(g: SessionGrant): Bytes {
  return encode((w) => {
    w.hash32(g.principal);
    w.hash32(g.sessionKey);
    // `Scope` is a plain struct field: inlined here, no tag, in its own
    // declaration order (tables, streams, maxSpendPerAction).
    w.vec(g.scope.tables, (ww, t) => ww.hash32(t));
    w.vec(g.scope.streams, (ww, s) => ww.hash32(s));
    w.u64(g.scope.maxSpendPerAction);
    w.u64(g.budgetGrains);
    w.u64(g.expiresAtRound);
    w.u64(g.grantNonce);
  });
}

/** A grant's content-addressed id: `blake3(signing_bytes)`. */
export function sessionId(g: SessionGrant): Bytes {
  return blake3(encodeGrant(g));
}

export interface SignedGrant {
  grant: SessionGrant;
  signature: Bytes;
}

/** What a session key is asking to do. Variant order matches the Rust enum. */
export type Action =
  | { kind: "write"; table: Id32; key: Bytes; value: Bytes }
  | { kind: "pay"; payee: Bytes; amount: bigint }
  | { kind: "subscribe"; stream: Id32; pricePerRecord: bigint }
  | { kind: "unsubscribe"; stream: Id32 };

/** Variant indices, fixed by the Rust `Action` enum's declaration order.
 *  Reordering the Rust enum is a wire-breaking change and would break this. */
const ACTION_VARIANT: Record<Action["kind"], number> = {
  write: 0,
  pay: 1,
  subscribe: 2,
  unsubscribe: 3,
};

function writeAction(w: BincodeWriter, a: Action): void {
  w.variant(ACTION_VARIANT[a.kind]);
  switch (a.kind) {
    case "write":
      w.hash32(a.table).byteVec(a.key).byteVec(a.value);
      break;
    case "pay":
      w.hash32(a.payee).u64(a.amount);
      break;
    case "subscribe":
      w.hash32(a.stream).u64(a.pricePerRecord);
      break;
    case "unsubscribe":
      w.hash32(a.stream);
      break;
  }
}

export interface SessionAction {
  sessionId: Bytes;
  nonce: bigint;
  action: Action;
}

/** Encode an action exactly as Rust's `SessionAction::signing_bytes()` does. */
export function encodeAction(a: SessionAction): Bytes {
  return encode((w) => {
    w.hash32(a.sessionId);
    w.u64(a.nonce);
    writeAction(w, a.action);
  });
}

export interface SignedAction {
  action: SessionAction;
  signature: Bytes;
}

// ── signing ─────────────────────────────────────────────────────────────────

/**
 * Sign `domain || message` with an ed25519 secret key (32-byte seed).
 *
 * The domain prefix is part of the signed bytes, exactly as in
 * `Keypair::sign`. Signing the message alone would let a signature be replayed
 * in another context.
 */
function signDomained(secretKey: Bytes, domain: Bytes, message: Bytes): Bytes {
  return ed25519.sign(concat(domain, message), secretKey);
}

/** The public key for a 32-byte secret seed. */
export function publicKeyOf(secretKey: Bytes): Bytes {
  return ed25519.getPublicKey(secretKey);
}

/** Sign a grant as the principal. */
export function signGrant(principalSecret: Bytes, grant: SessionGrant): SignedGrant {
  return {
    grant,
    signature: signDomained(principalSecret, GRANT_DOMAIN, encodeGrant(grant)),
  };
}

/** Sign an action as the session key. */
export function signAction(sessionSecret: Bytes, action: SessionAction): SignedAction {
  return {
    action,
    signature: signDomained(sessionSecret, ACTION_DOMAIN, encodeAction(action)),
  };
}

/**
 * Sign a revocation as the **principal**.
 *
 * Only the principal may revoke. A session key that could revoke itself could
 * also interfere with its own revocation, which would make revocation
 * advisory rather than final.
 */
export function signRevocation(principalSecret: Bytes, id: Bytes): Bytes {
  return signDomained(principalSecret, REVOKE_DOMAIN, id);
}

// ── ergonomics ──────────────────────────────────────────────────────────────

/**
 * Fluent grant construction.
 *
 * Every restriction starts at its **most restrictive** value — no tables, no
 * streams, no spend. Forgetting a builder call can only ever produce a session
 * that does *less* than intended, never more. An API where the unsafe thing is
 * the short thing is an API that produces unsafe sessions.
 */
export class SessionBuilder {
  #scope: Scope = { tables: [], streams: [], maxSpendPerAction: 0n };
  #budget = 0n;
  #expiresAtRound: bigint;
  #grantNonce = 0n;

  /**
   * @param expiresAtRound consensus round after which the session is dead.
   *   Mandatory: a session with no deadline is a permanent key, which is the
   *   thing this whole mechanism exists to avoid.
   */
  constructor(expiresAtRound: bigint | number) {
    this.#expiresAtRound = BigInt(expiresAtRound);
  }

  allowTable(table: Id32): this {
    this.#scope.tables.push(table);
    return this;
  }

  allowStream(stream: Id32): this {
    this.#scope.streams.push(stream);
    return this;
  }

  /** Total spend across the session's whole life. */
  budget(grains: bigint | number): this {
    this.#budget = BigInt(grains);
    return this;
  }

  /** Ceiling on any single payment or subscription price. */
  maxPerAction(grains: bigint | number): this {
    this.#scope.maxSpendPerAction = BigInt(grains);
    return this;
  }

  /** Distinguish this grant from an identical earlier one. */
  nonce(n: bigint | number): this {
    this.#grantNonce = BigInt(n);
    return this;
  }

  /** Build the unsigned grant for `sessionKey`. */
  build(principalPublic: Bytes, sessionKey: Bytes): SessionGrant {
    return {
      principal: principalPublic,
      sessionKey,
      scope: this.#scope,
      budgetGrains: this.#budget,
      expiresAtRound: this.#expiresAtRound,
      grantNonce: this.#grantNonce,
    };
  }

  /** Build and sign, deriving the principal's public key from its secret. */
  sign(principalSecret: Bytes, sessionKey: Bytes): SignedGrant {
    return signGrant(
      principalSecret,
      this.build(publicKeyOf(principalSecret), sessionKey),
    );
  }
}

/**
 * Tracks a session's nonce so an agent does not have to.
 *
 * A wrong nonce is refused by consensus, so getting this right is not
 * optional — and making callers track it by hand is how they get it wrong.
 */
export class SessionSigner {
  #secret: Bytes;
  #id: Bytes;
  #next = 0n;

  constructor(sessionSecret: Bytes, id: Bytes) {
    this.#secret = sessionSecret;
    this.#id = id;
  }

  get sessionId(): Bytes {
    return this.#id;
  }

  get nextNonce(): bigint {
    return this.#next;
  }

  /** Sign the next action, advancing the nonce. */
  sign(action: Action): SignedAction {
    const signed = signAction(this.#secret, {
      sessionId: this.#id,
      nonce: this.#next,
      action,
    });
    this.#next += 1n;
    return signed;
  }

  /**
   * Rewind after a rejected submission, so the next attempt reuses the nonce
   * the chain is still expecting. Without this, one refused action would
   * desynchronise the agent from the chain permanently.
   */
  rollback(): void {
    if (this.#next > 0n) this.#next -= 1n;
  }
}

/** Parse a hex string into a 32-byte id (throws if it is the wrong length). */
export function id32FromHex(hex: string): Id32 {
  const b = fromHex(hex);
  if (b.length !== 32) throw new Error(`expected 32 bytes, got ${b.length}`);
  return b;
}
