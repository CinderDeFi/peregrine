/**
 * An agent creating and using a scoped session key, in TypeScript.
 *
 * ```bash
 * cd sdk/js && node examples/agent-session.ts
 * ```
 *
 * Runs entirely offline: it builds and signs the messages a node would accept,
 * and prints them. Point `submit` at a real node to actually send them.
 *
 * The interesting part is not the signing — it is how little authority the
 * agent ends up holding.
 */
import {
  publicKeyOf,
  SessionBuilder,
  SessionSigner,
  sessionId,
  signRevocation,
  tableId,
  toHex,
  type Action,
} from "../src/index.ts";

// ── keys ────────────────────────────────────────────────────────────────────
// The principal's key is the valuable one; in production it lives in cold
// storage or a hardware wallet and signs the grant *once*. The agent's key is
// disposable — that is the entire point of the exercise.
const principalSecret = new Uint8Array(32).fill(1);
const agentSecret = new Uint8Array(32).fill(2);
const agentPublic = publicKeyOf(agentSecret);

// A stream the agent is allowed to buy. In a real flow this comes from the
// oracle's published identity, not from a constant.
const priceFeed = new Uint8Array(32).fill(9);

// ── 1. the principal delegates, once ────────────────────────────────────────
//
// Everything starts denied. Each capability is opened deliberately, so
// forgetting a line can only ever produce a *weaker* session.
//
// `expiresAtRound` is a consensus round, not a clock reading: read the chain's
// current round and add to it. A wall-clock TTL would expire at a different
// point in the committed order on every validator.
const currentRound = 1_000n; // e.g. from `await client.storeRoot()` era metadata
const grant = new SessionBuilder(currentRound + 500n)
  .allowTable(tableId("agent.notes"))
  .allowStream(priceFeed)
  .budget(50n) // total the agent may ever spend
  .maxPerAction(5n) // and never more than this at once
  .sign(principalSecret, agentPublic);

const id = sessionId(grant.grant);

console.log("── the delegation ────────────────────────────────────────");
console.log("  session id     :", toHex(id).slice(0, 16));
console.log("  budget         : 50 grains total, max 5 per action");
console.log("  expires        : round", grant.grant.expiresAtRound.toString());
console.log("  may write      : agent.notes");
console.log("  may buy        : one price feed");
console.log("  signature      :", toHex(grant.signature).slice(0, 32), "…");
// await client.openSession(grant);

// ── 2. the agent acts, without the principal's key ──────────────────────────
const signer = new SessionSigner(agentSecret, id);

// One signature buys an ongoing subscription. After this, payment happens on
// the fast path: one debit per committed record, no further signatures.
const subscribe: Action = {
  kind: "subscribe",
  stream: priceFeed,
  pricePerRecord: 2n,
};
const subscribed = signer.sign(subscribe);

const note: Action = {
  kind: "write",
  table: tableId("agent.notes"),
  key: new TextEncoder().encode("last-seen"),
  value: new TextEncoder().encode("BTC-USD"),
};
const wrote = signer.sign(note);

console.log("\n── the agent acts ────────────────────────────────────────");
console.log("  subscribe (nonce 0) :", toHex(subscribed.signature).slice(0, 32), "…");
console.log("  write     (nonce 1) :", toHex(wrote.signature).slice(0, 32), "…");
console.log("  next nonce          :", signer.nextNonce.toString());
// await client.sessionAction(subscribed);
// await client.sessionAction(wrote);

// If a submission is refused, roll the nonce back so the next attempt reuses
// the one the chain is still expecting — otherwise the agent desynchronises
// permanently after a single rejection.
// signer.rollback();

// ── 3. what the agent cannot do ─────────────────────────────────────────────
//
// These are signed perfectly well. They are refused by *consensus*, on every
// validator, because they fall outside the grant — not because the agent
// declined to try.
const outOfScope = signer.sign({
  kind: "write",
  table: tableId("treasury.reserve"), // not in scope
  key: new TextEncoder().encode("drain"),
  value: new TextEncoder().encode("everything"),
});
signer.rollback();

const overCap = signer.sign({
  kind: "pay",
  payee: new Uint8Array(32).fill(3),
  amount: 40n, // cap is 5
});
signer.rollback();

console.log("\n── refused by consensus, not by politeness ───────────────");
console.log("  write to treasury.reserve → table not in session scope");
console.log("  pay 40 grains             → exceeds per-action cap of 5");
console.log("  (both are validly signed; the grant is what stops them)");
void outOfScope;
void overCap;

// ── 4. the principal can end it at any time ─────────────────────────────────
const revocation = signRevocation(principalSecret, id);
console.log("\n── revocation ────────────────────────────────────────────");
console.log("  signed by the principal :", toHex(revocation).slice(0, 32), "…");
console.log("  a session key cannot revoke itself — or block its revocation");
// await client.revokeSession(principalSecret, id);

console.log(
  "\nThe agent held a key throughout. It could never spend past 50, never pay\n" +
    "more than 5 at once, never touch a table outside its scope, and stops the\n" +
    "instant its principal says so.\n",
);
