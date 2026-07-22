/**
 * Agent-payments usability: decoding committed session state (checked against a
 * real Rust fixture), the ergonomic `SessionSigner` helpers, and builder
 * validation. The signing-byte agreement itself lives in `sessions.test.ts`.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fromHex, toHex } from "../src/hash.ts";
import {
  decodeSessionState,
  isActive,
  isSubscribed,
  publicKeyOf,
  sessionRemaining,
  signAction,
  SessionBuilder,
  SessionSigner,
} from "../src/sessions.ts";
import { tableId } from "../src/client.ts";

const fx = JSON.parse(readFileSync(new URL("./fixtures/sessions.json", import.meta.url), "utf8"));

describe("session state decoding (Rust fixture)", () => {
  const s = fx.state;
  const g = fx.grant;

  it("decodes committed state byte-for-byte with Rust", () => {
    const st = decodeSessionState(fromHex(s.stateBytes));
    assert.ok(st, "decodes");
    assert.equal(st.spent, BigInt(s.spent));
    assert.equal(st.nextNonce, BigInt(s.nextNonce));
    assert.equal(st.revoked, s.revoked);
    assert.equal(st.grant.budgetGrains, BigInt(g.budgetGrains));
    assert.equal(st.grant.scope.maxSpendPerAction, BigInt(g.scope.maxSpendPerAction));
    assert.equal(st.grant.expiresAtRound, BigInt(g.expiresAtRound));
    assert.equal(st.grant.grantNonce, BigInt(g.grantNonce));
    assert.equal(st.grant.scope.tables.length, s.nTables);
    assert.equal(st.grant.scope.streams.length, s.nStreams);
    assert.equal(toHex(st.grant.principal), g.principal);
    assert.equal(toHex(st.grant.sessionKey), g.sessionKey);
  });

  it("exposes remaining budget, liveness, and subscriptions", () => {
    const st = decodeSessionState(fromHex(s.stateBytes));
    assert.ok(st);
    assert.equal(sessionRemaining(st), BigInt(s.remaining));
    assert.equal(st.subscriptions.length, 1);
    assert.equal(st.subscriptions[0].pricePerRecord, BigInt(s.subscriptions[0].pricePerRecord));
    assert.ok(isSubscribed(st, fromHex(s.subscriptions[0].stream)));
    assert.ok(!isSubscribed(st, new Uint8Array(32)));
    // expiresAtRound is 100, inclusive; not revoked.
    assert.ok(isActive(st, 100));
    assert.ok(!isActive(st, 101));
  });

  it("returns null for junk", () => {
    assert.equal(decodeSessionState(new Uint8Array(3)), null);
    // Trailing bytes → not a session state.
    const good = fromHex(s.stateBytes);
    const padded = new Uint8Array(good.length + 1);
    padded.set(good);
    assert.equal(decodeSessionState(padded), null);
  });
});

describe("SessionSigner ergonomics", () => {
  const secret = fromHex(fx.keys.agentSeed);
  const id = fromHex(fx.grant.sessionId);
  const payee = fromHex(fx.keys.payeePublic);
  const stream = fromHex(fx.grant.scope.streams[0]);

  it("helpers equal the hand-built action and advance the nonce", () => {
    const a = new SessionSigner(secret, id);
    const b = new SessionSigner(secret, id);
    const viaHelper = a.pay(payee, 5);
    const viaHand = signAction(secret, {
      sessionId: id,
      nonce: 0n,
      action: { kind: "pay", payee, amount: 5n },
    });
    assert.deepEqual(viaHelper.signature, viaHand.signature);
    assert.equal(a.nextNonce, 1n);

    // Mixed helpers keep advancing the nonce.
    assert.equal(a.subscribe(stream, 2).action.nonce, 1n);
    assert.equal(a.unsubscribe(stream).action.nonce, 2n);
    assert.equal(a.write(tableId("agent.notes"), new Uint8Array([1]), new Uint8Array([2])).action.nonce, 3n);
    assert.equal(b.nextNonce, 0n, "an untouched signer is unaffected");
  });
});

describe("SessionBuilder validation", () => {
  const principal = fromHex(fx.keys.principalSeed);
  const agent = publicKeyOf(fromHex(fx.keys.agentSeed));

  it("trySign refuses a funded session with no per-action cap", () => {
    assert.throws(() => new SessionBuilder(100).budget(50n).trySign(principal, agent));
    // With a cap it is fine.
    assert.ok(new SessionBuilder(100).budget(50n).maxPerAction(5n).trySign(principal, agent));
    // A scope-only session with no budget is fine.
    assert.ok(new SessionBuilder(100).allowTable(tableId("agent.notes")).trySign(principal, agent));
  });

  it("allowStreams scopes several streams at once", () => {
    const streams = [new Uint8Array(32).fill(1), new Uint8Array(32).fill(2)];
    const grant = new SessionBuilder(100)
      .allowStreams(streams)
      .maxPerAction(5n)
      .budget(50n)
      .trySign(principal, agent);
    assert.equal(grant.grant.scope.streams.length, 2);
  });
});
