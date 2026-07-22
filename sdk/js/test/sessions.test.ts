/**
 * Cross-language session signing.
 *
 * The fixture is produced by Rust
 * (`cargo run -p peregrine-node --example gen_session_fixture`) and contains
 * the exact bytes `signing_bytes()` returns plus the signature Rust makes over
 * them.
 *
 * **Byte equality is the real test.** A signature that merely "verifies" only
 * proves the key is right; it says nothing about whether the encoding matches
 * what a validator will reconstruct. ed25519 is deterministic (RFC 8032), so
 * an identical signature over an identical message is proof the whole stack —
 * bincode layout, domain prefix, key derivation — agrees with Rust.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { fromHex, toHex } from "../src/hash.ts";
import {
  encodeAction,
  encodeGrant,
  publicKeyOf,
  SessionBuilder,
  SessionSigner,
  sessionId,
  signAction,
  signGrant,
  signRevocation,
  type Action,
  type SessionGrant,
} from "../src/sessions.ts";
import { tableId } from "../src/client.ts";

interface Fixture {
  keys: {
    principalSeed: string;
    principalPublic: string;
    agentSeed: string;
    agentPublic: string;
    payeePublic: string;
  };
  grant: {
    principal: string;
    sessionKey: string;
    scope: { tables: string[]; streams: string[]; maxSpendPerAction: number };
    budgetGrains: number;
    expiresAtRound: number;
    grantNonce: number;
    signingBytes: string;
    sessionId: string;
    signature: string;
  };
  actions: { name: string; nonce: number; signingBytes: string; signature: string }[];
  revocation: { sessionId: string; signature: string };
}

const here = dirname(fileURLToPath(import.meta.url));
const fx = JSON.parse(
  readFileSync(join(here, "fixtures", "sessions.json"), "utf8"),
) as Fixture;

const principalSeed = fromHex(fx.keys.principalSeed);
const agentSeed = fromHex(fx.keys.agentSeed);

/** The exact grant the Rust fixture describes. */
function grant(): SessionGrant {
  return {
    principal: fromHex(fx.grant.principal),
    sessionKey: fromHex(fx.grant.sessionKey),
    scope: {
      tables: fx.grant.scope.tables.map(fromHex),
      streams: fx.grant.scope.streams.map(fromHex),
      maxSpendPerAction: BigInt(fx.grant.scope.maxSpendPerAction),
    },
    budgetGrains: BigInt(fx.grant.budgetGrains),
    expiresAtRound: BigInt(fx.grant.expiresAtRound),
    grantNonce: BigInt(fx.grant.grantNonce),
  };
}

describe("key derivation", () => {
  it("derives the same public keys as Rust", () => {
    assert.equal(toHex(publicKeyOf(principalSeed)), fx.keys.principalPublic);
    assert.equal(toHex(publicKeyOf(agentSeed)), fx.keys.agentPublic);
  });
});

describe("grant encoding", () => {
  /** The load-bearing assertion of this whole file. */
  it("encodes byte-for-byte identically to Rust bincode", () => {
    assert.equal(toHex(encodeGrant(grant())), fx.grant.signingBytes);
  });

  it("produces the expected length", () => {
    // 32 principal + 32 session key
    // + (8 len + 2*32 tables) + (8 len + 1*32 streams) + 8 maxSpendPerAction
    // + 8 budget + 8 expiry + 8 nonce = 208
    assert.equal(encodeGrant(grant()).length, 208);
  });

  it("derives the same session id as Rust", () => {
    assert.equal(toHex(sessionId(grant())), fx.grant.sessionId);
  });

  it("produces a byte-identical signature", () => {
    const signed = signGrant(principalSeed, grant());
    assert.equal(toHex(signed.signature), fx.grant.signature);
  });

  /** Guards the two mistakes that would otherwise pass a single-element test:
   *  a wrong `Vec` length width, and arrays being length-prefixed. */
  it("length-prefixes vectors but not fixed arrays", () => {
    const bytes = encodeGrant(grant());
    // Bytes 64..72 are the tables vector's u64 length = 2.
    const len = new DataView(bytes.buffer, bytes.byteOffset + 64, 8).getBigUint64(0, true);
    assert.equal(len, 2n);
    // The first table follows immediately, unprefixed.
    assert.equal(toHex(bytes.slice(72, 104)), fx.grant.scope.tables[0]);
  });

  it("changing any field changes the bytes", () => {
    const base = toHex(encodeGrant(grant()));
    for (const mutate of [
      (g: SessionGrant) => (g.budgetGrains += 1n),
      (g: SessionGrant) => (g.expiresAtRound += 1n),
      (g: SessionGrant) => (g.grantNonce += 1n),
      (g: SessionGrant) => (g.scope.maxSpendPerAction += 1n),
      (g: SessionGrant) => g.scope.tables.pop(),
    ]) {
      const g = grant();
      mutate(g);
      assert.notEqual(toHex(encodeGrant(g)), base);
    }
  });
});

describe("action encoding", () => {
  /** Every variant, so a wrong enum tag width cannot hide in an untested one. */
  const actions: Record<string, Action> = {
    write: {
      kind: "write",
      table: fromHex(fx.grant.scope.tables[0]),
      key: new TextEncoder().encode("title"),
      value: new TextEncoder().encode("PROP-1729"),
    },
    pay: { kind: "pay", payee: fromHex(fx.keys.payeePublic), amount: 3n },
    subscribe: {
      kind: "subscribe",
      stream: fromHex(fx.grant.scope.streams[0]),
      pricePerRecord: 2n,
    },
    unsubscribe: { kind: "unsubscribe", stream: fromHex(fx.grant.scope.streams[0]) },
  };

  for (const expected of fx.actions) {
    it(`encodes and signs '${expected.name}' identically to Rust`, () => {
      const action = actions[expected.name];
      assert.ok(action, `fixture covers an action the test does not: ${expected.name}`);

      const sa = {
        sessionId: fromHex(fx.grant.sessionId),
        nonce: BigInt(expected.nonce),
        action,
      };
      assert.equal(toHex(encodeAction(sa)), expected.signingBytes, "bytes");
      assert.equal(
        toHex(signAction(agentSeed, sa).signature),
        expected.signature,
        "signature",
      );
    });
  }

  it("covers every variant the Rust enum has", () => {
    assert.equal(fx.actions.length, 4, "all four Action variants must be fixtured");
  });
});

describe("revocation", () => {
  it("is signed by the principal, identically to Rust", () => {
    const sig = signRevocation(principalSeed, fromHex(fx.revocation.sessionId));
    assert.equal(toHex(sig), fx.revocation.signature);
  });

  /** A session key must not be able to produce a valid revocation — but more
   *  importantly, one signed by the wrong key must differ from the real one. */
  it("signed by the session key is not the principal's revocation", () => {
    const wrong = signRevocation(agentSeed, fromHex(fx.revocation.sessionId));
    assert.notEqual(toHex(wrong), fx.revocation.signature);
  });
});

describe("SessionBuilder", () => {
  it("reproduces the fixture grant through the fluent API", () => {
    const built = new SessionBuilder(fx.grant.expiresAtRound)
      .allowTable(fromHex(fx.grant.scope.tables[0]))
      .allowTable(fromHex(fx.grant.scope.tables[1]))
      .allowStream(fromHex(fx.grant.scope.streams[0]))
      .budget(fx.grant.budgetGrains)
      .maxPerAction(fx.grant.scope.maxSpendPerAction)
      .nonce(fx.grant.grantNonce)
      .sign(principalSeed, fromHex(fx.grant.sessionKey));

    assert.equal(toHex(built.signature), fx.grant.signature);
    assert.equal(toHex(sessionId(built.grant)), fx.grant.sessionId);
  });

  /** Everything starts denied, so forgetting a call can only ever produce a
   *  session that does *less* than intended. */
  it("starts with nothing allowed and no budget", () => {
    const g = new SessionBuilder(10).build(
      publicKeyOf(principalSeed),
      publicKeyOf(agentSeed),
    );
    assert.deepEqual(g.scope.tables, []);
    assert.deepEqual(g.scope.streams, []);
    assert.equal(g.scope.maxSpendPerAction, 0n);
    assert.equal(g.budgetGrains, 0n);
  });

  it("computes tableId the same way Rust does", () => {
    // `rwa.registry` is the second table in the fixture's scope.
    assert.equal(toHex(tableId("rwa.registry")), fx.grant.scope.tables[1]);
  });
});

describe("SessionSigner", () => {
  it("advances the nonce and can roll back a rejection", () => {
    const signer = new SessionSigner(agentSeed, fromHex(fx.grant.sessionId));
    const pay: Action = { kind: "pay", payee: fromHex(fx.keys.payeePublic), amount: 1n };

    assert.equal(signer.nextNonce, 0n);
    signer.sign(pay);
    assert.equal(signer.nextNonce, 1n);

    // A refused submission must not desynchronise the agent from the chain.
    signer.rollback();
    assert.equal(signer.nextNonce, 0n);
    signer.rollback();
    assert.equal(signer.nextNonce, 0n, "rollback must not go negative");
  });

  it("signs nonce 0 exactly as the fixture's first action", () => {
    const signer = new SessionSigner(agentSeed, fromHex(fx.grant.sessionId));
    const signed = signer.sign({
      kind: "write",
      table: fromHex(fx.grant.scope.tables[0]),
      key: new TextEncoder().encode("title"),
      value: new TextEncoder().encode("PROP-1729"),
    });
    assert.equal(toHex(signed.signature), fx.actions[0].signature);
  });
});
