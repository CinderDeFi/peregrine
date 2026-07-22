/**
 * Oracle feed decoding, checked against a **real Rust-produced fixture**
 * (`cargo run -p peregrine-node --example gen_feed_fixture`): a median price
 * feed's latest value + proof. If the TS decoder disagrees with Rust on the
 * cell layout or byte order, these fail.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fromHex } from "../src/hash.ts";
import { provenReadFromJson } from "../src/verify.ts";
import {
  Aggregation,
  decodeFeedValue,
  FeedKind,
  feedValueAsNumber,
  isFresh,
  readFeedValue,
  staleness,
} from "../src/feeds.ts";

const fx = JSON.parse(readFileSync(new URL("./fixtures/feed.json", import.meta.url), "utf8"));

describe("oracle feed (Rust fixture)", () => {
  const root = fromHex(fx.storeRoot);
  const read = () => provenReadFromJson(fx.read);
  const e = fx.expected;

  it("verifies the proof and decodes the aggregated value", () => {
    const fv = readFeedValue(read(), root);
    assert.ok(fv, "a value comes back for a valid proof");
    assert.equal(fv.value, BigInt(e.value));
    assert.equal(fv.decimals, e.decimals);
    assert.equal(fv.kind, FeedKind.Price);
    assert.equal(fv.kind, e.kind);
    assert.equal(fv.aggregation, Aggregation.Median);
    assert.equal(fv.aggregation, e.aggregation);
    assert.equal(fv.nSources, e.nSources);
    assert.equal(fv.updatedRound, BigInt(e.updatedRound));
  });

  it("applies decimals for display", () => {
    const fv = readFeedValue(read(), root);
    assert.ok(fv);
    assert.equal(feedValueAsNumber(fv), Number(e.value) / 10 ** e.decimals);
  });

  it("reports freshness against the committed round", () => {
    const fv = readFeedValue(read(), root);
    assert.ok(fv);
    assert.equal(staleness(fv, fx.nowRound), BigInt(fx.nowRound - e.updatedRound));
    assert.ok(isFresh(fv, fx.nowRound, fx.maxStalenessRounds), "fresh within the bound");
    assert.ok(!isFresh(fv, fx.staleRound, fx.maxStalenessRounds), "stale beyond the bound");
  });

  it("returns null for a proof against the wrong root", () => {
    assert.equal(readFeedValue(read(), new Uint8Array(32)), null);
  });

  it("refuses a malformed cell", () => {
    assert.equal(decodeFeedValue(new Uint8Array(5)), null);
    assert.equal(decodeFeedValue(new Uint8Array(21)), null); // version byte 0
  });
});
