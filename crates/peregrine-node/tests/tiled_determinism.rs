//! **The safety property the tiled pipeline rests on.**
//!
//! Tiles move signature verification off the consensus thread. That is only
//! sound if it changes *when* work happens and never *what* it decides — two
//! validators with different tile counts must commit byte-identical state, or
//! the network forks along hardware lines, which is about the worst failure
//! mode a chain can have.
//!
//! These tests drive the same committed payloads through pipelines configured
//! with 0, 1, and 8 tiles and require the resulting store roots to be equal.
//! The store root is the right thing to compare because it is exactly what
//! light clients pin: if it matches, every materialized row matches.

use peregrine_core::{Hash, Keypair};
use peregrine_data::streams::Publisher;
use peregrine_node::payload::WirePayload;
use peregrine_node::pipeline::ExecutionPipeline;
use peregrine_node::tiles::TilePool;
use std::sync::Arc;

/// Build a pipeline with `tiles` sig-verify tiles and a registered publisher.
fn pipeline_with(tiles: usize, pub_pk: peregrine_core::PublicKey) -> ExecutionPipeline {
    let mut p = ExecutionPipeline::new();
    if tiles > 0 {
        p = p.with_tiles(Arc::new(TilePool::new(tiles)));
    }
    p.streams.register("determinism/feed", pub_pk);
    p
}

/// A mixed batch: valid shreds, shreds with corrupted signatures, and a shred
/// from an unregistered stream. All three paths must agree across
/// configurations — the rejections as much as the acceptances.
///
/// Returns the payloads alongside the publisher key the pipeline must trust.
fn batch(n: usize) -> (Vec<WirePayload>, peregrine_core::PublicKey) {
    let mut rng = rand::rngs::OsRng;
    let pub_kp = Keypair::generate(&mut rng);
    let pub_pk = pub_kp.public();
    let mut publisher = Publisher::new("determinism/feed", pub_kp);
    let mut stray = Publisher::new("determinism/unregistered", Keypair::generate(&mut rng));

    let mut out = Vec::with_capacity(n + 1);
    for i in 0..n {
        let mut shred = publisher.emit((i as u64).to_le_bytes().to_vec());
        // Corrupt roughly every seventh signature so the rejection path is
        // exercised in bulk, not just once.
        if i % 7 == 3 {
            shred.signature.0[0] ^= 0xFF;
        }
        out.push(WirePayload::Shred(shred));
    }
    // A shred for a stream nobody registered: must be rejected everywhere.
    out.push(WirePayload::Shred(stray.emit(vec![9u8; 8])));
    (out, pub_pk)
}

/// Apply a batch through the **real commit path** and return the resulting
/// root. Uses `apply_decoded_batch`, not a loop over `apply_payload` — the
/// latter verifies inline and would bypass the tiles entirely, making these
/// tests pass without proving anything.
fn run(mut pipeline: ExecutionPipeline, payloads: &[WirePayload]) -> (Hash, u64) {
    pipeline.apply_decoded_batch(payloads);
    (pipeline.store_root(), pipeline.metrics.committed_records)
}

#[test]
fn tile_count_does_not_change_committed_state() {
    let (payloads, pk) = batch(400);

    let (root0, n0) = run(pipeline_with(0, pk), &payloads);
    let (root1, n1) = run(pipeline_with(1, pk), &payloads);
    let (root8, n8) = run(pipeline_with(8, pk), &payloads);

    assert_eq!(root0, root1, "1 tile must commit what 0 tiles commit");
    assert_eq!(root0, root8, "8 tiles must commit what 0 tiles commit");
    assert_eq!((n0, n0), (n1, n8), "accepted record counts must match");

    // And the batch must actually have done something, or this proves nothing.
    assert!(n0 > 0, "no records were accepted — the test is vacuous");
    assert_ne!(root0, Hash::ZERO, "state did not change");
}

/// Corrupted signatures must be rejected *identically* whether verification
/// ran on a tile or inline. A tile that returned `true` on failure would show
/// up here as a higher accepted count, not as a crash.
#[test]
fn invalid_signatures_are_rejected_under_every_tile_count() {
    // 70 records, every 7th of which (i % 7 == 3) is corrupt → 10 bad.
    let (payloads, pk) = batch(70);
    let expected_accepted = 60;

    for tiles in [0usize, 1, 4, 8] {
        let (_, accepted) = run(pipeline_with(tiles, pk), &payloads);
        assert_eq!(
            accepted, expected_accepted,
            "with {tiles} tiles: {accepted} accepted, expected {expected_accepted} \
             (10 corrupt signatures + 1 unregistered stream must all be refused)"
        );
    }
}

/// Repeated runs with the same input must give the same root — the tiles
/// introduce nondeterministic *scheduling*, and this checks none of it leaks
/// into the result.
#[test]
fn repeated_runs_with_tiles_are_stable() {
    let (payloads, pk) = batch(250);

    let (first, _) = run(pipeline_with(8, pk), &payloads);
    for round in 0..8 {
        let (again, _) = run(pipeline_with(8, pk), &payloads);
        assert_eq!(again, first, "run {round} diverged from the first");
    }
}
