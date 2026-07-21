//! Generate the cross-language proof fixtures consumed by the JS SDK's tests.
//!
//! The JS light-client verifier reimplements Peregrine's Merkle/SMT proof
//! checking in TypeScript. That reimplementation is only trustworthy if it
//! agrees with the Rust one *byte for byte*, so we emit real proofs here and
//! let the TS test suite verify them.
//!
//! **Both tree versions are emitted.** v1 and v2 commit the same rows to
//! different roots, and during a migration both are in flight, so a verifier
//! that only ever saw one of them would be untested against exactly the
//! situation the upgrade creates. Each fixture carries `treeVersion`, and the
//! TS side dispatches on it rather than assuming.
//!
//! Run: `cargo run -p peregrine-node --example gen_js_fixture`

use peregrine_data::tables::{RowProof, TableId, TableStore, TreeVersion};
use serde_json::{json, Value};
use std::path::PathBuf;

/// Build a store with a known shape, under `version`.
fn build(version: TreeVersion) -> (TableStore, TableId, TableId) {
    let mut store = TableStore::with_version(version);

    // Two tables so the store-level Merkle proof has real siblings, and enough
    // rows that the sparse-Merkle paths are non-trivial.
    let ticks = TableId::named("sys.stream_ticks");
    let answers = TableId::named("contract.answers");
    store.create_table(ticks);
    store.create_table(answers);

    for i in 0..64u64 {
        let mut key = Vec::with_capacity(40);
        key.extend_from_slice(&[7u8; 32]); // fake stream id
        key.extend_from_slice(&i.to_be_bytes());
        store.insert(ticks, key, (6_150_000u64 + i).to_le_bytes().to_vec());
    }
    store.insert(answers, b"sum".to_vec(), 55u64.to_le_bytes().to_vec());
    store.insert(answers, b"life".to_vec(), 42u64.to_le_bytes().to_vec());

    (store, ticks, answers)
}

/// The keys we prove, spread across both tables.
fn wanted(ticks: TableId, answers: TableId) -> Vec<(TableId, Vec<u8>)> {
    let mut v: Vec<(TableId, Vec<u8>)> =
        vec![(answers, b"sum".to_vec()), (answers, b"life".to_vec())];
    for i in [0u64, 1, 31, 63] {
        let mut key = Vec::with_capacity(40);
        key.extend_from_slice(&[7u8; 32]);
        key.extend_from_slice(&i.to_be_bytes());
        v.push((ticks, key));
    }
    v
}

/// Serialise a row proof, including the extra field v2 non-inclusion needs.
fn row_proof_json(p: &RowProof) -> Value {
    let siblings: Vec<String> = p.siblings().iter().map(|h| hex::encode(h.0)).collect();
    match p {
        RowProof::V1(_) => json!({ "siblings": siblings }),
        RowProof::V2(v2) => json!({
            "siblings": siblings,
            // Present only when a *different* key occupies the queried slot.
            // The verifier needs the preimage to recompute that leaf's hash
            // itself rather than trust a supplied digest.
            "otherLeaf": v2.other_leaf.as_ref().map(|(k, val)| json!({
                "key": hex::encode(k),
                "value": hex::encode(val),
            })),
        }),
    }
}

fn fixture_for(version: TreeVersion) -> Value {
    let (mut store, ticks, answers) = build(version);
    let store_root = store.store_root();

    let reads: Vec<Value> = wanted(ticks, answers)
        .into_iter()
        .map(|(table, key)| {
            let read = store.prove_read(table, &key).expect("key present");
            assert!(read.verify(&store_root), "rust must verify its own proof");
            json!({
                "table": hex::encode(read.table.0 .0),
                "key": hex::encode(&read.key),
                "value": hex::encode(&read.value),
                "tableRoot": hex::encode(read.table_root.0),
                "treeVersion": read.row_proof.version().as_str(),
                "rowProof": row_proof_json(&read.row_proof),
                "storeProof": {
                    "leafIndex": read.store_proof.leaf_index,
                    "siblings": read.store_proof.siblings.iter()
                        .map(|h| hex::encode(h.0)).collect::<Vec<_>>(),
                },
            })
        })
        .collect();

    // Absence proofs, which are where v2 differs most: a key can be absent
    // because its slot is empty *or* because another key occupies it, and the
    // two produce structurally different proofs. A verifier tested only on
    // inclusion would miss the second entirely.
    let absent: Vec<Value> = ["no-such-key", "absent-2", "missing-3", "nope-4"]
        .iter()
        .filter_map(|k| {
            let proof = store.prove_non_inclusion(answers, k.as_bytes())?;
            assert!(
                proof.verify(&store_root),
                "rust must verify its own absence proof"
            );
            Some(json!({
                "table": hex::encode(proof.table.0 .0),
                "key": hex::encode(k.as_bytes()),
                "tableRoot": hex::encode(proof.table_root.0),
                "treeVersion": proof.row_proof.version().as_str(),
                "rowProof": row_proof_json(&proof.row_proof),
                "storeProof": {
                    "leafIndex": proof.store_proof.leaf_index,
                    "siblings": proof.store_proof.siblings.iter()
                        .map(|h| hex::encode(h.0)).collect::<Vec<_>>(),
                },
            }))
        })
        .collect();

    json!({
        "treeVersion": version.as_str(),
        "storeRoot": hex::encode(store_root.0),
        "reads": reads,
        "absent": absent,
    })
}

fn main() -> anyhow::Result<()> {
    let v1 = fixture_for(TreeVersion::V1);
    let v2 = fixture_for(TreeVersion::V2);

    // The same rows under two rules must not land on the same root, or the
    // version tag would be decorative.
    assert_ne!(
        v1["storeRoot"], v2["storeRoot"],
        "v1 and v2 must commit the same rows to different roots"
    );

    let doc = json!({
        "_comment": "Generated by `cargo run -p peregrine-node --example gen_js_fixture`. \
                     Real proofs from the Rust implementation; the TS verifier must agree \
                     with both tree versions.",
        "v1": v1,
        "v2": v2,
    });

    let out = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../sdk/js/test/fixtures/proven-read.json");
    std::fs::create_dir_all(out.parent().expect("has parent"))?;
    std::fs::write(&out, serde_json::to_string_pretty(&doc)? + "\n")?;

    println!(
        "wrote v1 ({} reads, {} absent) + v2 ({} reads, {} absent) to {}",
        doc["v1"]["reads"].as_array().unwrap().len(),
        doc["v1"]["absent"].as_array().unwrap().len(),
        doc["v2"]["reads"].as_array().unwrap().len(),
        doc["v2"]["absent"].as_array().unwrap().len(),
        out.display()
    );
    Ok(())
}
