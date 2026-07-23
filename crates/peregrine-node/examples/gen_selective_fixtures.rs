//! Generate cross-language fixtures for selective disclosure and compliance.
//!
//! Emits real Rust-produced proofs to `sdk/js/test/fixtures/selective.json`, so
//! the TypeScript verifiers are checked byte-for-byte against the Rust
//! implementation — the same drift-guard used for `proven-read.json`.
//!
//! Run: `cargo run -p peregrine-node --example gen_selective_fixtures`

use peregrine_core::Keypair;
use peregrine_data::compliance::{cell_key, compliance_table, AttestationBuilder};
use peregrine_data::disclosure::FieldRow;
use peregrine_data::tables::{ProvenRead, RowProof, TableId, TableStore};
use serde_json::{json, Value};

/// Deterministic keypair from a byte seed, so the fixture is stable across runs.
fn kp(seed: u8) -> Keypair {
    Keypair::from_bytes(&[seed; 32])
}

fn row_proof_json(p: &RowProof) -> Value {
    let siblings: Vec<String> = p.siblings().iter().map(|h| hex::encode(h.0)).collect();
    match p {
        RowProof::V1(_) => json!({ "siblings": siblings }),
        RowProof::V2(v2) => json!({
            "siblings": siblings,
            "otherLeaf": v2.other_leaf.as_ref().map(|(k, val)| json!({
                "key": hex::encode(k),
                "value": hex::encode(val),
            })),
        }),
    }
}

/// The same ProvenRead → JSON shape `provenReadFromJson` consumes.
fn proven_read_json(read: &ProvenRead) -> Value {
    json!({
        "table": hex::encode(read.table.0 .0),
        "key": hex::encode(&read.key),
        "value": hex::encode(&read.value),
        "tableRoot": hex::encode(read.table_root.0),
        "treeVersion": read.row_proof.version().as_str(),
        "rowProof": row_proof_json(&read.row_proof),
        "storeProof": {
            "leafIndex": read.store_proof.leaf_index,
            "siblings": read.store_proof.siblings.iter().map(|h| hex::encode(h.0)).collect::<Vec<_>>(),
        },
    })
}

fn disclosure_fixture() -> Value {
    // A KYC record; only its field commitment goes on-chain.
    let fields = vec![
        b"Alice Smith".to_vec(),
        b"1990-01-01".to_vec(),
        b"passport-9931".to_vec(),
        b"US".to_vec(),
    ];
    let row = FieldRow::new(fields.clone());
    let table = TableId::named("kyc.records");
    let key = b"customer-1".to_vec();

    let mut store = TableStore::new();
    store.insert(TableId::named("sys.other"), b"noise".to_vec(), b"x".to_vec());
    store.insert(table, key.clone(), row.commit().0.to_vec());
    let store_root = store.store_root();
    let read = store.prove_read(table, &key).unwrap();

    // Reveal the residency (index 3) and date of birth (index 1); hide name and
    // passport number.
    let disc = row.disclose(read, &[1, 3]).unwrap();
    assert!(disc.verify(&store_root), "rust must verify its own disclosure");

    let reveals: Vec<Value> = disc
        .reveals
        .iter()
        .map(|r| {
            json!({
                "index": r.index,
                "value": hex::encode(&r.value),
                "proof": {
                    "leafIndex": r.proof.leaf_index,
                    "siblings": r.proof.siblings.iter().map(|h| hex::encode(h.0)).collect::<Vec<_>>(),
                },
            })
        })
        .collect();

    json!({
        "storeRoot": hex::encode(store_root.0),
        "arity": disc.arity,
        "read": proven_read_json(&disc.read),
        "reveals": reveals,
        // Plaintext of every field, so the test can assert the hidden ones never
        // appear in the disclosure.
        "allFields": fields.iter().map(hex::encode).collect::<Vec<_>>(),
        "hiddenIndices": [0u32, 2],
    })
}

fn compliance_fixture() -> Value {
    let subject = kp(1);
    let attester = kp(2);
    let other = kp(3);

    // Verified, valid over rounds [0, 500], scheme 7.
    let signed = AttestationBuilder::verified(0, 500)
        .scheme(7)
        .sign(&attester, &subject.public());
    assert!(signed.verify());

    // Materialize the flag exactly as the node's `apply_attestation` would.
    let mut store = TableStore::new();
    store.insert(TableId::named("sys.other"), b"noise".to_vec(), b"x".to_vec());
    store.insert(
        compliance_table(),
        cell_key(&subject.public(), &attester.public()),
        signed.attestation.flag_bytes(),
    );
    let store_root = store.store_root();
    let read = store
        .prove_read(
            compliance_table(),
            &cell_key(&subject.public(), &attester.public()),
        )
        .unwrap();

    json!({
        "storeRoot": hex::encode(store_root.0),
        "subject": hex::encode(subject.public().0),
        "attester": hex::encode(attester.public().0),
        "otherAttester": hex::encode(other.public().0),
        "scheme": 7,
        "nowRound": 250,          // within [0, 500] → compliant
        "expiredNowRound": 501,   // past expiry → refused
        "flag": hex::encode(signed.attestation.flag_bytes()),
        "read": proven_read_json(&read),
    })
}

fn main() {
    let out = json!({
        "_comment": "Generated by `cargo run -p peregrine-node --example gen_selective_fixtures`. \
                     Real selective-disclosure and compliance proofs from the Rust implementation; \
                     the TS verifiers must agree.",
        "disclosure": disclosure_fixture(),
        "compliance": compliance_fixture(),
    });
    let text = serde_json::to_string_pretty(&out).unwrap() + "\n";

    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../sdk/js/test/fixtures/selective.json");
    std::fs::create_dir_all(std::path::Path::new(path).parent().unwrap()).unwrap();
    std::fs::write(path, &text).unwrap();
    eprintln!("wrote {path} ({} bytes)", text.len());
}
