//! Integration: compliance attestations and selective disclosure through the
//! execution pipeline and its real store — the same store root a light client
//! pins.

use peregrine_core::Keypair;
use peregrine_data::compliance::{
    cell_key, compliance_table, AttestationBuilder, CompliancePolicy, ComplianceStatus,
    ATTEST_DOMAIN,
};
use peregrine_data::disclosure::FieldRow;
use peregrine_data::tables::TableId;
use peregrine_node::pipeline::ExecutionPipeline;

fn kp() -> Keypair {
    Keypair::generate(&mut rand::rngs::OsRng)
}

#[test]
fn an_attestation_materializes_into_a_provable_cell() {
    let (subject, attester) = (kp(), kp());
    let signed = AttestationBuilder::verified(0, 100).sign(&attester, &subject.public());

    let mut node = ExecutionPipeline::new();
    assert!(node.apply_attestation(&signed).unwrap());

    // The flag is committed state: provable against the store root a light
    // client trusts.
    let root = node.store_root();
    let read = node
        .prove_read(
            compliance_table(),
            &cell_key(&subject.public(), &attester.public()),
        )
        .expect("cell present");
    assert!(read.verify(&root));

    // An institution's off-chain gate accepts it, and rejects it against a
    // wrong root.
    let policy = CompliancePolicy::new(attester.public());
    assert!(policy.gate(&subject.public(), &read, &root, 50).is_ok());
    assert!(policy
        .gate(&subject.public(), &read, &peregrine_core::Hash::ZERO, 50)
        .is_err());
}

#[test]
fn a_forged_attestation_is_refused_and_writes_nothing() {
    let (subject, attester, impostor) = (kp(), kp(), kp());
    let mut signed = AttestationBuilder::verified(0, 100).sign(&attester, &subject.public());
    // Someone else signs, while the attestation still names `attester`.
    signed.signature = impostor.sign(ATTEST_DOMAIN, &signed.attestation.signing_bytes());

    let mut node = ExecutionPipeline::new();
    assert!(node.apply_attestation(&signed).is_err());
    assert!(
        node.compliance_flag(&subject.public(), &attester.public())
            .is_none(),
        "a refused attestation must leave no flag behind"
    );
}

#[test]
fn a_transfer_is_gated_on_committed_compliance() {
    let (subject, attester, other) = (kp(), kp(), kp());
    let mut node = ExecutionPipeline::new();
    let policy = CompliancePolicy::new(attester.public());

    // No attestation on record → refused, and nothing is credited.
    assert!(node
        .compliant_credit(&subject.public(), 100, &policy)
        .is_err());
    assert!(node
        .compliance_flag(&subject.public(), &attester.public())
        .is_none());

    // Attest, then the same transfer clears.
    let signed = AttestationBuilder::verified(0, 100).sign(&attester, &subject.public());
    node.apply_attestation(&signed).unwrap();
    assert!(node
        .compliant_credit(&subject.public(), 100, &policy)
        .is_ok());

    // A policy trusting a *different* attester consults a different (empty)
    // cell, so a stranger's attestation cannot satisfy it.
    let other_policy = CompliancePolicy::new(other.public());
    assert!(node
        .compliant_credit(&subject.public(), 100, &other_policy)
        .is_err());

    // A `Rejected` attestation is on record but does not clear the gate.
    let subject2 = kp();
    let rejected = AttestationBuilder::verified(0, 100)
        .status(ComplianceStatus::Rejected)
        .sign(&attester, &subject2.public());
    node.apply_attestation(&rejected).unwrap();
    assert!(node
        .compliant_credit(&subject2.public(), 50, &policy)
        .is_err());
}

#[test]
fn selective_disclosure_verifies_through_committed_state() {
    // A KYC record with four fields; only the field commitment goes on-chain.
    let row = FieldRow::new(vec![
        b"Alice Smith".to_vec(),
        b"1990-01-01".to_vec(),
        b"passport-9931".to_vec(),
        b"US".to_vec(),
    ]);
    let table = TableId::named("kyc.records");
    let key = b"customer-1".to_vec();

    let mut node = ExecutionPipeline::new();
    // Some unrelated state so the store has several tables/rows.
    node.tables
        .insert(TableId::named("sys.other"), b"a".to_vec(), b"b".to_vec());
    node.tables
        .insert(table, key.clone(), row.commit().0.to_vec());

    let root = node.store_root();
    let read = node.prove_read(table, &key).expect("row present");

    // Reveal only the residency field; the rest stays hidden.
    let disc = row.disclose(read, &[3]).expect("disclosure");
    assert!(disc.verify(&root));
    assert_eq!(
        disc.revealed().collect::<Vec<_>>(),
        vec![(3u32, b"US".as_slice())]
    );
    // Verifying against a wrong root fails.
    assert!(!disc.verify(&peregrine_core::Hash::ZERO));
}
