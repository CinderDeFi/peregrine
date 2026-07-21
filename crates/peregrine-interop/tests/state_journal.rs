//! The **Peregrine → Ethereum** statement: what the state guest proves, and
//! the exact bytes it commits.
//!
//! Two jobs here:
//!
//! 1. Test the rules — a quorum really is required, the inclusion proof really
//!    is checked against the *signed* root, and none of it can be bypassed.
//! 2. Pin the ABI encoding, and write it to a fixture that the Solidity test
//!    decodes. Rust and Solidity agreeing on the journal layout is not
//!    something either side can verify alone, and a silent disagreement would
//!    make every field of every proof mean something different than intended.

use peregrine_core::{Committee, Hash, Keypair, ValidatorId, ValidatorInfo};
use peregrine_data::tables::{TableId, TableStore};
use peregrine_interop::peregrine::{sign_checkpoint, CommitteeDigest, SignedCheckpoint};
use peregrine_interop::state::{
    decode_state_journal, encode_state_journal, StateError, StateWitness, STATE_JOURNAL_BYTES,
};
use peregrine_interop::Checkpoint;
use rand::rngs::StdRng;
use rand::SeedableRng;

const CHAIN: u64 = 4242;
const ROUND: u64 = 99;

/// Four validators with equal stake, from a fixed seed so the fixture — and
/// therefore the committee digest the Solidity test pins — is reproducible.
fn committee() -> (Vec<Keypair>, CommitteeDigest, Committee) {
    let mut rng = StdRng::seed_from_u64(0x9E57_1234_ABCD_0001);
    let keys: Vec<Keypair> = (0..4).map(|_| Keypair::generate(&mut rng)).collect();
    let validators: Vec<(ValidatorId, _, u64)> = keys
        .iter()
        .enumerate()
        .map(|(i, k)| (ValidatorId(i as u16), k.public(), 100))
        .collect();
    let digest = CommitteeDigest {
        epoch: 1,
        validators: validators.clone(),
    };
    let committee = Committee::new(
        validators
            .iter()
            .map(|(id, pk, stake)| ValidatorInfo {
                id: *id,
                public_key: *pk,
                stake: *stake,
            })
            .collect(),
    );
    (keys, digest, committee)
}

/// A store holding one row, plus the table id and key used throughout.
fn store_with_value(value: Vec<u8>) -> (TableStore, TableId, Vec<u8>) {
    let table = TableId::named("contract.answers");
    let key = b"meaning".to_vec();
    let mut store = TableStore::new();
    store.insert(table, key.clone(), value);
    (store, table, key)
}

/// Build a well-formed witness signed by `signers` validators.
fn witness_signed_by(signers: usize, value: Vec<u8>) -> (StateWitness, CommitteeDigest) {
    let (keys, digest, _) = committee();
    let (mut store, table, key) = store_with_value(value);
    let read = store.prove_read(table, &key).expect("row exists");
    let store_root = store.store_root();

    let checkpoint = Checkpoint {
        round: ROUND,
        store_root,
    };
    let signatures = keys
        .iter()
        .take(signers)
        .enumerate()
        .map(|(i, k)| (ValidatorId(i as u16), sign_checkpoint(k, &checkpoint)))
        .collect();

    (
        StateWitness {
            chain_id: CHAIN,
            committee: digest.clone(),
            signed: SignedCheckpoint {
                checkpoint,
                signatures,
            },
            read,
        },
        digest,
    )
}

// ── the happy path ──────────────────────────────────────────────────────────

#[test]
fn a_quorum_signed_read_verifies() {
    let (witness, digest) = witness_signed_by(3, 42u64.to_le_bytes().to_vec());
    let j = witness.verify().expect("3 of 4 is a quorum");

    assert_eq!(j.chain_id, CHAIN);
    assert_eq!(j.round, ROUND);
    assert_eq!(j.committee_digest, digest.digest());
    assert_eq!(j.value_len, 8);
    // 42 little-endian, right-aligned in the word.
    assert_eq!(&j.value[24..], &42u64.to_le_bytes());
    assert_eq!(j.key_hash, Hash::digest(b"meaning"));
}

// ── the rules ───────────────────────────────────────────────────────────────

/// **Without a quorum there is no statement.** Two of four is not enough, and
/// the failure is a refusal to produce a journal, not a journal with a caveat.
#[test]
fn a_minority_cannot_produce_a_journal() {
    let (witness, _) = witness_signed_by(2, vec![1]);
    assert!(matches!(
        witness.verify(),
        Err(StateError::Checkpoint(_)),
        // 200 of 400 stake, quorum needs > 2/3.
    ));
}

/// An empty committee has a quorum threshold of zero, so an empty signature set
/// would trivially "reach quorum". That must be refused explicitly rather than
/// left to threshold arithmetic.
#[test]
fn an_empty_committee_is_refused() {
    let (mut witness, _) = witness_signed_by(3, vec![1]);
    witness.committee.validators.clear();
    witness.signed.signatures.clear();
    assert!(matches!(witness.verify(), Err(StateError::EmptyCommittee)));
}

/// **The root comes from the checkpoint, never from the read.** A `ProvenRead`
/// carries its own root field; if verification trusted that, a relayer could
/// prove a value under a root no validator ever signed.
#[test]
fn the_inclusion_proof_is_checked_against_the_signed_root() {
    let (mut witness, _) = witness_signed_by(3, 7u64.to_le_bytes().to_vec());

    // Swap in a read from a *different* store. It is internally consistent and
    // verifies against its own root — but not against the signed one.
    let (mut other, table, key) = store_with_value(999u64.to_le_bytes().to_vec());
    witness.read = other.prove_read(table, &key).expect("row exists");

    assert!(matches!(
        witness.verify(),
        Err(StateError::BadInclusionProof)
    ));
}

/// Tampering with the value invalidates the inclusion proof — the tree is what
/// binds value to root.
#[test]
fn a_forged_value_is_refused() {
    let (mut witness, _) = witness_signed_by(3, 42u64.to_le_bytes().to_vec());
    witness.read.value = 43u64.to_le_bytes().to_vec();
    assert!(matches!(
        witness.verify(),
        Err(StateError::BadInclusionProof)
    ));
}

/// Signatures are over `(round, store_root)`, so moving the round invalidates
/// them — an attacker cannot re-date a checkpoint to outrank the current one.
#[test]
fn the_round_cannot_be_moved_after_signing() {
    let (mut witness, _) = witness_signed_by(3, vec![1]);
    witness.signed.checkpoint.round = ROUND + 1000;
    assert!(matches!(witness.verify(), Err(StateError::Checkpoint(_))));
}

/// One validator cannot be counted twice toward a quorum.
#[test]
fn duplicate_signatures_do_not_reach_quorum() {
    let (keys, digest, _) = committee();
    let (mut store, table, key) = store_with_value(vec![1]);
    let read = store.prove_read(table, &key).unwrap();
    let checkpoint = Checkpoint {
        round: ROUND,
        store_root: store.store_root(),
    };
    // The same validator, three times.
    let sig = sign_checkpoint(&keys[0], &checkpoint);
    let witness = StateWitness {
        chain_id: CHAIN,
        committee: digest,
        signed: SignedCheckpoint {
            checkpoint,
            signatures: vec![
                (ValidatorId(0), sig),
                (ValidatorId(0), sig),
                (ValidatorId(0), sig),
            ],
        },
        read,
    };
    assert!(matches!(witness.verify(), Err(StateError::Checkpoint(_))));
}

/// A value too long to fit a word is refused, never truncated. A truncated
/// value is a wrong value that still looks well-formed.
#[test]
fn an_oversized_value_is_refused_not_truncated() {
    let (witness, _) = witness_signed_by(3, vec![0xAB; 33]);
    match witness.verify() {
        Err(StateError::ValueTooLong { got, max }) => {
            assert_eq!(got, 33);
            assert_eq!(max, 32);
        }
        other => panic!("expected ValueTooLong, got {other:?}"),
    }
}

/// A 32-byte value is exactly at the limit and must work.
#[test]
fn a_full_word_value_is_accepted() {
    let (witness, _) = witness_signed_by(3, vec![0xCD; 32]);
    let j = witness.verify().expect("32 bytes fits");
    assert_eq!(j.value_len, 32);
    assert_eq!(j.value, [0xCD; 32]);
}

// ── encoding ────────────────────────────────────────────────────────────────

#[test]
fn journal_encoding_round_trips() {
    let (witness, _) = witness_signed_by(3, 42u64.to_le_bytes().to_vec());
    let j = witness.verify().unwrap();
    let bytes = encode_state_journal(&j);
    assert_eq!(bytes.len(), STATE_JOURNAL_BYTES);
    assert_eq!(decode_state_journal(&bytes).unwrap(), j);
}

#[test]
fn decoding_rejects_wrong_lengths() {
    let (witness, _) = witness_signed_by(3, vec![1]);
    let bytes = encode_state_journal(&witness.verify().unwrap());
    assert!(decode_state_journal(&bytes[..bytes.len() - 1]).is_err());
    assert!(decode_state_journal(&[bytes.clone(), vec![0]].concat()).is_err());
}

/// A u64 field with garbage in its high 24 bytes means the two sides disagree
/// about the layout. Masking it off would hide exactly the bug worth finding.
#[test]
fn decoding_rejects_u64_fields_that_overflow() {
    let (witness, _) = witness_signed_by(3, vec![1]);
    let mut bytes = encode_state_journal(&witness.verify().unwrap());
    bytes[0] = 0xFF; // high byte of `chain_id`'s word
    assert!(decode_state_journal(&bytes).is_err());
}

/// Writes the fixture the Solidity test decodes. Run with
/// `PEREGRINE_WRITE_FIXTURES=1` to regenerate; CI regenerates and diffs it, so
/// a layout change on either side shows up as a failing test rather than as a
/// misread field in production.
#[test]
fn write_solidity_fixture() {
    let (witness, digest) = witness_signed_by(3, 42u64.to_le_bytes().to_vec());
    let j = witness.verify().unwrap();
    let encoded = encode_state_journal(&j);

    let fixture = serde_json::json!({
        "_comment": "Generated by peregrine-interop tests/state_journal.rs. \
                     Decoded by contracts/test/PeregrineJournalAbi.t.sol to prove \
                     the Rust encoder and Solidity's abi.decode agree.",
        "chainId": j.chain_id,
        "round": j.round,
        "treeVersion": j.tree_version,
        "committeeDigest": format!("0x{}", hex::encode(j.committee_digest.0)),
        "storeRoot": format!("0x{}", hex::encode(j.store_root.0)),
        "table": format!("0x{}", hex::encode(j.table.0 .0)),
        "keyHash": format!("0x{}", hex::encode(j.key_hash.0)),
        "value": format!("0x{}", hex::encode(j.value)),
        "valueLen": j.value_len,
        "abiEncoded": format!("0x{}", hex::encode(&encoded)),
        "expectedUint": 42,
    });
    let text = serde_json::to_string_pretty(&fixture).unwrap() + "\n";

    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/test/fixtures/state-journal.json"
    );
    if std::env::var("PEREGRINE_WRITE_FIXTURES").is_ok() {
        std::fs::create_dir_all(std::path::Path::new(path).parent().unwrap()).unwrap();
        std::fs::write(path, &text).unwrap();
        eprintln!("wrote {path}");
    } else {
        let existing = std::fs::read_to_string(path)
            .expect("fixture missing — rerun with PEREGRINE_WRITE_FIXTURES=1");
        assert_eq!(
            existing, text,
            "the committed fixture no longer matches what the encoder produces; \
             regenerate with PEREGRINE_WRITE_FIXTURES=1 and re-run the Solidity tests"
        );
    }

    // Sanity: the digest the fixture pins is the one the committee produces.
    assert_eq!(j.committee_digest, digest.digest());
}
