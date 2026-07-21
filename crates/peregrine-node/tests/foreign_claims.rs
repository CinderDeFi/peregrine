//! On-chain verification of foreign-chain claims.
//!
//! A claim carries its own proof, so anyone may submit one — which means the
//! *node's* acceptance rules are the entire security boundary. These tests
//! pin down that boundary, and they run without SP1 installed because the
//! rules are pure logic.
//!
//! The end state matters as much as the decision: an accepted claim is written
//! into `sys.eth_state`, an ordinary table, so verified Ethereum state joins
//! Peregrine's store root and becomes provable to a light client like any other
//! row.

use peregrine_interop::beacon::Anchor;
use peregrine_interop::zk::{
    Claim, Journal, NativeProver, NativeVerifier, Proof, ProofSystem, Prover, StrictVerifier,
    VerifiedClaim,
};
use peregrine_node::pipeline::{eth_state_key, eth_state_table, ClaimPolicy, ExecutionPipeline};

const MAINNET: u64 = 1;
const WETH: [u8; 20] = [0xC0; 20];
/// The block every fixture journal is anchored to.
const ANCHORED_BLOCK: [u8; 32] = [0x11; 32];

/// A pipeline that trusts `ANCHORED_BLOCK`, as a node would after processing a
/// verified beacon light-client update.
fn anchored_pipeline(
    verifier: Box<dyn peregrine_interop::Verifier + Send + Sync>,
) -> ExecutionPipeline {
    let mut p = ExecutionPipeline::new();
    p.claim_policy = ClaimPolicy::Verified {
        verifier,
        chain_id: MAINNET,
    };
    p.anchors
        .insert(Anchor {
            slot: 1,
            block_number: 21_000_000,
            block_hash: ANCHORED_BLOCK,
            state_root: [0x22; 32],
        })
        .expect("first anchor");
    p
}

fn storage_journal(chain_id: u64, value: [u8; 32]) -> Journal {
    Journal {
        chain_id,
        block_number: 21_000_000,
        block_hash: [0x11; 32],
        state_root: [0x22; 32],
        claim: Claim::Storage {
            address: WETH,
            slot: [0x02; 32],
            value,
        },
    }
}

fn native_claim(chain_id: u64, value: [u8; 32]) -> VerifiedClaim {
    NativeProver
        .prove(storage_journal(chain_id, value))
        .unwrap()
}

/// The default must be to refuse. A node with no verifier configured has no
/// business accepting cross-chain state.
#[test]
fn default_policy_rejects_everything() {
    let mut pipeline = ExecutionPipeline::new();
    assert!(matches!(pipeline.claim_policy, ClaimPolicy::RejectAll));

    let err = pipeline
        .apply_foreign_claim(&native_claim(MAINNET, [0x42; 32]))
        .unwrap_err();
    assert!(err.contains("policy rejects"), "unexpected message: {err}");

    // And nothing was written.
    let key = eth_state_key(MAINNET, &WETH, &[0x02; 32]);
    assert!(pipeline.prove_read(eth_state_table(), &key).is_none());
}

/// A verified claim becomes ordinary, provable Peregrine state.
#[test]
fn verified_claim_materializes_into_provable_state() {
    let mut pipeline = anchored_pipeline(Box::new(NativeVerifier));

    let mut value = [0u8; 32];
    value[31] = 18; // WETH decimals, as recovered from a real proof elsewhere
    assert!(pipeline
        .apply_foreign_claim(&native_claim(MAINNET, value))
        .unwrap());

    // Readable by a contract via a plain table load...
    let key = eth_state_key(MAINNET, &WETH, &[0x02; 32]);
    let read = pipeline
        .prove_read(eth_state_table(), &key)
        .expect("state was written");
    assert_eq!(read.value, value.to_vec());

    // ...and provable to a light client against the store root.
    let root = pipeline.store_root();
    assert!(
        read.verify(&root),
        "foreign state must be provable like any other row"
    );
}

/// A claim about a different chain must not be accepted by a node configured
/// for mainnet — otherwise a testnet proof (valid! cheap!) becomes mainnet state.
#[test]
fn claim_for_the_wrong_chain_is_rejected() {
    let mut pipeline = anchored_pipeline(Box::new(NativeVerifier));

    const SEPOLIA: u64 = 11_155_111;
    let err = pipeline
        .apply_foreign_claim(&native_claim(SEPOLIA, [0x42; 32]))
        .unwrap_err();
    assert!(err.contains("chain"), "unexpected message: {err}");

    let key = eth_state_key(SEPOLIA, &WETH, &[0x02; 32]);
    assert!(pipeline.prove_read(eth_state_table(), &key).is_none());
}

/// Under a strict verifier — what a real deployment runs — an unproven claim is
/// refused even though the plumbing would happily store it.
#[test]
fn strict_policy_refuses_unproven_claims() {
    let mut pipeline = ExecutionPipeline::new();
    pipeline.claim_policy = ClaimPolicy::Verified {
        verifier: Box::new(StrictVerifier {
            expected_image_id: [0xAA; 32],
        }),
        chain_id: MAINNET,
    };

    assert!(pipeline
        .apply_foreign_claim(&native_claim(MAINNET, [0x42; 32]))
        .is_err());

    // A ZK proof of the *wrong program* is refused too.
    let wrong_program = VerifiedClaim {
        journal: storage_journal(MAINNET, [0x42; 32]),
        proof: Proof::Zk {
            system: ProofSystem::Sp1,
            image_id: [0xEE; 32],
            bytes: vec![1, 2, 3],
        },
    };
    assert!(pipeline.apply_foreign_claim(&wrong_program).is_err());

    let key = eth_state_key(MAINNET, &WETH, &[0x02; 32]);
    assert!(pipeline.prove_read(eth_state_table(), &key).is_none());
}

/// Header-chain claims verify but store nothing — they exist to anchor later
/// storage claims, and must not silently write a row.
#[test]
fn non_storage_claims_verify_without_writing_state() {
    let mut pipeline = anchored_pipeline(Box::new(NativeVerifier));

    let journal = Journal {
        chain_id: MAINNET,
        block_number: 21_000_000,
        block_hash: [0x11; 32],
        state_root: [0x22; 32],
        claim: Claim::HeaderChain {
            from_block: 20_999_900,
            to_block: 21_000_000,
        },
    };
    let claim = NativeProver.prove(journal).unwrap();
    let root_before = pipeline.store_root();

    assert!(
        !pipeline.apply_foreign_claim(&claim).unwrap(),
        "nothing to materialize"
    );
    assert_eq!(
        pipeline.store_root(),
        root_before,
        "state root must be untouched"
    );
}

/// Re-submitting the same claim is idempotent: the value is already there, and
/// the state root does not drift.
#[test]
fn replaying_a_claim_is_idempotent() {
    let mut pipeline = anchored_pipeline(Box::new(NativeVerifier));

    let claim = native_claim(MAINNET, [0x07; 32]);
    pipeline.apply_foreign_claim(&claim).unwrap();
    let root_once = pipeline.store_root();

    pipeline.apply_foreign_claim(&claim).unwrap();
    assert_eq!(
        pipeline.store_root(),
        root_once,
        "replay must not change state"
    );
}

/// **Anchoring is mandatory.** A perfectly-verified claim about a block this
/// node has not anchored must still be refused — otherwise a relayer could
/// prove a self-consistent chain it invented.
#[test]
fn unanchored_block_is_rejected_even_with_a_valid_proof() {
    let mut pipeline = anchored_pipeline(Box::new(NativeVerifier));

    let mut journal = storage_journal(MAINNET, [0x42; 32]);
    journal.block_hash = [0x99; 32]; // never anchored
    let claim = NativeProver.prove(journal).unwrap();

    let err = pipeline.apply_foreign_claim(&claim).unwrap_err();
    assert!(err.contains("not anchored"), "unexpected message: {err}");

    let key = eth_state_key(MAINNET, &WETH, &[0x02; 32]);
    assert!(pipeline.prove_read(eth_state_table(), &key).is_none());
}

/// A node with no anchors at all accepts nothing — the fail-closed default.
#[test]
fn a_node_without_anchors_accepts_nothing() {
    let mut pipeline = ExecutionPipeline::new();
    pipeline.claim_policy = ClaimPolicy::Verified {
        verifier: Box::new(NativeVerifier),
        chain_id: MAINNET,
    };
    assert!(pipeline.anchors.is_empty());
    assert!(pipeline
        .apply_foreign_claim(&native_claim(MAINNET, [0x42; 32]))
        .is_err());
}

// ── consensus safety: bounding proof-verification work ──────────────────────

/// Proof verification is orders of magnitude costlier than anything else on the
/// commit path, so a vertex stuffed with claims must not be able to halt
/// consensus. The budget caps it.
#[test]
fn verification_work_is_bounded_per_commit() {
    use peregrine_node::pipeline::MAX_CLAIMS_PER_COMMIT;

    let mut pipeline = anchored_pipeline(Box::new(NativeVerifier));

    // Distinct claims so nothing is deduplicated by accident.
    let mut accepted = 0;
    let mut refused = 0;
    for i in 0..(MAX_CLAIMS_PER_COMMIT + 3) {
        let mut value = [0u8; 32];
        value[31] = i as u8;
        match pipeline.apply_foreign_claim(&native_claim(MAINNET, value)) {
            Ok(_) => accepted += 1,
            Err(e) => {
                assert!(e.contains("budget exhausted"), "unexpected refusal: {e}");
                refused += 1;
            }
        }
    }
    assert_eq!(
        accepted, MAX_CLAIMS_PER_COMMIT,
        "exactly the budget is honoured"
    );
    assert_eq!(refused, 3, "the rest are refused, not silently dropped");
}

/// The budget must be *deterministic*: two validators replaying the same
/// committed order must accept exactly the same claims, or they fork.
#[test]
fn the_budget_is_deterministic_across_validators() {
    use peregrine_node::pipeline::MAX_CLAIMS_PER_COMMIT;

    let claims: Vec<_> = (0..(MAX_CLAIMS_PER_COMMIT + 2))
        .map(|i| {
            let mut v = [0u8; 32];
            v[31] = i as u8;
            native_claim(MAINNET, v)
        })
        .collect();

    let run = || {
        let mut p = anchored_pipeline(Box::new(NativeVerifier));
        let outcomes: Vec<bool> = claims
            .iter()
            .map(|c| p.apply_foreign_claim(c).is_ok())
            .collect();
        (outcomes, p.store_root())
    };

    let (outcomes_a, root_a) = run();
    let (outcomes_b, root_b) = run();
    assert_eq!(
        outcomes_a, outcomes_b,
        "same order must give the same decisions"
    );
    assert_eq!(root_a, root_b, "and therefore the same state root");
}

/// A build without a proving backend must refuse ZK claims outright — the
/// fail-closed default that keeps an unverifiable claim from being applied.
#[test]
fn a_node_without_a_backend_refuses_zk_claims() {
    use peregrine_node::pipeline::ClaimPolicy;

    let mut pipeline = ExecutionPipeline::new();
    pipeline.claim_policy = ClaimPolicy::strict([0xAA; 32], MAINNET);
    pipeline
        .anchors
        .insert(Anchor {
            slot: 1,
            block_number: 21_000_000,
            block_hash: ANCHORED_BLOCK,
            state_root: [0x22; 32],
        })
        .unwrap();

    let zk = VerifiedClaim {
        journal: storage_journal(MAINNET, [0x42; 32]),
        proof: Proof::Zk {
            system: ProofSystem::Sp1,
            image_id: [0xAA; 32], // correct image, but nothing can check it
            bytes: vec![1, 2, 3],
        },
    };
    let err = pipeline.apply_foreign_claim(&zk).unwrap_err();
    assert!(
        err.contains("not wired up") || err.contains("Sp1"),
        "expected an unsupported-backend refusal, got: {err}"
    );

    // And a native claim is refused for the other reason: no cryptography.
    assert!(pipeline
        .apply_foreign_claim(&native_claim(MAINNET, [0x42; 32]))
        .is_err());
}
