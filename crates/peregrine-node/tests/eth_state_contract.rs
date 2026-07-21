//! A Talon contract consuming **verified Ethereum state**, end to end.
//!
//! The full round-trip this exercises:
//!
//! ```text
//!   beacon update ──▶ Anchor ──▶ ForeignClaim (proof-carrying)
//!        └── verified on-chain ──▶ sys.eth_state ──▶ LoadEthState ──▶ contract
//! ```
//!
//! The security property under test is the one that distinguishes this from a
//! bridge: a contract reading Ethereum state either gets a **verified** value
//! or the transaction **traps**. There is no path where "we couldn't verify it"
//! silently becomes "the value is zero".

use peregrine_data::tables::TableId;
use peregrine_interop::beacon::Anchor;
use peregrine_interop::zk::{Claim, Journal, NativeProver, NativeVerifier, Prover};
use peregrine_node::payload::WirePayload;
use peregrine_node::pipeline::{ClaimPolicy, ExecutionPipeline};
use peregrine_vm::Instr;

const MAINNET: u64 = 1;
/// WETH, the contract we proved real storage for in `tests/mainnet.rs`.
const WETH: [u8; 20] = [
    0xc0, 0x2a, 0xaa, 0x39, 0xb2, 0x23, 0xfe, 0x8d, 0x0a, 0x0e, 0x5c, 0x4f, 0x27, 0xea, 0xd9, 0x08,
    0x3c, 0x75, 0x6c, 0xc2,
];
const ANCHORED_BLOCK: [u8; 32] = [0x11; 32];

/// Slot 2 of WETH holds `decimals` — 18 on mainnet.
fn decimals_slot() -> [u8; 32] {
    let mut s = [0u8; 32];
    s[31] = 2;
    s
}

fn word(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}

/// A node that has processed a beacon update and trusts one execution block.
fn node() -> ExecutionPipeline {
    let mut p = ExecutionPipeline::new();
    p.claim_policy = ClaimPolicy::Verified {
        verifier: Box::new(NativeVerifier),
        chain_id: MAINNET,
    };
    p.anchors
        .insert(Anchor {
            slot: 14_817_376,
            block_number: 25_580_735,
            block_hash: ANCHORED_BLOCK,
            state_root: [0x22; 32],
        })
        .unwrap();
    p
}

fn storage_claim(value: [u8; 32]) -> peregrine_interop::VerifiedClaim {
    NativeProver
        .prove(Journal {
            chain_id: MAINNET,
            block_number: 25_580_735,
            block_hash: ANCHORED_BLOCK,
            state_root: [0x22; 32],
            claim: Claim::Storage {
                address: WETH,
                slot: decimals_slot(),
                value,
            },
        })
        .unwrap()
}

/// A contract that reads WETH's `decimals` from Ethereum and stores it locally.
fn reader_program(out: TableId) -> Vec<Instr> {
    vec![
        Instr::LoadEthState {
            chain_id: MAINNET,
            address: WETH,
            slot: decimals_slot(),
        },
        Instr::StoreTable {
            table: out,
            key: b"weth_decimals".to_vec(),
        },
        Instr::Halt,
    ]
}

/// The happy path: claim verifies, contract reads the real value.
#[test]
fn contract_reads_verified_ethereum_state() {
    let mut pipeline = node();
    let out = TableId::named("app.mirror");

    // Before the claim, the contract cannot read it — and must *fail*, not
    // silently see zero.
    pipeline.apply_payload(&WirePayload::TalonTx {
        program: reader_program(out),
    });
    assert!(
        pipeline.prove_read(out, b"weth_decimals").is_none(),
        "an unverified read must trap, leaving nothing written"
    );

    // Submit the proof-carrying claim; every validator verifies it on commit.
    assert!(pipeline
        .apply_foreign_claim(&storage_claim(word(18)))
        .unwrap());

    // Now the same contract succeeds.
    pipeline.apply_payload(&WirePayload::TalonTx {
        program: reader_program(out),
    });
    let read = pipeline
        .prove_read(out, b"weth_decimals")
        .expect("contract wrote its result");
    assert_eq!(u64::from_le_bytes(read.value[..8].try_into().unwrap()), 18);

    // And the mirrored value is provable against Peregrine's store root, so a
    // light client can check an Ethereum-derived fact with 32 bytes.
    let root = pipeline.store_root();
    assert!(read.verify(&root));
}

/// The headline safety property, stated as a test: **absence traps**.
#[test]
fn unverified_state_traps_instead_of_reading_zero() {
    let mut pipeline = node();
    let out = TableId::named("app.mirror");

    // A slot nobody has proven.
    let mut unknown = [0u8; 32];
    unknown[31] = 99;
    let program = vec![
        Instr::LoadEthState {
            chain_id: MAINNET,
            address: WETH,
            slot: unknown,
        },
        Instr::StoreTable {
            table: out,
            key: b"never".to_vec(),
        },
        Instr::Halt,
    ];
    pipeline.apply_payload(&WirePayload::TalonTx { program });

    assert!(
        pipeline.prove_read(out, b"never").is_none(),
        "the tx must trap before storing anything"
    );
}

/// A value wider than 64 bits refuses rather than silently truncating — the
/// difference between a wrong balance and a failed transaction.
#[test]
fn oversized_values_refuse_to_truncate() {
    let mut pipeline = node();
    let out = TableId::named("app.mirror");

    // A full 32-byte word, e.g. a large token balance.
    let mut big = [0u8; 32];
    big[0] = 0x01;
    assert!(pipeline.apply_foreign_claim(&storage_claim(big)).unwrap());

    pipeline.apply_payload(&WirePayload::TalonTx {
        program: reader_program(out),
    });
    assert!(
        pipeline.prove_read(out, b"weth_decimals").is_none(),
        "a value that cannot fit in u64 must trap, not truncate"
    );
}

/// Claims for a chain the node does not accept never reach a contract.
#[test]
fn state_from_an_unaccepted_chain_is_not_readable() {
    let mut pipeline = node();
    const SEPOLIA: u64 = 11_155_111;

    let claim = NativeProver
        .prove(Journal {
            chain_id: SEPOLIA,
            block_number: 1,
            block_hash: ANCHORED_BLOCK,
            state_root: [0x22; 32],
            claim: Claim::Storage {
                address: WETH,
                slot: decimals_slot(),
                value: word(999),
            },
        })
        .unwrap();
    assert!(pipeline.apply_foreign_claim(&claim).is_err());

    let out = TableId::named("app.mirror");
    let program = vec![
        Instr::LoadEthState {
            chain_id: SEPOLIA,
            address: WETH,
            slot: decimals_slot(),
        },
        Instr::StoreTable {
            table: out,
            key: b"x".to_vec(),
        },
        Instr::Halt,
    ];
    pipeline.apply_payload(&WirePayload::TalonTx { program });
    assert!(pipeline.prove_read(out, b"x").is_none());
}
