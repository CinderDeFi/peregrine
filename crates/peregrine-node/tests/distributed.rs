//! Three **independent** single-identity validators, each with its own QUIC
//! transport, RPC endpoint, and storage, wired only by an explicit peer list —
//! the real distributed topology, co-located on localhost. They must form a
//! committee, commit a transaction submitted to one of them, and converge on
//! the same store root.

use peregrine_core::{Hash, ValidatorId};
use peregrine_node::devnet::{run_single_validator, SingleValidatorOptions, Validator};
use peregrine_node::genesis::Genesis;
use peregrine_sdk::{Client, Instr, TableId};
use std::net::SocketAddr;
use std::time::Duration;

/// Grab `n` distinct free UDP ports (bind all at once so they can't collide,
/// then release for the QUIC endpoints to rebind).
fn free_addrs(n: usize) -> Vec<SocketAddr> {
    let socks: Vec<std::net::UdpSocket> = (0..n)
        .map(|_| std::net::UdpSocket::bind("127.0.0.1:0").expect("bind"))
        .collect();
    socks
        .iter()
        .map(|s| s.local_addr().expect("addr"))
        .collect()
}

/// The `sum 1..=10 = 55` loop, writing the result into `table["sum"]`.
fn sum_program(table: TableId) -> Vec<Instr> {
    let sum = b"sum".to_vec();
    vec![
        Instr::Push(0),
        Instr::StoreTable {
            table,
            key: sum.clone(),
        },
        Instr::Push(10),
        Instr::Dup,
        Instr::JumpIf(6),
        Instr::Jump(13),
        Instr::Dup,
        Instr::LoadTable {
            table,
            key: sum.clone(),
        },
        Instr::Add,
        Instr::StoreTable {
            table,
            key: sum.clone(),
        },
        Instr::Push(1),
        Instr::Sub,
        Instr::Jump(3),
        Instr::Halt,
    ]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn three_independent_validators_form_a_committee_and_converge() {
    // A 3-validator genesis; each validator will be launched as its own process.
    let (genesis, keys, _) = Genesis::generate(3, 777, "dist-test", false);
    let committee = genesis.committee().expect("committee");
    let addrs = free_addrs(3);

    // Launch three separate single-identity validators. Each binds its own mesh
    // endpoint, dials the others (retry/backoff handles start order), serves its
    // own RPC, and keeps in-memory state. This is exactly the three-server
    // deployment, minus the physical hosts.
    let mut validators: Vec<Validator> = Vec::new();
    for (i, kp) in keys.into_iter().enumerate() {
        let v = run_single_validator(SingleValidatorOptions {
            identity: ValidatorId(i as u16),
            keypair: kp,
            committee: committee.clone(),
            addrs: addrs.clone(),
            rpc_addr: "127.0.0.1:0".parse().unwrap(),
            max_items_per_vertex: 512,
            storage: None,
            chain_id: genesis.chain_id,
            faucet: None,
            allocations: vec![],
        })
        .await
        .expect("start validator");
        validators.push(v);
    }

    // Submit a transaction through validator 0's RPC; it must disseminate and
    // commit on all three.
    let table = TableId::named("dist.contract");
    let client0 = Client::connect(validators[0].rpc_addr)
        .await
        .expect("connect v0");
    client0
        .submit_tx(sum_program(table))
        .await
        .expect("submit tx");

    // One client per validator, to read each node's own committed state.
    let mut clients = Vec::new();
    for v in &validators {
        clients.push(Client::connect(v.rpc_addr).await.expect("connect"));
    }

    // Poll until every validator proves sum == 55 against its own root, and all
    // three roots agree. Empty rounds don't change the store, so once all have
    // the one committed tx their roots are identical.
    let mut converged = false;
    let mut last_roots: Vec<Hash> = Vec::new();
    for _ in 0..200 {
        last_roots.clear();
        let mut all_have_sum = true;
        for c in &clients {
            let root = c.store_root().await.expect("root");
            last_roots.push(root);
            match c.prove_read(table, b"sum").await.expect("read") {
                Some(read)
                    if read.verify(&root)
                        && u64::from_le_bytes(read.value[..8].try_into().unwrap()) == 55 => {}
                _ => all_have_sum = false,
            }
        }
        let all_equal = last_roots.windows(2).all(|w| w[0] == w[1]);
        if all_have_sum && all_equal && last_roots[0] != Hash::ZERO {
            converged = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    assert!(
        converged,
        "three validators must form a committee, commit the tx, and converge on one root; \
         last roots = {last_roots:?}"
    );

    for v in validators {
        v.shutdown().await.expect("shutdown");
    }
}

#[tokio::test]
async fn single_validator_fails_closed_on_misconfiguration() {
    use peregrine_core::Keypair;
    let (genesis, keys, _) = Genesis::generate(3, 1, "fail-closed", false);
    let committee = genesis.committee().expect("committee");
    let addrs = free_addrs(3);

    let opts = |identity, keypair, addrs: Vec<SocketAddr>| SingleValidatorOptions {
        identity,
        keypair,
        committee: committee.clone(),
        addrs,
        rpc_addr: "127.0.0.1:0".parse().unwrap(),
        max_items_per_vertex: 512,
        storage: None,
        chain_id: 1,
        faucet: None,
        allocations: vec![],
    };
    let dup = |kp: &Keypair| Keypair::from_bytes(&kp.to_bytes());

    // Wrong key for the identity → refused (fail-closed).
    let e = run_single_validator(opts(
        ValidatorId(0),
        Keypair::from_bytes(&[200; 32]),
        addrs.clone(),
    ))
    .await
    .err()
    .expect("must fail")
    .to_string();
    assert!(e.contains("public key mismatch"), "got: {e}");

    // Identity index out of range → refused.
    let e = run_single_validator(opts(ValidatorId(5), dup(&keys[0]), addrs.clone()))
        .await
        .err()
        .expect("must fail")
        .to_string();
    assert!(e.contains("out of range"), "got: {e}");

    // Address list doesn't cover the committee → refused.
    let e = run_single_validator(opts(ValidatorId(0), dup(&keys[0]), addrs[..2].to_vec()))
        .await
        .err()
        .expect("must fail")
        .to_string();
    assert!(e.contains("validator addresses"), "got: {e}");
}
