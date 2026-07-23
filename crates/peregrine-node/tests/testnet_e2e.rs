//! End-to-end testnet path: launch a devnet **from genesis** (chain id, faucet,
//! and initial allocations included), then drive it over the real QUIC RPC —
//! confirming a genesis allocation, a faucet drip, and that a forged drip does
//! nothing. This is the flow a public testnet operator and a developer follow.

use peregrine_core::Keypair;
use peregrine_data::faucet::{FaucetDrip, SignedDrip};
use peregrine_node::devnet::{Devnet, DevnetOptions};
use peregrine_node::genesis::{Genesis, GenesisAllocation};
use peregrine_sdk::Client;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

/// Poll a proven balance until it reaches `target` (commit is asynchronous).
async fn await_balance(client: &Client, who: &peregrine_core::PublicKey, target: u64) -> u64 {
    for _ in 0..100 {
        let b = client.balance_of(who).await.expect("balance");
        if b >= target {
            return b;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    client.balance_of(who).await.expect("balance")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_testnet_launches_from_genesis_and_the_faucet_works() {
    // A genesis with a faucet and one pre-funded account.
    let (mut genesis, validator_keys, faucet_key) =
        Genesis::generate(4, 424242, "peregrine-testnet-e2e", true);
    let faucet_key = faucet_key.expect("faucet requested");

    let prefunded = Keypair::from_bytes(&[88; 32]);
    genesis.allocations.push(GenesisAllocation {
        account: hex::encode(prefunded.public().0),
        grains: 5_000,
    });
    genesis.validate().expect("valid genesis");

    let runtime = genesis.runtime(validator_keys).expect("bind keys");
    let devnet = Devnet::launch_from_genesis(
        DevnetOptions {
            validators: 4,
            rpc_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            max_items_per_vertex: 512,
            stream: "testnet/e2e".into(),
            storage: None,
        },
        runtime,
    )
    .await
    .expect("launch from genesis");

    let client = Client::connect(devnet.rpc_addr).await.expect("connect");

    // (1) the genesis allocation is present and provable from round one.
    assert_eq!(
        await_balance(&client, &prefunded.public(), 5_000).await,
        5_000
    );

    // (2) a signed faucet drip credits its recipient, over the wire.
    let alice = Keypair::from_bytes(&[77; 32]).public();
    let drip = FaucetDrip {
        recipient: alice,
        amount: 1_000,
        nonce: 0,
    };
    client
        .submit_drip(SignedDrip::new(&faucet_key, drip))
        .await
        .expect("submit drip");
    assert_eq!(await_balance(&client, &alice, 1_000).await, 1_000);

    // (3) a drip signed by anyone but the faucet authority credits nothing.
    let impostor = Keypair::from_bytes(&[66; 32]);
    let bob = Keypair::from_bytes(&[55; 32]).public();
    client
        .submit_drip(SignedDrip::new(
            &impostor,
            FaucetDrip {
                recipient: bob,
                amount: 500,
                nonce: 0,
            },
        ))
        .await
        .expect("queued");
    // Give it time to be committed and refused.
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(
        client.balance_of(&bob).await.unwrap(),
        0,
        "a forged drip funds nobody"
    );

    devnet.shutdown().await.expect("shutdown");
}
