//! Smoke test for the client-mode load harness (`peregrine bench --against`).
//!
//! It drives a *local* devnet through the same public SDK path a real run uses —
//! connect over QUIC, submit table writes, confirm each via a proven read — and
//! asserts the run actually did work and observed commits. This exercises the
//! whole client harness end to end without any WAN dependency, so it is safe for
//! CI; the real multi-host measurement is an operator step (see docs/TESTNET.md).
//!
//! It is deliberately short (2s, modest rate) and loopback, so it never flakes on
//! a busy runner the way a long WAN run would.

use peregrine_node::bench::{run_client, ClientBenchOptions};
use peregrine_node::devnet::Devnet;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_bench_drives_a_running_devnet_and_confirms_commits() {
    // A real local committee with a client-facing RPC endpoint.
    let devnet = Devnet::start().await.expect("start devnet");

    // Drive it exactly as `peregrine bench --against <rpc> --rate 200 --duration 2`
    // would: no local validators started here — we connect as an external client.
    let report = run_client(ClientBenchOptions {
        addrs: vec![devnet.rpc_addr],
        duration: Duration::from_secs(2),
        rate: 200,
        concurrency: 4,
    })
    .await
    .expect("client bench runs against the devnet");

    // It submitted work…
    assert!(
        report.submitted > 0,
        "the harness should have submitted writes (got {})",
        report.submitted
    );
    // …and observed commits via proven reads (the confirm path works)…
    assert!(
        report.confirmed > 0,
        "at least one write must be confirmed committed (submitted {}, tracked {}, confirmed {})",
        report.submitted,
        report.tracked,
        report.confirmed
    );
    // …with a real, positive publish→confirm latency recorded.
    assert!(
        report.p50_ms > 0.0,
        "a positive publish→confirm latency should be measured (p50={} ms)",
        report.p50_ms
    );
    // The node is up, so nothing should be a hard disconnect.
    assert_eq!(
        report.disconnected, 0,
        "no disconnects expected against a healthy local node"
    );

    devnet.shutdown().await.expect("shutdown");
}

/// Unreachable node → a clear, immediate error, not a hang or a run full of
/// disconnect counts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_bench_fails_clearly_when_node_unreachable() {
    // Nothing is listening here (port 1 on loopback).
    let dead: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
    let err = run_client(ClientBenchOptions {
        addrs: vec![dead],
        duration: Duration::from_secs(2),
        rate: 100,
        concurrency: 2,
    })
    .await
    .expect_err("connecting to a dead address must fail");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("cannot reach node"),
        "error should name the unreachable node, got: {msg}"
    );
}
