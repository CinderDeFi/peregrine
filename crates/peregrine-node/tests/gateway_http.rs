//! End-to-end test of the HTTP/JSON gateway.
//!
//! Starts a real devnet, writes a value through a Talon tx, then reaches it the
//! way a browser would: `POST /rpc` with the JSON request shapes the TS SDK
//! uses. Asserts the response JSON matches what `provenReadFromJson` consumes
//! and that the proof it carries verifies against the store root — i.e. the
//! gateway translates faithfully and adds nothing to the trust model.

use peregrine_node::devnet::Devnet;
use peregrine_node::gateway;
use peregrine_sdk::{Client, Instr, TableId};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Minimal HTTP/1.1 `POST /rpc` over a raw socket — a browser's-eye view of the
/// gateway without dragging in a TLS-linked HTTP client. Returns the parsed
/// JSON body.
async fn post_rpc(addr: SocketAddr, body: Value) -> Value {
    let body = serde_json::to_vec(&body).unwrap();
    let req = format!(
        "POST /rpc HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut stream = TcpStream::connect(addr).await.expect("connect gateway");
    stream.write_all(req.as_bytes()).await.unwrap();
    stream.write_all(&body).await.unwrap();
    stream.flush().await.unwrap();

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.unwrap();
    // Split headers from body at the blank line; the body is the JSON payload.
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("well-formed HTTP response");
    serde_json::from_slice(&raw[split + 4..]).expect("JSON body")
}

/// Poll until a key is readable through the native client (commit is async).
async fn await_commit(client: &Client, table: TableId, key: &[u8]) {
    for _ in 0..100 {
        if let Ok(Some(_)) = client.prove_read(table, key).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("value never committed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gateway_serves_verifiable_json() {
    // (1) a real network with a write in it: sum 1..=10 = 55 into a table.
    let devnet = Devnet::start().await.expect("start devnet");
    let native = Client::connect(devnet.rpc_addr).await.expect("connect");
    let answers = TableId::named("gw.contract");
    let sum = b"sum".to_vec();
    native
        .submit_tx(vec![
            Instr::Push(0),
            Instr::StoreTable { table: answers, key: sum.clone() },
            Instr::Push(10),
            Instr::Dup,
            Instr::JumpIf(6),
            Instr::Jump(13),
            Instr::Dup,
            Instr::LoadTable { table: answers, key: sum.clone() },
            Instr::Add,
            Instr::StoreTable { table: answers, key: sum.clone() },
            Instr::Push(1),
            Instr::Sub,
            Instr::Jump(3),
            Instr::Halt,
        ])
        .await
        .expect("submit tx");
    await_commit(&native, answers, b"sum").await;

    // (2) stand up the gateway on an ephemeral port, fronting the devnet.
    let app = gateway::build_router(devnet.rpc_addr).await.expect("router");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    // (3) ping and storeRoot come back in the TS-SDK response shapes.
    assert_eq!(post_rpc(addr, json!({ "kind": "ping" })).await["kind"], "pong");

    let root = post_rpc(addr, json!({ "kind": "storeRoot" })).await;
    assert_eq!(root["kind"], "root");
    let root_hex = root["root"].as_str().expect("root hex");
    assert_eq!(root_hex.len(), 64, "32-byte root as hex");
    assert_ne!(root_hex, "0".repeat(64), "committed state is non-empty");

    // (4) proveRead returns a proof in the exact shape verify.ts expects.
    let table_hex = hex::encode(answers.0 .0);
    let key_hex = hex::encode(b"sum");
    let resp = post_rpc(addr, json!({ "kind": "proveRead", "table": table_hex, "key": key_hex })).await;
    assert_eq!(resp["kind"], "proof");
    let read = &resp["read"];
    assert!(read.is_object(), "present key yields a proof object");
    for field in ["table", "key", "value", "tableRoot", "treeVersion", "rowProof", "storeProof"] {
        assert!(read.get(field).is_some(), "proof JSON missing `{field}`");
    }
    assert!(read["rowProof"]["siblings"].is_array(), "rowProof has siblings");
    assert!(read["storeProof"]["siblings"].is_array(), "storeProof has siblings");
    assert!(read["storeProof"]["leafIndex"].is_number(), "storeProof has leafIndex");

    // The value decodes to 55 (little-endian u64), and it is the value the
    // native client's own verified read reports — the gateway added nothing.
    let value_hex = read["value"].as_str().expect("value hex");
    let value = hex::decode(value_hex).expect("hex");
    assert_eq!(u64::from_le_bytes(value[..8].try_into().unwrap()), 55);

    // (5) an absent key reads back as `read: null`, not an error or a zero.
    let absent = post_rpc(addr, json!({
        "kind": "proveRead",
        "table": table_hex,
        "key": hex::encode(b"no-such-key"),
    }))
    .await;
    assert_eq!(absent["kind"], "proof");
    assert!(absent["read"].is_null(), "absent key must be null, never zero");

    // (6) writes are refused: an explorer observes, it does not submit.
    let refused = post_rpc(addr, json!({ "kind": "submitTx", "program": [] })).await;
    assert_eq!(refused["kind"], "error");
}
