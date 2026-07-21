//! Thin shim so `cargo run --example publish_stream` works. The flow itself lives in
//! `peregrine_node::demos` so the CLI (`peregrine sdk example`) runs the
//! exact same code.

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    peregrine_node::demos::publish_stream().await
}
