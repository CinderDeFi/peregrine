//! Where does the time go for one inbound vertex?
//!
//! ```bash
//! cargo run --release -p peregrine-node --example vertex_profile
//! ```
//!
//! The tiled pipeline is a bet that per-vertex cost is (a) large, (b)
//! parallelisable, and (c) currently serialised on the consensus thread. This
//! measures each step so that bet is made on numbers rather than on the usual
//! folklore about where blockchain nodes spend their time.

use peregrine_consensus::{Dag, Payload, PayloadItem, Vertex};
use peregrine_core::{Committee, Keypair, ValidatorId, ValidatorInfo};
use peregrine_data::streams::Publisher;
use peregrine_node::payload::WirePayload;
use std::time::Instant;

fn bench<T>(label: &str, iters: u32, mut f: impl FnMut() -> T) -> f64 {
    // One warm-up pass so allocator and branch predictors are not measured.
    std::hint::black_box(f());
    let t0 = Instant::now();
    for _ in 0..iters {
        std::hint::black_box(f());
    }
    let per = t0.elapsed().as_secs_f64() * 1e6 / iters as f64;
    println!("  {label:<38} {per:>9.1} µs");
    per
}

fn main() {
    let mut rng = rand::rngs::OsRng;
    let kp = Keypair::generate(&mut rng);
    let id = ValidatorId(0);
    let committee = Committee::new(vec![ValidatorInfo {
        id,
        public_key: kp.public(),
        stake: 100,
    }]);

    for items_per_vertex in [64usize, 512] {
        // A realistic payload: signed stream shreds, the thing that actually
        // rides consensus in this system.
        let mut pubr = Publisher::new("bench/feed", Keypair::generate(&mut rng));
        let items: Vec<PayloadItem> = (0..items_per_vertex)
            .map(|i| {
                let shred = pubr.emit((i as u64).to_le_bytes().to_vec());
                PayloadItem(WirePayload::Shred(shred).encode())
            })
            .collect();
        let payload = Payload { items };
        let vertex = Vertex::new_signed(&kp, id, 0, vec![], payload.clone());
        let wire = bincode::serialize(&vertex).expect("serialize");

        println!(
            "\n── {items_per_vertex} items/vertex ({} KiB on the wire) ──",
            wire.len() / 1024
        );

        let deser = bench("bincode::deserialize (wire → Vertex)", 200, || {
            bincode::deserialize::<Vertex>(&wire).unwrap()
        });
        let digest = bench("payload.digest() (blake3 over items)", 200, || {
            payload.digest()
        });
        let hash = bench("vertex.hash() (uncached)", 200, || {
            bincode::deserialize::<Vertex>(&wire).unwrap().hash()
        });
        let verify = bench("vertex.verify() (digest + ed25519)", 200, || {
            vertex.verify(&kp.public()).unwrap()
        });
        let clone = bench("vertex.clone() (deep copy of payload)", 200, || {
            vertex.clone()
        });
        let insert = bench("Dag::insert (fresh dag, incl. verify)", 200, || {
            let mut dag = Dag::new(committee.clone(), vec![]);
            dag.insert(vertex.clone()).unwrap()
        });
        let decode = bench("decode all items (WirePayload)", 200, || {
            payload
                .items
                .iter()
                .filter_map(|i| WirePayload::decode(&i.0))
                .count()
        });

        // The signature check alone, with no payload work, to separate the
        // fixed crypto cost from the payload-proportional cost.
        let hdr = bincode::serialize(&vertex.header).unwrap();
        let sig_only = bench("ed25519 verify alone (header only)", 200, || {
            peregrine_core::crypto::verify(
                &kp.public(),
                b"peregrine.vertex.v1",
                &hdr,
                &vertex.signature,
            )
        });

        println!("  {:-<50}", "");
        println!(
            "  {:<38} {:>9.1} µs",
            "payload-proportional in verify()", digest
        );
        println!("  {:<38} {:>9.1} µs", "fixed crypto in verify()", sig_only);
        println!(
            "  {:<38} {:>9.1} µs",
            "TOTAL on the consensus thread today",
            deser + insert + clone
        );
        println!(
            "  {:<38} {:>9.1} µs",
            "  of which is parallelisable",
            deser + verify + hash
        );
        let _ = (hash, decode);
    }

    println!(
        "\nThe parallelisable part is signature + digest + decode: pure functions of\n\
         one vertex, with no DAG state involved. That is what the verify tiles take.\n"
    );

    // ── the commit side ─────────────────────────────────────────────────────
    // Execution is inherently serial (it is the state transition), so it cannot
    // be tiled away. If it dominates, tiling the verify path buys little and
    // the honest answer is to say so.
    println!("── commit-side (serial by definition) ──");
    let mut pipeline = peregrine_node::pipeline::ExecutionPipeline::new();
    let pub_kp = Keypair::generate(&mut rng);
    // MUST register, or `apply_committed` bails with UnknownStream *before* the
    // signature check and the measurement is meaningless.
    pipeline.streams.register("bench/apply", pub_kp.public());
    let mut pubr = Publisher::new("bench/apply", pub_kp);
    let shreds: Vec<WirePayload> = (0..2000)
        .map(|i| WirePayload::Shred(pubr.emit((i as u64).to_le_bytes().to_vec())))
        .collect();

    let t0 = Instant::now();
    for s in &shreds {
        pipeline.apply_payload(s);
    }
    let per_item = t0.elapsed().as_secs_f64() * 1e6 / shreds.len() as f64;
    println!(
        "  {:<38} {per_item:>9.1} µs",
        "apply_payload (shred → SMT row)"
    );

    // `store_root()` refreshes every table's tree. Called per RPC read today.
    let root = bench("store_root() after 2000 rows", 100, || {
        pipeline.store_root()
    });

    println!("  {:<38} {:>9.1} µs", "store_root() refresh", root);

    // Decompose that 108 µs: which part is parallelisable and which is an
    // irreducibly serial state transition? The answer decides the design.
    // `signing_bytes` is private, so measure an equivalent-sized message: the
    // cost of ed25519 is a function of message length, not of its contents.
    let msg = vec![0u8; 64];
    let sig_kp = Keypair::generate(&mut rng);
    let sig = sig_kp.sign(b"peregrine.stream.v1", &msg);
    let sig_verify = bench("  |- ed25519 per record (parallelisable)", 500, || {
        peregrine_core::crypto::verify(&sig_kp.public(), b"peregrine.stream.v1", &msg, &sig)
    });

    let mut tbl = peregrine_data::tables::TableStore::new();
    let mut n = 0u64;
    let smt = bench("  └ SMT insert per row (SERIAL)", 500, || {
        n += 1;
        let mut key = Vec::with_capacity(40);
        key.extend_from_slice(&[0u8; 32]);
        key.extend_from_slice(&n.to_be_bytes());
        tbl.insert(
            peregrine_data::tables::TableId::named("sys.stream_ticks"),
            key,
            vec![7u8; 8],
        );
    });

    // v2: path-compressed. Same workload, so the numbers are comparable.
    let mut t2 = peregrine_data::smt_v2::SmtV2::new();
    let mut m = 0u64;
    let smt2 = bench("  |- SMT v2 insert per row (SERIAL)", 500, || {
        m += 1;
        let mut key = Vec::with_capacity(40);
        key.extend_from_slice(&[0u8; 32]);
        key.extend_from_slice(&m.to_be_bytes());
        t2.insert(&key, &[7u8; 8]);
    });

    println!("\n  ── the verdict ──");
    println!("  per record            : {per_item:>7.1} µs");
    println!(
        "  ├ ed25519 (parallel)  : {sig_verify:>7.1} µs  ({:.0}%)",
        100.0 * sig_verify / per_item
    );
    println!(
        "  ├ SMT v1 (serial)     : {smt:>7.1} µs  ({:.0}%)",
        100.0 * smt / per_item
    );
    println!(
        "  ├ SMT v2 (serial)     : {smt2:>7.1} µs  <- {:.0}x faster, path-compressed",
        smt / smt2.max(f64::MIN_POSITIVE)
    );
    println!(
        "  └ other               : {:>7.1} µs",
        per_item - sig_verify - smt
    );
    println!(
        "\n  A 512-item vertex costs ~{:.0} ms to execute; 4 per round ≈ {:.0} ms/round,\n  \
         which is exactly the round time the benchmark shows.",
        per_item * 512.0 / 1000.0,
        per_item * 512.0 * 4.0 / 1000.0
    );
}
