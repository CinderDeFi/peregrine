//! **The v1 → v2 Merkle upgrade.**
//!
//! Path compression changes what a node hash means, so it changes every store
//! root. That makes it a consensus upgrade, and the questions worth testing are
//! not "does the new tree work" (that is covered in `peregrine-data::smt_v2`)
//! but:
//!
//! * does migration preserve *state* while changing only its commitment?
//! * do all validators switch at the same committed round?
//! * does a migrated node come back from disk under the right rule?
//! * do old proofs still verify against old roots, and are they refused
//!   against new ones?
//!
//! A mistake in any of these forks the chain, so each gets a test.

use peregrine_data::tables::{TableId, TableStore, TreeVersion};
use peregrine_node::pipeline::ExecutionPipeline;
use peregrine_node::store::StateSnapshot;

fn table() -> TableId {
    TableId::named("migration.rows")
}

fn populate(store: &mut TableStore, n: u32) {
    for i in 0..n {
        store.insert(
            table(),
            format!("key-{i}").into_bytes(),
            format!("value-{i}").into_bytes(),
        );
    }
}

// ── the state itself must not move ──────────────────────────────────────────

/// Migration re-commits state; it does not rewrite it. Every row must read back
/// byte-identical afterwards — if a migration could change a *value*, it would
/// be a state transition masquerading as an upgrade.
#[test]
fn migration_preserves_every_row() {
    let mut store = TableStore::new();
    populate(&mut store, 500);

    let before: Vec<(Vec<u8>, Vec<u8>)> = (0..500)
        .map(|i| {
            let k = format!("key-{i}").into_bytes();
            let v = store.get(&table(), &k).unwrap().to_vec();
            (k, v)
        })
        .collect();

    store.migrate_to_v2();
    assert_eq!(store.version(), TreeVersion::V2);

    for (k, v) in &before {
        assert_eq!(
            store.get(&table(), k).map(|x| x.to_vec()).as_ref(),
            Some(v),
            "row changed across migration"
        );
    }
}

/// The root *must* change — that is the whole point, and a light client that
/// did not re-pin would otherwise silently accept stale proofs.
#[test]
fn migration_changes_the_store_root() {
    let mut store = TableStore::new();
    populate(&mut store, 100);
    let v1_root = store.store_root();

    let v2_root = store.migrate_to_v2();
    assert_ne!(v1_root, v2_root, "v2 must not reuse the v1 commitment");
}

/// Migrating twice is a no-op. A replayed activation — a node restarted mid
/// upgrade, a round re-delivered — must not churn the root.
#[test]
fn migration_is_idempotent() {
    let mut store = TableStore::new();
    populate(&mut store, 50);
    let once = store.migrate_to_v2();
    let twice = store.migrate_to_v2();
    assert_eq!(once, twice);
    assert_eq!(store.version(), TreeVersion::V2);
}

/// Migrating and building v2 from scratch must land on the same root, or the
/// migration path and the steady-state path disagree and a rebuilt node forks
/// from a migrated one.
#[test]
fn migrated_root_equals_natively_built_v2_root() {
    let mut migrated = TableStore::new();
    populate(&mut migrated, 300);
    let migrated_root = migrated.migrate_to_v2();

    let mut native = TableStore::with_version(TreeVersion::V2);
    populate(&mut native, 300);

    assert_eq!(
        migrated_root,
        native.store_root(),
        "a migrated store and a natively-v2 store must be indistinguishable"
    );
}

// ── proofs across the boundary ──────────────────────────────────────────────

/// Old proofs keep working against the old root, and are refused against the
/// new one. Both halves matter: the first is what lets a light client finish
/// verifying data it already fetched; the second is what stops it accepting a
/// pre-upgrade proof as current.
#[test]
fn v1_proofs_verify_against_v1_roots_and_not_v2_roots() {
    let mut store = TableStore::new();
    populate(&mut store, 100);
    let v1_root = store.store_root();
    let key = b"key-7".to_vec();
    let v1_proof = store.prove_read(table(), &key).expect("row exists");

    assert!(v1_proof.verify(&v1_root), "v1 proof must verify under v1");

    let v2_root = store.migrate_to_v2();
    assert!(
        !v1_proof.verify(&v2_root),
        "a v1 proof must NOT verify against a v2 root"
    );

    // And the freshly-issued v2 proof verifies under v2 but not under v1.
    let v2_proof = store.prove_read(table(), &key).expect("row still exists");
    assert!(v2_proof.verify(&v2_root));
    assert!(
        !v2_proof.verify(&v1_root),
        "a v2 proof must NOT verify against a v1 root"
    );
}

/// Proofs say which rule they follow, so a verifier can reject rather than
/// guess. During a rollout both are in flight at once.
#[test]
fn proofs_declare_their_version() {
    let mut store = TableStore::new();
    populate(&mut store, 10);
    let key = b"key-3".to_vec();

    let p1 = store.prove_read(table(), &key).unwrap();
    assert_eq!(p1.row_proof.version(), TreeVersion::V1);

    store.migrate_to_v2();
    let p2 = store.prove_read(table(), &key).unwrap();
    assert_eq!(p2.row_proof.version(), TreeVersion::V2);
}

// ── restart safety ──────────────────────────────────────────────────────────

/// **The restart trap.** The trees are rebuilt from rows on load, so a snapshot
/// that forgot its version would come back as v1 over v2 state and fork from
/// the network the node just agreed with.
#[test]
fn a_migrated_store_reloads_as_v2() {
    let mut store = TableStore::new();
    populate(&mut store, 200);
    let v2_root = store.migrate_to_v2();

    let snap = StateSnapshot::from_store(&store);
    assert_eq!(snap.tree_version, TreeVersion::V2);

    let mut reloaded = snap.into_store();
    assert_eq!(reloaded.version(), TreeVersion::V2);
    assert_eq!(
        reloaded.store_root(),
        v2_root,
        "root must survive save/reload after migration"
    );
}

/// An un-migrated store still round-trips as v1 — the upgrade must not change
/// the behaviour of nodes that have not reached the activation round.
#[test]
fn an_unmigrated_store_reloads_as_v1() {
    let mut store = TableStore::new();
    populate(&mut store, 200);
    let v1_root = store.store_root();

    let snap = StateSnapshot::from_store(&store);
    assert_eq!(snap.tree_version, TreeVersion::V1);

    let mut reloaded = snap.into_store();
    assert_eq!(reloaded.version(), TreeVersion::V1);
    assert_eq!(reloaded.store_root(), v1_root);
}

// ── the activation rule ─────────────────────────────────────────────────────

/// Below the activation round nothing happens; at or past it, exactly one
/// migration happens. This is what makes the switch a function of the committed
/// sequence rather than of wall-clock or operator timing.
#[test]
fn activation_is_keyed_to_the_committed_round() {
    // Not scheduled: never migrates, whatever round we reach.
    let never = ExecutionPipeline::new();
    assert_eq!(never.tables.version(), TreeVersion::V1);

    // Scheduled at round 10.
    let mut node = ExecutionPipeline::new().with_merkle_v2_at(10);
    assert_eq!(node.tables.version(), TreeVersion::V1);
    assert_eq!(node.metrics.merkle_migrations, 0);

    // Rounds before activation leave it alone. `apply_commit_for_test` drives
    // the same code path `on_commit` uses.
    for r in 0..10 {
        node.migrate_for_round(r);
        assert_eq!(
            node.tables.version(),
            TreeVersion::V1,
            "migrated early at round {r}"
        );
    }

    node.migrate_for_round(10);
    assert_eq!(
        node.tables.version(),
        TreeVersion::V2,
        "did not migrate at 10"
    );
    assert_eq!(node.metrics.merkle_migrations, 1);

    // Later rounds must not migrate again.
    for r in 11..20 {
        node.migrate_for_round(r);
    }
    assert_eq!(
        node.metrics.merkle_migrations, 1,
        "the upgrade must fire exactly once"
    );
}

/// A node that starts *after* the activation round still migrates on its first
/// commit, rather than running on v1 forever because it never saw round N.
#[test]
fn a_late_joiner_migrates_on_its_first_commit_past_activation() {
    let mut late = ExecutionPipeline::new().with_merkle_v2_at(10);
    late.migrate_for_round(97);
    assert_eq!(late.tables.version(), TreeVersion::V2);
    assert_eq!(late.metrics.merkle_migrations, 1);
}

/// Two validators that migrate at the same round agree, and one that has not
/// migrated yet does not — which is precisely why the round must be a consensus
/// parameter rather than a per-node flag.
#[test]
fn validators_agree_only_when_they_share_an_activation_round() {
    let build = |activation: Option<u64>, round: u64| {
        let mut p = match activation {
            Some(a) => ExecutionPipeline::new().with_merkle_v2_at(a),
            None => ExecutionPipeline::new(),
        };
        for i in 0..300u32 {
            p.tables.insert(
                table(),
                format!("key-{i}").into_bytes(),
                format!("value-{i}").into_bytes(),
            );
        }
        p.migrate_for_round(round);
        p.tables.store_root()
    };

    let a = build(Some(10), 10);
    let b = build(Some(10), 10);
    let stale = build(None, 10);

    assert_eq!(a, b, "same activation round → same root");
    assert_ne!(
        a, stale,
        "a validator that missed the upgrade must visibly disagree"
    );
}
