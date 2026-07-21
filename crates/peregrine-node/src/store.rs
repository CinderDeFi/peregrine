//! Node-owned persistence: crash-durable snapshots of a validator's DAG and
//! materialized table state, so a node survives a restart.
//!
//! ## Layout
//! A single [`redb`] database file with two tables, each holding one
//! bincode-encoded blob under a fixed key:
//!
//! ```text
//!   redb table "dag"   → SNAPSHOT_KEY → DagSnapshot   (all vertices held)
//!   redb table "state" → SNAPSHOT_KEY → StateSnapshot (all TableStore rows)
//! ```
//!
//! ## Why these two, and why together
//! * **DAG** — the consensus structure. Rebuilt by re-inserting the vertices
//!   in round order; the commit cursor is then re-derived by replaying the
//!   (pure, deterministic) commit rule over that DAG, so we never persist —
//!   or double-apply — committed payloads.
//! * **State** — the [`TableStore`] rows. The sparse Merkle trees are a pure
//!   function of the rows, so only rows are stored; the trees (and the store
//!   root) rebuild on load. This is the entire trust surface a light client
//!   pins, so its stability across reload is the property that matters.
//!
//! Both blobs are written in **one** redb write transaction. That atomicity
//! is load-bearing: it guarantees the persisted DAG and the persisted tables
//! always agree on "committed through the same anchor", which is exactly what
//! lets the restart path re-derive the commit cursor from the DAG and trust
//! that the restored tables already reflect it.
//!
//! ## Scope / limitations (bootstrap)
//! * The whole snapshot is rewritten each flush (no incremental deltas) — fine
//!   at bootstrap DAG sizes, a tracked follow-up at scale.
//! * Stream-registry sequence counters and fee/latency *metrics* are not
//!   persisted; they reset on restart. State roots — the consensus-critical
//!   part — are fully recovered. See the README for the rationale.

use peregrine_consensus::Vertex;
#[cfg(test)]
use peregrine_data::tables::TableId;
use peregrine_data::tables::{TableRows, TableStore};
use redb::{Database, TableDefinition};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Vertices → one blob. `SNAPSHOT_KEY` is the only key.
const DAG_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("dag");
/// Table rows → one blob. `SNAPSHOT_KEY` is the only key.
const STATE_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("state");
/// Single fixed key: each table stores exactly one current snapshot blob.
const SNAPSHOT_KEY: &str = "current";

/// Durable form of a validator's DAG: every vertex it holds. Re-inserting
/// these in round order rebuilds an identical, fully-validated DAG.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct DagSnapshot {
    pub vertices: Vec<Vertex>,
}

/// Durable form of the materialized state: `(table_id, [(key, value)])` for
/// every table. Trees rebuild from these on load.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    pub tables: TableRows,
}

impl StateSnapshot {
    /// Capture the current rows of a table store (tree-free).
    pub fn from_store(store: &TableStore) -> Self {
        Self {
            tables: store.snapshot_rows(),
        }
    }

    /// Rebuild a table store from this snapshot (trees + roots recomputed).
    pub fn into_store(self) -> TableStore {
        TableStore::restore_from_rows(self.tables)
    }
}

/// A node's on-disk persistence handle. Owns one redb database file.
pub struct Store {
    db: Database,
}

impl Store {
    /// Open (creating if absent) the database at `path`. This is the
    /// "load-or-init" entry point: a brand-new file simply has no snapshot
    /// yet, which [`restore`](Self::restore) reports as `None`.
    pub fn open(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let db = Database::create(path)?;
        Ok(Self { db })
    }

    /// Atomically persist both the DAG and the table state in a single write
    /// transaction. Either both land or neither does.
    pub fn snapshot(&self, dag: &DagSnapshot, state: &StateSnapshot) -> anyhow::Result<()> {
        let dag_bytes = bincode::serialize(dag)?;
        let state_bytes = bincode::serialize(state)?;

        let write = self.db.begin_write()?;
        {
            let mut t = write.open_table(DAG_TABLE)?;
            t.insert(SNAPSHOT_KEY, dag_bytes.as_slice())?;
        }
        {
            let mut t = write.open_table(STATE_TABLE)?;
            t.insert(SNAPSHOT_KEY, state_bytes.as_slice())?;
        }
        write.commit()?;
        Ok(())
    }

    /// Load the last committed snapshot, or `None` if the database has never
    /// been written (fresh node → initialize from genesis).
    pub fn restore(&self) -> anyhow::Result<Option<(DagSnapshot, StateSnapshot)>> {
        let read = self.db.begin_read()?;

        // A never-written database has no tables yet — that is the fresh-boot
        // signal, not an error.
        let dag_table = match read.open_table(DAG_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let Some(dag_val) = dag_table.get(SNAPSHOT_KEY)? else {
            return Ok(None);
        };
        let dag: DagSnapshot = bincode::deserialize(dag_val.value())?;

        // If the dag table exists and holds a snapshot, the atomic write
        // guarantees the state table does too.
        let state_table = read.open_table(STATE_TABLE)?;
        let Some(state_val) = state_table.get(SNAPSHOT_KEY)? else {
            return Ok(None);
        };
        let state: StateSnapshot = bincode::deserialize(state_val.value())?;

        Ok(Some((dag, state)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use peregrine_core::Hash;

    /// Unique scratch path per test invocation (redb takes a file lock, so
    /// tests must not share a path).
    fn temp_db_path(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir();
        dir.join(format!(
            "peregrine-store-test-{tag}-{}.redb",
            std::process::id()
        ))
    }

    /// The required round-trip: build state → save (bincode + redb) → reload
    /// into a fresh store → assert the store roots are identical.
    #[test]
    fn state_snapshot_roundtrip_equal_roots() {
        let path = temp_db_path("state-roundtrip");
        let _ = std::fs::remove_file(&path);

        // Build some state.
        let mut store = TableStore::new();
        let prices = TableId::named("prices");
        let agents = TableId::named("agents");
        for i in 0..64u32 {
            store.insert(
                prices,
                format!("asset-{i:03}").into_bytes(),
                i.to_le_bytes().to_vec(),
            );
            store.insert(agents, format!("agent-{i:03}").into_bytes(), vec![i as u8]);
        }
        let original_root = store.store_root();

        // Save.
        let db = Store::open(&path).expect("open db");
        db.snapshot(&DagSnapshot::default(), &StateSnapshot::from_store(&store))
            .expect("snapshot");

        // Reload into a completely fresh store.
        let (_dag, state) = db.restore().expect("restore ok").expect("snapshot present");
        let mut reloaded = state.into_store();
        let reloaded_root = reloaded.store_root();

        assert_eq!(
            reloaded_root, original_root,
            "root must be identical after save/reload"
        );
        assert_ne!(reloaded_root, Hash::ZERO);

        // And a proof from the reloaded store still verifies against that root.
        let read = reloaded
            .prove_read(prices, b"asset-042")
            .expect("row exists");
        assert!(read.verify(&reloaded_root));

        drop(db);
        let _ = std::fs::remove_file(&path);
    }

    /// A pristine database reports `None` (fresh-boot / initialize path).
    #[test]
    fn restore_on_fresh_db_is_none() {
        let path = temp_db_path("fresh");
        let _ = std::fs::remove_file(&path);
        let db = Store::open(&path).expect("open db");
        assert!(db.restore().expect("restore ok").is_none());
        drop(db);
        let _ = std::fs::remove_file(&path);
    }
}
