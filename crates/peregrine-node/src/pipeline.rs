//! The execution/data pipeline: everything that happens *after* consensus
//! hands us the committed total order.
//!
//! Responsibilities per committed vertex, in order:
//! 1. decode each payload item ([`WirePayload`]);
//! 2. **shreds** → validate + fan out via [`StreamRegistry`], then
//!    materialize into the `stream_ticks` table (our first materialized
//!    view: stream history becomes provable table state);
//! 3. **Talon transactions** → execute on [`Vm`] against the table store;
//! 4. meter everything on the dual meter and settle the 50/30/20 split.
//!
//! Every validator runs this identically over the identical committed
//! order, which is why their state roots must match at the end — the
//! simulation asserts exactly that.

use crate::payload::WirePayload;
use crate::tiles::TilePool;
use peregrine_consensus::{CommitObserver, Dag};
use peregrine_core::{Hash, Round};
use peregrine_data::fees::{DualMeter, FeeSchedule, FeeSplit};
use peregrine_data::streams::{StreamId, StreamRegistry, SubscriberHandle};
use peregrine_data::tables::{ProvenRead, TableId, TableStore, TreeVersion};
use peregrine_interop::beacon::AnchorStore;
use peregrine_interop::zk::Claim;
use peregrine_interop::{VerifiedClaim, Verifier};
use peregrine_vm::{Host, ProvenValue, Vm};
use std::sync::Arc;

/// Table that materializes committed stream records: key = (stream, seq).
pub fn ticks_table() -> TableId {
    TableId::named("sys.stream_ticks")
}

/// A compact, allocation-free latency histogram with power-of-two nanosecond
/// buckets (bucket `i` covers `[2^(i-1), 2^i)` ns). 64 buckets span 1 ns to
/// ~584 years, so it never overflows and needs no configuration; percentile
/// resolution is one power of two, which is plenty for p50/p99 reported in ms.
#[derive(Debug, Clone)]
pub struct LatencyHistogram {
    buckets: [u64; 64],
    count: u64,
}

impl Default for LatencyHistogram {
    fn default() -> Self {
        Self {
            buckets: [0; 64],
            count: 0,
        }
    }
}

impl LatencyHistogram {
    pub fn record(&mut self, ns: u64) {
        // Bucket = position of the most-significant set bit (0 → bucket 0).
        let idx = (64 - ns.max(1).leading_zeros()).min(63) as usize;
        self.buckets[idx] += 1;
        self.count += 1;
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    /// The `q`-quantile (0.0–1.0) as milliseconds, taking the bucket's upper
    /// bound as a conservative estimate.
    pub fn percentile_ms(&self, q: f64) -> f64 {
        if self.count == 0 {
            return 0.0;
        }
        let target = (q * self.count as f64).ceil() as u64;
        let mut cumulative = 0u64;
        for (i, &c) in self.buckets.iter().enumerate() {
            cumulative += c;
            if cumulative >= target {
                return (1u64 << i) as f64 / 1e6;
            }
        }
        (1u64 << 63) as f64 / 1e6
    }
}

/// Rolling metrics for the demo/report.
#[derive(Debug, Default, Clone)]
pub struct PipelineMetrics {
    /// Times the store migrated Merkle versions. Should be exactly 0 or 1 in
    /// a node's lifetime; anything higher means the activation rule is firing
    /// repeatedly and roots are churning.
    pub merkle_migrations: u64,
    pub committed_vertices: u64,
    pub committed_records: u64,
    pub committed_txs: u64,
    pub commit_rounds: u64,
    /// Sum of (commit wall-clock − record publish timestamp), nanoseconds.
    pub record_latency_ns_sum: u128,
    /// Distribution of publish→commit latency, for p50/p99 (see the bench).
    pub latency: LatencyHistogram,
    /// Foreign-chain claims that verified and were materialized.
    pub foreign_claims_applied: u64,
    /// Foreign-chain claims refused (bad proof, wrong chain, or policy).
    pub foreign_claims_rejected: u64,
}

impl PipelineMetrics {
    pub fn avg_record_latency_ms(&self) -> f64 {
        if self.committed_records == 0 {
            return 0.0;
        }
        (self.record_latency_ns_sum as f64 / self.committed_records as f64) / 1e6
    }

    pub fn p50_ms(&self) -> f64 {
        self.latency.percentile_ms(0.50)
    }

    pub fn p99_ms(&self) -> f64 {
        self.latency.percentile_ms(0.99)
    }
}

/// Table holding foreign-chain state that has been verified on-chain:
/// key = `chain_id ‖ address ‖ slot`, value = the 32-byte word.
///
/// Because it is an ordinary table, verified Ethereum state lands in
/// Peregrine's store root — so contracts read it with a plain `LoadTable`, and
/// a Peregrine light client can prove a value that *originated on Ethereum*
/// against a single 32-byte root.
pub fn eth_state_table() -> TableId {
    TableId::named("sys.eth_state")
}

/// Key for a foreign storage slot in [`eth_state_table`].
pub fn eth_state_key(chain_id: u64, address: &[u8; 20], slot: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(60);
    key.extend_from_slice(&chain_id.to_be_bytes());
    key.extend_from_slice(address);
    key.extend_from_slice(slot);
    key
}

/// Foreign-chain claims verified per commit batch.
///
/// Proof verification is orders of magnitude more expensive than anything else
/// on the commit path, so it must be bounded or a single vertex stuffed with
/// claims becomes a consensus-halting DoS. The cap is applied identically on
/// every validator (counted per commit batch, reset at the start of each), so
/// which claims are accepted stays a deterministic function of the committed
/// order — the bound cannot itself cause a fork.
pub const MAX_CLAIMS_PER_COMMIT: u32 = 4;

/// Compute units charged for attempting to verify one foreign claim.
///
/// Priced far above ordinary execution because it *is* far more expensive.
/// Charged whether or not verification succeeds — unpriced verification is a
/// denial-of-service vector, and an attacker must not get free proof-checking
/// by submitting garbage.
pub const CU_VERIFY_CLAIM: u64 = 500_000;

/// How this node decides whether a foreign claim is acceptable.
///
/// **This is a consensus rule, not a local preference.** Validators that
/// disagree about which proofs are acceptable will disagree about state and
/// fork the chain, so this must be configured uniformly across the network —
/// see the security notes in the README.
pub enum ClaimPolicy {
    /// Reject every foreign claim. The safe default: a node that cannot verify
    /// proofs must not accept claims on faith.
    RejectAll,
    /// Accept claims a [`Verifier`] approves, restricted to one chain.
    Verified {
        verifier: Box<dyn Verifier + Send + Sync>,
        chain_id: u64,
    },
}

impl ClaimPolicy {
    /// Accept only real SP1 proofs of the pinned guest program.
    ///
    /// This is the configuration a production validator runs. It fails to
    /// construct if the local guest ELF does not hash to `image_id`, so a
    /// misconfigured node refuses to start rather than silently disagreeing
    /// with its peers about which proofs are valid — which would fork the
    /// chain.
    ///
    /// Obtain `image_id` from **your own** build of the guest
    /// (`cargo prove build`), never from whoever supplies you proofs.
    #[cfg(feature = "sp1")]
    pub fn sp1(image_id: [u8; 32], chain_id: u64) -> Result<Self, String> {
        let verifier = peregrine_interop::Sp1Verifier::new(image_id, chain_id)
            .map_err(|e| format!("SP1 verifier unavailable: {e}"))?;
        Ok(ClaimPolicy::Verified {
            verifier: Box::new(verifier),
            chain_id,
        })
    }

    /// Accept claims a strict verifier approves, without a proving backend
    /// compiled in.
    ///
    /// This rejects *everything* — `Proof::Native` for carrying no
    /// cryptographic argument, and `Proof::Zk` because no backend can check
    /// it. That is the correct default for a build without `--features sp1`:
    /// a node that cannot verify must not accept.
    pub fn strict(image_id: [u8; 32], chain_id: u64) -> Self {
        ClaimPolicy::Verified {
            verifier: Box::new(peregrine_interop::zk::StrictVerifier {
                expected_image_id: image_id,
            }),
            chain_id,
        }
    }
}

impl std::fmt::Debug for ClaimPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClaimPolicy::RejectAll => write!(f, "RejectAll"),
            ClaimPolicy::Verified { chain_id, .. } => {
                write!(f, "Verified {{ chain_id: {chain_id} }}")
            }
        }
    }
}

/// The per-validator deterministic state machine.
pub struct ExecutionPipeline {
    pub streams: StreamRegistry,
    pub tables: TableStore,
    vm: Vm,
    fee_schedule: FeeSchedule,
    pub fee_split: FeeSplit,
    pub metrics: PipelineMetrics,
    /// Policy for [`WirePayload::ForeignClaim`]. Defaults to
    /// [`ClaimPolicy::RejectAll`] — failing closed.
    pub claim_policy: ClaimPolicy,
    /// Execution blocks this node treats as canonical, established by verified
    /// beacon light-client updates. **A claim is only accepted if its block is
    /// in here**, so an empty store rejects everything.
    pub anchors: AnchorStore,
    /// Claims verified so far in the current commit batch (see
    /// [`MAX_CLAIMS_PER_COMMIT`]). Reset at the start of every batch.
    claims_this_commit: u32,
    /// Round at which this node switches its table store to the
    /// path-compressed v2 Merkle rule, or `None` to stay on v1 forever.
    ///
    /// **This is a consensus rule, not a local setting.** Every validator must
    /// carry the same activation round, or they will commit different store
    /// roots for identical state from that round on and the chain forks. It
    /// belongs in genesis/config and changes only by coordinated upgrade —
    /// exactly like `ClaimPolicy`.
    pub merkle_v2_activation: Option<Round>,
    /// Optional sig-verify tiles. `None` → everything verifies inline, which is
    /// the old behaviour and what the determinism tests use.
    ///
    /// **Not a consensus input.** The tiles change *where* signature checks run,
    /// never what they decide, so two validators configured with different tile
    /// counts (or none) commit identical state. See [`crate::tiles`].
    tiles: Option<Arc<TilePool>>,
}

impl ExecutionPipeline {
    pub fn new() -> Self {
        let mut tables = TableStore::new();
        tables.create_table(ticks_table());
        tables.create_table(eth_state_table());
        Self {
            streams: StreamRegistry::new(),
            tables,
            vm: Vm::new(1_000_000),
            fee_schedule: FeeSchedule::default(),
            fee_split: FeeSplit::default(),
            metrics: PipelineMetrics::default(),
            claim_policy: ClaimPolicy::RejectAll,
            anchors: AnchorStore::new(256),
            claims_this_commit: 0,
            merkle_v2_activation: None,
            tiles: None,
        }
    }

    /// Schedule the v2 Merkle upgrade at `round`.
    ///
    /// Migration happens at the **first commit whose anchor round is at or past
    /// `round`**, before that batch's payloads are applied. Keying it to the
    /// committed round — rather than to wall-clock time, node start, or an
    /// operator command — is what makes it deterministic: every honest
    /// validator sees the same committed sequence, so every one migrates at the
    /// same point in that sequence and they all agree on every root thereafter.
    pub fn with_merkle_v2_at(mut self, round: Round) -> Self {
        self.merkle_v2_activation = Some(round);
        self
    }

    /// Drive the activation check for `round` without a full commit.
    ///
    /// Public so the upgrade can be tested at the rounds that matter — before,
    /// at, and after activation — without standing up a network for each. It is
    /// the same function `on_commit` calls, so a test here is a test of the
    /// real rule and not of a parallel reimplementation.
    pub fn migrate_for_round(&mut self, round: Round) -> bool {
        self.maybe_migrate(round)
    }

    /// Migrate now if this round activates the upgrade. Idempotent.
    ///
    /// Returns `true` if the migration ran on this call.
    fn maybe_migrate(&mut self, round: Round) -> bool {
        let Some(at) = self.merkle_v2_activation else {
            return false;
        };
        if round < at || self.tables.version() == TreeVersion::V2 {
            return false;
        }
        let before = self.tables.store_root();
        let after = self.tables.migrate_to_v2();
        self.metrics.merkle_migrations += 1;
        tracing::info!(
            round,
            activation = at,
            root_before = %before,
            root_after = %after,
            "migrated table store to path-compressed Merkle (v2) — store root              changes by design; light clients must re-pin"
        );
        true
    }

    /// Attach a sig-verify tile pool. Purely a performance choice; see the
    /// field docs for why it cannot affect committed state.
    pub fn with_tiles(mut self, tiles: Arc<TilePool>) -> Self {
        self.tiles = Some(tiles);
        self
    }

    pub fn subscribe(&self, id: &StreamId) -> Option<SubscriberHandle> {
        self.streams.subscribe(id).ok()
    }

    pub fn prove_read(&mut self, table: TableId, key: &[u8]) -> Option<ProvenRead> {
        self.tables.prove_read(table, key)
    }

    pub fn store_root(&mut self) -> Hash {
        self.tables.store_root()
    }

    /// Verify a foreign claim under this node's policy and, if it passes,
    /// materialize it into [`eth_state_table`].
    ///
    /// Returns `Ok(true)` when state was written, `Ok(false)` for a verified
    /// claim that carries nothing to store (e.g. a header-chain claim), and
    /// `Err` when the claim is refused.
    ///
    /// Note what is *not* checked here: whether `journal.block_hash` is
    /// canonical on Ethereum. A proof establishes that the verification ran,
    /// not that the block is real — anchoring is a separate concern and is
    /// called out in the README. Until an anchoring source exists, a node
    /// should run [`ClaimPolicy::RejectAll`] in production.
    pub fn apply_foreign_claim(&mut self, claim: &VerifiedClaim) -> Result<bool, String> {
        // Bound the verification work in this batch before doing any of it.
        if self.claims_this_commit >= MAX_CLAIMS_PER_COMMIT {
            return Err(format!(
                "claim budget exhausted ({MAX_CLAIMS_PER_COMMIT} per commit); resubmit later"
            ));
        }
        self.claims_this_commit += 1;

        let (verifier, chain_id) = match &self.claim_policy {
            ClaimPolicy::RejectAll => {
                return Err("node policy rejects foreign claims (no verifier configured)".into())
            }
            ClaimPolicy::Verified { verifier, chain_id } => (verifier, *chain_id),
        };

        if claim.journal.chain_id != chain_id {
            return Err(format!(
                "claim is for chain {}, this node accepts {chain_id}",
                claim.journal.chain_id
            ));
        }
        verifier.verify(claim).map_err(|e| e.to_string())?;

        // A proof shows the verification ran over *some* header; the anchor is
        // what says that header is Ethereum's. Without this check a relayer
        // could prove a self-consistent chain it invented, so an unanchored
        // block is refused no matter how good its proof is.
        if !self.anchors.is_anchored(&claim.journal.block_hash) {
            return Err(format!(
                "block {} is not anchored (no verified beacon update covers it)",
                hex::encode(&claim.journal.block_hash[..8])
            ));
        }

        match &claim.journal.claim {
            Claim::Storage {
                address,
                slot,
                value,
            } => {
                let key = eth_state_key(chain_id, address, slot);
                self.tables.insert(eth_state_table(), key, value.to_vec());
                Ok(true)
            }
            // Account and header-chain claims verify but have no single word to
            // materialize; they exist to anchor later storage claims.
            Claim::Account { .. } | Claim::HeaderChain { .. } => Ok(false),
        }
    }

    /// Apply an already-decoded, already-ordered batch: verify in parallel,
    /// then apply serially.
    ///
    /// Public because it is the real commit path, and a test that drove
    /// `apply_payload` in a loop instead would silently bypass the tiles and
    /// prove nothing about them. Callers must pass payloads in committed order;
    /// this function preserves it.
    pub fn apply_decoded_batch(&mut self, decoded: &[WirePayload]) {
        // ── phase 2: signature verification (parallel across tiles) ─────────
        // Pure predicates over each shred, so they can run anywhere. Verdicts
        // come back indexed by position and are consumed in committed order,
        // which is what keeps this deterministic regardless of tile count.
        let verdicts = self.verify_shreds(decoded);

        // ── phase 3: apply (serial, ordered — the state transition) ─────────
        for (i, payload) in decoded.iter().enumerate() {
            match payload {
                WirePayload::Shred(shred) => self.apply_shred(shred, verdicts[i]),
                other => self.apply_payload(other),
            }
        }
    }

    /// Verify every shred in a decoded batch, using the tiles when attached.
    ///
    /// Returns a verdict per element of `decoded`, positionally. Non-shred
    /// entries get `false`, which is never read — only [`WirePayload::Shred`]
    /// consults its verdict.
    fn verify_shreds(&self, decoded: &[WirePayload]) -> Vec<bool> {
        let mut verdicts = vec![false; decoded.len()];

        // Build the job list. A shred whose stream is unknown gets no job: it
        // will be rejected by `apply_committed_with` anyway, and dispatching a
        // verification for it would be wasted work.
        let mut jobs = Vec::new();
        for (i, p) in decoded.iter().enumerate() {
            if let WirePayload::Shred(shred) = p {
                if let Some(pk) = self.streams.publisher_key_for(shred) {
                    jobs.push(crate::tiles::VerifyJob {
                        index: i,
                        public_key: pk,
                        domain: peregrine_data::streams::STREAM_DOMAIN,
                        message: StreamRegistry::signing_bytes_of(shred),
                        signature: shred.signature,
                    });
                }
            }
        }
        if jobs.is_empty() {
            return verdicts;
        }

        match &self.tiles {
            Some(pool) => {
                // `verify_batch` returns a full-length positional vector, so
                // indices line up with `decoded` directly.
                let results = pool.verify_batch_indexed(jobs, decoded.len());
                verdicts = results;
            }
            None => {
                for job in &jobs {
                    verdicts[job.index] = peregrine_core::crypto::verify(
                        &job.public_key,
                        job.domain,
                        &job.message,
                        &job.signature,
                    )
                    .is_ok();
                }
            }
        }
        verdicts
    }

    /// Apply one committed shred given its precomputed signature verdict.
    fn apply_shred(&mut self, shred: &peregrine_data::streams::StreamShred, sig_ok: bool) {
        let mut meter = DualMeter::default();
        match self.streams.apply_committed_with(shred, sig_ok) {
            Ok(data_bytes) => {
                meter.tick_data(data_bytes);
                let mut key = Vec::with_capacity(40);
                key.extend_from_slice(&shred.record.stream.0 .0);
                key.extend_from_slice(&shred.record.seq.to_be_bytes());
                meter.tick_data((key.len() + shred.record.payload.len()) as u64);
                self.tables
                    .insert(ticks_table(), key, shred.record.payload.clone());

                self.metrics.committed_records += 1;
                let now = now_ns();
                let latency = now.saturating_sub(shred.record.timestamp_ns);
                self.metrics.record_latency_ns_sum += latency as u128;
                self.metrics.latency.record(latency);
            }
            Err(e) => tracing::warn!("rejected shred: {e}"),
        }
        // Same settlement as every other payload kind: work is priced whether
        // or not it was accepted.
        let quote = self.fee_schedule.quote(&meter);
        self.fee_split.settle(&quote);
    }

    /// Apply one decoded payload — the unit of work inside a committed vertex.
    ///
    /// Public so the effect of a single payload can be tested directly, which
    /// is how the cross-chain paths are covered without standing up a network.
    pub fn apply_payload(&mut self, payload: &WirePayload) {
        let payload = payload.clone();
        let mut meter = DualMeter::default();
        match payload {
            WirePayload::Shred(shred) => {
                match self.streams.apply_committed(&shred) {
                    Ok(data_bytes) => {
                        meter.tick_data(data_bytes);
                        // Materialized view: (stream, seq) -> payload.
                        let mut key = Vec::with_capacity(40);
                        key.extend_from_slice(&shred.record.stream.0 .0);
                        key.extend_from_slice(&shred.record.seq.to_be_bytes());
                        meter.tick_data((key.len() + shred.record.payload.len()) as u64);
                        self.tables
                            .insert(ticks_table(), key, shred.record.payload.clone());

                        self.metrics.committed_records += 1;
                        let now = now_ns();
                        let latency = now.saturating_sub(shred.record.timestamp_ns);
                        self.metrics.record_latency_ns_sum += latency as u128;
                        self.metrics.latency.record(latency);
                    }
                    Err(e) => tracing::warn!("rejected shred: {e}"),
                }
            }
            WirePayload::ForeignClaim(claim) => {
                // Verification runs on every validator, so acceptance is part
                // of the state transition rather than something a relayer is
                // trusted to have done. Metered on *both* meters whether or not
                // it is accepted: the proof's bytes on the data meter, and the
                // verification itself on the compute meter. Unpriced
                // verification is a denial-of-service vector.
                meter.tick_data(bincode::serialized_size(&claim).unwrap_or(0));
                meter.tick_compute(CU_VERIFY_CLAIM);
                match self.apply_foreign_claim(&claim) {
                    Ok(true) => self.metrics.foreign_claims_applied += 1,
                    Ok(false) => {}
                    Err(e) => {
                        self.metrics.foreign_claims_rejected += 1;
                        tracing::warn!("foreign claim rejected: {e}");
                    }
                }
            }
            WirePayload::TalonTx { program } => {
                let mut host = PipelineHost {
                    tables: &mut self.tables,
                };
                let res = self.vm.execute(&program, &mut host);
                // Charge fees for the work done whether or not the tx trapped —
                // a failed tx must not buy free computation.
                meter.merge(res.meter);
                match res.trap {
                    None => self.metrics.committed_txs += 1,
                    Some(e) => tracing::warn!("tx trapped (metered): {e}"),
                }
            }
        }
        let quote = self.fee_schedule.quote(&meter);
        self.fee_split.settle(&quote);
    }
}

impl Default for ExecutionPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl CommitObserver for ExecutionPipeline {
    fn on_commit(&mut self, round: Round, _anchor: Hash, ordered: &[Hash], dag: &Dag) {
        self.metrics.commit_rounds += 1;
        // Fresh proof-verification budget for this batch. Every validator
        // resets at the same point in the committed order, so the bound is
        // deterministic.
        self.claims_this_commit = 0;

        // ── phase 1: decode (serial, cheap) ─────────────────────────────────
        // Decoding is ~0.2 µs/item and allocates; doing it once here means the
        // serial apply loop below never re-parses, and it gives us the shred
        // list the verify tiles need.
        let mut decoded: Vec<WirePayload> = Vec::new();
        for h in ordered {
            let Some(vertex) = dag.get(h) else { continue };
            self.metrics.committed_vertices += 1;
            for item in &vertex.payload.items {
                match WirePayload::decode(&item.0) {
                    Some(p) => decoded.push(p),
                    None => tracing::warn!(
                        "undecodable payload item ({} bytes) — skipped",
                        item.0.len()
                    ),
                }
            }
        }

        // The upgrade happens *before* this batch is applied, so the boundary
        // is unambiguous: everything committed at or after the activation round
        // is authenticated under v2. Applying first and migrating after would
        // leave the same round meaning different things on different nodes
        // depending on ordering.
        self.maybe_migrate(round);

        self.apply_decoded_batch(&decoded);
    }
}

/// Host adapter: exposes the pipeline's table store to the VM.
struct PipelineHost<'a> {
    tables: &'a mut TableStore,
}

impl Host for PipelineHost<'_> {
    fn table_insert(&mut self, table: TableId, key: Vec<u8>, value: Vec<u8>) -> Result<(), String> {
        self.tables.insert(table, key, value);
        Ok(())
    }

    fn table_read(&mut self, table: TableId, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
        Ok(self.tables.get(&table, key).map(|v| v.to_vec()))
    }

    fn table_read_proven(
        &mut self,
        table: TableId,
        key: &[u8],
    ) -> Result<Option<ProvenValue>, String> {
        match self.tables.prove_read(table, key) {
            Some(read) => {
                // Serialize the real inclusion proof so the VM meters its true
                // byte cost; a stateless verifier re-checks it against `root`.
                let proof = bincode::serialize(&read).map_err(|e| e.to_string())?;
                Ok(Some(ProvenValue {
                    value: read.value,
                    proof,
                    root: self.tables.store_root(),
                }))
            }
            None => Ok(None),
        }
    }

    fn eth_state_read(
        &mut self,
        chain_id: u64,
        address: [u8; 20],
        slot: [u8; 32],
    ) -> Result<Option<[u8; 32]>, String> {
        let key = eth_state_key(chain_id, &address, &slot);
        Ok(self.tables.get(&eth_state_table(), &key).map(|v| {
            let mut word = [0u8; 32];
            let n = v.len().min(32);
            word[32 - n..].copy_from_slice(&v[v.len() - n..]);
            word
        }))
    }

    fn stream_emit(&mut self, _payload: Vec<u8>) -> Result<(), String> {
        // Contract-originated streams are a follow-up: requires a
        // node-owned publisher identity. Accepted and dropped for now.
        Ok(())
    }
}

fn now_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}
