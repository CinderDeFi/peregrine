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
use peregrine_data::compliance::{
    cell_key, compliance_table, ComplianceError, CompliancePolicy, SignedAttestation,
};
use peregrine_data::faucet::{faucet_table, DripRecord, FaucetPolicy, SignedDrip};
use peregrine_data::feeds::{
    aggregate, decode_source, encode_source, feed_latest_table, feed_source_table, feeds_table,
    source_key, FeedId, FeedObservation, FeedRegistry, FeedSpec, FeedValue,
};
use peregrine_data::fees::{DualMeter, FeeSchedule, FeeSplit};
use peregrine_data::sessions::{
    self as sessions, balances_table, sessions_table, Action, Grains, SessionState, SignedAction,
    SignedGrant,
};
use peregrine_data::streams::{StreamId, StreamRegistry, SubscriberHandle};
use peregrine_data::tables::{ProvenRead, TableId, TableStore, TreeVersion};
use peregrine_interop::beacon::AnchorStore;
use peregrine_interop::zk::Claim;
use peregrine_interop::{VerifiedClaim, Verifier};
use peregrine_vm::{Host, ProvenValue, Vm};
use std::collections::BTreeMap;
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
    /// Session actions accepted / refused by policy.
    pub session_actions_applied: u64,
    pub session_actions_rejected: u64,
    pub sessions_revoked: u64,
    /// Total grains moved by session-authorised payments.
    pub session_grains_spent: u64,
    /// Per-record subscription charges on the fast path, and their total.
    pub micropayments: u64,
    pub micropayment_grains: u64,
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
    /// Compliance attestations whose signature verified and were materialized.
    pub attestations_applied: u64,
    /// Compliance attestations refused (bad attester signature).
    pub attestations_rejected: u64,
    /// Oracle feeds registered.
    pub feeds_registered: u64,
    /// Feed values recomputed and written to `sys.feed_latest`.
    pub feed_updates: u64,
    /// Committed feed-stream records whose payload was not a valid observation.
    pub feed_observations_rejected: u64,
    /// Faucet drips that passed policy and credited a recipient.
    pub faucet_drips_applied: u64,
    /// Faucet drips refused (bad signature, over a cap, or on cooldown).
    pub faucet_drips_rejected: u64,
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
    /// Live session state, keyed by session id.
    ///
    /// A `BTreeMap` rather than a `HashMap`: this is consensus state, and its
    /// iteration order feeds the materialized `sys.sessions` table. A hash map
    /// would materialize rows in an order that varies per process, and two
    /// validators would compute different store roots.
    pub sessions: BTreeMap<Hash, SessionState>,
    /// Registered oracle feeds: their specs and the stream → (feed, provider)
    /// index. Built from committed `RegisterFeed` payloads, so it is identical
    /// on every validator; the values themselves live in tables.
    pub feeds: FeedRegistry,
    /// The network's chain id, from genesis. Committed checkpoints carry it so a
    /// proof of this chain's state can't be replayed as another's.
    pub chain_id: u64,
    /// The testnet faucet policy, from genesis. `None` = no faucet, and every
    /// drip is refused (fail-closed). The per-recipient limits it carries are
    /// enforced during commit, so they hold on every validator.
    pub faucet: Option<FaucetPolicy>,
    /// The round currently being committed. Session expiry is measured against
    /// this, never against wall-clock time — see [`peregrine_data::sessions`].
    current_round: Round,
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
        tables.create_table(sessions_table());
        tables.create_table(balances_table());
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
            sessions: BTreeMap::new(),
            feeds: FeedRegistry::default(),
            chain_id: 0,
            faucet: None,
            current_round: 0,
            tiles: None,
        }
    }

    /// Run a Talon program directly against this pipeline.
    ///
    /// Test/template seam: production programs arrive as committed
    /// `WirePayload::TalonTx`. Exposed so a contract template can be exercised
    /// without standing up a network for each assertion.
    pub fn run_program_for_test(&mut self, program: &[peregrine_vm::Instr]) {
        self.apply_payload(&WirePayload::TalonTx {
            program: program.to_vec(),
        });
    }

    /// Set the round used for session expiry, without driving a full commit.
    ///
    /// Test seam. Production sets this in `on_commit`, from the round consensus
    /// actually committed — which is the whole point of measuring TTL in rounds
    /// rather than seconds.
    pub fn set_round_for_test(&mut self, round: Round) {
        self.current_round = round;
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

    // ── sessions & micropayments ────────────────────────────────────────────

    /// Persist a session to the materialized `sys.sessions` table, so anyone
    /// can *prove* what a session is permitted to do rather than being told.
    fn materialize_session(&mut self, id: &Hash) {
        if let Some(st) = self.sessions.get(id) {
            let bytes = bincode::serialize(st).expect("session serialize");
            self.tables.insert(sessions_table(), id.0.to_vec(), bytes);
        }
    }

    fn balance_of(&self, who: &peregrine_core::PublicKey) -> Grains {
        self.tables
            .get(&balances_table(), &who.0)
            .and_then(|v| v.try_into().ok())
            .map(u64::from_le_bytes)
            .unwrap_or(0)
    }

    /// Credit `amount` grains to `who` in `sys.balances`.
    ///
    /// AUDIT M-1 — **grains are NOT conserved, by design.** This credits a payee
    /// with no matching debit of the payer, so `sys.balances` is a *credit-only*
    /// running total of grains received, not a ledger that conserves supply. A
    /// session's `budget_grains` caps how much that session can *emit*, but it is
    /// not backed by funds.
    ///
    /// This is deliberate, not an oversight: the scaffold has **no funding
    /// primitive** — no genesis allocation, faucet, or mint — so every account
    /// starts at zero. A conservative model (debit the principal, refuse when
    /// underfunded) would make the *first* payment impossible for everyone and
    /// break the working agent/RWA demos. Turning `sys.balances` into a real,
    /// conserved ledger is future economic work that must start with a funding
    /// source; until then, do not treat these balances as spendable value.
    fn credit(&mut self, who: &peregrine_core::PublicKey, amount: Grains) {
        let now = self.balance_of(who).saturating_add(amount);
        self.tables
            .insert(balances_table(), who.0.to_vec(), now.to_le_bytes().to_vec());
    }

    // ── compliance ──────────────────────────────────────────────────────────

    /// Materialize a signed attestation into `sys.compliance`.
    ///
    /// The attester's signature is verified here, on every validator, before the
    /// compact flag is written — the chain records a *signed* statement, it does
    /// not decide which attesters are legitimate. Idempotent: re-applying the
    /// same attestation rewrites the same cell. Returns `Ok(true)` when the flag
    /// was written, `Err` when the signature did not verify.
    pub fn apply_attestation(&mut self, signed: &SignedAttestation) -> Result<bool, String> {
        if !signed.verify() {
            return Err("attestation signature does not verify".into());
        }
        let att = &signed.attestation;
        self.tables.insert(
            compliance_table(),
            cell_key(&att.subject, &att.attester),
            att.flag_bytes(),
        );
        Ok(true)
    }

    /// The committed compliance flag for `subject` under `attester`, if present.
    pub fn compliance_flag(
        &self,
        subject: &peregrine_core::PublicKey,
        attester: &peregrine_core::PublicKey,
    ) -> Option<Vec<u8>> {
        self.tables
            .get(&compliance_table(), &cell_key(subject, attester))
            .map(|v| v.to_vec())
    }

    /// **A compliance-gated transfer.** Credit `subject` only if it holds a
    /// valid, unexpired `Verified` attestation from the policy's attester in
    /// committed state; otherwise change nothing and report why. Evaluated at the
    /// current committed round, so every validator reaches the same verdict — the
    /// "institution requires a compliance flag before accepting a transfer" rule,
    /// enforced on-chain rather than trusted to a relayer.
    pub fn compliant_credit(
        &mut self,
        subject: &peregrine_core::PublicKey,
        amount: Grains,
        policy: &CompliancePolicy,
    ) -> Result<(), ComplianceError> {
        let flag = self.compliance_flag(subject, &policy.attester);
        policy.require_compliant(flag.as_deref(), self.current_round)?;
        self.credit(subject, amount);
        Ok(())
    }

    // ── testnet faucet ───────────────────────────────────────────────────────

    /// Credit an account at genesis. A funding primitive distinct from the
    /// faucet — used once, when a genesis file lists an initial allocation.
    pub fn allocate(&mut self, account: &peregrine_core::PublicKey, grains: Grains) {
        self.credit(account, grains);
    }

    /// The committed faucet record for `recipient`, if any.
    pub fn faucet_record(&self, recipient: &peregrine_core::PublicKey) -> Option<DripRecord> {
        self.tables
            .get(&faucet_table(), &recipient.0)
            .and_then(DripRecord::decode)
    }

    /// Apply a signed faucet drip. Fails closed when no faucet is configured;
    /// otherwise verifies the authority's signature and enforces the per-request,
    /// cooldown, and lifetime limits from committed state — all on every
    /// validator, so a permissive node cannot wave a drip through. On success
    /// credits `sys.balances` and updates `sys.faucet[recipient]`.
    pub fn apply_faucet_drip(
        &mut self,
        signed: &SignedDrip,
    ) -> Result<(), peregrine_data::faucet::FaucetError> {
        use peregrine_data::faucet::FaucetError;
        let policy = self.faucet.ok_or(FaucetError::NotConfigured)?;
        if !signed.verify(&policy.authority) {
            return Err(FaucetError::BadSignature);
        }
        let recipient = signed.drip.recipient;
        let prior = self.faucet_record(&recipient);
        let record = policy.authorize(&signed.drip, prior, self.current_round)?;
        self.credit(&recipient, signed.drip.amount);
        self.tables
            .insert(faucet_table(), recipient.0.to_vec(), record.encode());
        Ok(())
    }

    // ── oracle feeds ─────────────────────────────────────────────────────────

    /// Register an oracle feed. Indexes each provider's stream so its
    /// observations materialize, and writes a compact spec summary to
    /// `sys.feeds`. Idempotent — a feed is content-addressed, so re-registering
    /// the same spec is a no-op.
    pub fn register_feed(&mut self, spec: FeedSpec) -> FeedId {
        let id = spec.id();
        if self.feeds.contains(&id) {
            return id;
        }
        // Register each provider's stream so the pipeline accepts their signed
        // records. Only the named provider can actually sign them.
        for p in &spec.providers {
            self.streams.register(&spec.channel, *p);
        }
        self.tables
            .insert(feeds_table(), id.0 .0.to_vec(), spec.summary_bytes());
        self.feeds.insert(spec);
        self.metrics.feeds_registered += 1;
        id
    }

    /// A committed observation from `provider` on `feed_id`. Writes the
    /// provider's latest into a per-source cell, then re-aggregates the **fresh**
    /// sources into `sys.feed_latest[feed_id]`. Stale sources — those that have
    /// not updated within the spec's staleness bound — are dropped, so a source
    /// that goes dark stops contributing to the median.
    fn materialize_feed_observation(
        &mut self,
        feed_id: FeedId,
        provider: peregrine_core::PublicKey,
        payload: &[u8],
    ) {
        // Clone the spec so the borrow of `self.feeds` ends before we touch
        // `self.tables`; a spec is small (a few keys and a channel name).
        let spec = match self.feeds.spec(&feed_id) {
            Some(s) => s.clone(),
            None => return,
        };
        let Some(obs) = FeedObservation::decode(payload) else {
            self.metrics.feed_observations_rejected += 1;
            return;
        };
        let round = self.current_round;

        // The provider's latest, stamped with the committed round.
        self.tables.insert(
            feed_source_table(),
            source_key(&feed_id, &provider),
            encode_source(obs.value, round),
        );

        // Collect the fresh sources' values, in the spec's (deterministic)
        // provider order.
        let mut fresh = Vec::with_capacity(spec.providers.len());
        for p in &spec.providers {
            if let Some(cell) = self
                .tables
                .get(&feed_source_table(), &source_key(&feed_id, p))
            {
                if let Some((value, r)) = decode_source(cell) {
                    if round.saturating_sub(r) <= spec.max_staleness_rounds {
                        fresh.push(value);
                    }
                }
            }
        }
        if fresh.is_empty() {
            return; // every source stale; leave the last good value in place
        }
        let fv = FeedValue {
            value: aggregate(&fresh, spec.aggregation),
            decimals: spec.decimals,
            kind: spec.kind,
            aggregation: spec.aggregation,
            n_sources: fresh.len().min(u8::MAX as usize) as u8,
            updated_round: round,
        };
        self.tables
            .insert(feed_latest_table(), feed_id.0 .0.to_vec(), fv.encode());
        self.metrics.feed_updates += 1;
    }

    /// Open a session. The grant must be signed by the principal it names.
    pub fn open_session(&mut self, signed: &SignedGrant) -> Result<Hash, sessions::SessionError> {
        if !signed.verify() {
            return Err(sessions::SessionError::BadGrant);
        }
        // A grant that is already expired is refused rather than stored: a
        // session nobody can use is just state everyone has to carry forever.
        if self.current_round > signed.grant.expires_at_round {
            return Err(sessions::SessionError::GrantAlreadyExpired {
                expires_at: signed.grant.expires_at_round,
                now: self.current_round,
            });
        }
        let id = signed.grant.id();
        // Idempotent: re-delivering the same grant must not reset spend or
        // resurrect a revoked session.
        self.sessions
            .entry(id)
            .or_insert_with(|| SessionState::open(signed.grant.clone()));
        self.materialize_session(&id);
        Ok(id)
    }

    /// Revoke a session. Only the principal may do this — a compromised
    /// session key must not be able to interfere with its own revocation.
    pub fn revoke_session(&mut self, id: &Hash, signature: &peregrine_core::Signature) -> bool {
        let Some(st) = self.sessions.get(id) else {
            return false;
        };
        if !sessions::verify_revocation(&st.grant.principal, id, signature) {
            return false;
        }
        if let Some(st) = self.sessions.get_mut(id) {
            st.revoked = true;
            // Stop the meter immediately: a revoked session must not keep
            // paying for streams it subscribed to.
            st.subscriptions.clear();
        }
        self.materialize_session(id);
        self.metrics.sessions_revoked += 1;
        true
    }

    /// Authorise and apply one session action.
    ///
    /// Every check happens *before* any state changes, so a refused action
    /// leaves nothing behind — no partial write, no advanced nonce, no debit.
    pub fn apply_session_action(
        &mut self,
        signed: &SignedAction,
    ) -> Result<Grains, sessions::SessionError> {
        let id = signed.action.session_id;
        let round = self.current_round;
        let state = self
            .sessions
            .get(&id)
            .ok_or(sessions::SessionError::UnknownSession)?;

        // Pure verdict first.
        let cost = sessions::authorize(state, signed, round)?;

        // Now commit the effects.
        let action = signed.action.action.clone();
        let principal = state.grant.principal;
        {
            let st = self.sessions.get_mut(&id).expect("checked above");
            st.next_nonce = st.next_nonce.saturating_add(1);
            st.spent = st.spent.saturating_add(cost);
            match &action {
                Action::Subscribe {
                    stream,
                    price_per_record,
                } => {
                    st.subscriptions.retain(|(s, _)| s != stream);
                    st.subscriptions.push((*stream, *price_per_record));
                }
                Action::Unsubscribe { stream } => {
                    st.subscriptions.retain(|(s, _)| s != stream);
                }
                _ => {}
            }
        }

        match action {
            Action::Write { table, key, value } => {
                self.tables.insert(table, key, value);
            }
            Action::Pay { payee, amount } => {
                self.credit(&payee, amount);
            }
            Action::Subscribe { .. } | Action::Unsubscribe { .. } => {}
        }
        let _ = principal;
        self.materialize_session(&id);
        Ok(cost)
    }

    /// Charge every session subscribed to `stream`, crediting the publisher.
    ///
    /// **This is the micropayment fast path.** It runs once per committed
    /// record and does no signature work — authorisation happened once, at
    /// subscribe time. Iteration is over a `BTreeMap`, so the order in which
    /// subscribers are charged (and therefore the resulting state) is identical
    /// on every validator.
    fn charge_subscribers(
        &mut self,
        stream: &peregrine_data::streams::StreamId,
        publisher: &peregrine_core::PublicKey,
    ) {
        let round = self.current_round;
        let mut charged: Vec<(Hash, Grains)> = Vec::new();
        for (id, st) in self.sessions.iter_mut() {
            if let Some(paid) = sessions::charge_subscription(st, stream, round) {
                charged.push((*id, paid));
            }
        }
        let mut total = 0u64;
        for (id, paid) in &charged {
            // AUDIT L-2: saturating, matching the discipline used everywhere else
            // in the fee/session path. Overflow is unreachable in practice, but a
            // silent wrap on a consensus path is not something to leave to chance.
            total = total.saturating_add(*paid);
            self.materialize_session(id);
        }
        if total > 0 {
            self.credit(publisher, total);
            self.metrics.micropayments += charged.len() as u64;
            self.metrics.micropayment_grains += total;
        }
    }

    /// Apply one committed shred given its precomputed signature verdict.
    fn apply_shred(&mut self, shred: &peregrine_data::streams::StreamShred, sig_ok: bool) {
        let mut meter = DualMeter::default();
        // Captured before the borrow below; the publisher is who subscription
        // fees are paid to.
        let publisher = self.streams.publisher_key_for(shred);
        match self.streams.apply_committed_with(shred, sig_ok) {
            Ok(data_bytes) => {
                meter.tick_data(data_bytes);
                let mut key = Vec::with_capacity(40);
                key.extend_from_slice(&shred.record.stream.0 .0);
                key.extend_from_slice(&shred.record.seq.to_be_bytes());
                meter.tick_data((key.len() + shred.record.payload.len()) as u64);
                self.tables
                    .insert(ticks_table(), key, shred.record.payload.clone());

                // If this stream belongs to a registered feed, materialize the
                // observation: update the provider's source cell and re-aggregate
                // the fresh sources into the feed's latest value.
                if let Some((feed_id, provider)) = self.feeds.feed_for_stream(&shred.record.stream)
                {
                    self.materialize_feed_observation(feed_id, provider, &shred.record.payload);
                }

                // Micropayments ride the same committed record: every session
                // subscribed to this stream pays its per-record price, and the
                // publisher is credited the total. Runs after the shred is
                // accepted, so nobody pays for data that was rejected.
                if let Some(publisher) = publisher {
                    self.charge_subscribers(&shred.record.stream, &publisher);
                }

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
                // Delegate to the one shred implementation rather than
                // duplicating it. An earlier revision had two copies of this
                // logic — the batch path and this one — and micropayments were
                // silently charged on only one of them. One path, one set of
                // effects. Verification is inline here because this entry point
                // has no tile pool behind it.
                let ok = self
                    .streams
                    .publisher_key_for(&shred)
                    .map(|pk| {
                        peregrine_core::crypto::verify(
                            &pk,
                            peregrine_data::streams::STREAM_DOMAIN,
                            &StreamRegistry::signing_bytes_of(&shred),
                            &shred.signature,
                        )
                        .is_ok()
                    })
                    .unwrap_or(false);
                self.apply_shred(&shred, ok);
                return; // `apply_shred` settles its own meter
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
            WirePayload::OpenSession(signed) => {
                meter.tick_data(bincode::serialized_size(&signed).unwrap_or(0));
                match self.open_session(&signed) {
                    Ok(id) => tracing::debug!(session = %id, "session opened"),
                    Err(e) => tracing::warn!("session grant rejected: {e}"),
                }
            }
            WirePayload::RevokeSession {
                session_id,
                signature,
            } => {
                if self.revoke_session(&session_id, &signature) {
                    tracing::debug!(session = %session_id, "session revoked");
                } else {
                    tracing::warn!("revocation rejected for {session_id}");
                }
                meter.tick_compute(1_000);
            }
            WirePayload::SessionAction(signed) => {
                meter.tick_data(bincode::serialized_size(&signed).unwrap_or(0));
                match self.apply_session_action(&signed) {
                    Ok(spent) => {
                        self.metrics.session_actions_applied += 1;
                        self.metrics.session_grains_spent += spent;
                    }
                    Err(e) => {
                        self.metrics.session_actions_rejected += 1;
                        tracing::warn!("session action rejected: {e}");
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
            WirePayload::Attestation(signed) => {
                // The attester's signature is verified on every validator before
                // the flag is materialized; metered on both meters like a claim,
                // so unpriced signature checking cannot be a DoS vector.
                meter.tick_data(bincode::serialized_size(&signed).unwrap_or(0));
                meter.tick_compute(CU_VERIFY_CLAIM);
                match self.apply_attestation(&signed) {
                    Ok(_) => self.metrics.attestations_applied += 1,
                    Err(e) => {
                        self.metrics.attestations_rejected += 1;
                        tracing::warn!("attestation rejected: {e}");
                    }
                }
            }
            WirePayload::RegisterFeed(spec) => {
                meter.tick_data(bincode::serialized_size(&spec).unwrap_or(0));
                let id = self.register_feed(*spec);
                tracing::debug!(feed = ?id, "feed registered");
            }
            WirePayload::FaucetDrip(signed) => {
                // One signature to verify plus a couple of table reads, like any
                // signed submission; metered so it cannot be a free DoS.
                meter.tick_data(bincode::serialized_size(&signed).unwrap_or(0));
                meter.tick_compute(CU_VERIFY_CLAIM);
                match self.apply_faucet_drip(&signed) {
                    Ok(()) => self.metrics.faucet_drips_applied += 1,
                    Err(e) => {
                        self.metrics.faucet_drips_rejected += 1;
                        tracing::debug!("faucet drip refused: {e}");
                    }
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
        // Every session rule below is evaluated against this round, so all
        // validators agree on exactly when a session expires.
        self.current_round = round;

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
