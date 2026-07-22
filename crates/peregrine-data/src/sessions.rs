//! # Session keys and micropayments
//!
//! Autonomous agents need to act continuously without holding a key that can
//! drain an account. A **session key** is a delegation: the principal signs a
//! grant that lets a throwaway key act on its behalf, but only within a scope,
//! only up to a budget, and only until a deadline.
//!
//! ```text
//!   principal  ──signs──▶  SessionGrant { scope, budget, expires_at_round }
//!                              │
//!   session key ──signs──▶  SessionAction { session_id, nonce, action }
//!                              │
//!                          commit path: scope? budget? expired? revoked?
//! ```
//!
//! ## Time is measured in committed rounds, never in seconds
//!
//! This is the single most important decision in this module. A session that
//! expired at a wall-clock timestamp would expire at a *different point in the
//! committed order* on every validator, because no two machines agree on the
//! time. Half the network would accept an action the other half rejected, and
//! the chain would fork.
//!
//! Rounds are the only clock every validator already agrees on, so
//! `expires_at_round` is compared against the round currently being committed.
//! It costs callers some convenience — a TTL in rounds is less intuitive than
//! one in minutes — and buys determinism, which is not negotiable.
//!
//! ## What a session key can and cannot do
//!
//! A grant is a *restriction*, never an expansion. A session key can do
//! strictly less than its principal:
//!
//! | | |
//! |---|---|
//! | write a table | only tables named in the scope |
//! | subscribe to a stream | only streams named in the scope |
//! | spend | up to `budget_grains` in total, and `max_spend_per_action` at once |
//! | act | only before `expires_at_round`, and only until revoked |
//! | delegate further | **never** — there is no sub-delegation |
//!
//! Every check is a pure function of committed state, so two validators reach
//! the same verdict for the same action at the same round.
//!
//! ## Replay
//!
//! Each action carries a strictly increasing `nonce` per session. Replaying a
//! signed action is refused because the stored `next_nonce` has already moved
//! past it — which also means actions from one session are totally ordered,
//! and a relayer cannot reorder an agent's intent.

use crate::streams::StreamId;
use crate::tables::TableId;
use peregrine_core::{crypto, Hash, PublicKey, Round, Signature};
use serde::{Deserialize, Serialize};

/// Domain tags. A grant signature must never be mistakable for an action
/// signature — otherwise a principal signing a grant could be tricked into
/// having signed an action, or vice versa.
pub const GRANT_DOMAIN: &[u8] = b"peregrine.session.grant.v1";
pub const ACTION_DOMAIN: &[u8] = b"peregrine.session.action.v1";
/// Revocation is signed by the principal, in its own domain so a revocation
/// can never be replayed as a grant or an action.
pub const REVOKE_DOMAIN: &[u8] = b"peregrine.session.revoke.v1";

/// Table holding live session state, readable like any other Peregrine table
/// so an agent (or anyone) can prove what a session is allowed to do.
pub fn sessions_table() -> TableId {
    TableId::named("sys.sessions")
}

/// Table holding grains **received** per account.
///
/// AUDIT M-1 — this is a **credit-only running total, not a conserved ledger**.
/// Payments credit the payee without debiting the payer, because the scaffold
/// has no funding primitive (no genesis allocation, faucet, or mint) so every
/// account starts at zero and a conservative model would make the first payment
/// impossible. A session's `budget_grains` caps emission per session; it is not
/// backed by funds. Do not treat these balances as spendable value — a real
/// ledger is future economic work. See `ExecutionPipeline::credit`.
pub fn balances_table() -> TableId {
    TableId::named("sys.balances")
}

/// Check a principal's revocation signature for `session_id`.
pub fn verify_revocation(principal: &PublicKey, session_id: &Hash, signature: &Signature) -> bool {
    crypto::verify(principal, REVOKE_DOMAIN, &session_id.0, signature).is_ok()
}

/// Sign a revocation (principal side).
pub fn sign_revocation(principal_key: &peregrine_core::Keypair, session_id: &Hash) -> Signature {
    principal_key.sign(REVOKE_DOMAIN, &session_id.0)
}

/// The unit of account, matching the fee schedule's grains.
pub type Grains = u64;

/// What a session key is permitted to do.
///
/// Deliberately an allow-list. A scope that defaulted to "everything except…"
/// would grant new capabilities to old sessions every time the protocol gained
/// a feature — the opposite of what a delegation should do.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scope {
    /// Tables this session may write. Empty means none.
    pub tables: Vec<TableId>,
    /// Streams this session may subscribe to (and pay for). Empty means none.
    pub streams: Vec<StreamId>,
    /// Ceiling on a single payment, independent of the total budget.
    ///
    /// The budget bounds total loss; this bounds loss per mistake. An agent
    /// with a 10,000-grain budget and a 5-grain cap can be wrong two thousand
    /// times cheaply, rather than once catastrophically.
    pub max_spend_per_action: Grains,
}

impl Scope {
    pub fn allows_table(&self, t: &TableId) -> bool {
        self.tables.contains(t)
    }
    pub fn allows_stream(&self, s: &StreamId) -> bool {
        self.streams.contains(s)
    }
}

/// A principal's delegation to a session key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionGrant {
    /// The account being spent from and acted for.
    pub principal: PublicKey,
    /// The delegated key. Held by the agent; compromise is bounded by scope,
    /// budget, and expiry.
    pub session_key: PublicKey,
    pub scope: Scope,
    /// Total spend this session may ever authorise.
    pub budget_grains: Grains,
    /// Last round at which this session is valid, **inclusive**.
    pub expires_at_round: Round,
    /// Distinguishes grants that are otherwise identical, so a principal can
    /// re-open a session with the same parameters after revoking one.
    pub grant_nonce: u64,
}

impl SessionGrant {
    /// Exact bytes the principal signs.
    pub fn signing_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("grant serialize")
    }

    /// Content-addressed identity. Two different grants can never share an id,
    /// so a session cannot be silently replaced by another with a wider scope.
    pub fn id(&self) -> Hash {
        Hash::digest(&self.signing_bytes())
    }

    /// Catch a grant that is misconfigured in a way that makes it useless. A
    /// budget with no per-action cap can never authorise a single payment (every
    /// spend of a positive amount exceeds a zero cap), so a caller that funds a
    /// session but forgets `max_per_action` has silently built a session that
    /// can never pay. Surfacing that here turns a confusing runtime rejection
    /// into a clear one before the grant is ever signed or submitted.
    ///
    /// A *scope-only* session (no budget, no cap) is valid — it just cannot
    /// spend, which is exactly what a write-only agent wants.
    pub fn validate(&self) -> Result<(), SessionError> {
        if self.budget_grains > 0 && self.scope.max_spend_per_action == 0 {
            return Err(SessionError::UnspendableBudget {
                budget: self.budget_grains,
            });
        }
        Ok(())
    }
}

/// A grant plus the principal's signature over it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedGrant {
    pub grant: SessionGrant,
    pub signature: Signature,
}

impl SignedGrant {
    pub fn new(principal_key: &peregrine_core::Keypair, grant: SessionGrant) -> Self {
        let signature = principal_key.sign(GRANT_DOMAIN, &grant.signing_bytes());
        Self { grant, signature }
    }

    /// Check the principal really authorised this grant.
    pub fn verify(&self) -> bool {
        crypto::verify(
            &self.grant.principal,
            GRANT_DOMAIN,
            &self.grant.signing_bytes(),
            &self.signature,
        )
        .is_ok()
    }
}

/// What a session key is asking to do.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    /// Write a value into a table the scope allows.
    Write {
        table: TableId,
        key: Vec<u8>,
        value: Vec<u8>,
    },
    /// Pay `amount` to `payee` from the session budget.
    Pay { payee: PublicKey, amount: Grains },
    /// Subscribe to a stream, paying `price_per_record` for each committed
    /// record until the budget runs out or the session ends.
    ///
    /// This is the micropayment primitive: once open, payment happens on the
    /// fast path with no further signatures, one debit per record, in
    /// committed order.
    Subscribe {
        stream: StreamId,
        price_per_record: Grains,
    },
    /// Stop paying for a stream.
    Unsubscribe { stream: StreamId },
}

/// An action authorised by a session key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionAction {
    pub session_id: Hash,
    /// Strictly increasing per session. Replays are refused.
    pub nonce: u64,
    pub action: Action,
}

impl SessionAction {
    pub fn signing_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("action serialize")
    }
}

/// A session action plus the session key's signature.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedAction {
    pub action: SessionAction,
    pub signature: Signature,
}

impl SignedAction {
    pub fn new(session_key: &peregrine_core::Keypair, action: SessionAction) -> Self {
        let signature = session_key.sign(ACTION_DOMAIN, &action.signing_bytes());
        Self { action, signature }
    }
}

/// Live state of a session, as committed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionState {
    pub grant: SessionGrant,
    /// Grains spent so far. Never exceeds `grant.budget_grains`.
    pub spent: Grains,
    /// Next acceptable nonce.
    pub next_nonce: u64,
    /// Revoked by the principal. Terminal — a revoked session is never
    /// reusable, because reactivating one would make revocation advisory.
    pub revoked: bool,
    /// Streams currently paid for, with their per-record price.
    pub subscriptions: Vec<(StreamId, Grains)>,
}

impl SessionState {
    pub fn open(grant: SessionGrant) -> Self {
        Self {
            grant,
            spent: 0,
            next_nonce: 0,
            revoked: false,
            subscriptions: Vec::new(),
        }
    }

    pub fn remaining(&self) -> Grains {
        self.grant.budget_grains.saturating_sub(self.spent)
    }

    pub fn price_for(&self, stream: &StreamId) -> Option<Grains> {
        self.subscriptions
            .iter()
            .find(|(s, _)| s == stream)
            .map(|(_, p)| *p)
    }

    /// Whether the session can still act at `round`: not revoked and not
    /// expired. The same predicate `authorize` and `charge_subscription` apply,
    /// exposed so an agent can check before it bothers signing.
    pub fn is_active(&self, round: Round) -> bool {
        !self.revoked && round <= self.grant.expires_at_round
    }

    /// Whether this session is currently paying for `stream`.
    pub fn is_subscribed(&self, stream: &StreamId) -> bool {
        self.price_for(stream).is_some()
    }

    /// Serialize the committed state — the exact bytes materialized into
    /// `sys.sessions`.
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("session state serialize")
    }

    /// Decode committed state read from `sys.sessions`, so an agent (or anyone)
    /// can **prove** what a session is allowed to do and how much it has left,
    /// rather than being told. `None` if the bytes are not a session state.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        bincode::deserialize(bytes).ok()
    }
}

/// Why an action was refused. Each variant is a distinct rule, so a rejection
/// is legible in a log rather than a generic failure.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SessionError {
    #[error("no such session")]
    UnknownSession,
    #[error("session was revoked")]
    Revoked,
    #[error("session expired at round {expires_at}, now {now}")]
    Expired { expires_at: Round, now: Round },
    #[error("bad session-key signature")]
    BadSignature,
    #[error("nonce {got} replays or skips; expected {expected}")]
    BadNonce { got: u64, expected: u64 },
    #[error("table not in session scope")]
    TableOutOfScope,
    #[error("stream not in session scope")]
    StreamOutOfScope,
    #[error("payment of {amount} exceeds per-action cap {cap}")]
    ExceedsPerActionCap { amount: Grains, cap: Grains },
    #[error("payment of {amount} exceeds remaining budget {remaining}")]
    ExceedsBudget { amount: Grains, remaining: Grains },
    #[error("grant signature is not from the named principal")]
    BadGrant,
    #[error("grant already expired at open (round {expires_at}, now {now})")]
    GrantAlreadyExpired { expires_at: Round, now: Round },
    #[error("only the principal may revoke")]
    NotPrincipal,
    #[error("grant has a {budget}-grain budget but a per-action cap of 0 — it could never spend a grain; set max_per_action")]
    UnspendableBudget { budget: Grains },
}

/// Validate a signed action against a session at `round`.
///
/// **Pure.** Takes state and returns a verdict; mutates nothing. That is what
/// lets the caller check every rule before touching state, and what makes the
/// rules testable without a chain.
///
/// Order matters: identity and authorisation are established before anything
/// derived from the action's contents is trusted.
pub fn authorize(
    state: &SessionState,
    signed: &SignedAction,
    round: Round,
) -> Result<Grains, SessionError> {
    // 1. Is this session usable at all?
    if state.revoked {
        return Err(SessionError::Revoked);
    }
    if round > state.grant.expires_at_round {
        return Err(SessionError::Expired {
            expires_at: state.grant.expires_at_round,
            now: round,
        });
    }

    // 2. Did the session key actually sign this? Checked before any field of
    //    the action is used, so unsigned data never reaches a policy decision.
    if crypto::verify(
        &state.grant.session_key,
        ACTION_DOMAIN,
        &signed.action.signing_bytes(),
        &signed.signature,
    )
    .is_err()
    {
        return Err(SessionError::BadSignature);
    }

    // 3. Exactly the next nonce — no replays, no gaps.
    if signed.action.nonce != state.next_nonce {
        return Err(SessionError::BadNonce {
            got: signed.action.nonce,
            expected: state.next_nonce,
        });
    }

    // 4. Scope and budget. Returns what this action will cost.
    let cost = match &signed.action.action {
        Action::Write { table, .. } => {
            if !state.grant.scope.allows_table(table) {
                return Err(SessionError::TableOutOfScope);
            }
            0
        }
        Action::Pay { amount, .. } => {
            check_spend(state, *amount)?;
            *amount
        }
        Action::Subscribe {
            stream,
            price_per_record,
        } => {
            if !state.grant.scope.allows_stream(stream) {
                return Err(SessionError::StreamOutOfScope);
            }
            // The per-action cap applies to the *price*, because that price is
            // charged repeatedly without further authorisation. Checking it
            // only at subscribe time is the whole point: it is the last moment
            // a human-authorised signature is involved.
            if *price_per_record > state.grant.scope.max_spend_per_action {
                return Err(SessionError::ExceedsPerActionCap {
                    amount: *price_per_record,
                    cap: state.grant.scope.max_spend_per_action,
                });
            }
            0
        }
        Action::Unsubscribe { .. } => 0,
    };

    Ok(cost)
}

fn check_spend(state: &SessionState, amount: Grains) -> Result<(), SessionError> {
    if amount > state.grant.scope.max_spend_per_action {
        return Err(SessionError::ExceedsPerActionCap {
            amount,
            cap: state.grant.scope.max_spend_per_action,
        });
    }
    if amount > state.remaining() {
        return Err(SessionError::ExceedsBudget {
            amount,
            remaining: state.remaining(),
        });
    }
    Ok(())
}

/// Charge a per-record subscription fee, if this session is paying for the
/// stream and can still afford it.
///
/// Returns the amount actually charged. **Runs on the fast path**, once per
/// committed record per subscriber, so it does no signature work: the
/// authorisation happened once, at subscribe time.
///
/// A session that runs out of budget simply stops paying — and therefore stops
/// being owed data. It is not an error, and it must not be: an agent whose
/// budget lapses mid-stream should degrade, not halt the chain.
pub fn charge_subscription(
    state: &mut SessionState,
    stream: &StreamId,
    round: Round,
) -> Option<Grains> {
    if state.revoked || round > state.grant.expires_at_round {
        return None;
    }
    let price = state.price_for(stream)?;
    if price > state.remaining() {
        return None;
    }
    state.spent = state.spent.saturating_add(price);
    Some(price)
}

/// Fluent construction of a session grant.
///
/// Sessions are a security primitive, so the ergonomics matter: an API that
/// makes the safe thing verbose is an API that gets bypassed. Every restriction
/// starts at its **most restrictive** value — no tables, no streams, no spend —
/// and must be widened explicitly. Forgetting a builder call can only ever
/// produce a session that does less than intended.
pub struct SessionBuilder {
    scope: Scope,
    budget: Grains,
    expires_at_round: Round,
    grant_nonce: u64,
}

impl SessionBuilder {
    /// Start a grant that expires at `expires_at_round`.
    ///
    /// Expiry is mandatory rather than optional because there is no sensible
    /// default: a session with no deadline is a permanent key, which is the
    /// thing this whole module exists to avoid.
    pub fn new(expires_at_round: Round) -> Self {
        Self {
            scope: Scope::default(),
            budget: 0,
            expires_at_round,
            grant_nonce: 0,
        }
    }

    /// Allow writes to `table`.
    pub fn allow_table(mut self, table: TableId) -> Self {
        self.scope.tables.push(table);
        self
    }

    /// Allow subscribing to (and paying for) `stream`.
    pub fn allow_stream(mut self, stream: StreamId) -> Self {
        self.scope.streams.push(stream);
        self
    }

    /// Allow several streams at once — e.g. every source of a feed via
    /// [`FeedSpec::provider_streams`](crate::feeds::FeedSpec::provider_streams).
    pub fn allow_streams<I: IntoIterator<Item = StreamId>>(mut self, streams: I) -> Self {
        self.scope.streams.extend(streams);
        self
    }

    /// Total spend across the session's whole life.
    pub fn budget(mut self, grains: Grains) -> Self {
        self.budget = grains;
        self
    }

    /// Ceiling on any single payment or subscription price.
    pub fn max_per_action(mut self, grains: Grains) -> Self {
        self.scope.max_spend_per_action = grains;
        self
    }

    /// Distinguish this grant from an identical earlier one.
    pub fn nonce(mut self, n: u64) -> Self {
        self.grant_nonce = n;
        self
    }

    /// The unsigned grant this builder describes, for `session_key`.
    pub fn build(&self, principal: PublicKey, session_key: PublicKey) -> SessionGrant {
        SessionGrant {
            principal,
            session_key,
            scope: self.scope.clone(),
            budget_grains: self.budget,
            expires_at_round: self.expires_at_round,
            grant_nonce: self.grant_nonce,
        }
    }

    /// Sign the grant with the principal's key, delegating to `session_key`.
    ///
    /// Infallible for backward compatibility; prefer [`try_sign`](Self::try_sign),
    /// which first rejects a misconfigured grant (e.g. a budget with no
    /// per-action cap) with a clear error instead of leaving the agent to
    /// discover at spend time that it can never pay.
    pub fn sign(self, principal: &peregrine_core::Keypair, session_key: &PublicKey) -> SignedGrant {
        let grant = self.build(principal.public(), *session_key);
        SignedGrant::new(principal, grant)
    }

    /// Validate the grant, then sign it. Returns [`SessionError::UnspendableBudget`]
    /// for a funded session that could never spend.
    pub fn try_sign(
        self,
        principal: &peregrine_core::Keypair,
        session_key: &PublicKey,
    ) -> Result<SignedGrant, SessionError> {
        let grant = self.build(principal.public(), *session_key);
        grant.validate()?;
        Ok(SignedGrant::new(principal, grant))
    }
}

/// Client-side helper: tracks a session's nonce so an agent does not have to.
///
/// A wrong nonce is refused, so getting this right is not optional — and
/// making callers track it by hand is how they get it wrong.
pub struct SessionSigner {
    session_key: peregrine_core::Keypair,
    session_id: Hash,
    next_nonce: u64,
}

impl SessionSigner {
    pub fn new(session_key: peregrine_core::Keypair, session_id: Hash) -> Self {
        Self {
            session_key,
            session_id,
            next_nonce: 0,
        }
    }

    pub fn session_id(&self) -> Hash {
        self.session_id
    }

    /// The nonce the next signed action will carry.
    pub fn next_nonce(&self) -> u64 {
        self.next_nonce
    }

    /// Sign the next action, advancing the nonce.
    pub fn sign(&mut self, action: Action) -> SignedAction {
        let signed = SignedAction::new(
            &self.session_key,
            SessionAction {
                session_id: self.session_id,
                nonce: self.next_nonce,
                action,
            },
        );
        self.next_nonce += 1;
        signed
    }

    // ── ergonomic action builders ────────────────────────────────────────────
    // One call each, so an agent never hand-assembles an `Action` or forgets a
    // field. All go through `sign`, so they share its nonce discipline.

    /// Pay `amount` grains to `payee`.
    pub fn pay(&mut self, payee: PublicKey, amount: Grains) -> SignedAction {
        self.sign(Action::Pay { payee, amount })
    }

    /// Subscribe to `stream`, paying `price_per_record` per committed record
    /// thereafter — the micropayment fast path, one signature for an ongoing
    /// stream of debits.
    pub fn subscribe(&mut self, stream: StreamId, price_per_record: Grains) -> SignedAction {
        self.sign(Action::Subscribe {
            stream,
            price_per_record,
        })
    }

    /// Stop paying for `stream`.
    pub fn unsubscribe(&mut self, stream: StreamId) -> SignedAction {
        self.sign(Action::Unsubscribe { stream })
    }

    /// Write `value` at `key` in `table` (must be in the session's scope).
    pub fn write(&mut self, table: TableId, key: Vec<u8>, value: Vec<u8>) -> SignedAction {
        self.sign(Action::Write { table, key, value })
    }

    /// Rewind after a rejected submission, so the next attempt reuses the
    /// nonce the chain is still expecting.
    pub fn rollback(&mut self) {
        self.next_nonce = self.next_nonce.saturating_sub(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use peregrine_core::Keypair;

    fn keys() -> (Keypair, Keypair) {
        let mut rng = rand::rngs::OsRng;
        (Keypair::generate(&mut rng), Keypair::generate(&mut rng))
    }

    fn table() -> TableId {
        TableId::named("agent.notes")
    }
    fn other_table() -> TableId {
        TableId::named("treasury.balances")
    }
    fn stream() -> StreamId {
        StreamId::derive(
            "prices/BTC",
            &Keypair::generate(&mut rand::rngs::OsRng).public(),
        )
    }

    fn session(
        principal: &Keypair,
        agent: &Keypair,
        budget: Grains,
        expires: Round,
    ) -> SessionState {
        SessionState::open(SessionGrant {
            principal: principal.public(),
            session_key: agent.public(),
            scope: Scope {
                tables: vec![table()],
                streams: vec![],
                max_spend_per_action: 100,
            },
            budget_grains: budget,
            expires_at_round: expires,
            grant_nonce: 0,
        })
    }

    fn act(agent: &Keypair, st: &SessionState, nonce: u64, action: Action) -> SignedAction {
        SignedAction::new(
            agent,
            SessionAction {
                session_id: st.grant.id(),
                nonce,
                action,
            },
        )
    }

    // ── grants ──────────────────────────────────────────────────────────────

    #[test]
    fn a_grant_verifies_only_against_its_principal() {
        let (principal, agent) = keys();
        let st = session(&principal, &agent, 1000, 100);
        let signed = SignedGrant::new(&principal, st.grant.clone());
        assert!(signed.verify());

        // Signed by someone else entirely.
        let mut forged = signed.clone();
        forged.signature = agent.sign(GRANT_DOMAIN, &st.grant.signing_bytes());
        assert!(!forged.verify(), "only the principal may grant");
    }

    #[test]
    fn changing_any_grant_field_invalidates_the_signature() {
        let (principal, agent) = keys();
        let st = session(&principal, &agent, 1000, 100);
        let signed = SignedGrant::new(&principal, st.grant.clone());

        let mut widened = signed.clone();
        widened.grant.budget_grains = 1_000_000;
        assert!(!widened.verify(), "budget must be covered by the signature");

        let mut extended = signed.clone();
        extended.grant.expires_at_round = 999_999;
        assert!(!extended.verify(), "expiry must be covered");

        let mut rescoped = signed;
        rescoped.grant.scope.tables.push(other_table());
        assert!(!rescoped.verify(), "scope must be covered");
    }

    #[test]
    fn session_ids_differ_whenever_grants_differ() {
        let (principal, agent) = keys();
        let a = session(&principal, &agent, 1000, 100);
        let mut b = a.clone();
        b.grant.budget_grains = 1001;
        assert_ne!(a.grant.id(), b.grant.id());
    }

    // ── authorisation ───────────────────────────────────────────────────────

    #[test]
    fn a_scoped_write_is_allowed_and_an_unscoped_one_is_not() {
        let (principal, agent) = keys();
        let st = session(&principal, &agent, 1000, 100);

        let ok = act(
            &agent,
            &st,
            0,
            Action::Write {
                table: table(),
                key: b"k".to_vec(),
                value: b"v".to_vec(),
            },
        );
        assert_eq!(authorize(&st, &ok, 1), Ok(0));

        let nope = act(
            &agent,
            &st,
            0,
            Action::Write {
                table: other_table(),
                key: b"k".to_vec(),
                value: b"v".to_vec(),
            },
        );
        assert_eq!(authorize(&st, &nope, 1), Err(SessionError::TableOutOfScope));
    }

    #[test]
    fn only_the_session_key_can_act() {
        let (principal, agent) = keys();
        let (_, impostor) = keys();
        let st = session(&principal, &agent, 1000, 100);

        let forged = act(
            &impostor,
            &st,
            0,
            Action::Pay {
                payee: principal.public(),
                amount: 1,
            },
        );
        assert_eq!(authorize(&st, &forged, 1), Err(SessionError::BadSignature));
    }

    /// **The budget is the point of the whole design.** A compromised session
    /// key must not be able to spend more than the principal allotted.
    #[test]
    fn spending_is_capped_by_the_budget() {
        let (principal, agent) = keys();
        let mut st = session(&principal, &agent, 250, 100);
        st.grant.scope.max_spend_per_action = 1000; // per-action cap not the binding constraint

        let a = act(
            &agent,
            &st,
            0,
            Action::Pay {
                payee: principal.public(),
                amount: 300,
            },
        );
        assert_eq!(
            authorize(&st, &a, 1),
            Err(SessionError::ExceedsBudget {
                amount: 300,
                remaining: 250
            })
        );

        // And after partial spend, the remainder shrinks.
        st.spent = 200;
        let b = act(
            &agent,
            &st,
            0,
            Action::Pay {
                payee: principal.public(),
                amount: 60,
            },
        );
        assert!(matches!(
            authorize(&st, &b, 1),
            Err(SessionError::ExceedsBudget { .. })
        ));
    }

    #[test]
    fn the_per_action_cap_bounds_a_single_mistake() {
        let (principal, agent) = keys();
        let st = session(&principal, &agent, 1_000_000, 100);
        let a = act(
            &agent,
            &st,
            0,
            Action::Pay {
                payee: principal.public(),
                amount: 101,
            },
        );
        assert_eq!(
            authorize(&st, &a, 1),
            Err(SessionError::ExceedsPerActionCap {
                amount: 101,
                cap: 100
            })
        );
    }

    /// Expiry is compared against the **committed round**, so every validator
    /// reaches the same verdict. A wall-clock TTL would fork the chain.
    #[test]
    fn expiry_is_evaluated_against_the_committed_round() {
        let (principal, agent) = keys();
        let st = session(&principal, &agent, 1000, 50);
        let a = act(
            &agent,
            &st,
            0,
            Action::Pay {
                payee: principal.public(),
                amount: 1,
            },
        );

        assert!(authorize(&st, &a, 49).is_ok(), "before expiry");
        assert!(authorize(&st, &a, 50).is_ok(), "expiry round is inclusive");
        assert_eq!(
            authorize(&st, &a, 51),
            Err(SessionError::Expired {
                expires_at: 50,
                now: 51
            })
        );
    }

    #[test]
    fn revocation_is_immediate_and_terminal() {
        let (principal, agent) = keys();
        let mut st = session(&principal, &agent, 1000, 100);
        st.revoked = true;
        let a = act(
            &agent,
            &st,
            0,
            Action::Pay {
                payee: principal.public(),
                amount: 1,
            },
        );
        assert_eq!(authorize(&st, &a, 1), Err(SessionError::Revoked));
        // Even an otherwise-perfect action at a valid round stays refused.
        assert_eq!(authorize(&st, &a, 2), Err(SessionError::Revoked));
    }

    #[test]
    fn a_replayed_action_is_refused() {
        let (principal, agent) = keys();
        let mut st = session(&principal, &agent, 1000, 100);
        let a = act(
            &agent,
            &st,
            0,
            Action::Pay {
                payee: principal.public(),
                amount: 5,
            },
        );
        assert!(authorize(&st, &a, 1).is_ok());

        // Simulate application: nonce advances.
        st.next_nonce = 1;
        assert_eq!(
            authorize(&st, &a, 1),
            Err(SessionError::BadNonce {
                got: 0,
                expected: 1
            })
        );
    }

    #[test]
    fn nonces_may_not_skip() {
        let (principal, agent) = keys();
        let st = session(&principal, &agent, 1000, 100);
        let a = act(
            &agent,
            &st,
            7,
            Action::Pay {
                payee: principal.public(),
                amount: 1,
            },
        );
        assert_eq!(
            authorize(&st, &a, 1),
            Err(SessionError::BadNonce {
                got: 7,
                expected: 0
            })
        );
    }

    // ── subscriptions (the micropayment fast path) ──────────────────────────

    #[test]
    fn subscribing_requires_the_stream_to_be_in_scope() {
        let (principal, agent) = keys();
        let st = session(&principal, &agent, 1000, 100);
        let a = act(
            &agent,
            &st,
            0,
            Action::Subscribe {
                stream: stream(),
                price_per_record: 1,
            },
        );
        assert_eq!(authorize(&st, &a, 1), Err(SessionError::StreamOutOfScope));
    }

    #[test]
    fn a_subscription_price_is_capped_at_subscribe_time() {
        let (principal, agent) = keys();
        let s = stream();
        let mut st = session(&principal, &agent, 1_000_000, 100);
        st.grant.scope.streams.push(s);

        let a = act(
            &agent,
            &st,
            0,
            Action::Subscribe {
                stream: s,
                price_per_record: 500, // above the 100 cap
            },
        );
        assert!(matches!(
            authorize(&st, &a, 1),
            Err(SessionError::ExceedsPerActionCap { .. })
        ));
    }

    #[test]
    fn each_record_debits_the_budget_once() {
        let (principal, agent) = keys();
        let s = stream();
        let mut st = session(&principal, &agent, 25, 100);
        st.subscriptions.push((s, 10));

        assert_eq!(charge_subscription(&mut st, &s, 1), Some(10));
        assert_eq!(charge_subscription(&mut st, &s, 1), Some(10));
        assert_eq!(st.spent, 20);
        // Third record costs more than the 5 remaining.
        assert_eq!(charge_subscription(&mut st, &s, 1), None);
        assert_eq!(st.spent, 20, "a refused charge must not partially debit");
    }

    /// Running out of budget stops the payments, not the chain.
    #[test]
    fn an_exhausted_budget_stops_paying_without_erroring() {
        let (principal, agent) = keys();
        let s = stream();
        let mut st = session(&principal, &agent, 10, 100);
        st.subscriptions.push((s, 10));
        assert_eq!(charge_subscription(&mut st, &s, 1), Some(10));
        for _ in 0..100 {
            assert_eq!(charge_subscription(&mut st, &s, 1), None);
        }
        assert_eq!(st.spent, 10, "never over-spends");
    }

    #[test]
    fn expiry_and_revocation_stop_subscription_charges() {
        let (principal, agent) = keys();
        let s = stream();
        let mut st = session(&principal, &agent, 1000, 50);
        st.subscriptions.push((s, 1));

        assert_eq!(charge_subscription(&mut st, &s, 50), Some(1));
        assert_eq!(charge_subscription(&mut st, &s, 51), None, "expired");

        let mut revoked = session(&principal, &agent, 1000, 100);
        revoked.subscriptions.push((s, 1));
        revoked.revoked = true;
        assert_eq!(charge_subscription(&mut revoked, &s, 1), None);
    }

    #[test]
    fn an_unsubscribed_stream_is_never_charged() {
        let (principal, agent) = keys();
        let mut st = session(&principal, &agent, 1000, 100);
        assert_eq!(charge_subscription(&mut st, &stream(), 1), None);
        assert_eq!(st.spent, 0);
    }

    // ── usability: validation, ergonomic signing, introspection ─────────────

    #[test]
    fn a_funded_session_with_no_per_action_cap_is_rejected() {
        let (principal, agent) = keys();
        // Budget but no per-action cap — it could never spend a grain.
        let err = SessionBuilder::new(100)
            .budget(1_000)
            .try_sign(&principal, &agent.public())
            .unwrap_err();
        assert_eq!(err, SessionError::UnspendableBudget { budget: 1_000 });

        // The same builder with a cap is fine.
        assert!(SessionBuilder::new(100)
            .budget(1_000)
            .max_per_action(10)
            .try_sign(&principal, &agent.public())
            .is_ok());

        // A scope-only (write-only) session with no budget is valid.
        assert!(SessionBuilder::new(100)
            .allow_table(table())
            .try_sign(&principal, &agent.public())
            .is_ok());
    }

    #[test]
    fn signer_helpers_match_hand_built_actions() {
        let (_, agent) = keys();
        let id = Hash::digest(b"session");
        // Two signers from the same key/id produce identical bytes for the same
        // logical action — the helper is exactly `sign(Action::…)`.
        let mut a = SessionSigner::new(Keypair::from_bytes(&agent.to_bytes()), id);
        let mut b = SessionSigner::new(Keypair::from_bytes(&agent.to_bytes()), id);
        let payee = keys().0.public();

        let h1 = a.pay(payee, 5);
        let h2 = b.sign(Action::Pay { payee, amount: 5 });
        assert_eq!(h1.action, h2.action);
        assert_eq!(h1.signature.0, h2.signature.0);
        assert_eq!(a.next_nonce(), 1, "helper advances the nonce");

        // Nonces keep advancing across mixed helpers.
        let s = stream();
        assert_eq!(a.subscribe(s, 2).action.nonce, 1);
        assert_eq!(a.unsubscribe(s).action.nonce, 2);
        assert_eq!(a.write(table(), b"k".to_vec(), b"v".to_vec()).action.nonce, 3);
    }

    #[test]
    fn session_state_round_trips_and_reports_liveness() {
        let (principal, agent) = keys();
        let mut st = session(&principal, &agent, 1000, 50);
        let s = stream();
        st.subscriptions.push((s, 3));
        st.spent = 120;

        // Materialize → read back (the sys.sessions round trip).
        let decoded = SessionState::from_bytes(&st.to_bytes()).expect("decodes");
        assert_eq!(decoded, st);
        assert_eq!(decoded.remaining(), 880);
        assert!(decoded.is_subscribed(&s));
        assert!(decoded.is_active(50), "expiry round is inclusive");
        assert!(!decoded.is_active(51), "expired");

        let mut revoked = st.clone();
        revoked.revoked = true;
        assert!(!revoked.is_active(1), "a revoked session is never active");
        assert_eq!(SessionState::from_bytes(b"junk"), None);
    }

    #[test]
    fn allow_streams_scopes_a_whole_set_at_once() {
        let (principal, agent) = keys();
        let streams: Vec<StreamId> = (0..3)
            .map(|i| StreamId::derive(&format!("s{i}"), &agent.public()))
            .collect();
        let signed = SessionBuilder::new(100)
            .allow_streams(streams.clone())
            .max_per_action(10)
            .budget(100)
            .try_sign(&principal, &agent.public())
            .unwrap();
        for s in &streams {
            assert!(signed.grant.scope.allows_stream(s));
        }
    }
}
