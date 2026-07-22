//! Session keys and micropayments **through the commit path**.
//!
//! `sessions.rs` unit-tests the policy in isolation. These tests check the
//! things that only exist once policy meets state: that a refused action
//! leaves nothing behind, that budgets survive contact with the fast path,
//! that revocation actually stops the meter, and that two validators reach the
//! same state.

use peregrine_core::{Hash, Keypair, PublicKey};
use peregrine_data::sessions::{
    balances_table, sign_revocation, Action, Grains, Scope, SessionAction, SessionGrant,
    SignedAction, SignedGrant,
};
use peregrine_data::streams::{Publisher, StreamId};
use peregrine_data::tables::TableId;
use peregrine_node::payload::WirePayload;
use peregrine_node::pipeline::ExecutionPipeline;

const AGENT_TABLE: &str = "agent.notes";
const OFF_LIMITS: &str = "treasury.reserve";

struct Fixture {
    node: ExecutionPipeline,
    principal: Keypair,
    agent: Keypair,
    publisher_key: PublicKey,
    stream: StreamId,
    session_id: Hash,
    nonce: u64,
}

/// A node with a registered stream and one open session, at round 1.
fn setup(budget: Grains, per_action: Grains, expires: u64) -> (Fixture, Publisher) {
    let mut rng = rand::rngs::OsRng;
    let principal = Keypair::generate(&mut rng);
    let agent = Keypair::generate(&mut rng);
    let pub_kp = Keypair::generate(&mut rng);
    let publisher_key = pub_kp.public();

    let mut node = ExecutionPipeline::new();
    node.tables.create_table(TableId::named(AGENT_TABLE));
    let stream = node.streams.register("prices/BTC", publisher_key);
    node.set_round_for_test(1);

    let grant = SessionGrant {
        principal: principal.public(),
        session_key: agent.public(),
        scope: Scope {
            tables: vec![TableId::named(AGENT_TABLE)],
            streams: vec![stream],
            max_spend_per_action: per_action,
        },
        budget_grains: budget,
        expires_at_round: expires,
        grant_nonce: 0,
    };
    let session_id = grant.id();
    node.apply_payload(&WirePayload::OpenSession(Box::new(SignedGrant::new(
        &principal, grant,
    ))));

    (
        Fixture {
            node,
            principal,
            agent,
            publisher_key,
            stream,
            session_id,
            nonce: 0,
        },
        Publisher::new("prices/BTC", pub_kp),
    )
}

impl Fixture {
    /// Submit an action from the session key, advancing the local nonce.
    fn act(&mut self, action: Action) {
        let signed = SignedAction::new(
            &self.agent,
            SessionAction {
                session_id: self.session_id,
                nonce: self.nonce,
                action,
            },
        );
        self.node
            .apply_payload(&WirePayload::SessionAction(Box::new(signed)));
        self.nonce += 1;
    }

    fn spent(&self) -> Grains {
        self.node
            .sessions
            .get(&self.session_id)
            .map(|s| s.spent)
            .unwrap_or(0)
    }

    fn balance(&self, who: &PublicKey) -> u64 {
        self.node
            .tables
            .get(&balances_table(), &who.0)
            .and_then(|v| v.try_into().ok())
            .map(u64::from_le_bytes)
            .unwrap_or(0)
    }
}

// ── opening ─────────────────────────────────────────────────────────────────

#[test]
fn an_opened_session_is_readable_from_state() {
    let (fx, _) = setup(1_000, 100, 500);
    assert!(fx.node.sessions.contains_key(&fx.session_id));
    // Materialized, so anyone can *prove* what this session may do rather than
    // being told by a node.
    assert!(fx
        .node
        .tables
        .get(
            &peregrine_data::sessions::sessions_table(),
            &fx.session_id.0
        )
        .is_some());
}

#[test]
fn a_grant_signed_by_the_wrong_key_is_refused() {
    let mut rng = rand::rngs::OsRng;
    let principal = Keypair::generate(&mut rng);
    let impostor = Keypair::generate(&mut rng);
    let agent = Keypair::generate(&mut rng);
    let mut node = ExecutionPipeline::new();
    node.set_round_for_test(1);

    let grant = SessionGrant {
        principal: principal.public(), // claims to be the principal…
        session_key: agent.public(),
        scope: Scope::default(),
        budget_grains: 1_000_000,
        expires_at_round: 100,
        grant_nonce: 0,
    };
    // …but signed by someone else.
    let forged = SignedGrant::new(&impostor, grant);
    assert!(node.open_session(&forged).is_err());
    assert!(node.sessions.is_empty(), "nothing stored");
}

/// Re-delivering a grant must not reset spend — otherwise a replayed open
/// would refill the budget forever.
#[test]
fn reopening_a_session_does_not_refill_its_budget() {
    let (mut fx, _) = setup(100, 100, 500);
    fx.act(Action::Pay {
        payee: fx.publisher_key,
        amount: 60,
    });
    assert_eq!(fx.spent(), 60);

    let grant = fx.node.sessions[&fx.session_id].grant.clone();
    let replay = SignedGrant::new(&fx.principal, grant);
    fx.node.open_session(&replay).unwrap();

    assert_eq!(fx.spent(), 60, "budget must not reset");
}

// ── policy enforcement, end to end ──────────────────────────────────────────

#[test]
fn a_scoped_write_lands_and_an_unscoped_one_does_not() {
    let (mut fx, _) = setup(1_000, 100, 500);

    fx.act(Action::Write {
        table: TableId::named(AGENT_TABLE),
        key: b"note".to_vec(),
        value: b"hello".to_vec(),
    });
    assert_eq!(
        fx.node.tables.get(&TableId::named(AGENT_TABLE), b"note"),
        Some(&b"hello"[..])
    );

    // Out of scope: refused, and nothing is written.
    fx.act(Action::Write {
        table: TableId::named(OFF_LIMITS),
        key: b"drain".to_vec(),
        value: b"1".to_vec(),
    });
    assert_eq!(
        fx.node.tables.get(&TableId::named(OFF_LIMITS), b"drain"),
        None,
        "a session must not write outside its scope"
    );
    assert_eq!(fx.node.metrics.session_actions_rejected, 1);
}

/// **A refused action must leave nothing behind** — no debit, no nonce bump,
/// no partial write. Otherwise an attacker could burn a session's nonce space
/// or drain its budget with actions that never take effect.
#[test]
fn a_refused_action_changes_no_state() {
    let (mut fx, _) = setup(1_000, 10, 500);
    let before_spent = fx.spent();
    let before_nonce = fx.node.sessions[&fx.session_id].next_nonce;

    // Over the per-action cap.
    fx.act(Action::Pay {
        payee: fx.publisher_key,
        amount: 500,
    });

    assert_eq!(fx.spent(), before_spent, "no debit");
    assert_eq!(
        fx.node.sessions[&fx.session_id].next_nonce, before_nonce,
        "nonce must not advance on a refused action"
    );
    assert_eq!(fx.balance(&fx.publisher_key), 0, "no credit");
}

#[test]
fn payments_move_grains_and_are_bounded_by_the_budget() {
    let (mut fx, _) = setup(250, 100, 500);

    fx.act(Action::Pay {
        payee: fx.publisher_key,
        amount: 100,
    });
    fx.act(Action::Pay {
        payee: fx.publisher_key,
        amount: 100,
    });
    assert_eq!(fx.balance(&fx.publisher_key), 200);
    assert_eq!(fx.spent(), 200);

    // Third payment would exceed the 250 budget.
    fx.act(Action::Pay {
        payee: fx.publisher_key,
        amount: 100,
    });
    assert_eq!(
        fx.balance(&fx.publisher_key),
        200,
        "budget is a hard ceiling"
    );
    assert_eq!(fx.spent(), 200);
}

#[test]
fn an_expired_session_stops_acting() {
    let (mut fx, _) = setup(1_000, 100, 10);
    fx.node.set_round_for_test(10); // inclusive — still valid
    fx.act(Action::Pay {
        payee: fx.publisher_key,
        amount: 5,
    });
    assert_eq!(fx.spent(), 5);

    fx.node.set_round_for_test(11);
    fx.act(Action::Pay {
        payee: fx.publisher_key,
        amount: 5,
    });
    assert_eq!(fx.spent(), 5, "expired sessions cannot spend");
}

#[test]
fn only_the_principal_can_revoke() {
    let (mut fx, _) = setup(1_000, 100, 500);

    // The agent tries to revoke its own session — refused.
    let by_agent = sign_revocation(&fx.agent, &fx.session_id);
    assert!(!fx.node.revoke_session(&fx.session_id, &by_agent));
    assert!(!fx.node.sessions[&fx.session_id].revoked);

    let by_principal = sign_revocation(&fx.principal, &fx.session_id);
    assert!(fx.node.revoke_session(&fx.session_id, &by_principal));
    assert!(fx.node.sessions[&fx.session_id].revoked);
}

#[test]
fn revocation_stops_further_actions() {
    let (mut fx, _) = setup(1_000, 100, 500);
    let sig = sign_revocation(&fx.principal, &fx.session_id);
    fx.node.revoke_session(&fx.session_id, &sig);

    fx.act(Action::Pay {
        payee: fx.publisher_key,
        amount: 10,
    });
    assert_eq!(fx.spent(), 0);
    assert_eq!(fx.balance(&fx.publisher_key), 0);
}

// ── micropayments on the fast path ──────────────────────────────────────────

/// The headline: an agent subscribes once, then pays per committed record with
/// no further signatures.
#[test]
fn a_subscription_pays_per_committed_record() {
    let (mut fx, mut publisher) = setup(1_000, 10, 500);

    fx.act(Action::Subscribe {
        stream: fx.stream,
        price_per_record: 3,
    });

    for i in 0..5u64 {
        let shred = publisher.emit(i.to_le_bytes().to_vec());
        fx.node.apply_payload(&WirePayload::Shred(shred));
    }

    assert_eq!(fx.spent(), 15, "5 records x 3 grains");
    assert_eq!(fx.balance(&fx.publisher_key), 15, "publisher is credited");
    assert_eq!(fx.node.metrics.micropayments, 5);
}

/// **Running out of budget degrades, it does not halt.** The chain must keep
/// committing records; the agent simply stops paying (and stops being owed).
#[test]
fn an_exhausted_budget_stops_payment_but_not_the_stream() {
    let (mut fx, mut publisher) = setup(10, 10, 500);

    fx.act(Action::Subscribe {
        stream: fx.stream,
        price_per_record: 4,
    });

    for i in 0..10u64 {
        let shred = publisher.emit(i.to_le_bytes().to_vec());
        fx.node.apply_payload(&WirePayload::Shred(shred));
    }

    assert_eq!(fx.spent(), 8, "two records affordable, then nothing");
    assert_eq!(fx.balance(&fx.publisher_key), 8);
    // The records themselves still committed.
    assert_eq!(fx.node.metrics.committed_records, 10);
}

#[test]
fn unsubscribing_and_revoking_both_stop_the_meter() {
    let (mut fx, mut publisher) = setup(1_000, 10, 500);
    fx.act(Action::Subscribe {
        stream: fx.stream,
        price_per_record: 2,
    });
    fx.node
        .apply_payload(&WirePayload::Shred(publisher.emit(vec![1])));
    assert_eq!(fx.spent(), 2);

    fx.act(Action::Unsubscribe { stream: fx.stream });
    fx.node
        .apply_payload(&WirePayload::Shred(publisher.emit(vec![2])));
    assert_eq!(fx.spent(), 2, "unsubscribed sessions stop paying");

    // Re-subscribe, then revoke.
    fx.act(Action::Subscribe {
        stream: fx.stream,
        price_per_record: 2,
    });
    let sig = sign_revocation(&fx.principal, &fx.session_id);
    fx.node.revoke_session(&fx.session_id, &sig);
    fx.node
        .apply_payload(&WirePayload::Shred(publisher.emit(vec![3])));
    assert_eq!(fx.spent(), 2, "revocation stops the meter immediately");
}

/// A session may only pay for streams its principal allowed.
#[test]
fn a_session_cannot_subscribe_outside_its_scope() {
    let (mut fx, _) = setup(1_000, 10, 500);
    let mut rng = rand::rngs::OsRng;
    let other = StreamId::derive("prices/ETH", &Keypair::generate(&mut rng).public());

    fx.act(Action::Subscribe {
        stream: other,
        price_per_record: 1,
    });
    assert!(fx.node.sessions[&fx.session_id].subscriptions.is_empty());
    assert_eq!(fx.node.metrics.session_actions_rejected, 1);
}

// ── determinism ─────────────────────────────────────────────────────────────

/// Two validators applying the same committed sequence must reach identical
/// state. Session state feeds the materialized `sys.sessions` table, so a
/// non-deterministic iteration order here would move the store root and fork
/// the chain.
#[test]
fn two_nodes_applying_the_same_actions_agree() {
    fn run() -> Hash {
        // Fixed keys so both runs are genuinely the same input.
        let principal = Keypair::from_bytes(&[7u8; 32]);
        let agent = Keypair::from_bytes(&[9u8; 32]);
        let pub_kp = Keypair::from_bytes(&[11u8; 32]);

        let mut node = ExecutionPipeline::new();
        node.tables.create_table(TableId::named(AGENT_TABLE));
        let stream = node.streams.register("prices/BTC", pub_kp.public());
        node.set_round_for_test(1);

        // Several sessions, so map iteration order matters.
        for n in 0..4u64 {
            let grant = SessionGrant {
                principal: principal.public(),
                session_key: agent.public(),
                scope: Scope {
                    tables: vec![TableId::named(AGENT_TABLE)],
                    streams: vec![stream],
                    max_spend_per_action: 50,
                },
                budget_grains: 500,
                expires_at_round: 900,
                grant_nonce: n,
            };
            let id = grant.id();
            node.apply_payload(&WirePayload::OpenSession(Box::new(SignedGrant::new(
                &principal, grant,
            ))));
            let signed = SignedAction::new(
                &agent,
                SessionAction {
                    session_id: id,
                    nonce: 0,
                    action: Action::Subscribe {
                        stream,
                        price_per_record: 2,
                    },
                },
            );
            node.apply_payload(&WirePayload::SessionAction(Box::new(signed)));
        }

        let mut publisher = Publisher::new("prices/BTC", pub_kp);
        for i in 0..6u64 {
            node.apply_payload(&WirePayload::Shred(
                publisher.emit(i.to_le_bytes().to_vec()),
            ));
        }
        node.store_root()
    }

    let a = run();
    let b = run();
    assert_eq!(a, b, "identical inputs must give identical store roots");
}
