//! # RWA contract templates
//!
//! Ready-made TalonVM programs for the real-world-asset patterns that keep
//! recurring, so an integrator does not hand-assemble opcodes to do something
//! ordinary. Each returns a `Vec<Instr>` you can submit with
//! [`Client::submit_tx`](peregrine_sdk::Client::submit_tx).
//!
//! ## The property these all share
//!
//! Every template that touches foreign state uses [`Instr::LoadEthState`],
//! which **traps** when the value has not been proven — it never pushes zero.
//! That asymmetry is the whole reason these are worth templating: the naive
//! version of a collateral check reads a balance, gets `0` because the oracle
//! was down, and marks an under-collateralised loan healthy. Here the
//! transaction aborts and the loan's health simply is not updated, which is the
//! correct outcome for a missing fact.
//!
//! ## What these are not
//!
//! They are *templates*, not audited financial contracts. They demonstrate the
//! shape of a data-native RWA flow — an oracle valuation, a proven off-chain
//! balance, a deterministic verdict — and are deliberately small enough to read
//! in full before you trust one.

use peregrine_data::tables::TableId;
use peregrine_vm::Instr;

/// Registry of property titles: `property_id -> valuation`.
pub fn registry_table() -> TableId {
    TableId::named("rwa.registry")
}

/// Health verdicts: `property_id -> 1 healthy | 0 under-collateralised`.
pub fn health_table() -> TableId {
    TableId::named("rwa.health")
}

/// Ownership records: `property_id -> owner id`.
pub fn title_table() -> TableId {
    TableId::named("rwa.titles")
}

/// **Register a property title.**
///
/// Writes `owner_id` under `property_id` in `rwa.titles`. The simplest useful
/// RWA primitive: an assertion of ownership that anyone can later verify
/// against the store root without asking the registrar.
pub fn register_title(property_id: &[u8], owner_id: u64) -> Vec<Instr> {
    vec![
        Instr::Push(owner_id),
        Instr::StoreTable {
            table: title_table(),
            key: property_id.to_vec(),
        },
        Instr::Halt,
    ]
}

/// **Record an oracle valuation** for a property.
///
/// Separate from [`register_title`] on purpose: title and valuation change on
/// completely different schedules, and bundling them would force a re-assertion
/// of ownership every time a price moved.
pub fn record_valuation(property_id: &[u8], valuation: u64) -> Vec<Instr> {
    vec![
        Instr::Push(valuation),
        Instr::StoreTable {
            table: registry_table(),
            key: property_id.to_vec(),
        },
        Instr::Halt,
    ]
}

/// **Collateral health check against a *proven* Ethereum balance.**
///
/// Computes `required = valuation * ratio_pct / 100`, reads the borrower's
/// on-Ethereum collateral, and writes `1` (healthy) or `0` to `rwa.health`.
///
/// ```text
///   valuation  ←  rwa.registry[property]        (oracle, on Peregrine)
///   required   =  valuation * ratio_pct / 100
///   collateral ←  eth_state[chain, token, slot] (PROVEN, or the tx traps)
///   healthy    =  required < collateral
/// ```
///
/// The ordering matters. `LoadEthState` runs **before** the comparison, so a
/// missing proof aborts the transaction and leaves the previous verdict
/// standing. A version that defaulted the balance to zero would silently mark
/// every loan under-collateralised during an oracle outage — or, with the
/// comparison flipped, silently mark them all healthy. Neither is acceptable,
/// so the value is simply unavailable rather than wrong.
pub fn collateral_health(
    property_id: &[u8],
    ratio_pct: u64,
    chain_id: u64,
    token: [u8; 20],
    holder_slot: [u8; 32],
) -> Vec<Instr> {
    vec![
        // required = valuation * ratio_pct / 100
        Instr::LoadTable {
            table: registry_table(),
            key: property_id.to_vec(),
        },
        Instr::Push(ratio_pct),
        Instr::Mul,
        Instr::Push(100),
        Instr::Div,
        // collateral — traps if unproven, which is the point
        Instr::LoadEthState {
            chain_id,
            address: token,
            slot: holder_slot,
        },
        // healthy = required < collateral
        Instr::Lt,
        Instr::StoreTable {
            table: health_table(),
            key: property_id.to_vec(),
        },
        Instr::Halt,
    ]
}

/// **Tokenized asset with a proven reserve.**
///
/// Writes `1` to `rwa.health` only if the on-Ethereum reserve covers
/// `shares * price_per_share`. Same trap-on-unproven guarantee as
/// [`collateral_health`]; the difference is that supply is a program constant
/// rather than a table read, which suits assets whose share count is fixed at
/// issuance.
pub fn reserve_backed_token(
    asset_id: &[u8],
    shares: u64,
    price_per_share: u64,
    chain_id: u64,
    token: [u8; 20],
    reserve_slot: [u8; 32],
) -> Vec<Instr> {
    vec![
        Instr::Push(shares),
        Instr::Push(price_per_share),
        Instr::Mul, // liabilities
        Instr::LoadEthState {
            chain_id,
            address: token,
            slot: reserve_slot,
        }, // reserve (proven)
        Instr::Lt,  // liabilities < reserve
        Instr::StoreTable {
            table: health_table(),
            key: asset_id.to_vec(),
        },
        Instr::Halt,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::{eth_state_key, eth_state_table, ExecutionPipeline};

    const CHAIN: u64 = 1;
    const TOKEN: [u8; 20] = [0xAB; 20];
    const PROPERTY: &[u8] = b"PROP-1729";

    fn slot() -> [u8; 32] {
        let mut s = [0u8; 32];
        s[31] = 9;
        s
    }

    /// Seed a proven Ethereum balance, the way a verified claim would.
    fn with_collateral(node: &mut ExecutionPipeline, amount: u64) {
        let mut word = [0u8; 32];
        word[24..].copy_from_slice(&amount.to_be_bytes());
        node.tables.insert(
            eth_state_table(),
            eth_state_key(CHAIN, &TOKEN, &slot()),
            word.to_vec(),
        );
    }

    fn health(node: &ExecutionPipeline) -> Option<u64> {
        node.tables.get(&health_table(), PROPERTY).map(|v| {
            let mut b = [0u8; 8];
            b.copy_from_slice(&v[..8]);
            u64::from_le_bytes(b)
        })
    }

    #[test]
    fn a_title_registers_and_reads_back() {
        let mut node = ExecutionPipeline::new();
        node.tables.create_table(title_table());
        node.run_program_for_test(&register_title(PROPERTY, 42));
        assert_eq!(
            node.tables
                .get(&title_table(), PROPERTY)
                .map(|v| v[..8].to_vec()),
            Some(42u64.to_le_bytes().to_vec())
        );
    }

    #[test]
    fn a_well_collateralised_loan_is_healthy() {
        let mut node = ExecutionPipeline::new();
        node.tables.create_table(registry_table());
        node.tables.create_table(health_table());
        node.run_program_for_test(&record_valuation(PROPERTY, 500_000));
        with_collateral(&mut node, 200_000); // required = 30% = 150,000

        node.run_program_for_test(&collateral_health(PROPERTY, 30, CHAIN, TOKEN, slot()));
        assert_eq!(health(&node), Some(1));
    }

    #[test]
    fn a_short_loan_is_flagged() {
        let mut node = ExecutionPipeline::new();
        node.tables.create_table(registry_table());
        node.tables.create_table(health_table());
        node.run_program_for_test(&record_valuation(PROPERTY, 500_000));
        with_collateral(&mut node, 100_000); // below the 150,000 required

        node.run_program_for_test(&collateral_health(PROPERTY, 30, CHAIN, TOKEN, slot()));
        assert_eq!(health(&node), Some(0));
    }

    /// **The template's reason for existing.** With no proven collateral the
    /// transaction traps and no verdict is written — rather than reading zero
    /// and marking the loan under-collateralised (or, worse, healthy) on the
    /// strength of data nobody verified.
    #[test]
    fn an_unproven_balance_traps_instead_of_reading_zero() {
        let mut node = ExecutionPipeline::new();
        node.tables.create_table(registry_table());
        node.tables.create_table(health_table());
        node.run_program_for_test(&record_valuation(PROPERTY, 500_000));
        // deliberately no collateral proven

        node.run_program_for_test(&collateral_health(PROPERTY, 30, CHAIN, TOKEN, slot()));
        assert_eq!(
            health(&node),
            None,
            "an unverified balance must not produce a verdict"
        );
    }

    #[test]
    fn a_reserve_backed_token_tracks_its_reserve() {
        let mut node = ExecutionPipeline::new();
        node.tables.create_table(health_table());
        with_collateral(&mut node, 1_000_000);

        // 100 shares x 5,000 = 500,000 liabilities, under a 1,000,000 reserve.
        node.run_program_for_test(&reserve_backed_token(
            PROPERTY,
            100,
            5_000,
            CHAIN,
            TOKEN,
            slot(),
        ));
        assert_eq!(health(&node), Some(1));

        // 300 x 5,000 = 1,500,000 — over the reserve.
        node.run_program_for_test(&reserve_backed_token(
            PROPERTY,
            300,
            5_000,
            CHAIN,
            TOKEN,
            slot(),
        ));
        assert_eq!(health(&node), Some(0));
    }
}
