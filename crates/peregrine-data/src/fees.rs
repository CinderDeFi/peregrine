//! The dual-meter fee model (design doc §4.4 metering + §5.2 fee flows).
//!
//! Two independent meters:
//! * **compute units (CU)** — VM cycles, priced like gas;
//! * **data bytes** — stream/table/blob bytes, priced ~1000× cheaper.
//!
//! Every settled fee is split 50/30/20 (burn / validators / Data Endowment).
//! Amounts are in "grains": 1 $WING = 1e9 grains (integer math only —
//! floating point never touches money).

use serde::{Deserialize, Serialize};

/// Smallest unit: 1 WING = 1_000_000_000 grains.
pub const GRAINS_PER_WING: u64 = 1_000_000_000;

/// Usage accumulated by one transaction / one commit batch.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct DualMeter {
    pub compute_units: u64,
    pub data_bytes: u64,
}

impl DualMeter {
    pub fn tick_compute(&mut self, units: u64) {
        self.compute_units = self.compute_units.saturating_add(units);
    }

    pub fn tick_data(&mut self, bytes: u64) {
        self.data_bytes = self.data_bytes.saturating_add(bytes);
    }

    pub fn merge(&mut self, other: DualMeter) {
        self.tick_compute(other.compute_units);
        self.tick_data(other.data_bytes);
    }
}

/// Prices per unit, in grains. Bootstrap values chosen so the demo prints
/// honest relative economics: a data byte costs 1/1000th of a compute unit.
/// Production: both floats via independent EIP-1559-style controllers, plus
/// per-object local surge pricing.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct FeeSchedule {
    pub grains_per_compute_unit: u64,
    pub grains_per_data_byte: u64,
}

impl Default for FeeSchedule {
    fn default() -> Self {
        Self {
            grains_per_compute_unit: 1_000,
            grains_per_data_byte: 1,
        }
    }
}

/// A priced quote for a metered workload.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct FeeQuote {
    pub compute_fee_grains: u64,
    pub data_fee_grains: u64,
}

impl FeeQuote {
    pub fn total_grains(&self) -> u64 {
        self.compute_fee_grains.saturating_add(self.data_fee_grains)
    }
}

impl FeeSchedule {
    pub fn quote(&self, meter: &DualMeter) -> FeeQuote {
        FeeQuote {
            compute_fee_grains: meter
                .compute_units
                .saturating_mul(self.grains_per_compute_unit),
            data_fee_grains: meter.data_bytes.saturating_mul(self.grains_per_data_byte),
        }
    }
}

/// Cumulative destination accounting for settled fees: 50% burn,
/// 30% validators, 20% Data Endowment (§5.2). Remainders go to burn so the
/// split never mints dust.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct FeeSplit {
    pub burned_grains: u64,
    pub validator_grains: u64,
    pub endowment_grains: u64,
}

impl FeeSplit {
    pub fn settle(&mut self, quote: &FeeQuote) {
        let total = quote.total_grains();
        let validators = total * 30 / 100;
        let endowment = total * 20 / 100;
        let burn = total - validators - endowment; // 50% + rounding dust
        self.burned_grains += burn;
        self.validator_grains += validators;
        self.endowment_grains += endowment;
    }

    pub fn total(&self) -> u64 {
        self.burned_grains + self.validator_grains + self.endowment_grains
    }
}

/// Pretty-print grains as WING for logs/demos.
pub fn fmt_wing(grains: u64) -> String {
    format!(
        "{}.{:09} WING",
        grains / GRAINS_PER_WING,
        grains % GRAINS_PER_WING
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_is_1000x_cheaper() {
        let sched = FeeSchedule::default();
        let mut m = DualMeter::default();
        m.tick_compute(100); // e.g. a transfer
        m.tick_data(100); // 100 bytes of stream data
        let q = sched.quote(&m);
        assert_eq!(q.compute_fee_grains, 100_000);
        assert_eq!(q.data_fee_grains, 100);
    }

    #[test]
    fn split_conserves_total() {
        let mut split = FeeSplit::default();
        let q = FeeQuote {
            compute_fee_grains: 12_345,
            data_fee_grains: 678,
        };
        split.settle(&q);
        assert_eq!(split.total(), q.total_grains());
    }
}
