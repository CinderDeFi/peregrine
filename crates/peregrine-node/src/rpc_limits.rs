//! Admission control for the client-facing RPC: cost weighting, rate limiting,
//! and optional bearer auth.
//!
//! # Why requests are weighted rather than counted
//!
//! A `Ping` and a `SubmitClaim` are not remotely the same load. A claim can
//! carry a multi-megabyte proof, and every validator will later spend real work
//! verifying it. Counting requests would let an attacker send the expensive one
//! at the same rate as the cheap one, so each request costs [`RequestCost`]
//! tokens from a per-connection bucket.
//!
//! # What this does and does not protect
//!
//! It bounds what *one connection* can push at a node, which is what stops a
//! single client from crowding consensus traffic out of the ingest queue.
//!
//! It is **not** Sybil resistance: an attacker with many connections gets many
//! buckets. Real protection needs stake- or key-weighted admission across
//! connections, which this scaffold does not have — see SECURITY.md. The
//! honest framing is that this raises the cost of casual abuse and makes
//! accidental floods (a looping script) harmless.

use std::time::Instant;

/// Token cost of a request, by kind.
///
/// Roughly proportional to the work a request imposes downstream, not to the
/// bytes on the wire.
pub mod cost {
    /// Liveness check — nearly free.
    pub const PING: u32 = 1;
    /// A read served from committed state.
    pub const QUERY: u32 = 4;
    /// A signed record or program entering the ingest queue.
    pub const SUBMIT: u32 = 16;
    /// A proof-carrying claim: large on the wire, and expensive to verify
    /// later on every validator.
    pub const CLAIM: u32 = 256;
}

/// A refill-over-time token bucket.
///
/// Chosen over a fixed window because it absorbs a legitimate burst (a client
/// publishing a batch of ticks) while still bounding the sustained rate — a
/// fixed window would either reject the burst or permit twice the intended
/// rate across a boundary.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    capacity: f64,
    tokens: f64,
    refill_per_sec: f64,
    last: Instant,
}

impl TokenBucket {
    /// `capacity` tokens, refilling at `refill_per_sec`. Starts full so a
    /// client's first burst is not penalised.
    pub fn new(capacity: u32, refill_per_sec: f64) -> Self {
        Self {
            capacity: capacity as f64,
            tokens: capacity as f64,
            refill_per_sec,
            last: Instant::now(),
        }
    }

    /// Try to spend `cost` tokens. `false` means "over budget, try later".
    pub fn try_spend(&mut self, cost: u32) -> bool {
        self.refill(Instant::now());
        let cost = cost as f64;
        if self.tokens >= cost {
            self.tokens -= cost;
            true
        } else {
            false
        }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
            self.last = now;
        }
    }

    /// Tokens currently available (for tests and diagnostics).
    pub fn available(&self) -> f64 {
        self.tokens
    }

    /// Advance the clock by `d` without waiting — test seam only.
    #[cfg(test)]
    pub fn advance(&mut self, d: std::time::Duration) {
        self.last -= d;
        self.refill(Instant::now());
    }
}

/// RPC admission-control settings.
#[derive(Debug, Clone)]
pub struct RpcLimits {
    /// Burst capacity, in tokens, per connection.
    pub burst: u32,
    /// Sustained refill rate, tokens per second.
    pub refill_per_sec: f64,
    /// When `Some`, every request must carry this token.
    ///
    /// Deliberately not a default: a token baked into a public scaffold would
    /// be worse than none, because it would look like protection.
    pub auth_token: Option<String>,
}

impl Default for RpcLimits {
    fn default() -> Self {
        // ~4 claims of burst, refilling one claim every ~2s: generous for a
        // relayer, useless for a flood.
        Self {
            burst: 1024,
            refill_per_sec: 128.0,
            auth_token: None,
        }
    }
}

impl RpcLimits {
    /// A bucket for one freshly-accepted connection.
    pub fn bucket(&self) -> TokenBucket {
        TokenBucket::new(self.burst, self.refill_per_sec)
    }

    /// Check a presented token against the configured one.
    ///
    /// Compared in constant time: a byte-by-byte early return leaks the shared
    /// secret one character at a time to anyone who can measure responses.
    pub fn authorize(&self, presented: Option<&str>) -> bool {
        let Some(expected) = &self.auth_token else {
            return true; // auth disabled
        };
        let Some(presented) = presented else {
            return false;
        };
        constant_time_eq(expected.as_bytes(), presented.as_bytes())
    }
}

/// Length-independent-ish equality: always compares the full expected length
/// and never short-circuits on the first differing byte.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = (a.len() ^ b.len()) as u8;
    for i in 0..a.len().max(b.len()) {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn bucket_allows_a_burst_then_throttles() {
        let mut b = TokenBucket::new(100, 10.0);
        // A burst up to capacity is fine.
        assert!(b.try_spend(100));
        // And then we are out.
        assert!(!b.try_spend(1));
    }

    #[test]
    fn bucket_refills_over_time() {
        let mut b = TokenBucket::new(100, 10.0);
        assert!(b.try_spend(100));
        assert!(!b.try_spend(50));
        b.advance(Duration::from_secs(6)); // 60 tokens back
        assert!(b.try_spend(50), "should have refilled enough");
        assert!(!b.try_spend(50), "but not more than earned");
    }

    #[test]
    fn refill_is_capped_at_capacity() {
        let mut b = TokenBucket::new(100, 10.0);
        b.advance(Duration::from_secs(3600));
        assert!(
            b.available() <= 100.0,
            "an idle bucket must not accumulate credit forever"
        );
    }

    // The weighting is the point: an attacker must not get claim throughput at
    // ping prices. Enforced at compile time so no future edit can quietly
    // flatten the ordering.
    const _: () = assert!(
        cost::CLAIM > cost::SUBMIT && cost::SUBMIT > cost::QUERY && cost::QUERY > cost::PING,
        "request costs must stay strictly ordered by downstream work"
    );

    #[test]
    fn claims_cost_far_more_than_pings() {
        let limits = RpcLimits::default();
        let mut b = limits.bucket();
        let mut claims = 0;
        while b.try_spend(cost::CLAIM) {
            claims += 1;
        }
        assert!(
            (1..=8).contains(&claims),
            "burst should be a handful of claims, got {claims}"
        );
    }

    #[test]
    fn auth_is_off_by_default_and_enforced_when_set() {
        let open = RpcLimits::default();
        assert!(open.authorize(None), "no token configured means no auth");

        let guarded = RpcLimits {
            auth_token: Some("s3cret".into()),
            ..Default::default()
        };
        assert!(guarded.authorize(Some("s3cret")));
        assert!(!guarded.authorize(Some("s3cres")), "wrong token");
        assert!(!guarded.authorize(Some("s3cret ")), "length must matter");
        assert!(
            !guarded.authorize(None),
            "missing token when one is required"
        );
    }

    #[test]
    fn constant_time_eq_matches_normal_equality() {
        assert!(constant_time_eq(b"", b""));
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"ab", b"abc"));
    }
}
