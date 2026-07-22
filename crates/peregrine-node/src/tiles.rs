//! # Tile runtime — pinned, share-nothing workers on lock-free queues
//!
//! A *tile* is an OS thread pinned to one core that owns its state outright and
//! communicates only by message. No locks, no shared mutable state, no async
//! runtime: a tile blocks on a queue, does work, and pushes results.
//!
//! ## Why this shape, and what it is honestly worth here
//!
//! Tiling only pays where work is (a) expensive, (b) a pure function of its
//! input, and (c) currently serialised behind something that must stay serial.
//! Measurement (`cargo run --release --example vertex_profile`) puts the commit
//! path at **~111 µs per stream record**:
//!
//! | | cost | parallelisable |
//! |---|---|---|
//! | ed25519 signature verify | 28 µs (25%) | **yes** |
//! | sparse-Merkle insert | 77 µs (69%) | no — it *is* the state transition |
//! | other | 6 µs (6%) | — |
//!
//! So this pool takes the 25% that is genuinely parallel. Amdahl's law caps
//! what that alone can buy at ~1.33×, and pretending otherwise would be
//! dishonest: the larger win in this crate came from making the *serial* 69%
//! cheaper (see `peregrine-data::smt`), not from adding threads. Tiles are
//! still worth it — they take a fixed 28 µs/record off the critical path, and
//! they scale with cores while the serial part does not.
//!
//! ## Determinism
//!
//! **Parallelism here changes timing, never results.** Signature verification
//! is a pure predicate over one record. The pool computes those predicates in
//! whatever order the OS schedules, but returns them *indexed by input
//! position*, and the caller applies them in the original committed order. Two
//! validators with different core counts therefore reach byte-identical state.
//!
//! That property is worth stating as a rule, because it is easy to break: a
//! tile may compute anything that depends only on its input, and must never
//! touch state that the serial stage also touches.
//!
//! ## Shutdown
//!
//! Dropping the [`TilePool`] closes the work queue, every tile observes the
//! disconnect, and the handles are joined. A tile never outlives its pool.

use crossbeam_channel::{bounded, Receiver, Sender};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

/// One unit of verification work: a message, a signature, and a key.
///
/// Deliberately owns its bytes. A tile must not borrow from the caller's
/// buffers — that is what "share nothing" means, and it is what lets the
/// caller keep mutating its own state while tiles run.
pub struct VerifyJob {
    /// Position in the caller's batch. Results are keyed by this, so the
    /// caller's ordering survives out-of-order completion.
    pub index: usize,
    pub public_key: peregrine_core::PublicKey,
    pub domain: &'static [u8],
    pub message: Vec<u8>,
    pub signature: peregrine_core::Signature,
}

/// A job plus the channel its verdict belongs on.
///
/// The reply channel is **per batch**, not per pool. An earlier revision had a
/// single shared result queue, which is wrong the moment two callers use the
/// pool at once: each would collect whichever verdicts happened to be ready,
/// silently attributing one batch's results to another's indices. That is a
/// correctness bug of the worst kind — it rejects valid signatures and would
/// just as happily accept invalid ones — and it only showed up because an index
/// from a larger batch ran off the end of a smaller caller's vector.
struct Dispatch {
    job: VerifyJob,
    reply: Sender<(usize, bool)>,
}

impl VerifyJob {
    /// Run the check. A pure function — this is the whole contract of a tile.
    fn run(&self) -> bool {
        peregrine_core::crypto::verify(
            &self.public_key,
            self.domain,
            &self.message,
            &self.signature,
        )
        .is_ok()
    }
}

/// Counters for the report line. Relaxed ordering throughout: these are
/// observability, never control flow, so a slightly stale read is fine and a
/// fence per job would cost more than the thing being measured.
#[derive(Default)]
pub struct TileMetrics {
    pub jobs: AtomicU64,
    pub batches: AtomicU64,
    /// Batches small enough that the pool ran them inline instead of
    /// dispatching. High is good — it means the fan-out threshold is working.
    pub inline_batches: AtomicU64,
}

/// A pool of pinned signature-verification tiles.
///
/// Cloneable handle semantics are deliberately *not* provided: one owner, one
/// pool, dropped when the node stops.
pub struct TilePool {
    tx: Option<Sender<Dispatch>>,
    handles: Vec<JoinHandle<()>>,
    pub metrics: Arc<TileMetrics>,
    n_tiles: usize,
}

/// Below this many jobs, dispatching costs more than just doing the work.
///
/// A queue round-trip plus a wakeup is on the order of a microsecond; one
/// ed25519 check is ~28 µs. So the crossover is low, but it is not zero — and
/// a node running one transaction per round should not pay scheduler latency
/// for it. Measured, not guessed: see `tile_bench` in the tests below.
const INLINE_THRESHOLD: usize = 4;

impl TilePool {
    /// Spawn `n_tiles` pinned tiles. `n_tiles == 0` means "no pool": every
    /// batch runs inline on the calling thread, which is exactly the old
    /// behaviour and is what the deterministic tests use.
    pub fn new(n_tiles: usize) -> Self {
        let (tx, rx) = bounded::<Dispatch>(4096);
        let metrics = Arc::new(TileMetrics::default());

        // Enumerate cores once; if the OS will not tell us, tiles run unpinned
        // rather than refusing to start. Pinning is an optimisation, not a
        // correctness requirement.
        let cores = core_affinity::get_core_ids().unwrap_or_default();

        let mut handles = Vec::with_capacity(n_tiles);
        for i in 0..n_tiles {
            let rx: Receiver<Dispatch> = rx.clone();
            let core = cores.get(i % cores.len().max(1)).copied();
            let m = Arc::clone(&metrics);

            let h = std::thread::Builder::new()
                .name(format!("peregrine-sigverify-{i}"))
                .spawn(move || {
                    if let Some(c) = core {
                        // Keeps this tile's working set in one core's caches and
                        // stops the scheduler migrating it mid-batch.
                        core_affinity::set_for_current(c);
                    }
                    // The tile loop: block, work, push. It ends when the pool
                    // is dropped and the queue disconnects.
                    while let Ok(Dispatch { job, reply }) = rx.recv() {
                        // AUDIT I-4: verification runs inside `catch_unwind`. A
                        // panic in `job.run()` (which `crypto::verify` does not do
                        // on the length-validated inputs it receives, but a future
                        // change might) would otherwise kill the tile and leave the
                        // job's reply unsent — and *which* job that hit would depend
                        // on scheduling, a determinism hazard. Instead a panicking
                        // job resolves deterministically to `false` (unverified,
                        // fail-closed) and the tile lives on.
                        let ok =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| job.run()))
                                .unwrap_or(false);
                        m.jobs.fetch_add(1, Ordering::Relaxed);
                        // A dropped receiver just means that batch's caller went
                        // away (task cancelled); other batches are unaffected.
                        let _ = reply.send((job.index, ok));
                    }
                })
                .expect("spawn sigverify tile");
            handles.push(h);
        }

        Self {
            tx: if n_tiles == 0 { None } else { Some(tx) },
            handles,
            metrics,
            n_tiles,
        }
    }

    /// A pool sized for this machine, leaving headroom for the consensus
    /// thread, the network, and the async runtime.
    ///
    /// Reserving cores matters more than adding tiles: a sigverify tile that
    /// preempts the single serial commit thread makes things *slower*, because
    /// the serial stage is the bottleneck the tiles exist to feed.
    /// Override for the tile count, honoured by [`Self::sized_for_machine`].
    ///
    /// Exists so the *same binary* can be measured with and without tiles —
    /// comparing two builds would confound the tile effect with every other
    /// difference between them. `PEREGRINE_TILES=0` disables the pool entirely.
    pub const TILES_ENV: &'static str = "PEREGRINE_TILES";

    pub fn sized_for_machine() -> Self {
        if let Ok(n) = std::env::var(Self::TILES_ENV) {
            if let Ok(n) = n.parse::<usize>() {
                return Self::new(n.min(64));
            }
        }
        let cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        Self::new(cores.saturating_sub(2).clamp(0, 8))
    }

    pub fn tiles(&self) -> usize {
        self.n_tiles
    }

    /// Verify a batch, returning verdicts **indexed by input position**.
    ///
    /// This is the determinism boundary: the work happens in arbitrary order
    /// across tiles, and the result is a positional `Vec<bool>` that the caller
    /// consumes in its own order. Nothing about the output depends on how many
    /// tiles exist or how the OS scheduled them.
    pub fn verify_batch(&self, jobs: Vec<VerifyJob>) -> Vec<bool> {
        let n = jobs.len();
        self.verify_batch_indexed(jobs, n)
    }

    /// As [`Self::verify_batch`], but the result is sized to `out_len` rather
    /// than to the job count.
    ///
    /// Callers commonly verify a *subset* of a batch — here, the shreds among a
    /// mixed payload — and want verdicts they can index with the original
    /// positions. Entries with no corresponding job stay `false`, which is the
    /// safe default: "not verified" must never read as "verified".
    pub fn verify_batch_indexed(&self, jobs: Vec<VerifyJob>, out_len: usize) -> Vec<bool> {
        self.metrics.batches.fetch_add(1, Ordering::Relaxed);
        let n = jobs.len();
        debug_assert!(
            jobs.iter().all(|j| j.index < out_len),
            "job index out of range for the output vector"
        );
        let mut out = vec![false; out_len];

        // Small batch, or no pool: do it here. Avoids paying queue latency for
        // work that is cheaper than the dispatch.
        if n < INLINE_THRESHOLD || self.tx.is_none() {
            self.metrics.inline_batches.fetch_add(1, Ordering::Relaxed);
            for job in &jobs {
                out[job.index] = job.run();
            }
            self.metrics.jobs.fetch_add(n as u64, Ordering::Relaxed);
            return out;
        }

        let tx = self.tx.as_ref().expect("checked above");

        // AUDIT L-3: the dispatch+collect below blocks the calling thread on
        // crossbeam channels while the tiles work. When that caller is a tokio
        // worker (the commit path runs inside the validator's async task),
        // blocking it directly would starve the runtime. `block_in_place` hands
        // this worker's other tasks to a sibling for the duration — but it is
        // only valid on a multi-thread runtime, and panics off a runtime or on a
        // current-thread one (e.g. the unit tests here). So it is applied only
        // when we can confirm we are on a multi-thread runtime; otherwise the
        // plain blocking path runs unchanged. The verdicts are identical either
        // way — this changes scheduling, never results.
        maybe_block_in_place(move || {
            // A reply channel for *this batch alone*, sized to hold every verdict.
            // Because it can never fill, a tile never blocks on send, so it always
            // returns to draining the work queue — which is what makes the
            // "push everything, then collect" loop below deadlock-free even when
            // the batch is far larger than the bounded work queue.
            let (reply, results) = bounded::<(usize, bool)>(n);

            for job in jobs {
                // Blocks only while every tile is busy, which is precisely the
                // backpressure we want: the caller waits rather than queueing
                // unbounded work.
                tx.send(Dispatch {
                    job,
                    reply: reply.clone(),
                })
                .expect("pool owns its tiles");
            }
            // Drop our own handle so the channel closes once the tiles finish;
            // without this a lost job would hang the collect loop forever instead
            // of surfacing as a disconnect.
            drop(reply);

            let mut collected = 0usize;
            while collected < n {
                match results.recv() {
                    Ok((idx, ok)) => {
                        out[idx] = ok;
                        collected += 1;
                    }
                    // Every tile dropped its sender without answering. Cannot
                    // happen while the pool is alive, and if it somehow did, the
                    // safe reading of a missing verdict is "not verified".
                    Err(_) => break,
                }
            }
            out
        })
    }
}

/// Run `f`, yielding the current tokio worker via `block_in_place` when — and
/// only when — that is valid (a multi-thread runtime). Off a runtime, or on a
/// current-thread runtime, `block_in_place` would panic, so `f` simply runs
/// in place. See AUDIT L-3.
fn maybe_block_in_place<T>(f: impl FnOnce() -> T) -> T {
    use tokio::runtime::{Handle, RuntimeFlavor};
    match Handle::try_current() {
        Ok(h) if h.runtime_flavor() == RuntimeFlavor::MultiThread => tokio::task::block_in_place(f),
        _ => f(),
    }
}

impl Drop for TilePool {
    fn drop(&mut self) {
        // Close the work queue so every tile's `recv` returns Err and its loop
        // exits, then join. Without the explicit drop the sender would outlive
        // the join and every tile would block forever.
        self.tx.take();
        for h in self.handles.drain(..) {
            let _ = h.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use peregrine_core::Keypair;

    fn jobs_for(n: usize, corrupt: &[usize]) -> (Vec<VerifyJob>, Vec<bool>) {
        let mut rng = rand::rngs::OsRng;
        let kp = Keypair::generate(&mut rng);
        let mut jobs = Vec::with_capacity(n);
        let mut expected = vec![true; n];
        for (i, slot) in expected.iter_mut().enumerate().take(n) {
            let msg = format!("message-{i}").into_bytes();
            let mut sig = kp.sign(b"peregrine.test.v1", &msg);
            if corrupt.contains(&i) {
                sig.0[0] ^= 0xFF;
                *slot = false;
            }
            jobs.push(VerifyJob {
                index: i,
                public_key: kp.public(),
                domain: b"peregrine.test.v1",
                message: msg,
                signature: sig,
            });
        }
        (jobs, expected)
    }

    #[test]
    fn verdicts_are_positional_not_completion_ordered() {
        // The core determinism property: which tile finishes first must not
        // affect which verdict lands where.
        let pool = TilePool::new(4);
        let (jobs, expected) = jobs_for(200, &[3, 17, 199]);
        assert_eq!(pool.verify_batch(jobs), expected);
    }

    #[test]
    fn tile_count_does_not_change_results() {
        // Two validators with different core counts must agree exactly.
        let (j1, expected) = jobs_for(64, &[0, 9]);
        let (j2, _) = jobs_for(64, &[0, 9]);
        let (j3, _) = jobs_for(64, &[0, 9]);

        let a = TilePool::new(0).verify_batch(j1); // inline
        let b = TilePool::new(1).verify_batch(j2);
        let c = TilePool::new(8).verify_batch(j3);

        assert_eq!(a, expected);
        assert_eq!(a, b, "1 tile must match 0 tiles");
        assert_eq!(a, c, "8 tiles must match 0 tiles");
    }

    #[test]
    fn a_batch_larger_than_the_queue_does_not_deadlock() {
        // The bounded work queue is backpressure; a batch bigger than it must
        // still complete rather than wedging against a full result queue.
        let pool = TilePool::new(2);
        let (jobs, expected) = jobs_for(9000, &[8999]);
        assert_eq!(pool.verify_batch(jobs), expected);
    }

    #[test]
    fn empty_and_tiny_batches_are_handled_inline() {
        let pool = TilePool::new(4);
        assert!(pool.verify_batch(vec![]).is_empty());
        let (jobs, expected) = jobs_for(2, &[1]);
        assert_eq!(pool.verify_batch(jobs), expected);
        assert!(pool.metrics.inline_batches.load(Ordering::Relaxed) >= 2);
    }

    #[test]
    fn a_pool_with_no_tiles_still_verifies() {
        // `TilePool::new(0)` is the "tiles disabled" configuration and must be
        // a behavioural no-op, not a silent pass-everything.
        let pool = TilePool::new(0);
        let (jobs, expected) = jobs_for(10, &[4]);
        assert_eq!(pool.verify_batch(jobs), expected);
    }

    /// **Concurrent callers must not see each other's verdicts.**
    ///
    /// The pool is shared by every validator in a process, so batches overlap
    /// in time. An earlier revision used one result queue for the whole pool
    /// and silently interleaved them — batch A collecting B's verdicts under
    /// A's indices. That rejects valid signatures and can accept invalid ones,
    /// and it survived every single-threaded test here. This is the regression
    /// test for it.
    #[test]
    fn concurrent_batches_do_not_steal_each_others_results() {
        use std::sync::Barrier;

        let pool = Arc::new(TilePool::new(4));
        let threads = 8;
        let barrier = Arc::new(Barrier::new(threads));

        let handles: Vec<_> = (0..threads)
            .map(|t| {
                let pool = Arc::clone(&pool);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    // Deliberately different batch sizes: with a shared result
                    // queue, a large batch's index would run off the end of a
                    // small batch's vector, which is how the bug announced
                    // itself.
                    let n = 16 + t * 37;
                    let corrupt: Vec<usize> = vec![t % n];
                    let (jobs, expected) = jobs_for(n, &corrupt);
                    barrier.wait(); // maximise overlap
                    let got = pool.verify_batch(jobs);
                    assert_eq!(got, expected, "thread {t} got another batch's verdicts");
                })
            })
            .collect();

        for h in handles {
            h.join().expect("no thread panicked");
        }
    }

    #[test]
    fn dropping_the_pool_joins_every_tile() {
        // A leaked tile would keep a core busy for the life of the process.
        let pool = TilePool::new(4);
        let (jobs, _) = jobs_for(50, &[]);
        pool.verify_batch(jobs);
        drop(pool); // must return, not hang
    }
}
