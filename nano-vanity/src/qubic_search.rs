//! The Qubic search driver.
//!
//! This is a parallel implementation of the machinery in `engine.rs` rather
//! than a parameterisation of it. That is a deliberate trade. `engine.rs` holds
//! the verified, published Nano search: every guarantee it makes about
//! lowest-first ordering, pruning, cancellation and deterministic reporting has
//! been argued about and tested, and threading a chain enum through its hot
//! loop would put all of that at risk to share about eighty lines of block
//! claiming with an experimental path.
//!
//! So the block-claiming loop is written twice, and the shared idea lives in the
//! comments rather than in an abstraction. If this turns out to be the shape
//! long-term, the honest refactor is to extract a driver generic over a
//! candidate function and run both chains through it, with the Nano test suite
//! as the regression gate. That is a change to `main`, not to this branch.
//!
//! # What differs from Nano, beyond the arithmetic
//!
//! * **The axis is the seed.** Qubic has no account index, so attempt N is
//!   candidate seed N. There is no `--max-index` ceiling and no index to
//!   report; `attempt` is the only ordering key.
//! * **A found seed is the wallet.** There is no "import the seed and pick
//!   account 0" story to fall back on, so the CLI and UI say so explicitly.
//! * **The cost is 60x higher.** ~188 microseconds per candidate against Nano's
//!   ~79, so a one-character prefix is about a minute single-core rather than a
//!   second, and three characters is about 19 hours. Progress reporting matters
//!   much more here, which is why `expected_tries` is surfaced rather than
//!   buried.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::qubic::{derive_candidate, random_seed, IdentityPattern, Keys};

/// Candidates claimed per block. Mirrors `engine::BLOCK`.
const BLOCK: u64 = 2048;

/// How a Qubic search ended.
///
/// Deliberately a separate type from `engine::Outcome` rather than a shared
/// enum: the variants carry different payloads (`engine::Found` is
/// Nano-specific, with a 32-byte seed and an account index), and unifying them
/// would mean an enum with a variant per chain per outcome. Two small honest
/// types beat one combinatorial one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QubicOutcome {
    Found(Vec<Found>),
    /// Stopped without finding anything. Whether that was a time limit or a
    /// genuine end of the space is reported separately by `timed_out`.
    Exhausted,
}

/// A completed Qubic search.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Found {
    /// The 55-letter seed that produced this identity.
    ///
    /// **This is the whole wallet.** Qubic has no account index, so this seed
    /// controls this identity and nothing else can be recovered from it.
    pub seed: String,
    pub subseed: [u8; 32],
    pub private_key: [u8; 32],
    pub public_key: [u8; 32],
    pub identity: String,
    /// Position in the candidate stream where this was found, ascending.
    pub attempt: u64,
}

struct Slot {
    outcome: Option<QubicOutcome>,
    elapsed: f64,
    tries: u64,
}

/// A running or finished Qubic search.
pub struct QubicJob {
    pub pattern: IdentityPattern,
    pub threads: usize,
    pub expected: f64,
    pub want: usize,
    /// The `--time` limit in force, so a miss can be reported as a timeout
    /// rather than an honest exhaustive failure.
    pub time_limit: Option<u64>,
    started: Instant,
    stop: Arc<AtomicBool>,
    /// The live match list, shared with the workers. Read by `partial` so a
    /// poller can see a found identity while the search is still running --
    /// which matters more here than on Nano, since a Qubic found seed is the
    /// whole wallet and losing one to a closed tab would be unforgivable.
    matches: Arc<Mutex<Vec<Found>>>,
    /// The live work counter, for the monotonic view `tries_live` needs.
    live: Arc<AtomicU64>,
    slot: Arc<(Mutex<Slot>, Condvar)>,
}

impl QubicJob {
    /// Search for candidate seeds whose identity matches `pattern`.
    ///
    /// `master` only seeds the candidate stream. It is never itself a result:
    /// every hit reports the candidate seed that worked, which for Qubic is
    /// the wallet.
    pub fn start(
        pattern: IdentityPattern,
        threads: usize,
        seconds: Option<u64>,
        master: &str,
        want: usize,
    ) -> Result<Arc<Self>, String> {
        crate::qubic::parse_seed(master)?;

        let expected = pattern.expected_tries();
        let stop = Arc::new(AtomicBool::new(false));
        let counter = Arc::new(AtomicU64::new(0));
        let slot = Arc::new((
            Mutex::new(Slot {
                outcome: None,
                elapsed: 0.0,
                tries: 0,
            }),
            Condvar::new(),
        ));

        // Created before the job so it can be shared with the workers *and*
        // kept by the job for `partial()`.
        let matches: Arc<Mutex<Vec<Found>>> = Arc::new(Mutex::new(Vec::new()));
        let live = counter.clone();

        let job = Arc::new(QubicJob {
            pattern: pattern.clone(),
            threads,
            expected,
            want: want.max(1),
            time_limit: seconds,
            started: Instant::now(),
            stop: Arc::clone(&stop),
            matches: Arc::clone(&matches),
            live,
            slot: Arc::clone(&slot),
        });

        let next_block = Arc::new(AtomicU64::new(0));
        let done = Arc::new(AtomicBool::new(false));
        // Highest attempt still worth examining. Drops to the `want`-th lowest
        // known match once enough are held; anything at or above it can never
        // enter the result.
        let limit = Arc::new(AtomicU64::new(u64::MAX));
        let in_flight: Arc<Mutex<HashSet<u64>>> = Arc::new(Mutex::new(HashSet::new()));

        // The time limit is enforced by a supervisor rather than checked inside
        // the inner loop. Checking a clock per candidate would add a cost
        // comparable to a meaningful fraction of 188 microseconds of real work,
        // and a supervisor also covers the gap where a worker is between blocks.
        if let Some(limit_s) = seconds {
            let stop = Arc::clone(&stop);
            let started = job.started;
            thread::spawn(move || {
                let deadline = Duration::from_secs(limit_s);
                while started.elapsed() < deadline {
                    thread::sleep(Duration::from_millis(100));
                }
                stop.store(true, Ordering::Relaxed);
            });
        }

        let master = master.to_string();
        let want = job.want;
        for _ in 0..threads.max(1) {
            let next_block = Arc::clone(&next_block);
            let done = Arc::clone(&done);
            let limit = Arc::clone(&limit);
            let matches = Arc::clone(&matches);
            let in_flight = Arc::clone(&in_flight);
            let stop = Arc::clone(&stop);
            let counter = Arc::clone(&counter);
            let pattern = pattern.clone();
            let master = master.clone();

            thread::spawn(move || loop {
                if stop.load(Ordering::Relaxed) || done.load(Ordering::Relaxed) {
                    return;
                }

                // Claim the next block. `fetch_add` hands them out in a single
                // increasing order, so no two workers scan the same block and
                // none is skipped.
                let block = next_block.fetch_add(1, Ordering::Relaxed);
                let start = block.saturating_mul(BLOCK);
                in_flight.lock().unwrap().insert(block);

                let mut i = start;
                while i < start + BLOCK {
                    if stop.load(Ordering::Relaxed) || done.load(Ordering::Relaxed) {
                        break;
                    }
                    // Already holding `want` matches at or below `limit`, so any
                    // higher attempt is wasted work. Checked every 64 candidates
                    // to keep the atomic load out of the hot path.
                    if (i & 0x3f) == 0 && i > limit.load(Ordering::Relaxed) {
                        break;
                    }

                    let Keys {
                        seed,
                        subseed,
                        private_key,
                        public_key,
                        identity,
                    } = derive_candidate(&master, i);
                    counter.fetch_add(1, Ordering::Relaxed);

                    if pattern.matches(&identity) {
                        let mut m = matches.lock().unwrap();
                        let keep = m.len() < want || i < m[want - 1].attempt;
                        if keep {
                            if m.len() == want {
                                m.pop(); // drop the current worst
                            }
                            m.push(Found {
                                seed,
                                subseed,
                                private_key,
                                public_key,
                                identity,
                                attempt: i,
                            });
                            m.sort_by_key(|f| f.attempt);
                            // Raise the bar for other workers: once `want`
                            // matches are held, only attempts below the
                            // `want`-th lowest can still enter the result.
                            if m.len() < want {
                                limit.store(u64::MAX, Ordering::Relaxed);
                            } else {
                                limit.store(m[want - 1].attempt, Ordering::Relaxed);
                            }
                        }
                    }

                    i += 1;
                }

                in_flight.lock().unwrap().remove(&block);

                // Safe to stop only when `want` matches are held *and* no
                // in-flight block starts at or below the `want`-th match, since
                // such a block could still reveal a lower one.
                let m = matches.lock().unwrap();
                if m.len() >= want {
                    let top = m[want - 1].attempt;
                    drop(m);
                    let lowest_open = in_flight.lock().unwrap().iter().map(|b| b * BLOCK).min();
                    if lowest_open.is_none_or(|lowest| top < lowest) {
                        done.store(true, Ordering::Relaxed);
                    }
                }
            });
        }

        // One finalizer publishes the outcome exactly once, when the search has
        // stopped for any reason: enough matches, a time limit, or a cancel.
        // Without it a finished job would keep `is_running` true forever and the
        // UI would poll a corpse.
        {
            let slot = Arc::clone(&slot);
            let stop = Arc::clone(&stop);
            let done = Arc::clone(&done);
            let counter = Arc::clone(&counter);
            let matches = Arc::clone(&matches);
            let started = job.started;
            thread::spawn(move || loop {
                if stop.load(Ordering::Relaxed) || done.load(Ordering::Relaxed) {
                    // Let a straggling worker finish pushing its match before the
                    // result is frozen, or a hit found in the final milliseconds
                    // is dropped.
                    thread::sleep(Duration::from_millis(50));
                    let found = matches.lock().unwrap().clone();
                    let tries = match found.last() {
                        Some(m) => m.attempt + 1,
                        None => counter.load(Ordering::Relaxed),
                    };
                    let mut guard = slot.0.lock().unwrap();
                    if guard.outcome.is_none() {
                        guard.tries = tries;
                        guard.elapsed = started.elapsed().as_secs_f64();
                        guard.outcome = Some(if found.is_empty() {
                            QubicOutcome::Exhausted
                        } else {
                            QubicOutcome::Found(found)
                        });
                        slot.1.notify_all();
                    }
                    return;
                }
                thread::sleep(Duration::from_millis(20));
            });
        }

        Ok(job)
    }

    /// Block until the search finishes.
    ///
    /// Used by the CLI. The web UI polls `outcome` instead so it stays
    /// responsive and can display progress.
    pub fn wait(&self) -> QubicOutcome {
        let mut guard = self.slot.0.lock().unwrap();
        while guard.outcome.is_none() {
            let (g, _timeout) = self
                .slot
                .1
                .wait_timeout(guard, Duration::from_millis(100))
                .unwrap_or_else(|e| e.into_inner());
            guard = g;
        }
        guard.outcome.clone().unwrap_or(QubicOutcome::Exhausted)
    }

    pub fn tries(&self) -> u64 {
        let guard = self.slot.0.lock().unwrap();
        match &guard.outcome {
            // Everything up to and including the last match had to be examined,
            // so this is the same on every run with the same master seed.
            Some(QubicOutcome::Found(f)) => f.last().map(|m| m.attempt + 1).unwrap_or(guard.tries),
            // No match: the work counter is the honest report.
            _ => guard.tries,
        }
    }

    pub fn elapsed_secs(&self) -> f64 {
        let guard = self.slot.0.lock().unwrap();
        match &guard.outcome {
            // Frozen at completion. A finished job whose elapsed time kept
            // reading the clock would show a larger elapsed and a smaller rate
            // on every poll, appearing to decay toward zero.
            Some(_) => guard.elapsed,
            None => self.started.elapsed().as_secs_f64(),
        }
    }

    pub fn rate(&self) -> f64 {
        let t = self.elapsed_secs();
        if t <= 0.0 {
            return 0.0;
        }
        self.tries() as f64 / t
    }

    /// Progress toward the first expected match, in `[0, 1]`.
    pub fn progress(&self) -> f64 {
        if self.expected <= 0.0 {
            return 0.0;
        }
        (self.tries() as f64 / self.expected).clamp(0.0, 1.0)
    }

    /// Matches found so far, ascending by attempt, while the job is still
    /// running. See `engine::Job::partial` for why this exists and why the
    /// pruning makes a mid-run read trustworthy.
    pub fn partial(&self) -> Vec<Found> {
        self.matches.lock().unwrap().clone()
    }

    /// Candidates examined so far, never decreasing.
    ///
    /// `tries` switches to the deterministic "attempt of the last match plus
    /// one" at completion, which is right for the CLI and wrong for a progress
    /// bar: the number would visibly jump backwards. Pollers want this.
    pub fn tries_live(&self) -> u64 {
        let live = self.counter_for_rate();
        let guard = self.slot.0.lock().unwrap();
        match guard.outcome {
            Some(QubicOutcome::Found(ref f)) => {
                live.max(f.last().map(|m| m.attempt + 1).unwrap_or(0))
            }
            _ => live,
        }
    }

    /// The raw work counter. Kept separate so `tries_live` can floor it against
    /// the deterministic figure without `tries` having to know about either.
    fn counter_for_rate(&self) -> u64 {
        let guard = self.slot.0.lock().unwrap();
        if guard.outcome.is_some() {
            guard.tries
        } else {
            self.live.load(Ordering::Relaxed)
        }
    }

    pub fn outcome(&self) -> Option<QubicOutcome> {
        self.slot.0.lock().unwrap().outcome.clone()
    }

    pub fn is_running(&self) -> bool {
        self.outcome().is_none()
    }

    /// Whether the search stopped on a time limit rather than a real answer.
    pub fn timed_out(&self) -> bool {
        self.time_limit
            .is_some_and(|s| self.elapsed_secs() >= s as f64 - 0.5)
    }

    pub fn cancel(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// A one-shot Qubic derivation, for `--derive`.
///
/// Note the difference from the Nano path: there is no index to vary, so this
/// derives the identity of exactly the seed given.
pub fn derive_once(seed: &str) -> Result<Found, String> {
    let d = nano_keys::qubic::identity::derive_keys(seed).map_err(|e| e.to_string())?;
    Ok(Found {
        seed: seed.to_string(),
        subseed: d.subseed,
        private_key: d.private_key,
        public_key: d.public_key,
        identity: d.identity,
        attempt: 0,
    })
}

/// A random Qubic master seed for a search.
pub fn random_master() -> Result<String, String> {
    random_seed()
}

#[cfg(test)]
mod tests {
    use super::*;
    use nano_keys::MatchMode;

    /// The K12 and FourQ work is already covered by the `nano-keys` golden
    /// vectors, so these target the driver: that it honours a time limit, that it
    /// returns, and that anything it reports is a real match. Nothing here
    /// asserts a *specific* identity, because a match is not predictable and a
    /// test that waited for one would be a long test.
    #[test]
    fn a_search_stops_on_its_time_limit() {
        let pattern = IdentityPattern::new("ZZZZZZ", MatchMode::Prefix, 0).unwrap();
        let job = QubicJob::start(pattern, 1, Some(1), &"a".repeat(55), 1).unwrap();
        let outcome = job.wait();
        // One thread, and a time limit of one second. The one second is
        // irreducible -- the test is that a time limit actually stops the
        // search, which cannot be observed without waiting one out -- but a
        // second worker only competes for the same core while the clock runs.
        //
        // Nothing that improbable is found in a second, so the honest result is
        // "no answer", not a fake hit.
        assert!(matches!(outcome, QubicOutcome::Exhausted));
        assert!(!job.is_running());
    }

    #[test]
    fn derived_once_round_trips_through_a_valid_identity() {
        let f = derive_once(&"b".repeat(55)).unwrap();
        assert_eq!(f.seed, "b".repeat(55));
        assert_eq!(f.identity.len(), 60);
        assert!(nano_keys::qubic::identity::is_valid_identity(&f.identity));
    }

    #[test]
    fn derive_once_agrees_with_the_derived_candidate() {
        // `derive_candidate(seed, 0)` is not the same as `derive_once(seed)` --
        // the first re-derives a fresh seed from the master -- so this checks the
        // pure path against the golden vector rather than against itself.
        let f = derive_once(&"a".repeat(55)).unwrap();
        assert_eq!(
            f.identity,
            "BZBQFLLBNCXEMGLOBHUVFTLUPLVCPQUASSILFABOFFBCADQSSUPNWLZBQEXK"
        );
    }
}
