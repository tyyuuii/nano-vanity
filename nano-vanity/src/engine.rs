//! The grind engine, shared by the CLI and the web UI.
//!
//! Extracted from `main.rs` so that both front-ends drive exactly the same
//! search loop. Keeping one implementation matters here: a second copy that
//! drifted would mean the two front-ends disagree about which public key maps
//! to which address, and the whole point of this tool is that the printed key
//! really does control the printed address.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use nano_keys::{
    expand_private_key, private_scalar_to_public, public_key_to_address, MatchMode, Pattern,
    BODY_LEN,
};

/// A successful result. Everything a wallet needs is present.
#[derive(Clone, Debug)]
pub struct Found {
    pub seed: [u8; 32],
    pub index: u32,
    pub private_key: [u8; 32],
    pub address: String,
    /// Position in the search where this was found, ascending.
    ///
    /// In the default mode this equals `index`. When grinding seeds it is the
    /// attempt counter instead, because every candidate shares one account
    /// index and ordering by that would make "keep the N lowest matches"
    /// meaningless. Ordering and pruning always use this; the report uses
    /// `seed` and `index`.
    pub attempt: u64,
}

/// What a search varies.
///
/// The default walks one seed's account indices. [`Axis::Seed`] walks seeds at
/// a single fixed account index, which is what "I want the vanity address to be
/// account 0 so importing the seed is enough" actually requires.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Axis {
    /// One seed, scanning its account indices.
    Index,
    /// A fresh candidate seed per attempt, each derived at the same index.
    Seed {
        /// Account index every candidate seed is derived at.
        index: u32,
    },
}

/// A completed job: the matches found, or a stop with nothing to show.
///
/// `Found` may hold fewer entries than were requested (a time limit or cancel
/// cut the search short), so front-ends should show what they got rather than
/// assume the full count.
#[derive(Clone, Debug)]
pub enum Outcome {
    Found(Vec<Found>),
    Exhausted,
}

/// RETIRED. This constant encoded the belief that a seed can only be restored
/// by walking accounts 0..=index, so anything past ~1000 was unreachable and
/// the private key was the only route. That belief was wrong.
///
/// Nault's documentation states that "Nault, for example, can access any index
/// if you so want", and its import flow takes the account index directly, so
/// `(seed, index)` restores any address in the 2^32 space without any of the
/// preceding accounts ever existing. The same is true of the other wallets that
/// expose an index field. Nothing in Nano's derivation requires the walk.
///
/// `--max-index` survives as a genuine, useful search ceiling; it just is not
/// a wallet limit, and the tool no longer treats it as one.
#[allow(dead_code)]
pub const SEED_RESTORE_PLAUSIBLE_MAX: u32 = 1000;

pub fn hex_upper(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

/// A fresh 32-byte wallet seed.
///
/// This matters for more than tidiness. The private key is
/// `Blake2b-256(seed || index)`, so with the all-zero seed anyone who learns
/// the index can recompute the key. Two people grinding the same prefix from
/// the zero seed would therefore derive the *same* private key, and both would
/// believe they owned the address. A random seed per run removes both problems:
/// every run yields a different address, and the key cannot be derived from the
/// prefix alone.
pub fn random_seed() -> Result<[u8; 32], String> {
    use std::io::Read;
    let mut f = std::fs::File::open("/dev/urandom")
        .map_err(|e| format!("cannot open /dev/urandom: {e}"))?;
    let mut seed = [0u8; 32];
    f.read_exact(&mut seed)
        .map_err(|e| format!("short read from /dev/urandom: {e}"))?;
    Ok(seed)
}

/// Parses a user-supplied seed: the literal `random`, or 64 hex characters.
pub fn parse_seed(input: &str) -> Result<[u8; 32], String> {
    let t = input.trim();
    if t.eq_ignore_ascii_case("random") {
        return random_seed();
    }
    if t.len() != 64 {
        return Err(format!(
            "seed must be 64 hex characters (32 bytes) or the word 'random', got {} chars",
            t.len()
        ));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in t.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char)
            .to_digit(16)
            .ok_or_else(|| format!("seed has a non-hex character: {:?}", chunk[0] as char))?;
        let lo = (chunk[1] as char)
            .to_digit(16)
            .ok_or_else(|| format!("seed has a non-hex character: {:?}", chunk[1] as char))?;
        out[i] = (hi * 16 + lo) as u8;
    }
    Ok(out)
}

/// Candidate block size. Threads claim blocks of this size in increasing index
/// order, and that ordering is what makes a result reproducible.
const BLOCK: u64 = 2048;

/// Size of the searched space: one `u32` account index per seed, so 2^32.
const INDEX_SPACE: u64 = 1 << 32;

/// Searches the seed's account-index space and returns the `want` **lowest**
/// matching indices, plus the number of candidates needed to establish them.
///
/// Determinism is the whole point of this function. The original version used
/// `rayon::find_map_any`, which yields whichever thread happens to finish
/// first; the same prefix therefore produced a different address, account index
/// and try-count on every run. For a tool that prints a key to receive money
/// at, a result you cannot reproduce is a result you cannot check.
///
/// The invariant: every index below the last returned one has been examined, so
/// the answer is the first `want` matches in index order regardless of thread
/// count or OS scheduling.
///
/// Termination never uses the shared stop flag for a match. Setting it from a
/// winning thread would abort a thread still scanning a *lower* block and could
/// throw away the true first match. Instead each worker notices, via `limit`,
/// that everything above a certain index is irrelevant and leaves.
///
/// Note the split of responsibility: this function makes the *search*
/// reproducible, while the seed makes the *result* unreproducible. Re-running
/// with the same seed gives the same addresses back; running with a fresh
/// random seed gives different ones. Both behaviours are wanted.
#[allow(clippy::too_many_arguments)] // see note on Job::start
fn search(
    pattern: &Pattern,
    seed: [u8; 32],
    want: usize,
    threads: usize,
    stop: &AtomicBool,
    counter: &AtomicU64,
    ceiling: u64,
    axis: Axis,
) -> (Vec<Found>, u64) {
    assert!(want >= 1, "want must be at least 1");

    let next_block = AtomicU64::new(0);
    let done = AtomicBool::new(false);
    // Highest index still worth examining. Drops to the `want`-th lowest known
    // match once enough have been collected; everything at or above it can
    // never enter the result.
    let limit = AtomicU64::new(u64::MAX);
    // Matches, ascending by index, never longer than `want`.
    let matches: Mutex<Vec<Found>> = Mutex::new(Vec::new());
    // Block ids currently held by a worker. Used to decide when a match sitting
    // in a block that is still running can be trusted as final.
    let in_flight: Mutex<HashSet<u64>> = Mutex::new(HashSet::new());

    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                // Reused by the suffix/contains modes so the hot loop stays
                // allocation-free. The prefix path never touches it.
                let mut scratch = [0u8; BODY_LEN];
                loop {
                    if stop.load(Ordering::Relaxed) || done.load(Ordering::Relaxed) {
                        return;
                    }

                    // Claim the next block. `fetch_add` hands them out in a single
                    // increasing order, so no two workers ever scan the same block
                    // and no block is skipped.
                    let block = next_block.fetch_add(1, Ordering::Relaxed);
                    let start = block.saturating_mul(BLOCK);
                    if start >= ceiling {
                        return; // the whole permitted space has been claimed
                    }
                    in_flight.lock().unwrap().insert(block);

                    let end = (start + BLOCK).min(ceiling);
                    let mut i = start;
                    while i < end {
                        // Parentheses matter: `&` binds looser than `==` in Rust
                        // exactly as in C, so `i & 0x3f == 0` would not compile.
                        if (i & 0x3f) == 0 {
                            if stop.load(Ordering::Relaxed) {
                                break;
                            }
                            // We already hold `want` matches at or below `limit`, so
                            // any higher index is wasted work.
                            if i > limit.load(Ordering::Relaxed) {
                                break;
                            }
                        }

                        // In the default mode the seed is fixed and the attempt
                        // number is the account index. When grinding seeds the
                        // reverse holds: each attempt is a fresh candidate seed,
                        // all derived at one fixed account index.
                        //
                        // The candidate seed is `Blake2b-256(master ‖ attempt_be)`,
                        // reusing the seed derivation itself. That is uniform over
                        // 2^256, so candidates are indistinguishable from fresh
                        // random seeds, and re-running with the same master seed
                        // reproduces the same winners.
                        let (wallet_seed, idx) = match axis {
                            Axis::Index => (seed, i as u32),
                            Axis::Seed { index } => {
                                (nano_keys::derive_private_key(&seed, i as u32), index)
                            }
                        };
                        let private_key = nano_keys::derive_private_key(&wallet_seed, idx);
                        let scalar = expand_private_key(&private_key);
                        let pk = private_scalar_to_public(&scalar);
                        counter.fetch_add(1, Ordering::Relaxed);

                        if pattern.matches(&pk, &mut scratch) {
                            let address = public_key_to_address(&pk);
                            // The matcher compares raw bits; this confirms the
                            // *encoded string* really carries the prefix the user
                            // typed. A disagreement here is the one failure mode
                            // that silently yields a useless address.
                            debug_assert!(
                                pattern.matches_reference(&private_scalar_to_public(
                                    &expand_private_key(&private_key)
                                )),
                                "pattern and encoder disagree for {:?} in {} mode",
                                pattern.needle(),
                                pattern.mode().as_str()
                            );

                            let mut m = matches.lock().unwrap();
                            let keep = m.len() < want || i < m[want - 1].attempt;
                            if keep {
                                if m.len() == want {
                                    m.pop(); // drop the current worst
                                }
                                m.push(Found {
                                    seed: wallet_seed,
                                    index: idx,
                                    private_key,
                                    address,
                                    attempt: i,
                                });
                                m.sort_by_key(|f| f.attempt);
                                // Raising the bar for other workers: once `want`
                                // matches are held, only attempts below the
                                // `want`-th lowest are still interesting.
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
                }
            });
        }
    });

    let found = matches.lock().unwrap().clone();
    let tries = match found.last() {
        // Everything up to and including the last match had to be examined, so
        // this is the same on every run with the same seed.
        Some(f) => f.index as u64 + 1,
        // Nothing matched: the work counter is the honest report.
        None => counter.load(Ordering::Relaxed),
    };
    (found, tries)
}

/// Completion state, guarded by a condvar so that waiters wake the instant work
/// stops rather than on the next poll tick.
struct Slot {
    outcome: Option<Outcome>,
    /// Wall-clock seconds at the moment work stopped. Freezing this matters for
    /// polling clients: if `elapsed_secs` kept reading the clock after the
    /// answer was known, every subsequent poll would show a larger elapsed time
    /// and a smaller rate (the numerator is fixed), so a finished job would
    /// appear to decay toward zero addr/s.
    elapsed: f64,
    /// Candidates examined, frozen at completion for the same reason as
    /// `elapsed`. For a match this is the deterministic `index + 1`, not the
    /// larger speculative work total.
    tries: u64,
}

/// A running or finished search. Cheap to clone via `Arc`.
pub struct Job {
    pub prefix: String,
    pub threads: usize,
    pub expected: f64,
    /// How many matches the caller asked for.
    pub want: usize,
    /// Whether the leading `1`/`3` is ignored when matching (prefix mode only).
    pub skip_first: bool,
    /// How the pattern is applied to the address.
    pub mode: MatchMode,
    /// Highest account index this search may return, if the user capped it.
    pub max_index: Option<u32>,
    /// Number of account indices this search was allowed to examine.
    pub ceiling: u64,
    /// The `--time` limit in force, so a miss can say it was a timeout.
    pub time_limit: Option<u64>,
    /// What this search varies: one seed's indices, or seeds at a fixed index.
    pub axis: Axis,
    started: Instant,
    stop: Arc<AtomicBool>,
    counter: Arc<AtomicU64>,
    slot: Arc<(Mutex<Slot>, Condvar)>,
}

impl Job {
    /// Starts a search on detached threads.
    ///
    /// Returns as soon as the workers are spawned, so a front-end can respond
    /// immediately and poll [`Job::status`] afterwards.
    /// A search is configured by eight independent knobs. Bundling them into a
    /// struct would widen every call site without making any call clearer, and
    /// each call already names its arguments.
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        prefix: String,
        threads: usize,
        seconds: Option<u64>,
        seed: [u8; 32],
        want: usize,
        skip_first: bool,
        mode: MatchMode,
        max_index: Option<u32>,
    ) -> Result<Arc<Job>, String> {
        Self::start_with(
            prefix,
            threads,
            seconds,
            seed,
            want,
            skip_first,
            mode,
            max_index,
            Axis::Index,
        )
    }

    /// Searches candidate **seeds** at one fixed account index.
    ///
    /// This is what makes account 0 vanity, which is the only form that is
    /// genuinely "just import the seed". Searching indices of a single seed
    /// cannot do it: there is exactly one account at index 0 per seed, so a
    /// fixed seed either matches or it does not, and the only way to change
    /// the outcome is to change the seed.
    ///
    /// `master` only seeds the candidate stream. It is never itself a wallet
    /// seed in the result; each hit reports the candidate seed that worked.
    #[allow(clippy::too_many_arguments)] // see note on Job::start
    pub fn start_grinding(
        prefix: String,
        threads: usize,
        seconds: Option<u64>,
        master: [u8; 32],
        want: usize,
        skip_first: bool,
        mode: MatchMode,
        index: u32,
    ) -> Result<Arc<Job>, String> {
        // The search ceiling bounds candidate *seeds*, not account indices, so
        // an account-index cap is meaningless here and is not accepted.
        Self::start_with(
            prefix,
            threads,
            seconds,
            master,
            want,
            skip_first,
            mode,
            None,
            Axis::Seed { index },
        )
    }

    #[allow(clippy::too_many_arguments)] // see note on Job::start
    fn start_with(
        prefix: String,
        threads: usize,
        seconds: Option<u64>,
        seed: [u8; 32],
        want: usize,
        skip_first: bool,
        mode: MatchMode,
        max_index: Option<u32>,
        axis: Axis,
    ) -> Result<Arc<Job>, String> {
        let prefix = prefix.trim().to_string();
        let pattern = Pattern::new(&prefix, mode, skip_first)?;
        // Only an anchored prefix can be impossible; suffix and contains accept
        // any alphabet character because they can land anywhere.
        if let Some(reason) = pattern.unsatisfiable_reason() {
            return Err(reason);
        }
        if threads == 0 {
            return Err("thread count must be at least 1".into());
        }
        if want == 0 {
            return Err("must want at least 1 address".into());
        }
        // Bounded so a typo cannot ask the engine to hold a huge result set
        // in memory, and so the time limit stays meaningful.
        if want > 1000 {
            return Err("cannot request more than 1000 addresses at once".into());
        }

        // A seed does not "contain" its accounts: restoring one means deriving
        // every account before it, which is why a match at index 48,385 is
        // unreachable through a wallet even though the seed can produce it.
        // `--max-index` therefore caps the search, and the reported expectation
        // is scaled to the permitted space rather than the full 2^32.
        let ceiling = match max_index {
            Some(m) => (m as u64) + 1,
            None => INDEX_SPACE,
        };
        // `expected` describes the pattern, not the permitted space. Clamping
        // it to the ceiling made the ETA report "~0s" for a 2M-try search that
        // had only been allowed 1001 tries, which is worse than no estimate.
        let expected = pattern.expected_tries();
        let stop = Arc::new(AtomicBool::new(false));
        let counter = Arc::new(AtomicU64::new(0));
        let started = Instant::now();
        let slot = Arc::new((
            Mutex::new(Slot {
                outcome: None,
                elapsed: 0.0,
                tries: 0,
            }),
            Condvar::new(),
        ));

        let job = Arc::new(Job {
            prefix,
            threads,
            expected,
            want,
            skip_first,
            mode,
            max_index,
            ceiling,
            time_limit: seconds,
            axis,
            started,
            stop: stop.clone(),
            counter: counter.clone(),
            slot: slot.clone(),
        });

        if let Some(limit) = seconds {
            let stop = stop.clone();
            std::thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(limit);
                while Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(50));
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }
                }
                stop.store(true, Ordering::Relaxed);
            });
        }

        let pattern_for_run = pattern;
        let axis_for_run = axis;
        let stop_for_run = stop.clone();
        let counter_for_run = counter.clone();
        std::thread::spawn(move || {
            // Always the same answer for the same prefix: see `search`.
            let (found, tries) = search(
                &pattern_for_run,
                seed,
                want,
                threads,
                &stop_for_run,
                &counter_for_run,
                ceiling,
                axis_for_run,
            );
            // Fewer matches than asked for is still a success: report what was
            // actually found and let the front-end report the shortfall.
            let outcome = if found.is_empty() {
                Outcome::Exhausted
            } else {
                Outcome::Found(found)
            };

            let (lock, cv) = &*slot;
            let mut guard = lock.lock().unwrap();
            guard.outcome = Some(outcome);
            guard.elapsed = started.elapsed().as_secs_f64();
            guard.tries = tries;
            drop(guard);
            cv.notify_all();
        });

        Ok(job)
    }

    /// Candidates examined. Deterministic once the job has finished: for a
    /// match this is the first matching index plus one.
    pub fn tries(&self) -> u64 {
        let guard = self.slot.0.lock().unwrap();
        if guard.outcome.is_some() {
            guard.tries
        } else {
            // Still running: the live counter is speculative and will exceed
            // the final value, because threads probe past the winning block.
            self.counter.load(Ordering::Relaxed)
        }
    }

    pub fn elapsed_secs(&self) -> f64 {
        let guard = self.slot.0.lock().unwrap();
        if guard.outcome.is_some() {
            // Frozen at completion; see `Slot::elapsed`.
            guard.elapsed
        } else {
            self.started.elapsed().as_secs_f64()
        }
    }

    pub fn rate(&self) -> f64 {
        let e = self.elapsed_secs();
        if e <= 0.0 {
            0.0
        } else {
            self.tries() as f64 / e
        }
    }

    /// Fraction of the expected work completed, saturating at 1.0. Scales by
    /// the number of addresses requested, so the bar means "how far along".
    pub fn progress(&self) -> f64 {
        if self.expected > 0.0 {
            let target = self.expected * self.want as f64;
            (self.tries() as f64 / target).min(1.0)
        } else {
            0.0
        }
    }

    /// `None` while running, `Some(outcome)` once work has fully stopped.
    pub fn outcome(&self) -> Option<Outcome> {
        self.slot.0.lock().unwrap().outcome.clone()
    }

    /// True while the workers are still running. Part of the engine's
    /// front-end API (used by tests; the web status endpoint derives the same
    /// fact from [`Job::outcome`]).
    #[allow(dead_code)]
    pub fn is_running(&self) -> bool {
        self.slot.0.lock().unwrap().outcome.is_none()
    }

    /// True when the search stopped because it used up a `--max-index` cap
    /// rather than because it found nothing in the whole 2^32 space.
    ///
    /// These need very different messages: one is a real negative result, the
    /// other means the search was never allowed to look far enough.
    pub fn capped_out(&self) -> bool {
        self.max_index.is_some() && self.tries() >= self.ceiling
    }

    /// Waits up to `timeout` for completion. Returns the outcome if the job has
    /// finished, otherwise `None` after the timeout elapses.
    pub fn wait_timeout(&self, timeout: Duration) -> Option<Outcome> {
        let (lock, cv) = &*self.slot;
        let guard = lock.lock().unwrap();
        if guard.outcome.is_some() {
            return guard.outcome.clone();
        }
        let (guard, _) = cv.wait_timeout(guard, timeout).unwrap();
        guard.outcome.clone()
    }

    /// Cancels a running search. Workers notice the flag at their next batch
    /// boundary and return; whatever they found so far is kept.
    pub fn cancel(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        // Detached workers would otherwise keep burning CPU after the last
        // handle is gone (for example once the web UI reaps an old job).
        self.stop.store(true, Ordering::Relaxed);
    }
}
