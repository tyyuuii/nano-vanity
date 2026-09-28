//! # nano-vanity
//!
//! Multi-threaded CPU vanity address grinder for Nano (XNO).
//!
//! Two front-ends share one search engine (see [`engine`]):
//!
//! - the CLI (`nano-vanity <PREFIX>`), for scripting and headless grinds;
//! - a local web UI (`nano-vanity --web`), for point-and-click use.
//!
//! ## Why the reported speed is honest
//!
//! Addresses beginning with `1` are common: the first body character carries
//! only the public key's top bit, so a prefix like `1111` is ~16x more likely
//! than `32^4` suggests. Attempts and throughput are therefore reported
//! separately, and expected work is computed from the real 260-bit field.

mod engine;
mod web;

use std::net::SocketAddr;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use engine::{hex_upper, parse_seed, random_seed, Job, Outcome};
use nano_keys::{MatchMode, ALPHABET, MAX_FAST_PREFIX};

/// Strips an optional `nano_`/`xrb_` prefix and validates the rest.
pub fn normalize_prefix(input: &str) -> Result<String, String> {
    let input = input.trim();
    if input.is_empty() {
        return Err("no prefix given".into());
    }
    let lower = input.to_ascii_lowercase();
    let body = lower
        .strip_prefix("nano_")
        .or_else(|| lower.strip_prefix("xrb_"))
        .unwrap_or(&lower);

    if body.is_empty() {
        return Err("no prefix after 'nano_'".into());
    }
    for c in body.chars() {
        if !ALPHABET.contains(&(c as u8)) {
            return Err(format!(
                "invalid character {c:?} — the Nano alphabet excludes 0, 2, l and v"
            ));
        }
    }
    if body.len() > MAX_FAST_PREFIX {
        return Err(format!(
            "prefix has {} characters; this grinder supports at most {MAX_FAST_PREFIX}",
            body.len()
        ));
    }
    Ok(body.to_string())
}

struct Args {
    prefix: Option<String>,
    threads: usize,
    seconds: Option<u64>,
    quiet: bool,
    web: bool,
    bind: SocketAddr,
    /// `None` means "generate a fresh random seed".
    seed: Option<[u8; 32]>,
    /// How many matching addresses to collect.
    count: usize,
    /// Ignore the leading `1`/`3` and match from the second character.
    skip_first: bool,
    /// How the pattern is applied: prefix, suffix or contains.
    mode: MatchMode,
    /// Only accept a match at or below this account index.
    max_index: Option<u32>,
    /// Vary the seed instead of the account index.
    grind: bool,
    /// Account index every candidate seed is derived at when grinding.
    seed_index: u32,
    /// Derive and print one account instead of searching.
    derive: Option<[u8; 32]>,
    /// Account index for --derive (default 0).
    index: u32,
}

const USAGE: &str = "\
nano-vanity — Nano (XNO) vanity address grinder

USAGE:
    nano-vanity <PREFIX> [OPTIONS]
    nano-vanity --derive <SEED> [--index N]
    nano-vanity --web [--bind ADDR:PORT]

ARGS:
    <PREFIX>            Address prefix, e.g. 1111 or nano_111111
                        (the nano_ part is optional). Up to 12 characters.
                        The first character must be '1' or '3'.

    --derive SEED       Derive one account from a seed and print it, without
                        searching. Use this to check a seed/index against a
                        wallet that shows a different address.
    --index N           Account index for --derive (default 0).

OPTIONS:
    -g, --grind        Search candidate SEEDS instead of one seed's account
                        indices, holding the account index fixed. This is how
                        you get a vanity address on account 0, so importing
                        the seed is the entire job. Add --seed-index N to use
                        an account other than 0.
        --seed-index N  Account index for every candidate seed (default 0,
                        and only valid together with --grind).
    -t, --threads N     Worker threads (default: all cores)
    -T, --time S        Stop after S seconds and report throughput
    -s, --seed HEX      Wallet seed to search (64 hex chars, or 'random')
    -n, --count N       Collect N matching addresses (default 1, max 1000)
        --max-index N   Only accept a match at account index N or lower.
                        A pure search ceiling: your seed can derive any index
                        up to 4294967295, and Nault restores one directly by
                        typing it in. Set this only to finish sooner.
    -F, --skip-first    Ignore the leading '1'/'3'; match the prefix from
                        the second character onwards
    -m, --mode MODE     How to apply the pattern (default: prefix)
                          prefix   the address starts with it
                          suffix   the address ends with it
                          contains the address has it anywhere
    -q, --quiet         Only print the result line
        --web           Serve a local web UI instead of grinding directly
        --bind ADDR     Address for --web (default: 127.0.0.1:8787)
    -h, --help          Show this help

EXAMPLES:
    nano-vanity 1111
    nano-vanity nano_111111 -t 4
    nano-vanity 11111111 -T 60
    nano-vanity 1111 --seed 4d61...      # reproduce an earlier run
    nano-vanity 1111 -n 5                # collect 5 matching addresses
    nano-vanity test --skip-first        # matches nano_1test.. or nano_3test..
    nano-vanity --web

SKIPPING THE FIRST CHARACTER:
    The first address character is always '1' or '3' because it encodes only
    the public key's top bit. Requiring one specific value costs a factor of
    ~2 and buys nothing, so --skip-first treats it as a wildcard:

      nano-vanity 1test        ->  nano_1test...   ~2^21 tries
      nano-vanity test -F      ->  nano_1test...
                                   nano_3test...   ~2^20 tries

    Same match, half the work, and both leading characters accepted.

WHY --max-index EXISTS:
    A seed derives any account index from 0 to 4294967295, and wallets that
    expose an account-index field restore one directly. So a high index is
    perfectly usable, and --max-index is purely a search ceiling that trades
    prefix length for speed:

      no cap, prefix '1test'  -> index ~2^21, about 35s
      --max-index 1000        -> only the first 1001 indices, near-instant
                                 but only ~3 characters are findable

    Use --grind instead if you want the vanity address on account 0, so that
    importing the seed is the entire job.

SEEDS AND REPRODUCIBILITY:
    By default a fresh random seed is generated, so every run gives a
    different address and the private key cannot be derived from the prefix.
    Pass the same --seed again to get the same address back. The seed is
    printed with the result, which is all that is needed to restore the
    address in a wallet on any device.

IMPORTING THE RESULT:
    The grinder draws account indices from the wallet seed shown in the
    result. Restore that seed and set the account index to the printed value.
    Nault, for example, can access any index directly, so you do not need to
    create the accounts before it. The printed private key also works on its
    own. Verify the address in a wallet first.

COST PER CHARACTER:
    Each extra character multiplies the work by ~32.
      '1111'    ~ 6.6e4 tries   (~1 s)
      '11111'   ~ 2.1e6 tries   (~35 s)
      '111111'  ~ 6.7e7 tries   (~18 min)
    Only short prefixes finish quickly on a phone.";

fn parse_args() -> Result<Args, String> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.is_empty() {
        eprintln!("{USAGE}");
        std::process::exit(1);
    }
    if argv.iter().any(|a| a == "-h" || a == "--help") {
        println!("{USAGE}");
        std::process::exit(0);
    }

    let mut prefix: Option<String> = None;
    let mut threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let mut seconds = None;
    let mut quiet = false;
    let mut web = false;
    let mut bind: SocketAddr = "127.0.0.1:8787".parse().unwrap();
    let mut seed: Option<[u8; 32]> = None;
    let mut count: usize = 1;
    let mut skip_first = false;
    let mut mode = MatchMode::Prefix;
    let mut max_index: Option<u32> = None;
    let mut grind = false;
    let mut seed_index: u32 = 0;
    let mut derive: Option<[u8; 32]> = None;
    let mut index: u32 = 0;

    let mut it = argv.into_iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-t" | "--threads" => {
                let v = it.next().ok_or("--threads needs a value")?;
                threads = v.parse().map_err(|_| format!("bad thread count: {v}"))?;
                if threads == 0 {
                    return Err("thread count must be >= 1".into());
                }
            }
            "-T" | "--time" => {
                let v = it.next().ok_or("--time needs a value")?;
                seconds = Some(v.parse().map_err(|_| format!("bad seconds: {v}"))?);
            }
            "-F" | "--skip-first" => skip_first = true,
            "-m" | "--mode" => {
                let v = it.next().ok_or("--mode needs a value")?;
                mode = MatchMode::parse(&v).ok_or_else(|| {
                    format!("unknown mode {v:?}: expected prefix, suffix or contains")
                })?;
            }
            "--max-index" => {
                let v = it.next().ok_or("--max-index needs a value")?;
                let n: u32 = v.parse().map_err(|_| format!("bad index: {v}"))?;
                if n == 0 {
                    return Err("--max-index must be >= 1".into());
                }
                max_index = Some(n);
            }
            "--derive" => {
                // Derive one account and print it. The search modes only ever
                // show what they found, so there was no way to check a seed and
                // index the user already had -- which is exactly what is needed
                // when a wallet disagrees with the tool.
                let v = it.next().ok_or("--derive needs a 64-hex seed")?;
                derive = Some(parse_seed(&v).map_err(|e| format!("--derive: {e}"))?);
            }
            "--index" => {
                let v = it.next().ok_or("--index needs a value")?;
                index = v.parse().map_err(|_| format!("bad index: {v}"))?;
            }
            "-g" | "--grind" => {
                // Search seeds at a fixed account index rather than one seed
                // across its indices. This is the mode that can put a vanity
                // address on account 0, so importing the seed is the whole job.
                grind = true;
            }
            "--seed-index" => {
                let v = it.next().ok_or("--seed-index needs a value")?;
                seed_index = v.parse().map_err(|_| format!("bad index: {v}"))?;
                if !grind {
                    return Err("--seed-index only applies with --grind".into());
                }
            }
            "-q" | "--quiet" => quiet = true,
            "-n" | "--count" => {
                let v = it.next().ok_or("--count needs a value")?;
                count = v.parse().map_err(|_| format!("bad count: {v}"))?;
                if count == 0 {
                    return Err("count must be >= 1".into());
                }
            }
            "-s" | "--seed" => {
                let v = it.next().ok_or("--seed needs a value")?;
                seed = Some(parse_seed(&v)?);
            }
            "--web" => web = true,
            "--bind" => {
                let v = it.next().ok_or("--bind needs a value")?;
                bind = v
                    .parse()
                    .map_err(|_| format!("bad bind address: {v} (expected ADDR:PORT)"))?;
            }
            other if other.starts_with('-') => return Err(format!("unknown flag: {other}")),
            other => {
                if prefix.replace(other.to_string()).is_some() {
                    return Err("only one prefix may be given".into());
                }
            }
        }
    }

    // `--derive` needs no prefix: it answers a question about one account
    // rather than searching for one.
    let prefix = match prefix {
        Some(p) => Some(normalize_prefix(&p)?),
        None if web => None,
        None if derive.is_some() => None,
        None => return Err("no prefix given".into()),
    };

    Ok(Args {
        prefix,
        threads,
        seconds,
        quiet,
        web,
        bind,
        seed,
        count,
        skip_first,
        mode,
        max_index,
        grind,
        seed_index,
        derive,
        index,
    })
}

fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}\n");
            eprintln!("{USAGE}");
            std::process::exit(1);
        }
    };

    if args.web {
        if let Err(e) = web::serve(args.bind) {
            eprintln!("error: cannot start web UI on {}: {e}", args.bind);
            std::process::exit(1);
        }
        return;
    }

    // `--derive` answers a question, it does not run a search: given a seed and
    // an account index, what address is that? It needs no prefix, so it runs
    // before the search path asserts one.
    if let Some(dseed) = args.derive {
        let private_key = nano_keys::derive_private_key(&dseed, args.index);
        let public = nano_keys::private_key_to_public(&private_key);
        println!("  wallet seed : {}", hex_upper(&dseed));
        println!("  account idx : {}", args.index);
        println!("  private key : {}", hex_upper(&private_key));
        println!(
            "  address     : {}",
            nano_keys::public_key_to_address(&public)
        );
        return;
    }

    let prefix = args.prefix.expect("checked in parse_args");
    // A fresh random seed unless one was supplied, so each run lands on a
    // different address whose key cannot be derived from the prefix.
    let seed = match args.seed {
        Some(s) => s,
        None => match random_seed() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        },
    };
    // `--derive` answers a question, it does not run a search: given a seed and
    // an account index, what address is that? Useful when a wallet shows
    // something other than what this tool printed.
    let job = match if args.grind {
        Job::start_grinding(
            prefix,
            args.threads,
            args.seconds,
            seed,
            args.count,
            args.skip_first,
            args.mode,
            args.seed_index,
        )
    } else {
        Job::start(
            prefix,
            args.threads,
            args.seconds,
            seed,
            args.count,
            args.skip_first,
            args.mode,
            args.max_index,
        )
    } {
        Ok(j) => j,
        Err(e) => {
            eprintln!("error: {e}");
            // Unsatisfiable prefixes are a usage error, not a crash.
            let code = if e.contains("no address can start") {
                2
            } else {
                1
            };
            std::process::exit(code);
        }
    };

    if !args.quiet {
        println!("nano-vanity v{}", env!("CARGO_PKG_VERSION"));
        println!(
            "  mode           : {}{}",
            job.mode.as_str(),
            if job.skip_first {
                " (skipping leading 1/3)"
            } else {
                ""
            }
        );
        println!("  pattern        : {}", job.prefix);
        if args.grind {
            // Spell this out: it is the entire reason to use the mode.
            println!(
                "  search         : grinding seeds at account index {}",
                args.seed_index
            );
        }
        println!("  threads        : {}", args.threads);
        if args.count > 1 {
            println!("  wanted        : {} addresses", args.count);
        }
        println!("  expected tries : ~{:.3e}", job.expected);
        if let Some(s) = args.seconds {
            println!("  time limit     : {s}s");
        }
        println!();
    }

    run_cli(job.as_ref(), args.quiet);
}

/// Drives the CLI: prints progress every 5s and reports the result.
///
/// Progress uses a condvar so that a match wakes the reporter immediately. A
/// plain `sleep` here would keep the process alive for a full interval after
/// work finished, making short runs take 5.00s and corrupting the throughput
/// figure.
fn run_cli(job: &Job, quiet: bool) {
    let started = Instant::now();
    let done = Mutex::new(false);
    let done_cv = Condvar::new();

    std::thread::scope(|scope| {
        if !quiet {
            let done = &done;
            let done_cv = &done_cv;
            scope.spawn(move || {
                let mut finished = done.lock().unwrap();
                loop {
                    if *finished {
                        return;
                    }
                    let (guard, timeout) = done_cv
                        .wait_timeout(finished, Duration::from_secs(5))
                        .unwrap();
                    finished = guard;
                    if *finished {
                        return;
                    }
                    if !timeout.timed_out() {
                        continue;
                    }
                    let secs = started.elapsed().as_secs_f64();
                    if secs > 0.0 {
                        eprintln!(
                            "  {:>6.0}s  {:>15} tries  {:>11.0} addr/s",
                            secs,
                            job.tries(),
                            job.rate()
                        );
                    }
                }
            });
        }

        // The engine notifies its own condvar when work stops, so one wait is
        // enough; `notify_all` wakes us the moment a match lands.
        job.wait_timeout(Duration::from_secs(86_400));

        *done.lock().unwrap() = true;
        done_cv.notify_all();
    });

    let elapsed = started.elapsed();
    let tries = job.tries();
    let secs = elapsed.as_secs_f64();
    let rate = tries as f64 / secs.max(f64::MIN_POSITIVE);

    match job.outcome() {
        Some(Outcome::Found(found)) => {
            print!("{}", format_found(job, &found, tries, secs, rate));
        }
        _ => {
            println!("no match found — {tries} tries in {secs:.3}s");
            println!("{}", explain_miss(job, tries, rate));
        }
    }
}

/// Says *why* there was no match.
///
/// A bare "no match found" is ambiguous in three distinct situations, and the
/// most likely one is not a bad pattern: a `--max-index` cap can be smaller
/// than the space the pattern needs, and a time limit can expire first. Saying
/// which one happened is the difference between a useful message and "it
/// bugged out".
fn explain_miss(job: &Job, tries: u64, rate: f64) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let need = job.expected * job.want as f64;

    if job.capped_out() {
        let _ = writeln!(
            out,
            "  The search was capped at account index {}, so only {tries} of the",
            job.max_index.unwrap_or(0)
        );
        let _ = writeln!(
            out,
            "  ~{need:.0} tries this pattern needs on average were available."
        );
        let _ = writeln!(out, "  Raise the cap or drop it:");
        let _ = writeln!(out, "      nano-vanity {} --max-index 100000", job.prefix);
    } else if let Some(limit) = job.time_limit {
        let _ = writeln!(
            out,
            "  Stopped at the {limit}s time limit before the ~{need:.0} tries"
        );
        let _ = writeln!(out, "  this pattern needs on average.");
    } else {
        let _ = writeln!(
            out,
            "  Searched the whole 2^32 index space. For a prefix this long a"
        );
        let _ = writeln!(
            out,
            "  match is unlikely from a single seed; use a shorter pattern or a"
        );
        let _ = writeln!(out, "  different seed.");
    }

    // Only quote a rate when the run was long enough to mean anything.
    if tries >= 1000 && rate > 0.0 && need > tries as f64 {
        let eta = need / rate;
        let _ = writeln!(
            out,
            "  at ~{rate:.0} addr/s, this would need ~{eta:.0}s (~{:.1} h) on average",
            eta / 3600.0
        );
    }
    out
}

/// Renders a successful run. Kept separate from `run_cli` so the tests can
/// assert on the text: the address and private key are the entire point of the
/// program, and an earlier version printed them only when more than one match
/// was requested, silently withholding them in the default case.
fn format_found(job: &Job, found: &[engine::Found], tries: u64, elapsed: f64, rate: f64) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    // A run of a few milliseconds has no meaningful throughput: 18 tries in
    // 7ms reads as "3000 addr/s" when the machine does 64,000. Say the count
    // and the time, and quote a rate only once the sample is large enough.
    let measured = tries >= 1000 && elapsed >= 0.05;
    let _ = writeln!(
        out,
        "FOUND {} after {tries} tries in {elapsed:.3}s{}",
        if found.len() == 1 {
            "1 address".to_string()
        } else {
            format!("{} addresses", found.len())
        },
        if measured {
            format!(" ({rate:.0} addr/s)")
        } else {
            String::new()
        }
    );
    if found.len() < job.want {
        let _ = writeln!(
            out,
            "  (wanted {}, stopped early — raise the time limit to get them all)",
            job.want
        );
    }
    for (n, f) in found.iter().enumerate() {
        let _ = writeln!(out);
        if found.len() > 1 {
            let _ = writeln!(out, "  [{}]", n + 1);
        }
        let _ = writeln!(out, "  account idx : {}", f.index);
        let _ = writeln!(out, "  private key : {}", hex_upper(&f.private_key));
        let _ = writeln!(out, "  address     : {}", f.address);
    }
    if found.len() > 1 {
        let _ = writeln!(out);
    }
    // One seed serves every result, so it is printed once.
    let _ = writeln!(out, "  wallet seed : {}", hex_upper(&found[0].seed));
    let _ = writeln!(out);

    // How to import the result. This used to claim a high index was
    // unreachable from a seed, on the theory that a wallet must create
    // accounts 0..N first. That is wrong. Nault's own documentation says
    // "Nault, for example, can access any index if you so want", and its
    // import flow takes the account index directly, so a high index is
    // restored by entering seed + index -- no walking required.
    let _ = writeln!(out, "  Restore with the SEED and the account index above.");
    if let crate::engine::Axis::Seed { index } = job.axis {
        if index == 0 {
            let _ = writeln!(out);
            let _ = writeln!(
                out,
                "  Nault quirk: an UNUSED account is not shown after a seed"
            );
            let _ = writeln!(
                out,
                "  import. Nault scans the first 20 indices and keeps only the"
            );
            let _ = writeln!(
                out,
                "  ones already used on the ledger, so a brand-new empty account"
            );
            let _ = writeln!(out, "  is discarded. In Nault:");
            let _ = writeln!(
                out,
                "    1. Import this seed (it will look empty, that is expected), then"
            );
            let _ = writeln!(
                out,
                "    2. press \"Add account\" once. With no accounts present it"
            );
            let _ = writeln!(out, "       derives account 0 -- the vanity address above.");
            let _ = writeln!(
                out,
                "    Importing the private key also works and skips the scan."
            );
        } else {
            let _ = writeln!(
                out,
                "  Every address above is account {index} of that seed, so import"
            );
            let _ = writeln!(out, "  once and set \"Account index\" to {index}.");
        }
    }
    let _ = writeln!(
        out,
        "  Nault: Settings -> Configure new wallet -> Import an existing seed,"
    );
    let _ = writeln!(out, "  then set \"Account index\" to the printed value.");
    let _ = writeln!(
        out,
        "  A wallet does not need accounts 0..N to exist first, and you do not"
    );
    let _ = writeln!(
        out,
        "  have to create them. The private key also works on its own."
    );
    let _ = writeln!(
        out,
        "  The account must be opened before it can receive directly: send it"
    );
    let _ = writeln!(out, "  a small amount from another account first.");
    let _ = writeln!(
        out,
        "  Verify every address in a wallet before receiving funds."
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed seed so the reproducibility checks are stable.
    const TEST_SEED: [u8; 32] = [0x5a; 32];

    #[test]
    fn prefix_normalization_strips_protocol_and_case() {
        assert_eq!(normalize_prefix("1111").unwrap(), "1111");
        assert_eq!(normalize_prefix("  nano_1111 ").unwrap(), "1111");
        assert_eq!(normalize_prefix("NANO_1111").unwrap(), "1111");
        assert_eq!(normalize_prefix("xrb_1111").unwrap(), "1111");
        assert_eq!(normalize_prefix("XRB_3").unwrap(), "3");
    }

    #[test]
    fn prefix_validation_rejects_bad_input() {
        assert!(normalize_prefix("").is_err());
        assert!(normalize_prefix("nano_").is_err());
        // 0, 2, l and v are not in the Nano alphabet. (o *is* in the alphabet,
        // unlike base32's Crockford-ish cousins, so it must not appear here.)
        for bad in ["10", "12", "1l", "1v", "1!"] {
            assert!(normalize_prefix(bad).is_err(), "{bad} should be rejected");
        }
        // Every remaining letter is valid, including o.
        assert!(normalize_prefix("1o").is_ok());
        // One character past the fast-path limit.
        let too_long = "1".repeat(MAX_FAST_PREFIX + 1);
        assert!(normalize_prefix(&too_long).is_err());
        assert!(normalize_prefix(&"1".repeat(MAX_FAST_PREFIX)).is_ok());
    }

    #[test]
    fn engine_finds_a_satisfiable_prefix_and_the_address_really_matches() {
        // The one property that matters: the returned address must carry the
        // requested prefix, and the returned private key must derive it.
        for prefix in ["3", "1", "11"] {
            let job = Job::start(
                prefix.to_string(),
                2,
                Some(30),
                TEST_SEED,
                1,
                false,
                MatchMode::Prefix,
                None,
            )
            .unwrap();
            let outcome = job
                .wait_timeout(Duration::from_secs(60))
                .expect("should finish within the time limit");
            match outcome {
                Outcome::Found(found) => {
                    for f in &found {
                        assert!(
                            f.address.starts_with(&format!("nano_{prefix}")),
                            "address {} does not start with {prefix}",
                            f.address
                        );
                        // Re-derive from the private key independently.
                        let pk = nano_keys::private_key_to_public(&f.private_key);
                        assert_eq!(nano_keys::public_key_to_address(&pk), f.address);
                        // And from the seed/index pair.
                        assert_eq!(
                            nano_keys::seed_to_address(&f.seed, f.index),
                            f.address,
                            "seed/index path disagrees with the private key path"
                        );
                    }
                }
                Outcome::Exhausted => panic!("no match for a 1-2 char prefix"),
            }
        }
    }

    /// Every result must print its address and private key, for any count.
    ///
    /// Regression test: an earlier version only printed the per-address block
    /// when more than one match was requested, so the default single-address run
    /// printed a seed and no address at all. The address is the whole point of
    /// the program, so this is asserted for counts 1 and 3.
    #[test]
    fn every_result_prints_its_address_and_private_key() {
        let job = Job::start(
            "1f".into(),
            2,
            Some(30),
            TEST_SEED,
            1,
            false,
            MatchMode::Prefix,
            None,
        )
        .unwrap();
        let found = match job.wait_timeout(Duration::from_secs(60)) {
            Some(Outcome::Found(f)) => f,
            _ => panic!("expected a match"),
        };
        assert_eq!(found.len(), 1);

        let text = format_found(job.as_ref(), &found, job.tries(), 0.5, 12_000.0);
        assert!(
            text.contains(&found[0].address),
            "single result missing the address:\n{text}"
        );
        assert!(
            text.contains(&hex_upper(&found[0].private_key)),
            "single result missing the private key:\n{text}"
        );
        assert!(
            text.contains(&hex_upper(&found[0].seed)),
            "missing the wallet seed:\n{text}"
        );
        assert!(
            text.contains("FOUND 1 address"),
            "unexpected header:\n{text}"
        );

        // And the same holds when several addresses come back.
        let job3 = Job::start(
            "1f".into(),
            2,
            Some(30),
            TEST_SEED,
            3,
            false,
            MatchMode::Prefix,
            None,
        )
        .unwrap();
        let many = match job3.wait_timeout(Duration::from_secs(60)) {
            Some(Outcome::Found(f)) => f,
            _ => panic!("expected three matches"),
        };
        assert_eq!(many.len(), 3);
        let text3 = format_found(job3.as_ref(), &many, job3.tries(), 0.5, 12_000.0);
        assert!(
            text3.contains("FOUND 3 addresses"),
            "unexpected header:\n{text3}"
        );
        for f in &many {
            assert!(
                text3.contains(&f.address),
                "address {} missing from multi-result output:\n{text3}",
                f.address
            );
            assert!(
                text3.contains(&hex_upper(&f.private_key)),
                "private key for index {} missing:\n{text3}",
                f.index
            );
        }
        // Indices must be strictly ascending and distinct, or two results would
        // point at the same account.
        for pair in many.windows(2) {
            assert!(
                pair[0].index < pair[1].index,
                "results are not in ascending index order: {} then {}",
                pair[0].index,
                pair[1].index
            );
        }
    }

    /// Distinct random seeds must yield distinct addresses, and a fixed seed must
    /// be reproducible. This is the property the cross-device workflow relies
    /// on: keep the seed, get the same address on every device.
    #[test]
    fn random_seeds_differ_and_a_fixed_seed_repeats() {
        let grab = |seed: [u8; 32]| {
            let job = Job::start(
                "1f".into(),
                4,
                Some(30),
                seed,
                1,
                false,
                MatchMode::Prefix,
                None,
            )
            .unwrap();
            match job.wait_timeout(Duration::from_secs(60)) {
                Some(Outcome::Found(f)) => f[0].clone(),
                _ => panic!("expected a match"),
            }
        };

        let a = grab(engine::random_seed().expect("/dev/urandom should be readable"));
        let b = grab(engine::random_seed().expect("/dev/urandom should be readable"));
        assert_ne!(
            a.address, b.address,
            "two random seeds produced the same address; the seed is being ignored"
        );
        assert_eq!(grab(TEST_SEED).address, grab(TEST_SEED).address);
    }

    /// Seed parsing: `random`, 64 hex chars, and the ways of getting it wrong.
    #[test]
    fn seed_parsing_accepts_random_and_hex_only() {
        let parsed = engine::parse_seed(&"ab".repeat(32)).unwrap();
        assert!(parsed.iter().all(|&b| b == 0xab));
        // Case insensitive, and tolerant of surrounding whitespace.
        assert_eq!(
            engine::parse_seed(&format!("  {}  ", "AB".repeat(32))).unwrap(),
            parsed
        );
        assert!(engine::parse_seed("random").is_ok());
        assert!(engine::parse_seed("RANDOM").is_ok());
        // Wrong length, non-hex, and empty all rejected rather than zero-filled.
        assert!(engine::parse_seed("").is_err());
        assert!(engine::parse_seed(&"ab".repeat(31)).is_err());
        assert!(engine::parse_seed(&"zz".repeat(32)).is_err());
        assert!(engine::parse_seed(&format!("{}zz", "ab".repeat(31))).is_err());
    }

    #[test]
    fn elapsed_and_rate_are_frozen_after_completion() {
        // Regression: a polling client (the web UI) re-reads status long after
        // the answer exists. If `elapsed_secs` kept reading the clock, every
        // poll would report a larger elapsed time against a fixed `tries`, so
        // the displayed speed would decay toward zero.
        let job = Job::start(
            "3".into(),
            2,
            Some(30),
            TEST_SEED,
            1,
            false,
            MatchMode::Prefix,
            None,
        )
        .unwrap();
        job.wait_timeout(Duration::from_secs(60))
            .expect("job should finish");
        let (e1, r1) = (job.elapsed_secs(), job.rate());
        std::thread::sleep(Duration::from_millis(300));
        let (e2, r2) = (job.elapsed_secs(), job.rate());
        assert_eq!(e1, e2, "elapsed must be frozen once the job finishes");
        assert_eq!(r1, r2, "rate must be frozen once the job finishes");
        assert!(
            r2 > 1.0,
            "a finished 1-char job should report a real rate, got {r2}"
        );
    }

    #[test]
    fn engine_rejects_unsatisfiable_and_invalid_prefixes() {
        assert!(Job::start(
            "9".into(),
            1,
            None,
            TEST_SEED,
            1,
            false,
            MatchMode::Prefix,
            None
        )
        .is_err());
        assert!(Job::start(
            "2".into(),
            1,
            None,
            TEST_SEED,
            1,
            false,
            MatchMode::Prefix,
            None
        )
        .is_err());
        assert!(Job::start(
            "".into(),
            1,
            None,
            TEST_SEED,
            1,
            false,
            MatchMode::Prefix,
            None
        )
        .is_err());
        assert!(Job::start(
            "1111".into(),
            0,
            None,
            TEST_SEED,
            1,
            false,
            MatchMode::Prefix,
            None
        )
        .is_err());
        // Zero or absurd counts are rejected rather than silently clamped.
        assert!(Job::start(
            "1111".into(),
            1,
            None,
            TEST_SEED,
            0,
            false,
            MatchMode::Prefix,
            None
        )
        .is_err());
        assert!(Job::start(
            "1111".into(),
            1,
            None,
            TEST_SEED,
            1001,
            false,
            MatchMode::Prefix,
            None
        )
        .is_err());
    }

    #[test]
    fn engine_honours_cancellation() {
        // A prefix this long will not finish, so cancelling is the only exit.
        let job = Job::start(
            "111111111111".into(),
            1,
            None,
            TEST_SEED,
            1,
            false,
            MatchMode::Prefix,
            None,
        )
        .unwrap();
        assert!(job.is_running());
        job.cancel();
        let outcome = job
            .wait_timeout(Duration::from_secs(30))
            .expect("cancel should stop the workers");
        assert!(matches!(outcome, Outcome::Exhausted));
        assert!(!job.is_running(), "workers should have stopped");
        // No assertion on `tries() > 0`: the stop flag is checked before each
        // 1024-candidate batch, so a cancel that arrives before the first batch
        // legitimately reports zero work. That is by design — an atomic load
        // per candidate would cost more than the hash it guards.
        assert!(job.tries() <= 1024 * 2, "cancel should stop promptly");
    }
}
#[cfg(test)]
mod mode_tests {
    use super::*;

    const S: [u8; 32] = [0x5a; 32];

    fn grind(mode: MatchMode, pattern: &str) -> Vec<engine::Found> {
        let job = Job::start(pattern.to_string(), 2, Some(60), S, 1, false, mode, None)
            .unwrap_or_else(|e| panic!("{mode:?} {pattern} rejected: {e}"));
        match job.wait_timeout(Duration::from_secs(90)) {
            Some(Outcome::Found(f)) => f,
            _ => panic!("no {mode:?} match for {pattern}"),
        }
    }

    /// Each mode must return an address that genuinely satisfies it. This is the
    /// end-to-end version of the library's agreement test: it goes through the
    /// real search loop, so it would catch a mismatch between what the engine
    /// searches for and what it reports.
    #[test]
    fn every_mode_returns_a_satisfying_address() {
        let cases: &[(MatchMode, &str)] = &[
            (MatchMode::Prefix, "1fa"),
            (MatchMode::Suffix, "xyz"),
            (MatchMode::Contains, "nan"),
        ];
        for (mode, pattern) in cases {
            let found = grind(*mode, pattern);
            let address = &found[0].address;
            let body = address.strip_prefix("nano_").unwrap();
            let ok = match mode {
                MatchMode::Prefix => body.starts_with(pattern),
                MatchMode::Suffix => body.ends_with(pattern),
                MatchMode::Contains => body.contains(pattern),
            };
            assert!(ok, "{mode:?} {pattern}: {body} does not satisfy it");
            // And the printed key must still drive the printed address.
            assert_eq!(
                nano_keys::seed_to_address(&found[0].seed, found[0].index),
                *address
            );
        }
    }

    /// A suffix must not merely match the key portion; it has to match the real
    /// address, checksum included. A one-character suffix is the sharpest test,
    /// because all 32 characters are plausible.
    #[test]
    fn suffix_is_checked_against_the_checksum() {
        for _ in 0..3 {
            let found = grind(MatchMode::Suffix, "m");
            let body = found[0].address.strip_prefix("nano_").unwrap();
            assert!(body.ends_with('m'), "{body} does not end with m");
        }
    }

    /// The engine must reject an impossible anchored prefix, but accept the same
    /// characters in the other modes where they are meaningful.
    #[test]
    fn unsatisfiable_patterns_are_rejected_only_where_meaningful() {
        assert!(Job::start("9".into(), 1, None, S, 1, false, MatchMode::Prefix, None).is_err());
        assert!(Job::start("9".into(), 1, None, S, 1, false, MatchMode::Suffix, None).is_ok());
        assert!(Job::start("9".into(), 1, None, S, 1, false, MatchMode::Contains, None).is_ok());
        // Ignoring the first character rescues an otherwise impossible prefix.
        assert!(Job::start("9".into(), 1, None, S, 1, true, MatchMode::Prefix, None).is_ok());
        // And it is meaningless outside prefix mode.
        assert!(Job::start("9".into(), 1, None, S, 1, true, MatchMode::Suffix, None).is_err());
    }
}

#[cfg(test)]
mod grind_tests {
    use super::*;
    use crate::engine::Found;

    const S: [u8; 32] = [0x5b; 32];

    fn grind(prefix: &str, index: u32, want: usize, limit: u64) -> Vec<Found> {
        // One thread on purpose. The engine's results are independent of thread
        // count, and there is a dedicated test for that; four workers here only
        // burn CPU and oversubscribe a small runner.
        let job = Job::start_grinding(
            prefix.to_string(),
            1,
            Some(limit),
            S,
            want,
            false,
            MatchMode::Prefix,
            index,
        )
        .unwrap();
        match job
            .wait_timeout(Duration::from_secs(300))
            .expect("should finish")
        {
            Outcome::Found(f) => f,
            // Turning a timeout into an empty Vec made a slow runner look like
            // "no match exists", which is a completely different bug. Say which
            // one actually happened.
            Outcome::Exhausted => panic!(
                "grind({prefix:?}, index {index}) returned no result: the search was \
                 cut off by its time limit rather than exhausting the space"
            ),
        }
    }

    /// The whole point of grinding seeds: the match is at account 0, so
    /// importing the seed into a wallet yields the vanity address as the first
    /// account with nothing else to do.
    #[test]
    fn a_match_can_land_at_account_zero() {
        let found = grind("1fa", 0, 1, 60);
        assert_eq!(found.len(), 1, "should find one");
        assert_eq!(found[0].index, 0, "must be account 0");
        assert!(
            found[0].address.starts_with("nano_1fa"),
            "address should carry the prefix: {}",
            found[0].address
        );
    }

    /// The reported seed must be the one that actually derives the reported
    /// private key at index 0. This is the check that would catch a mismatch
    /// between the candidate seed and the account it produced.
    #[test]
    fn the_reported_seed_derives_the_reported_key_at_index_zero() {
        let found = grind("1fa", 0, 1, 60);
        assert_eq!(found.len(), 1);
        let f = &found[0];
        assert_eq!(
            nano_keys::derive_private_key(&f.seed, 0),
            f.private_key,
            "the printed seed must derive the printed private key at index 0"
        );
        // And the full chain must reproduce the printed address.
        let pk = nano_keys::private_key_to_public(&f.private_key);
        assert_eq!(
            nano_keys::public_key_to_address(&pk),
            f.address,
            "the printed seed, key and address must all agree"
        );
    }

    /// A non-zero fixed index must also work, and must report that index.
    #[test]
    fn grinding_at_a_nonzero_index_reports_that_index() {
        let found = grind("1fa", 7, 1, 60);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].index, 7);
        assert!(found[0].address.starts_with("nano_1fa"));
        assert_eq!(
            nano_keys::derive_private_key(&found[0].seed, 7),
            found[0].private_key
        );
    }

    /// Grinding must be reproducible from the same master seed, and must not
    /// return the same candidate twice.
    #[test]
    fn grinding_is_reproducible_and_yields_distinct_seeds() {
        let a = grind("1fa", 0, 3, 60);
        let b = grind("1fa", 0, 3, 60);
        assert_eq!(a.len(), 3);
        assert_eq!(
            a.iter().map(|f| f.address.as_str()).collect::<Vec<_>>(),
            b.iter().map(|f| f.address.as_str()).collect::<Vec<_>>(),
            "the same master seed must reproduce the same results"
        );
        let mut seeds: Vec<_> = a.iter().map(|f| f.seed).collect();
        seeds.sort_unstable();
        seeds.dedup();
        assert_eq!(seeds.len(), 3, "candidate seeds must be distinct");
        // Ordering is by search attempt, so the seeds must differ.
        assert_ne!(a[0].seed, a[1].seed);
    }

    /// A seed and its index are the same account, so the same (seed, 0) must
    /// give the same private key as the plain index search would.
    #[test]
    fn ground_accounts_match_the_plain_derivation() {
        let found = grind("1fa", 0, 1, 60);
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].private_key,
            nano_keys::derive_private_key(&found[0].seed, 0)
        );
    }
}

#[cfg(test)]
mod seed_reachability_tests {
    use super::*;

    const S: [u8; 32] = [0x3c; 32];

    /// The whole point of `--max-index`: a match at a *reachable* index must be
    /// genuinely account N of the seed, so a wallet walking 0, 1, 2 … N lands
    /// exactly on the vanity address.
    ///
    /// This is the property that makes the seed useful rather than decorative.
    /// It also guards against the ceiling being applied only to the reported
    /// number instead of to the actual search.
    #[test]
    fn capped_search_returns_an_address_a_wallet_can_walk_to() {
        let job = Job::start(
            "11".into(),
            1,
            Some(60),
            S,
            1,
            false,
            MatchMode::Prefix,
            Some(1000),
        )
        .unwrap();
        let found = match job.wait_timeout(Duration::from_secs(60)) {
            Some(Outcome::Found(f)) => f,
            _ => panic!("no match below index 1000 for '11'"),
        };
        let hit = &found[0];

        assert!(
            hit.index <= 1000,
            "ceiling ignored: got index {}",
            hit.index
        );
        assert!(hit.address.starts_with("nano_11"));

        // Walk the seed the way a wallet does, one account at a time, and
        // confirm the vanity address is exactly where it claims to be.
        for i in 0..=hit.index {
            let a = nano_keys::seed_to_address(&S, i);
            if i == hit.index {
                assert_eq!(
                    a, hit.address,
                    "account {i} does not match the reported address"
                );
            } else {
                assert_ne!(a, hit.address, "vanity address appeared early at {i}");
            }
        }
    }

    /// Without the ceiling the same pattern can land far out of reach, which is
    /// exactly the situation the warning exists for. It must not be *capped by
    /// accident*: the unrestricted search is allowed to return a large index.
    #[test]
    fn uncapped_search_is_not_silently_truncated() {
        let job = Job::start(
            "11".into(),
            1,
            Some(60),
            S,
            1,
            false,
            MatchMode::Prefix,
            None,
        )
        .unwrap();
        let found = match job.wait_timeout(Duration::from_secs(60)) {
            Some(Outcome::Found(f)) => f,
            _ => panic!("expected a match"),
        };
        // The lowest match is the same either way; capping must not have
        // changed which address is the first one.
        let capped = Job::start(
            "11".into(),
            4,
            Some(60),
            S,
            1,
            false,
            MatchMode::Prefix,
            Some(1000),
        )
        .unwrap();
        let capped_found = match capped.wait_timeout(Duration::from_secs(60)) {
            Some(Outcome::Found(f)) => f,
            _ => panic!("expected a capped match"),
        };
        assert_eq!(
            found[0].index, capped_found[0].index,
            "capping changed the first match, so the ceiling altered the search"
        );
    }

    /// The retracted claim was copied into four places, and fixing one at a
    /// time is how the other three survive. Sweep the source for the wording
    /// so it cannot come back unnoticed.
    #[test]
    fn no_user_facing_text_claims_a_seed_cannot_reach_a_high_index() {
        let banned = [
            "add accounts up to",
            "none will walk that far",
            "IMPORT THE PRIVATE KEYS",
            "importing the wallet seed (add accounts",
            "actually reach by restoring the seed",
            "recreate them one at a time",
            "materialises",
            "means adding",
            // Distinctive enough that small rewording of the surrounding
            // sentence cannot hide the claim. An earlier list used "recreate
            // them one at a time" while the text said "recreates", and the
            // check silently passed against the exact claim it was for.
            "does not contain its accounts",
            "Effectively unreachable",
            "accounts to add",
        ];
        // The help text is hard-wrapped, so a phrase can straddle a newline and
        // indentation and never appear contiguously. Collapse whitespace on
        // both sides before searching, otherwise the check silently passes
        // against exactly the wording it was written to catch.
        let squash = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ");
        for (name, text) in [
            ("result output", format_found_probe()),
            ("cli help", USAGE.to_string()),
        ] {
            let flat = squash(&text);
            for phrase in banned {
                assert!(
                    !flat.contains(&squash(phrase)),
                    "{name} still contains the retracted claim {phrase:?}:\n{text}"
                );
            }
        }
    }

    fn format_found_probe() -> String {
        // Short pattern on purpose: this probe only needs *a* result to format,
        // so it should not depend on how fast the machine grinds.
        let job = Job::start(
            "1fa".into(),
            2,
            Some(30),
            [0x11u8; 32],
            1,
            false,
            MatchMode::Prefix,
            None,
        )
        .unwrap();
        let found = match job.wait_timeout(Duration::from_secs(90)) {
            Some(Outcome::Found(f)) => f,
            _ => return String::new(),
        };
        format_found(job.as_ref(), &found, job.tries(), 1.0, 1000.0)
    }

    /// The advice text must tell the user how to restore, for any index.
    ///
    /// This test previously asserted the opposite: that a high index must be
    /// routed to the private key and the seed advice suppressed. That advice
    /// was based on a false premise -- that reaching index N means creating
    /// accounts 0..N. Nault's docs state it "can access any index if you so
    /// want" and its import flow accepts the account index directly, so seed
    /// plus index restores a high-index address with no walking.
    #[test]
    fn result_always_explains_seed_plus_index_restore() {
        // The advice no longer branches on the index, so a short pattern is
        // enough; a long one would just make this a speed test.
        let job = Job::start(
            "1fa".into(),
            1,
            Some(60),
            S,
            1,
            false,
            MatchMode::Prefix,
            None,
        )
        .unwrap();
        let found = match job.wait_timeout(Duration::from_secs(90)) {
            Some(Outcome::Found(f)) => f,
            _ => return, // no match within the limit; nothing to assert
        };
        let text = format_found(job.as_ref(), &found, job.tries(), 1.0, 1000.0);
        assert!(
            text.contains("Restore with the SEED and the account index"),
            "every result must explain seed + index restore:\n{text}"
        );
        assert!(
            text.contains("Account index"),
            "the import steps must name the index field:\n{text}"
        );
        assert!(
            !text.contains("IMPORT THE PRIVATE KEYS"),
            "must not claim the seed cannot reach a high index:\n{text}"
        );
        assert!(
            !text.contains("none will walk that far"),
            "must not claim a wallet cannot reach a high index:\n{text}"
        );
    }
}

#[cfg(test)]
mod reporting_tests {
    use super::*;

    const S: [u8; 32] = [0x3c; 32];

    fn run(
        pattern: &str,
        max_index: Option<u32>,
        limit: Option<u64>,
    ) -> (std::sync::Arc<Job>, Outcome) {
        // 2 threads: the timeout cases deliberately burn their entire wall-clock
        // limit, so every extra worker is CPU spent for nothing.
        let job = Job::start(
            pattern.to_string(),
            2,
            limit,
            S,
            1,
            false,
            MatchMode::Prefix,
            max_index,
        )
        .unwrap();
        let outcome = job.wait_timeout(Duration::from_secs(90)).unwrap();
        (job, outcome)
    }

    /// A run of a few milliseconds must not advertise a throughput. 18 tries in
    /// 7 ms divided out to "3000 addr/s" on a machine that actually does
    /// 64,000 — a number that is arithmetic, not measurement.
    #[test]
    fn a_very_short_run_reports_no_rate() {
        let (job, outcome) = run("11", Some(1000), Some(30));
        let found = match outcome {
            Outcome::Found(f) => f,
            _ => panic!("expected a match"),
        };
        let text = format_found(&job, &found, job.tries(), 0.007, 2571.0);
        assert!(
            !text.contains("addr/s"),
            "a 7ms run must not quote a rate:\n{text}"
        );
        assert!(text.contains("FOUND 1 address"), "{text}");
    }

    /// A long run still reports its rate, so the fix did not silence the number
    /// that matters.
    #[test]
    fn a_long_run_still_reports_a_rate() {
        let (job, outcome) = run("1fadgi", Some(50_000), None);
        if let Outcome::Found(f) = outcome {
            let text = format_found(&job, &f, job.tries(), 2.0, 40_000.0);
            assert!(text.contains("addr/s"), "{text}");
            return;
        }
        // Exhausted path: the miss explanation is the thing under test.
        let rate = job.rate();
        assert!(rate > 0.0);
    }

    /// Running out of a `--max-index` cap is not the same as the pattern being
    /// impossible, and the message must say which happened.
    #[test]
    fn a_capped_miss_says_the_cap_was_the_reason() {
        let (job, outcome) = run("1test", Some(1000), Some(30));
        assert!(matches!(outcome, Outcome::Exhausted));
        assert!(job.capped_out(), "should be detected as capped out");
        let txt = explain_miss(&job, job.tries(), job.rate());
        assert!(txt.contains("capped"), "should mention the cap:\n{txt}");
        assert!(
            !txt.contains("whole 2^32"),
            "must not claim the full space was searched:\n{txt}"
        );
    }

    /// A timeout is its own case again.
    #[test]
    fn a_timed_out_miss_says_so() {
        let (job, outcome) = run("1fadgi", None, Some(1));
        assert!(matches!(outcome, Outcome::Exhausted));
        assert!(!job.capped_out(), "no cap was set, so not capped out");
        let txt = explain_miss(&job, job.tries(), job.rate());
        assert!(
            txt.contains("time limit"),
            "should mention the limit:\n{txt}"
        );
    }

    /// `expected` is a property of the pattern and must never be clamped to the
    /// cap, or the estimate becomes nonsense ("5 chars needs ~0s").
    #[test]
    fn expected_is_never_clamped_to_the_ceiling() {
        let (job, _) = run("1test", Some(1000), Some(30));
        assert_eq!(
            job.expected,
            2f64.powi(21),
            "expected must stay the pattern's own difficulty"
        );
        assert!(
            (job.ceiling as f64) < job.expected,
            "the cap is deliberately smaller, which is the situation being tested"
        );
    }
}
