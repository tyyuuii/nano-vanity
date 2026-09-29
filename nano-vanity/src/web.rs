//! A tiny local web UI for the grinder.
//!
//! Deliberately dependency-free: the whole server is `std::net` plus a few
//! hundred lines. Pulling in axum/tokio would mean a much heavier build on a
//! phone (and realistically an OOM risk with `-j 2`), for a tool whose entire
//! front-end is one form and one status poll.
//!
//! The server binds to loopback by default. Exposing it would let anyone on the
//! same network start jobs and read the seed/private keys it produces.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use crate::engine::{self, Job, Outcome};

/// How many finished jobs to keep around for status polling. Each retained job
/// holds a seed and private keys in memory, so this is deliberately small.
const MAX_JOBS: usize = 32;
use crate::qubic::Chain;
use crate::qubic_search::{QubicJob, QubicOutcome};
use nano_keys::MatchMode;

/// A job on either chain.
///
/// The two job types are kept apart rather than unified behind a trait
/// because they share almost nothing: the Nano job scans one seed's account
/// indices and reports an index, the Qubic job scans seeds and has no index
/// at all. A trait would need a method per divergent field, and the dispatch
/// below is a handful of lines.
#[derive(Clone)]
pub enum AnyJob {
    Nano(Arc<Job>),
    Qubic(Arc<QubicJob>),
}

impl AnyJob {
    pub fn is_running(&self) -> bool {
        match self {
            AnyJob::Nano(j) => j.is_running(),
            AnyJob::Qubic(j) => j.is_running(),
        }
    }

    pub fn cancel(&self) {
        match self {
            AnyJob::Nano(j) => j.cancel(),
            AnyJob::Qubic(j) => j.cancel(),
        }
    }

    /// The polling payload for this job, in the same JSON shape on both
    /// chains. `status_json` and `qubic_status_json` keep their own shapes and
    /// this is the single place they are chosen between.
    pub fn status_json(&self) -> String {
        match self {
            AnyJob::Nano(j) => status_json(j),
            AnyJob::Qubic(j) => qubic_status_json(j),
        }
    }
}

struct State {
    jobs: Mutex<HashMap<u64, AnyJob>>,
    next_id: Mutex<u64>,
    /// The chain the UI opens on, from `--chain`. Held in the state rather than
    /// threaded through every request handler, because the only consumer is the
    /// HTML, which is served from the same state as the jobs it creates.
    default_chain: Chain,
}

impl State {
    fn with_chain(default_chain: Chain) -> Self {
        Self {
            jobs: Mutex::new(HashMap::new()),
            next_id: Mutex::new(1),
            default_chain,
        }
    }
}

/// Insert a job and reap finished ones, for either chain.
///
/// The reaping used to live inline in the Nano branch only, so a Qubic job was
/// inserted and never reclaimed: the map grew for the lifetime of the server,
/// holding every finished Qubic job's seed and private keys in memory. That
/// matters more for Qubic than for Nano, because a Qubic seed *is* a wallet --
/// the identity cannot be recovered from anything else -- so an unbounded pile
/// of finished jobs is an unbounded pile of wallets sitting in the process.
///
/// Only *finished* jobs are dropped, so a running job is never pulled out from
/// under a poller.
fn store_job(state: &State, id: u64, job: AnyJob) {
    let mut jobs = state.jobs.lock().unwrap();
    jobs.insert(id, job);
    if jobs.len() > MAX_JOBS {
        // Sorted by id, so the *oldest* finished jobs go first. Iterating the
        // map directly would pick an arbitrary one among the finished jobs,
        // since HashMap order is not stable -- which could retire a job someone
        // was still polling while keeping a newer one.
        let mut finished: Vec<u64> = jobs
            .iter()
            .filter(|(_, j)| !j.is_running())
            .map(|(k, _)| *k)
            .collect();
        finished.sort_unstable();
        for k in finished.into_iter().take(jobs.len() - MAX_JOBS) {
            jobs.remove(&k);
        }
    }
}

fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Extracts a JSON string field. Sufficient for the flat request bodies used
/// here; the values are validated again by `Job::start`.
fn json_field(body: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let start = body.find(&needle)? + needle.len();
    let rest = &body[start..];
    let colon = rest.find(':')? + 1;
    let rest = rest[colon..].trim_start();
    if let Some(r) = rest.strip_prefix('"') {
        let end = r.find('"')?;
        Some(r[..end].to_string())
    } else {
        let end = rest.find([',', '}']).unwrap_or(rest.len());
        Some(rest[..end].trim().to_string())
    }
}

fn status_json(job: &Job) -> String {
    // The monotonic counter, not `tries()`. `tries` switches to the
    // deterministic "first matching index plus one" the moment the search
    // completes, so a polled run watched its try count climb and then snap
    // *backwards* at the end -- a decreasing number reads as a bug even when it
    // is the more correct figure. The CLI still reports `tries`.
    let tries = job.tries_live();
    let elapsed = job.elapsed_secs();
    let rate = if tries == 0 {
        0.0
    } else {
        tries as f64 / elapsed.max(f64::MIN_POSITIVE)
    };
    let progress = job.progress();

    let mut out = String::from("{");
    out.push_str(&format!("\"prefix\":{},", json_str(&job.prefix)));
    out.push_str(&format!("\"threads\":{},", job.threads));
    out.push_str(&format!("\"tries\":{tries},"));
    out.push_str(&format!("\"elapsed\":{elapsed:.3},"));
    out.push_str(&format!("\"rate\":{rate:.0},"));
    out.push_str(&format!("\"expected\":{:.0},", job.expected));
    out.push_str(&format!("\"want\":{},", job.want));
    out.push_str(&format!("\"skip_first\":{},", job.skip_first));
    out.push_str(&format!("\"mode\":{},", json_str(job.mode.as_str())));
    out.push_str(&format!(
        "\"max_index\":{},",
        job.max_index.map_or("null".to_string(), |n| n.to_string())
    ));
    out.push_str(&format!("\"progress\":{progress:.6},"));

    match job.outcome() {
        // While running, report whatever has already been found rather than
        // nothing. The match list used to be unreachable until the search
        // returned, so a request for 5 addresses displayed zero results for the
        // whole run and then all five at once.
        None => {
            let partial = job.partial();
            out.push_str("\"state\":\"running\",");
            out.push_str(&format!("\"count\":{},", partial.len()));
            out.push_str("\"partial\":true,\"results\":[");
            for (n, f) in partial.iter().enumerate() {
                if n > 0 {
                    out.push(',');
                }
                out.push_str(&format!(
                    "{{\"address\":{},\"private_key\":{},\"index\":{}}}",
                    json_str(&f.address),
                    json_str(&engine::hex_upper(&f.private_key)),
                    f.index
                ));
            }
            out.push(']');
        }
        Some(Outcome::Exhausted) => {
            // A capped miss is not the same as an impossible pattern, and the UI
            // used to say only "exhausted", which reads as "it bugged out".
            let why = if job.capped_out() {
                "capped"
            } else if job.time_limit.is_some() {
                "timeout"
            } else {
                "exhausted"
            };
            // No trailing comma: this arm is terminal, and `,}` is not valid JSON,
            // which made the browser throw on every capped or timed-out search.
            out.push_str(&format!("\"state\":\"exhausted\",\"why\":\"{why}\""));
        }
        Some(Outcome::Found(found)) => {
            out.push_str("\"state\":\"found\",");
            out.push_str(&format!("\"count\":{},", found.len()));
            out.push_str("\"results\":[");
            for (n, f) in found.iter().enumerate() {
                if n > 0 {
                    out.push(',');
                }
                out.push_str(&format!(
                    "{{\"address\":{},\"private_key\":{},\"index\":{}}}",
                    json_str(&f.address),
                    json_str(&engine::hex_upper(&f.private_key)),
                    f.index
                ));
            }
            out.push_str("],");
            // The seed is shared by every result, so it is reported once here
            // as well as in the first entry, to keep old clients working.
            out.push_str("\"seed\":");
            out.push_str(&json_str(&engine::hex_upper(&found[0].seed)));
            if let Some(first) = found.first() {
                out.push(',');
                out.push_str("\"address\":");
                out.push_str(&json_str(&first.address));
                out.push(',');
                out.push_str("\"private_key\":");
                out.push_str(&json_str(&engine::hex_upper(&first.private_key)));
                out.push(',');
                out.push_str(&format!("\"index\":{}", first.index));
            }
        }
    }
    out.push('}');
    out
}

/// The same shape as `status_json`, for a Qubic job.
///
/// A separate function rather than a parameterised one because the two report
/// genuinely different things: there is no `index`, no `max_index` and no
/// `capped` state on the Qubic side, and a Qubic result carries a 55-letter
/// seed that *is* the wallet rather than a shared 64-hex seed.
fn qubic_status_json(job: &QubicJob) -> String {
    // See `status_json`: the monotonic counter, because `tries` drops to the
    // deterministic value at completion and a decreasing number reads as a bug.
    let tries = job.tries_live();
    let elapsed = job.elapsed_secs();
    let rate = if tries == 0 {
        0.0
    } else {
        tries as f64 / elapsed.max(f64::MIN_POSITIVE)
    };
    let progress = job.progress();

    let mut out = String::from("{");
    out.push_str("\"chain\":\"qubic\",");
    out.push_str(&format!("\"prefix\":{},", json_str(job.pattern.needle())));
    out.push_str(&format!("\"threads\":{},", job.threads));
    out.push_str(&format!("\"tries\":{tries},"));
    out.push_str(&format!("\"elapsed\":{elapsed:.3},"));
    out.push_str(&format!("\"rate\":{rate:.0},"));
    out.push_str(&format!("\"expected\":{:.0},", job.expected));
    out.push_str(&format!("\"want\":{},", job.want));
    out.push_str(&format!(
        "\"mode\":{},",
        json_str(job.pattern.mode().as_str())
    ));
    out.push_str("\"max_index\":null,");
    out.push_str(&format!("\"progress\":{progress:.6},"));

    match job.outcome() {
        // Stream matches while the search runs. This matters more here than on
        // Nano: a Qubic found seed *is* the wallet, so an identity that turned
        // up ten minutes into a two-hour search should not be invisible until
        // the search ends.
        None => {
            let partial = job.partial();
            out.push_str("\"state\":\"running\",");
            out.push_str(&format!("\"count\":{},", partial.len()));
            out.push_str("\"partial\":true,\"results\":[");
            for (n, f) in partial.iter().enumerate() {
                if n > 0 {
                    out.push(',');
                }
                out.push_str(&format!(
                    "{{\"address\":{},\"private_key\":{},\"seed\":{},\"attempt\":{}}}",
                    json_str(&f.identity),
                    json_str(&engine::hex_upper(&f.private_key)),
                    json_str(&f.seed),
                    f.attempt
                ));
            }
            out.push(']');
        }
        Some(QubicOutcome::Exhausted) => {
            // No "capped" state exists on this chain: there is no index ceiling
            // to hit. A time limit is the only way to stop early.
            let why = if job.timed_out() {
                "timeout"
            } else {
                "exhausted"
            };
            out.push_str(&format!("\"state\":\"exhausted\",\"why\":\"{why}\""));
        }
        Some(QubicOutcome::Found(found)) => {
            out.push_str("\"state\":\"found\",");
            out.push_str(&format!("\"count\":{},", found.len()));
            out.push_str("\"results\":[");
            for (n, f) in found.iter().enumerate() {
                if n > 0 {
                    out.push(',');
                }
                out.push_str(&format!(
                    "{{\"address\":{},\"private_key\":{},\"seed\":{},\"attempt\":{}}}",
                    json_str(&f.identity),
                    json_str(&engine::hex_upper(&f.private_key)),
                    json_str(&f.seed),
                    f.attempt
                ));
            }
            out.push_str("],");
            if let Some(first) = found.first() {
                out.push_str("\"address\":");
                out.push_str(&json_str(&first.identity));
                out.push(',');
                out.push_str("\"private_key\":");
                out.push_str(&json_str(&engine::hex_upper(&first.private_key)));
                out.push(',');
                out.push_str("\"seed\":");
                out.push_str(&json_str(&first.seed));
            }
        }
    }
    out.push('}');
    out
}

fn write_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &str,
) -> std::io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body.as_bytes())?;
    stream.flush()
}

fn handle(state: &Arc<State>, mut stream: TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    let mut reader = BufReader::new(stream.try_clone()?);

    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(());
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("/").to_string();

    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap_or(0);
        }
    }

    let mut body = String::new();
    if content_length > 0 {
        let mut buf = vec![0u8; content_length.min(64 * 1024)];
        reader.read_exact(&mut buf)?;
        body = String::from_utf8_lossy(&buf).into_owned();
    }

    let route = path.split('?').next().unwrap_or("/").to_string();

    match (method.as_str(), route.as_str()) {
        // Identity endpoint. The launcher uses this to tell "my installed
        // binary is serving this port" apart from "some other, possibly older
        // nano-vanity is holding the port", which a bare port probe cannot.
        ("GET", "/api/version") => write_response(
            &mut stream,
            "200 OK",
            "application/json",
            &format!(
                "{{\"name\":\"nano-vanity\",\"version\":\"{}\"}}",
                env!("CARGO_PKG_VERSION")
            ),
        ),
        ("GET", "/") => write_response(
            &mut stream,
            "200 OK",
            "text/html; charset=utf-8",
            &INDEX_HTML
                .replace("VERSION_PLACEHOLDER", env!("CARGO_PKG_VERSION"))
                .replace("CHAIN_PLACEHOLDER", state.default_chain.as_str()),
        ),
        ("POST", "/api/start") => {
            let prefix = json_field(&body, "prefix")
                .unwrap_or_default()
                .trim()
                .trim_start_matches("nano_")
                .trim_start_matches("xrb_")
                .to_string();
            let threads = json_field(&body, "threads")
                .and_then(|v| v.parse::<usize>().ok())
                .filter(|&n| (1..=64).contains(&n))
                .unwrap_or_else(|| {
                    std::thread::available_parallelism()
                        .map(|n| n.get())
                        .unwrap_or(1)
                });
            let seconds = json_field(&body, "seconds")
                .and_then(|v| v.parse::<u64>().ok())
                .filter(|&n| n > 0);

            // The seed's syntax depends on the chain: 64 hex for Nano, 55
            // letters for Qubic. So only the raw string is extracted here and
            // the parse happens inside each branch. Parsing it up front meant a
            // Qubic request carrying its 55-letter master seed failed in the
            // *Nano* parser and never reached the Qubic branch, so the web UI's
            // "Master seed" field was silently broken for Qubic while the
            // no-seed path worked fine.
            let seed_str = json_field(&body, "seed")
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());

            // The chain is read before anything chain-specific is validated.
            let chain = match json_field(&body, "chain").as_deref() {
                Some("qubic") | Some("q") => Chain::Qubic,
                _ => Chain::Nano,
            };

            let mode = json_field(&body, "mode")
                .and_then(|v| MatchMode::parse(&v))
                .unwrap_or(MatchMode::Prefix);
            let skip_first = json_field(&body, "skip_first")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false);
            let count = json_field(&body, "count")
                .and_then(|v| v.parse::<usize>().ok())
                .filter(|&n| (1..=1000).contains(&n))
                .unwrap_or(1);

            let max_index = json_field(&body, "max_index")
                .and_then(|v| v.parse::<u32>().ok())
                .filter(|&n| n > 0);

            // Grounding varies the seed at a fixed account index, which is how
            // the vanity address lands on account 0. An account-index cap has
            // no meaning in that mode, so reject the combination rather than
            // silently ignoring one of them.
            let grind = json_field(&body, "grind")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false);
            let seed_index = json_field(&body, "seed_index")
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(0);
            if grind && max_index.is_some() {
                write_response(
                    &mut stream,
                    "400 Bad Request",
                    "application/json",
                    "{\"error\":\"Grinding seeds already fixes the account index, so Max account index does not apply.\"}",
                )?;
                return Ok(());
            }

            // The chain is read before anything chain-specific is validated.
            // A Qubic request is dispatched to its own job type; the Nano
            // fields below are still parsed so a stale client that omits
            // `chain` keeps working exactly as it did.
            //
            // Both chains run in this one server at the same time. They are
            // separate job types, not separate servers, so a Nano search and a
            // Qubic search can be in flight together on the same port and the
            // status endpoint serves either, keyed by the job's own chain.
            if chain == Chain::Qubic {
                // Qubic: no prefix anchoring, no index, no grinding. A stale
                // Nano flag is reported rather than ignored, because a user who
                // leaves `max_index` ticked after switching chains would
                // otherwise get a search that quietly ignores their cap.
                for (field, present) in [
                    (
                        "Max account index",
                        json_field(&body, "max_index").is_some(),
                    ),
                    (
                        "Grind seeds",
                        json_field(&body, "grind")
                            .map(|v| v == "true" || v == "1")
                            .unwrap_or(false),
                    ),
                    (
                        "Skip first character",
                        json_field(&body, "skip_first")
                            .map(|v| v == "true" || v == "1")
                            .unwrap_or(false),
                    ),
                ] {
                    if present {
                        write_response(
                            &mut stream,
                            "400 Bad Request",
                            "application/json",
                            &format!(
                                "{{\"error\":\"{field} does not apply to Qubic: it has no account index.\"}}"
                            ),
                        )?;
                        return Ok(());
                    }
                }

                let pattern = match crate::qubic::IdentityPattern::new(&prefix, mode, 0) {
                    Ok(p) => p,
                    Err(e) => {
                        write_response(
                            &mut stream,
                            "400 Bad Request",
                            "application/json",
                            &format!("{{\"error\":{}}}", json_str(&e)),
                        )?;
                        return Ok(());
                    }
                };
                // The master seed is a 55-letter Qubic seed, parsed with the
                // Qubic rules rather than the Nano ones.
                let master = match seed_str {
                    Some(ref s) => match crate::qubic::parse_seed(s) {
                        Ok(s) => s,
                        Err(e) => {
                            write_response(
                                &mut stream,
                                "400 Bad Request",
                                "application/json",
                                &format!("{{\"error\":{}}}", json_str(&e)),
                            )?;
                            return Ok(());
                        }
                    },
                    None => match crate::qubic_search::random_master() {
                        Ok(s) => s,
                        Err(e) => {
                            write_response(
                                &mut stream,
                                "500 Internal Server Error",
                                "application/json",
                                &format!("{{\"error\":{}}}", json_str(&e)),
                            )?;
                            return Ok(());
                        }
                    },
                };
                match QubicJob::start(pattern, threads, seconds, &master, count) {
                    Ok(job) => {
                        let mut id = state.next_id.lock().unwrap();
                        let this = *id;
                        *id += 1;
                        drop(id);
                        store_job(state, this, AnyJob::Qubic(job));
                        write_response(
                            &mut stream,
                            "200 OK",
                            "application/json",
                            &format!("{{\"id\":{this}}}"),
                        )
                    }
                    Err(e) => {
                        let esc = json_str(&e);
                        write_response(
                            &mut stream,
                            "400 Bad Request",
                            "application/json",
                            &format!("{{\"error\":{esc}}}"),
                        )
                    }
                }?;
                return Ok(());
            }

            // Nano's seed parsing happens here, after the Qubic branch has
            // returned, so each chain validates its own syntax. An absent or
            // empty seed means "draw a fresh random one", so each run lands on
            // a different address; a supplied seed reproduces an earlier run.
            let seed = match seed_str {
                Some(ref s) => match crate::engine::parse_seed(s) {
                    Ok(seed) => seed,
                    Err(e) => {
                        let esc = json_str(&e);
                        write_response(
                            &mut stream,
                            "400 Bad Request",
                            "application/json",
                            &format!("{{\"error\":{esc}}}"),
                        )?;
                        return Ok(());
                    }
                },
                None => match crate::engine::random_seed() {
                    Ok(seed) => seed,
                    Err(e) => {
                        let esc = json_str(&e);
                        write_response(
                            &mut stream,
                            "500 Internal Server Error",
                            "application/json",
                            &format!("{{\"error\":{esc}}}"),
                        )?;
                        return Ok(());
                    }
                },
            };

            let started = if grind {
                Job::start_grinding(
                    prefix, threads, seconds, seed, count, skip_first, mode, seed_index,
                )
            } else {
                Job::start(
                    prefix, threads, seconds, seed, count, skip_first, mode, max_index,
                )
            };
            match started {
                Ok(job) => {
                    let mut id = state.next_id.lock().unwrap();
                    let this = *id;
                    *id += 1;
                    drop(id);
                    store_job(state, this, AnyJob::Nano(job));
                    write_response(
                        &mut stream,
                        "200 OK",
                        "application/json",
                        &format!("{{\"id\":{this}}}"),
                    )
                }
                Err(e) => {
                    let esc = json_str(&e);
                    write_response(
                        &mut stream,
                        "400 Bad Request",
                        "application/json",
                        &format!("{{\"error\":{esc}}}"),
                    )
                }
            }
        }
        ("GET", "/api/status") => {
            let id: Option<u64> = path
                .split("id=")
                .nth(1)
                .and_then(|v| v.split('&').next())
                .and_then(|v| v.parse().ok());
            let job = id.and_then(|i| state.jobs.lock().unwrap().get(&i).cloned());
            match job {
                Some(j) => {
                    write_response(&mut stream, "200 OK", "application/json", &j.status_json())
                }
                None => write_response(
                    &mut stream,
                    "404 Not Found",
                    "application/json",
                    "{\"error\":\"unknown job\"}",
                ),
            }
        }
        ("POST", "/api/cancel") => {
            let id: Option<u64> = json_field(&body, "id").and_then(|v| v.parse().ok());
            let job = id.and_then(|i| state.jobs.lock().unwrap().get(&i).cloned());
            match job {
                Some(j) => {
                    j.cancel();
                    write_response(&mut stream, "200 OK", "application/json", "{\"ok\":true}")
                }
                None => write_response(
                    &mut stream,
                    "404 Not Found",
                    "application/json",
                    "{\"error\":\"unknown job\"}",
                ),
            }
        }
        _ => write_response(&mut stream, "404 Not Found", "text/plain", "not found"),
    }
}

/// Serves until killed with Ctrl-C.
pub fn serve(addr: SocketAddr, default_chain: Chain) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    serve_listener_with(listener, default_chain)
}

/// Serves on an already-bound listener, with an explicit starting chain.
///
/// Test-only in practice: this is a binary crate, so `pub` does not make an
/// item reachable from outside and nothing but the tests calls it.
#[cfg(test)]
pub fn serve_listener(listener: TcpListener) -> std::io::Result<()> {
    serve_listener_with(listener, Chain::Nano)
}

/// The real serve loop, with the chain the UI starts on.
///
/// Split out so tests can hand over a listener they already hold. Binding port
/// 0 to *discover* a free port and then releasing it before rebinding is a
/// TOCTOU race: under a loaded runner another thread can take the port in
/// between, and the silently-failed bind then routes requests to the wrong
/// server. Holding the listener removes the window entirely.
fn serve_listener_with(listener: TcpListener, default_chain: Chain) -> std::io::Result<()> {
    let local = listener.local_addr()?;
    let shown = if local.ip().is_unspecified() {
        format!("http://{}:{}/", local_hostname(), local.port())
    } else {
        format!("http://{local}/")
    };
    println!("nano-vanity web UI: {shown}");
    if !local.ip().is_loopback() {
        println!(
            "  WARNING: bound to {} — anyone who can reach this port can start\n\
             \x20          jobs and read the seeds and private keys it produces.",
            local.ip()
        );
    }
    println!("  Ctrl-C to stop.");

    let state = Arc::new(State::with_chain(default_chain));
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let state = state.clone();
                // One thread per connection: trivial and quite sufficient, since
                // a single browser holds at most a couple of connections.
                std::thread::spawn(move || {
                    if let Err(e) = handle(&state, s) {
                        eprintln!("connection error: {e}");
                    }
                });
            }
            Err(e) => eprintln!("accept error: {e}"),
        }
    }
    Ok(())
}

fn local_hostname() -> String {
    // Best-effort. For an all-interfaces bind, localhost is the useful default.
    "127.0.0.1".to_string()
}

const INDEX_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="nano-vanity-version" content="VERSION_PLACEHOLDER">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>nano-vanity</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 1rem; max-width: 40rem; margin-inline: auto;
    font: 15px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace;
    background: #10131a; color: #dfe3ee;
  }
  h1 { font-size: 1.1rem; margin: 0 0 .25rem; letter-spacing: .02em; }
  .sub { color: #8b93a7; font-size: .82rem; margin-bottom: 1rem; }
  label { display: block; font-size: .78rem; color: #8b93a7; margin-bottom: .25rem; }
  label.check {
    display: flex; align-items: center; gap: .45rem;
    color: #dfe3ee; font-size: .82rem; margin: .6rem 0 .2rem; cursor: pointer;
  }
  label.check input { width: auto; margin: 0; accent-color: #6ea8ff; }
  input, button, select {
    font: inherit; border-radius: .5rem; border: 1px solid #2b3346;
    background: #171c26; color: #dfe3ee; padding: .6rem .7rem; width: 100%;
  }
  input:focus { outline: 2px solid #3d6ce0; outline-offset: 1px; }
  button { cursor: pointer; background: #2f4fa8; border-color: #3d6ce0; font-weight: 600; }
  button:hover:not(:disabled) { background: #3a5fc4; }
  button:disabled { opacity: .45; cursor: default; }
  button.ghost { background: #171c26; border-color: #2b3346; font-weight: 400; }
  .row { display: flex; gap: .5rem; }
  .row > * { flex: 1; }
  .field { margin-bottom: .75rem; }
  .hint { font-size: .76rem; color: #6f7789; margin-top: .3rem; }
  .err { color: #ff9c9c; font-size: .82rem; min-height: 1.2em; margin-top: .5rem; }
  .panel { border: 1px solid #2b3346; border-radius: .6rem; padding: .8rem; margin-top: 1rem; background: #141924; }
  .bar { height: .5rem; background: #232a3a; border-radius: 1rem; overflow: hidden; margin: .6rem 0; }
  .bar > i { display: block; height: 100%; width: 0; background: #3d6ce0; transition: width .3s; }
  .stats { display: grid; grid-template-columns: auto 1fr; gap: .2rem .8rem; font-size: .84rem; }
  .stats b { color: #8b93a7; font-weight: 400; }
  .out { margin-top: .3rem; }
  .kv { display: grid; grid-template-columns: 6.5rem 1fr; gap: .35rem .6rem; font-size: .84rem; align-items: start; }
  .kv b { color: #8b93a7; font-weight: 400; }
  .kv span { word-break: break-all; color: #a8e6a3; }
  .warn { border-left: 3px solid #d8a13a; padding: .5rem .7rem; background: #221d12; color: #e8d5a8;
          font-size: .8rem; border-radius: .3rem; margin-top: .8rem; }
  .addr { font-size: .95rem; }
  details { margin-top: .8rem; }
  summary { cursor: pointer; color: #8b93a7; font-size: .8rem; }
  table { width: 100%; border-collapse: collapse; font-size: .8rem; margin-top: .4rem; }
  td { padding: .25rem .4rem; border-bottom: 1px solid #232a3a; }
  td:last-child { text-align: right; color: #8b93a7; }
  .dim { color: #6f7789; }
</style>
</head>
<body>
<h1>nano-vanity</h1>
<div class="sub">Nano (XNO) and Qubic (Q) vanity generator &middot; runs on this device</div>

<form id="form" autocomplete="off">
  <div class="field">
    <label for="chain">Chain</label>
    <select id="chain">
      <option value="nano">Nano (XNO) &mdash; nano_ addresses</option>
      <option value="qubic">Qubic (Q) &mdash; 60-letter identities</option>
    </select>
    <div class="hint" id="chain-hint"></div>
  </div>
  <div class="field">
    <label for="prefix">Address prefix</label>
    <div class="row" style="gap:.5rem;align-items:flex-end">
      <div style="flex:1">
        <label for="prefix">Pattern</label>
        <input id="prefix" placeholder="1111" spellcheck="false" value="1111">
      </div>
      <div style="flex:0 0 9.5rem">
        <label for="mode">Match</label>
        <select id="mode">
          <option value="prefix">starts with</option>
          <option value="suffix">ends with</option>
          <option value="contains">contains</option>
        </select>
      </div>
    </div>
    <div class="hint" id="prefix-hint"></div>
    <label class="check" id="skipfirst-row" for="skipfirst">
      <input type="checkbox" id="skipfirst"> Ignore the leading <code>1</code>/<code>3</code>
    </label>
    <div class="hint" id="skipfirst-hint"></div>
  </div>
  <details>
    <summary>Advanced</summary>
    <div class="field" style="margin-top:.6rem">
      <label for="threads">Threads</label>
      <input id="threads" type="number" min="1" max="64" placeholder="all cores">
    </div>
    <div class="field">
      <label for="seconds">Time limit (seconds, optional)</label>
      <input id="seconds" type="number" min="1" placeholder="none">
    </div>
    <div class="field">
      <label for="count">How many addresses</label>
      <input id="count" type="number" min="1" max="1000" value="1">
      <div class="hint">Collects the N lowest matches for the seed. The last one
      sets how long the search runs.</div>
    </div>
    <div class="field" id="grind-field">
      <label for="grind">Search seeds (vanity on account 0)</label>
      <label class="check"><input id="grind" type="checkbox"> Grind candidate seeds instead of one
      seed's indices. This is what puts the vanity address on account 0, so importing
      the seed is the whole job.</label>
    </div>
    <div class="field" id="seedindex-field">
      <label for="seedindex">Account index for ground seeds</label>
      <input id="seedindex" type="number" min="0" value="0" disabled>
      <div class="hint">Used only with the box above. 0 means the vanity address is the wallet's
      first account.</div>
    </div>
    <div class="field" id="maxindex-field">
      <label for="maxindex">Max account index (optional)</label>
      <input id="maxindex" type="number" min="1" placeholder="no limit">
      <div class="hint">Optional ceiling on the search. Your seed can derive any account
      index from 0 to 4294967295, and Nault restores a high index directly by
      typing it in — you do not have to create the accounts before it. Set this
      only to make the search finish sooner.</div>
    </div>
    <div class="field" id="qubic-only" style="display:none">
      <div class="hint" style="border:1px solid #b45309;border-radius:.4rem;padding:.6rem;
           background:#1c1408;color:#fcd9a0">
        <strong>A Qubic seed is the wallet.</strong> Qubic has no account index, so a
        55-letter seed maps to exactly one identity, forever. Every search varies the
        seed, and whatever this tool finds <em>is</em> the wallet &mdash; there is
        nothing else to recover from it. Write the seed down before using the identity.
      </div>
    </div>
    <div class="field">
      <label for="seed" id="seed-label">Seed (optional)</label>
      <input id="seed" placeholder="random" spellcheck="false">
      <div class="hint" id="seed-hint">Leave empty for a fresh random seed each run. Paste a seed from an
      earlier result to reproduce those exact addresses.</div>
    </div>
  </details>
  <div class="row" style="margin-top:.75rem">
    <button id="go" type="submit">Generate</button>
    <button id="stop" type="button" class="ghost" disabled>Cancel</button>
  </div>
  <div class="err" id="err"></div>
</form>

<div class="panel" id="progress" hidden>
  <div class="stats">
    <b>prefix</b><span id="p-prefix">—</span>
    <b>tries</b><span id="p-tries">—</span>
    <b>elapsed</b><span id="p-elapsed">—</span>
    <b>speed</b><span id="p-rate">—</span>
  </div>
  <div class="bar"><i id="p-bar"></i></div>
  <div class="hint" id="p-eta"></div>
</div>

<div class="panel" id="result" hidden>
  <div class="hint" id="r-title"></div>
  <div class="out" id="r-list"></div>
  <div class="kv" style="margin-top:.7rem">
    <b>wallet seed</b><span id="r-seed"></span>
  </div>
  <div class="row" style="margin-top:.7rem">
    <button type="button" class="ghost" onclick="copyAll('address')">Copy all addresses</button>
    <button type="button" class="ghost" onclick="copyAll('private_key')">Copy all keys</button>
  </div>
  <div class="warn">
    Verify this address in a wallet before receiving funds. Restore it with
    the seed plus the printed account index — Nault can access any index
    directly, so you do not need to create the accounts before it. The private
    key also works on its own. Never paste a seed or private key into a site
    you do not control.
  </div>
</div>

<div class="panel">
  <div style="font-size:.8rem;color:#8b93a7">Expected work</div>
  <table>
    <tr><td>1111</td><td>~6.6e4 tries · ~1s</td></tr>
    <tr><td>11111</td><td>~2.1e6 tries · ~35s</td></tr>
    <tr><td>111111</td><td>~6.7e7 tries · ~18min</td></tr>
    <tr><td>1111111</td><td>~2.1e9 tries · ~10h</td></tr>
  </table>
  <div class="hint">Times are rough, at ~60k addr/s on a mid-range phone.</div>
</div>

<script>
let jobId = null, timer = null;

const $ = (id) => document.getElementById(id);

function nfmt(n) { return n.toLocaleString('en-US'); }
function dur(s) {
  if (s < 60) return s.toFixed(1) + 's';
  const m = Math.floor(s / 60), sec = Math.floor(s % 60);
  if (m < 60) return m + 'm ' + sec + 's';
  return Math.floor(m / 60) + 'h ' + (m % 60) + 'm';
}

function busy(on) {
  $('go').disabled = on;
  $('stop').disabled = !on;
}

function err(msg) { $('err').textContent = msg || ''; }

// The seed-index box only means something while grinding seeds, so grey it out
// rather than letting someone set an index that will be ignored.
$('grind').addEventListener('change', () => {
  $('seedindex').disabled = !$('grind').checked;
  $('maxindex').disabled = $('grind').checked;
});

async function start(ev) {
  ev.preventDefault();
  // Always clear the previous poller first. Submitting the form with Enter
  // bypasses the disabled Generate button, so this path is reachable while a
  // job is still running; without this the old setInterval is orphaned and
  // never stops.
  if (timer !== null) stopPolling();
  err('');
  $('result').hidden = true;
  const prefix = $('prefix').value.trim();
  if (!prefix) { err(chainName() === 'Qubic' ? 'Enter a pattern.' : 'Enter a prefix.'); return; }

  const body = { prefix, chain: $('chain').value };
  if ($('threads').value) body.threads = parseInt($('threads').value, 10);
  if ($('seconds').value) body.seconds = parseInt($('seconds').value, 10);
  body.mode = $('mode').value;
  if ($('maxindex').value) body.max_index = parseInt($('maxindex').value, 10);
  if ($('grind').checked) {
    body.grind = 'true';
    body.seed_index = parseInt($('seedindex').value || '0', 10);
  }
  if ($('seed').value.trim()) body.seed = $('seed').value.trim();
  if ($('count').value) body.count = parseInt($('count').value, 10);
  if ($('skipfirst').checked) body.skip_first = 'true';

  try {
    const res = await fetch('/api/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const data = await res.json();
    if (!res.ok) {
      busy(false);
      err(data.error || 'Failed to start.');
      return;
    }
    jobId = data.id;
    tickFails = 0;
    busy(true);
    $('progress').hidden = false;
    scheduleTick(0);
  } catch (e) {
    stopPolling();
    busy(false);
    err('Request failed: ' + e.message);
  }
}

async function tick() {
  if (jobId === null) return;
  let data;
  try {
    const res = await fetch('/api/status?id=' + jobId);
    data = await res.json();
    if (!res.ok) {
      // Release the UI as well as the poller. Skipping busy(false) here left
      // Generate permanently disabled, which is what looked like "stuck".
      stopPolling();
      busy(false);
      $('progress').hidden = true;
      err(data.error || 'Lost the job.');
      return;
    }
  } catch (e) {
    // A blip should not end the job, but an endless silent retry looks like a
    // freeze. Count consecutive failures and bail out visibly.
    tickFails = (tickFails || 0) + 1;
    if (tickFails >= 4) {
      stopPolling();
      busy(false);
      $('progress').hidden = true;
      // Say what actually failed. Blaming the server was wrong: the usual
      // cause is the device being saturated by the search itself.
      err('Could not reach the server after ' + tickFails +
          ' attempts (' + (e && e.message ? e.message : 'network error') +
          '). The search is saturating all cores, which can starve the UI.');
    }
    return;
  }
  tickFails = 0;

  $('p-prefix').textContent = data.prefix;
  $('p-tries').textContent = nfmt(data.tries) + ' / ~' + nfmt(data.expected);
  $('p-elapsed').textContent = dur(data.elapsed);
  $('p-rate').textContent = nfmt(data.rate) + ' addr/s';
  $('p-bar').style.width = Math.min(100, data.progress * 100).toFixed(2) + '%';

  if (data.state === 'running') {
    // Show matches as they are found instead of holding every one back until the
  // search ends. The API sends them on every poll, marked `partial`, so a
  // two-hour search shows its first result the minute it turns up rather than an
  // empty screen. Re-rendering each poll is fine: the list only grows, or swaps
  // a higher attempt for a lower one that was found later.
  if (data.partial && (data.results || []).length) {
    lastResults = data.results;
    renderCards(data.results, data);
    $('r-seed').textContent = '';
    $('r-title').textContent =
      'Found ' + data.results.length + ' so far, still searching\u2026';
    $('result').hidden = false;
  }
  const remaining = Math.max(0, data.expected - data.tries);
    $('p-eta').textContent = data.rate > 0
      ? 'expected total ~' + dur(data.expected / data.rate) + ' · ~' + dur(remaining / data.rate) + ' to go'
      : '';
    return;
  }

  stopPolling();
  busy(false);
  $('progress').hidden = true;

  if (data.state === 'found') {
    // Render every result; the API returns a list even when a single address
    // was asked for, so there is only one code path here.
    const results = data.results || [];
    lastResults = results;
    $('r-seed').textContent = data.seed || '';
    renderCards(results, data);
    let title = results.length === 1
      ? 'Found 1 address.'
      : 'Found ' + results.length + ' addresses.';
    if (results.length < (data.want || 1)) {
      title += ' Wanted ' + data.want + ' — raise the time limit for more.';
    }
    if (data.chain === 'qubic') {
      // The single most important sentence the tool can say about a Qubic hit.
      // There is no account index to fall back on, so the seed is the whole
      // wallet and losing it loses the identity permanently.
      title += ' The seed above is the entire wallet: Qubic has no account index, ' +
        'so write it down before using the identity.';
    } else {
      // A high account index means the seed cannot restore the address without
      // walking every earlier account, so say so instead of implying it can.
      const highest = Math.max.apply(null, results.map(r => r.index));
      if (highest > 1000) {
        title += ' Import the PRIVATE KEY, not the seed: reaching account ' +
          highest + ' would mean adding ' + highest +
          ' accounts first. Set "Max account index" to get a reachable one.';
      }
    }
    $('r-title').textContent = title;
    $('result').hidden = false;
    $('result').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  } else {
    // Say which of the three reasons actually applied.
    const WHY = {
      capped: 'The Max account index was smaller than this pattern needs. ' +
              'Raise it, or clear the box to search the whole seed.',
      timeout: 'The time limit ran out first. Raise it, or use a shorter pattern.',
      exhausted: 'Searched the whole 2^32 index space. A match this long is ' +
                 'unlikely from one seed — try a shorter pattern.'
    };
    err('No match found. ' + (WHY[data.why] || WHY.exhausted));
  }
}

// Builds the result cards. Shared by the finished and in-progress paths, so a
// live match is displayed exactly the way a final one will be.
function renderCards(results, data) {
  $('r-list').textContent = '';
  results.forEach(function (r, i) {
    const card = document.createElement('div');
    card.className = 'kv';
    const add = function (label, value, cls) {
      const b = document.createElement('b');
      b.textContent = label;
      const s = document.createElement('span');
      s.textContent = value;
      if (cls) { s.className = cls; }
      card.appendChild(b);
      card.appendChild(s);
    };
    add(results.length > 1 ? '#' + (i + 1) + ' address' : 'address', r.address, 'addr');
    add('private key', r.private_key);
    // A Qubic result has no account index and carries its own seed, which is
    // the wallet. Showing "account index: null" would be worse than showing the
    // field that actually matters.
    if (data.chain === 'qubic') {
      add('seed \u2014 this IS the wallet', r.seed, 'seed');
    } else {
      add('account index', r.index);
    }
    $('r-list').appendChild(card);
  });
}

function stopPolling() {
  if (timer !== null) { clearTimeout(timer); timer = null; }
  jobId = null;
}

// Self-chaining poll. setInterval(tick, 500) fires a new request every 500ms
// even while the previous one is still waiting, and while the search saturates
// every core the server can be slower than that. The requests then queue and
// eventually the browser aborts them, which showed up as the UI claiming the
// server had gone away. Chaining guarantees exactly one request in flight.
function scheduleTick(delay) {
  if (timer !== null) clearTimeout(timer);
  timer = setTimeout(async () => {
    await tick();
    if (jobId !== null) scheduleTick(500);
  }, delay);
}

async function cancel() {
  // Always release the controls, even if there is nothing to cancel, so a
  // stray click can never leave the button disabled.
  busy(false);
  if (jobId === null) return;
  const id = jobId;
  stopPolling();
  busy(false);
  $('progress').hidden = true;
  try {
    await fetch('/api/cancel', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id })
    });
  } catch (e) { /* server may already be gone */ }
}

function copy(id) {
  const text = $(id).textContent;
  navigator.clipboard.writeText(text).then(
    () => { err(''); flash(id); },
    () => err('Copy failed — select the text manually.')
  );
}

// Copies one field of every result, newline separated. Keeping the results in
// a JS array avoids having to scrape them back out of the DOM.
let lastResults = [];
function copyAll(field) {
  if (!lastResults.length) return;
  const text = lastResults.map(r => r[field]).join('\n');
  navigator.clipboard.writeText(text).then(
    () => { err(''); flash('r-list'); },
    () => err('Copy failed — select the text manually.')
  );
}

function flash(id) {
  const el = $(id);
  const old = el.style.color;
  el.style.color = '#fff';
  setTimeout(() => { el.style.color = old; }, 250);
}

// Keep the help text honest about what the selected mode will actually do.
//
// The Nano hints describe a `nano_` address body: a `1`/`3` anchor, and a
// checksum occupying the last 8 characters. None of that applies to a Qubic
// identity, which is 56 base-26 characters plus 4 checksum characters and has
// no anchored leading character, so the two chains get their own hint tables
// rather than one table with branches in the text.
const NANO_HINTS = {
  prefix: {
    main: 'Must start with <code>1</code> or <code>3</code>. Up to 12 characters.',
    skip: 'Match from the <em>second</em> character, so <code>test</code> finds ' +
          '<code>nano_1test…</code> <em>or</em> <code>nano_3test…</code>. ' +
          'Cheaper, since pinning the first character costs a factor of ~2.'
  },
  suffix: {
    main: 'The last 8 characters are the checksum, so this is checked against the ' +
          'real address, not just the key.',
    skip: null
  },
  contains: {
    main: 'Matches anywhere in the address. Roughly 60x likelier per character, ' +
          'because there are 60 positions to land in.',
    skip: null
  }
};

const QUBIC_HINTS = {
  prefix: {
    main: 'Letters <code>A</code>&ndash;<code>Z</code> against the 60-character identity. ' +
          'The first character tracks the <em>low</em> bits of the public key, ' +
          'not the high ones.',
    skip: null
  },
  suffix: {
    main: 'The last 4 characters are a K12 checksum, so this is checked against ' +
          'the real identity rather than just the key.',
    skip: null
  },
  contains: {
    main: 'Matches anywhere in the 60-character identity, so roughly 60x likelier ' +
          'per character than a prefix.',
    skip: null
  }
};

const CHAIN_HINTS = {
  nano: 'One 64-hex seed. The search scans that seed\'s account indices, so the ' +
        'seed is reusable and the result is not the whole wallet.',
  qubic: 'A 55-letter lowercase seed. There is no account index, so the search ' +
         'varies the seed itself and a found seed <em>is</em> the wallet. ' +
         'FourQ costs about 2.4x a Nano candidate per unit of matching, so ' +
         'prefer <code>contains</code> or <code>suffix</code> over a long prefix.'
};

function chainName() {
  return $('chain').value === 'qubic' ? 'Qubic' : 'Nano';
}

function syncChain() {
  const q = $('chain').value === 'qubic';
  $('chain-hint').innerHTML = CHAIN_HINTS[$('chain').value] || '';

  // These four are Nano-only. They are hidden rather than disabled: a visible
  // greyed-out field invites the question of why it stopped working, and the
  // server rejects them outright anyway, so hiding is the honest signal.
  $('grind-field').style.display = q ? 'none' : '';
  $('seedindex-field').style.display = q ? 'none' : '';
  $('maxindex-field').style.display = q ? 'none' : '';
  $('qubic-only').style.display = q ? '' : 'none';

  // The leading-character trick is a Nano concept. On Qubic, `identity[0]`
  // already varies uniformly, so there is no factor-of-2 saving to be had and
  // the row is hidden for both prefix and non-prefix modes.
  $('skipfirst-row').style.display = q ? 'none' : '';
  $('skipfirst').checked = false;

  $('prefix').placeholder = q ? 'AB' : '1111';
  if (q) $('prefix').value = ($('prefix').value || '').toUpperCase();
  $('seed-label').textContent = q ? 'Master seed (optional)' : 'Seed (optional)';
  $('seed').placeholder = q ? 'random' : 'random';
  $('seed-hint').innerHTML = q
    ? 'Leave empty for a fresh random master seed each run. On Qubic this seeds ' +
      'the <em>candidate stream</em>, not the result: each match reports the ' +
      '55-letter seed that worked, and that seed is the wallet.'
    : 'Leave empty for a fresh random seed each run. Paste a seed from an ' +
      'earlier result to reproduce those exact addresses.';

  // Counts read very differently between the chains, so say so where the user
  // sets the number rather than leaving them to discover it from a wait.
  $('count').parentElement.querySelector('.hint').innerHTML = q
    ? 'Collects the N lowest matching candidates. Qubic is about 2.4x slower per ' +
      'candidate than Nano, so a 4-character prefix is a multi-day search even on ' +
      'every core.'
    : 'Collects the N lowest matches for the seed. The last one sets how long the ' +
      'search runs.';

  syncHints();
}

function syncHints() {
  const table = $('chain').value === 'qubic' ? QUBIC_HINTS : NANO_HINTS;
  const h = table[$('mode').value] || table.prefix;
  $('prefix-hint').innerHTML = h.main;
  const q = $('chain').value === 'qubic';
  const isPrefix = $('mode').value === 'prefix';
  // The leading-character trick only means something for a Nano prefix.
  $('skipfirst-row').style.display = (isPrefix && !q) ? '' : 'none';
  $('skipfirst').disabled = !isPrefix || q;
  $('skipfirst-hint').innerHTML = (isPrefix && !q) ? (h.skip || '') : '';
}

$('mode').addEventListener('change', syncHints);
$('chain').addEventListener('change', syncChain);
// The starting chain comes from `--chain` on the command line, so the UI opens
// on whichever chain the user actually launched the tool for.
$('chain').value = 'CHAIN_PLACEHOLDER';
syncChain();

$('form').addEventListener('submit', start);
$('stop').addEventListener('click', cancel);
</script>
</body>
</html>
"##;
#[cfg(test)]
mod tests {
    use super::*;
    use nano_keys::MatchMode;
    use std::time::Duration;

    /// Fixed seed so reproducibility tests compare like with like.
    const TEST_SEED: [u8; 32] = [0x5a; 32];

    /// The same prefix must always produce the same address.
    ///
    /// Regression test for a real defect: the engine used to fan out over rayon
    /// with `find_map_any`, so it returned whichever worker finished first. The
    /// prefix, account index, private key and try-count all changed from run to
    /// run, which made a result impossible to re-verify. The search now always
    /// returns the lowest matching index.
    ///
    /// Thread count is varied on purpose: the answer must depend on the prefix
    /// alone, not on how many workers happened to be running.
    #[test]
    fn search_is_deterministic_across_runs_and_thread_counts() {
        for prefix in ["1", "11", "1f"] {
            let mut seen: Option<(u32, String, u64)> = None;
            for threads in [1usize, 2, 8] {
                let job = Job::start(
                    prefix.to_string(),
                    threads,
                    Some(60),
                    TEST_SEED,
                    1,
                    false,
                    MatchMode::Prefix,
                    None,
                )
                .unwrap();
                let found = match job.wait_timeout(Duration::from_secs(90)) {
                    Some(Outcome::Found(f)) => f,
                    _ => panic!("no match for {prefix} on {threads} threads"),
                };
                let first = found[0].clone();
                let got = (first.index, first.address.clone(), job.tries());
                let index = got.0;
                let address = got.1.clone();
                let tries = got.2;
                match &seen {
                    None => seen = Some(got),
                    Some(first) => assert_eq!(
                        &got, first,
                        "{prefix}: run on {threads} threads disagreed with the first run"
                    ),
                }
                // tries must be exactly the first matching index plus one.
                assert_eq!(
                    index as u64 + 1,
                    tries,
                    "{prefix}: reported tries should be index + 1"
                );
                assert!(address.starts_with(&format!("nano_{prefix}")));
            }
        }
    }

    /// The result must equal what a plain sequential scan would find.
    ///
    /// This pins "lowest matching index" to an independent, obviously-correct
    /// reference implementation rather than to the engine's own behaviour.
    #[test]
    fn result_matches_a_sequential_scan() {
        let prefix = "1f";
        let matcher = nano_keys::PrefixMatcher::new(prefix).unwrap();
        // Must be the same seed the job below uses, or the two searches are
        // looking at different key spaces.
        let seed = TEST_SEED;

        let expected_index = (0u64..5_000_000)
            .map(|i| i as u32)
            .find(|&i| {
                let pk = nano_keys::private_key_to_public(&nano_keys::derive_private_key(&seed, i));
                matcher.matches(&pk)
            })
            .expect("a 1f match should appear well within 5M indices");

        let job = Job::start(
            prefix.to_string(),
            8,
            Some(60),
            TEST_SEED,
            1,
            false,
            MatchMode::Prefix,
            None,
        )
        .unwrap();
        let found = match job.wait_timeout(Duration::from_secs(90)) {
            Some(Outcome::Found(f)) => f,
            _ => panic!("engine found no match for {prefix}"),
        };
        let first = &found[0];

        assert_eq!(
            first.index, expected_index,
            "engine returned index {} but the lowest match is {expected_index}",
            first.index
        );
        assert_eq!(job.tries(), expected_index as u64 + 1);
        // And the printed key really does drive the printed address.
        assert_eq!(
            nano_keys::seed_to_address(&TEST_SEED, first.index),
            first.address
        );
    }

    #[test]
    fn index_html_version_placeholder_is_present_and_rendered() {
        // The launcher and the browser both use this marker to tell a current
        // server from a stale one holding the port. If the placeholder were
        // dropped from the template, the substitution would silently do
        // nothing and every server would look current.
        assert!(
            INDEX_HTML.contains("VERSION_PLACEHOLDER"),
            "INDEX_HTML must keep the version placeholder"
        );
        let rendered = INDEX_HTML.replace("VERSION_PLACEHOLDER", env!("CARGO_PKG_VERSION"));
        assert!(!rendered.contains("VERSION_PLACEHOLDER"));
        assert!(rendered.contains(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn version_endpoint_reports_name_and_version() {
        // Exercised over a real socket so the route table itself is covered,
        // not just the string formatting.
        let addr = spawn_test_server();
        let body = http_get(addr, "/api/version");
        assert!(body.contains("\"name\":\"nano-vanity\""), "got: {body}");
        assert!(
            body.contains(env!("CARGO_PKG_VERSION")),
            "version missing from {body}"
        );
    }

    #[test]
    fn index_reports_the_version_marker() {
        let addr = spawn_test_server();
        let body = http_get(addr, "/");
        assert!(
            body.contains(&format!(
                "nano-vanity-version\" content=\"{}\"",
                env!("CARGO_PKG_VERSION")
            )),
            "index page did not carry the version marker"
        );
        assert!(!body.contains("VERSION_PLACEHOLDER"));
    }

    /// Every status response must be valid JSON, in every state.
    ///
    /// Regression: the "exhausted" arm ended with a trailing comma, producing
    /// `..."why":"capped",}`. The browser's `JSON.parse` rejects that, so every
    /// capped or timed-out search threw and the UI reported the server as
    /// unreachable while it was answering perfectly. A hand-rolled serialiser
    /// needs its output actually parsed, not just eyeballed.
    #[test]
    fn status_json_is_valid_in_every_state() {
        // running
        let job = Job::start(
            "111111111111".into(),
            1,
            None,
            [7u8; 32],
            1,
            false,
            MatchMode::Prefix,
            None,
        )
        .unwrap();
        assert_json_ok(&status_json(&job), "running");

        // found
        // 1 thread and a cap of 100. What is under test is that the status
        // payload is valid JSON in the "found" state, not that a 1,000-index
        // scan succeeds, so a tenth of the indices and no parallelism is
        // plenty. Thread-count independence has its own test.
        let done = Job::start(
            "11".into(),
            1,
            Some(30),
            [7u8; 32],
            1,
            false,
            MatchMode::Prefix,
            Some(100),
        )
        .unwrap();
        done.wait_timeout(Duration::from_secs(60))
            .expect("should finish");
        assert_json_ok(&status_json(&done), "found");

        // Exhausted, covering the variants that can actually occur.
        //
        // There is deliberately no "no cap, no time limit" case. That would
        // mean scanning the whole 2^32 index space, which no test can reach, so
        // in practice every uncapped run ends in the time limit below and this
        // loop would duplicate it -- while burning its entire limit grinding a
        // pattern long enough to be unfindable. It was 30 of the suite's 33
        // seconds for zero extra coverage.
        for (label, max_index, limit) in [
            ("capped", Some(50u32), Some(30)),
            ("timeout", None, Some(1)),
        ] {
            let j = Job::start(
                "1fadgi".into(),
                2,
                limit,
                [7u8; 32],
                1,
                false,
                MatchMode::Prefix,
                max_index,
            )
            .unwrap();
            j.wait_timeout(Duration::from_secs(90))
                .expect("should finish");
            assert_json_ok(&status_json(&j), label);
        }
    }

    fn assert_json_ok(body: &str, label: &str) {
        if let Err(e) = MiniJson::parse_document(body) {
            panic!("{label}: response is not valid JSON: {e}\n  body: {body}");
        }
    }

    /// A deliberately strict, minimal JSON parser.
    ///
    /// Strict in exactly the ways that matter here: property names must be
    /// double-quoted, and no trailing commas. There is no JSON dependency in
    /// this crate, and adding one to test a serialiser would be silly, so the
    /// test parses the output itself. The error strings mirror the browser's so
    /// a failure reads the same as the user's report.
    struct MiniJson {
        b: Vec<char>,
        i: usize,
    }

    impl MiniJson {
        fn parse_document(s: &str) -> Result<(), String> {
            let mut p = MiniJson {
                b: s.chars().collect(),
                i: 0,
            };
            p.value()?;
            p.ws();
            if p.i != p.b.len() {
                return Err(format!("trailing data at column {}", p.i + 1));
            }
            Ok(())
        }

        fn ws(&mut self) {
            while self.i < self.b.len() && self.b[self.i].is_whitespace() {
                self.i += 1;
            }
        }

        fn at(&self) -> Result<char, String> {
            self.b
                .get(self.i)
                .copied()
                .ok_or_else(|| "unexpected end of input".to_string())
        }

        fn value(&mut self) -> Result<(), String> {
            self.ws();
            match self.b.get(self.i) {
                Some('{') => self.object(),
                Some('[') => self.array(),
                Some('"') => self.string(),
                Some('t') => self.lit("true"),
                Some('f') => self.lit("false"),
                Some('n') => self.lit("null"),
                Some(c) if *c == '-' || c.is_ascii_digit() => self.number(),
                Some(c) => Err(format!("unexpected {c:?} at column {}", self.i + 1)),
                None => Err("unexpected end of input".into()),
            }
        }

        fn object(&mut self) -> Result<(), String> {
            self.i += 1;
            self.ws();
            if self.b.get(self.i) == Some(&'}') {
                self.i += 1;
                return Ok(());
            }
            loop {
                self.ws();
                if self.at()? != '"' {
                    return Err(format!(
                        "expected double-quoted property name at column {}",
                        self.i + 1
                    ));
                }
                self.string()?;
                self.ws();
                if self.at()? != ':' {
                    return Err(format!("expected ':' at column {}", self.i + 1));
                }
                self.i += 1;
                self.value()?;
                self.ws();
                match self.b.get(self.i) {
                    Some(',') => self.i += 1,
                    Some('}') => {
                        self.i += 1;
                        return Ok(());
                    }
                    other => {
                        return Err(format!(
                            "expected ',' or '}}' at column {}, found {other:?}",
                            self.i + 1
                        ))
                    }
                }
            }
        }

        fn array(&mut self) -> Result<(), String> {
            self.i += 1;
            self.ws();
            if self.b.get(self.i) == Some(&']') {
                self.i += 1;
                return Ok(());
            }
            loop {
                self.value()?;
                self.ws();
                match self.b.get(self.i) {
                    Some(',') => self.i += 1,
                    Some(']') => {
                        self.i += 1;
                        return Ok(());
                    }
                    other => {
                        return Err(format!(
                            "expected ',' or ']' at column {}, found {other:?}",
                            self.i + 1
                        ))
                    }
                }
            }
        }

        fn string(&mut self) -> Result<(), String> {
            self.i += 1;
            loop {
                match self.at()? {
                    '"' => {
                        self.i += 1;
                        return Ok(());
                    }
                    '\\' => self.i += 2,
                    c => {
                        if (c as u32) < 0x20 {
                            return Err(format!(
                                "raw control char in string at column {}",
                                self.i + 1
                            ));
                        }
                        self.i += 1;
                    }
                }
            }
        }

        fn number(&mut self) -> Result<(), String> {
            if self.b.get(self.i) == Some(&'-') {
                self.i += 1;
            }
            while matches!(self.b.get(self.i), Some(c) if c.is_ascii_digit()) {
                self.i += 1;
            }
            if self.b.get(self.i) == Some(&'.') {
                self.i += 1;
                while matches!(self.b.get(self.i), Some(c) if c.is_ascii_digit()) {
                    self.i += 1;
                }
            }
            Ok(())
        }

        fn lit(&mut self, word: &str) -> Result<(), String> {
            for c in word.chars() {
                if self.at()? != c {
                    return Err(format!("bad literal at column {}", self.i + 1));
                }
                self.i += 1;
            }
            Ok(())
        }
    }

    #[test]
    fn unknown_routes_are_404() {
        let addr = spawn_test_server();
        assert!(http_get(addr, "/nope").contains("not found"));
        assert!(http_get(addr, "/api/status?id=99999").contains("unknown job"));
    }

    /// Start the web server on an ephemeral port and wait until it accepts.
    /// The server thread runs until the test process exits.
    fn spawn_test_server() -> std::net::SocketAddr {
        // Bind the listener here and hand it straight to the server, rather
        // than discovering a free port and racing to rebind it.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        // Detached on purpose: `serve` loops forever and the process exit
        // tears it down. Joining would hang the suite.
        std::thread::spawn(move || {
            let _ = super::serve_listener(listener);
        });
        for _ in 0..150 {
            if std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(50))
                .is_ok()
            {
                return addr;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        panic!("test server did not start");
    }

    /// Minimal HTTP/1.0 GET, returning the response body.
    fn http_get(addr: std::net::SocketAddr, path: &str) -> String {
        use std::io::{Read, Write};
        let mut s = std::net::TcpStream::connect(addr).unwrap();
        s.write_all(format!("GET {path} HTTP/1.0\r\nHost: x\r\n\r\n").as_bytes())
            .unwrap();
        let mut buf = String::new();
        s.read_to_string(&mut buf).unwrap();
        buf.split("\r\n\r\n").nth(1).unwrap_or("").to_string()
    }
}
