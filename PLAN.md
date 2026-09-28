# PLAN — make the CPU fast enough to matter

> **Supersedes the GPU plan.** GPU acceleration on this device was measured and
> closed: see `ERRATA.md` §9. The Mali-G51 MP2 has no `shader_int64`, so a
> 32-bit-only field multiply costs 2–4x more integer ops than the CPU's, and
> the GPU measured 0.79x the whole 8-core CPU on raw op rate *before* that
> penalty. It lands at 0.20x–0.39x of break-even. One day of measurement
> saved three to five weeks of kernel work.

## Scope

Android-first, Termux, `aarch64-linux-android`. No new runtime dependencies
unless a step explicitly says otherwise. `main` stays correct and shipping at
every commit; this branch carries the optimisation work.

### The baseline drifts, and that constrains how we measure

The same binary on the same idle phone measured **64,000–67,500 addr/s** early
in this investigation and **53,600–54,900 addr/s** hours later. Nothing in the
code changed. Termux cannot read the thermal zones or the cpufreq governor, so
the cause cannot be confirmed, but the practical rule is unambiguous:

> **Always measure the baseline immediately before the optimised build, in the
> same session, and quote the pair.**

Never compare a number from one session against a number from another. An
optimisation that appears to give 1.24x against a stale 67k baseline may be
1.00x against the 54k measured five minutes earlier. The per-operation
microbenchmarks in `breakdown.rs` are far more stable than the end-to-end
address rate, and are the better signal; the address rate is the confirmation,
not the measurement.

## Context

The grinder runs at **~67,000 addr/s** on this phone (Huawei Kirin 710,
4x Cortex-A73 + 4x A53). Profiling says the Ed25519 fixed-base scalar
multiply is essentially all of it. The consequence is a ceiling on usefulness:

| Prefix | Tries | Time at 67k/s |
|---|---|---|
| `1test` (5) | 2.1e6 | 31 s |
| `1testi` (6) | 6.7e7 | 17 min |
| `1testio` (7) | 2.1e9 | 9 hours |

Every step in this plan is aimed at that multiply, and nothing is aimed at
anything else, because nothing else is measurable.

### What is already measured (`cargo run --release --example breakdown -p nano-keys`)

```
blake2b-512 (scalar expand)                 372.3 ns/op     0.5%
Scalar::from_bytes_mod_order                174.8 ns/op     0.2%
basepoint multiply (no compress)          62179.2 ns/op    78.5%
compress + to_bytes                       16482.8 ns/op    20.8%
                                          -----------
total                                     79209.1 ns/candidate
```

**The multiply is 78.5%.** Hashing and scalar reduction are together under 1%
and are not worth touching, no matter how convenient that would be.

### What is already closed

| Idea | Result | Verdict |
|---|---|---|
| Upgrade dalek 4.1.3 -> 5.0.0 | **1.000x**, bit-identical | No win. `Auto serial backend selection` and `maximum NAF window` change nothing on aarch64. |
| Expect the u32 backend to be the problem | dalek's build.rs already picks `Dalek64` on 64-bit targets | Hypothesis was wrong; do not retry. |
| Wider basepoint comb (43 vs 64 additions) | Constructor unreachable | `BasepointTable` and `mul_by_pow_2` are `pub(crate)`. Needs a vendored dalek fork. |

Do not re-run these. The benchmarks that proved them stay in the repo as
`dalek_ab.rs` and `table_ab.rs`.

## Approach

Three steps, cheapest first, each independently shippable and independently
measured. The plan deliberately front-loads a certain 1.25x before
committing to a 2–3 week NEON effort that might not pay off.

---

### Step 1 — Stop compressing in prefix mode *(1.25x, 1–2 days, certain)*

**The observation.** The Nano address body is a 260-bit value: 255 bits of the
Edwards **y** coordinate, then 1 bit holding the sign of **x**. That sign bit
is the *last* bit of the number, so it only ever affects a **suffix**.

A **prefix** is therefore determined entirely by the top bits of y. To test a
prefix we never need x, and never need `compress()` at all — which removes
the modular inversion *and* the square root, 20.8% of the loop.

Normalising y is a separate, much cheaper problem: the point is projective,
`y = Y/Z`, so we need one inversion per point. But `curve25519-dalek` exposes
`AffineNielsPoint::batch_invert`, which does n inversions with 1 inversion plus
3(n−1) multiplications instead of n separate exponentiations. Across a block
of 2048 candidates the inversion cost effectively disappears.

- [ ] Add `nano-keys::prefix_needs_only_y()` documenting the above, so the
      reasoning lives next to the code that depends on it
- [ ] Add a `derive_public_key_y` path that skips `compress()` and returns
      normalised y
- [ ] Batch-normalise each `BLOCK` of candidates in `engine.rs` via
      `batch_invert`, then match prefixes against the top bits of y
- [ ] **Keep `compress()` for suffix and contains modes** — those need the sign
      bit, so they are untouched and remain correct
- [ ] Gate: all 71 existing tests pass unchanged, and
      `python3 research/cross_check.py` still reports `ALL PASS`
- [ ] Add a test asserting the y-only path and the compress path agree on every
      published vector, for all three `MatchMode`s

**Expected:** 79.2 µs -> ~63.5 µs per candidate, 67k -> ~84k addr/s.

---

### Step 2 — Measure, then decide on NEON *(the decision, not the code)*

Step 1 leaves the multiply as 94% of the loop. After it lands, re-run
`breakdown.rs` and commit the new numbers before starting anything else. The
NEON decision should be made against measured post-Step-1 numbers, not these.

The prize is real: dalek's field arithmetic is generic 64-bit limb code with
no aarch64 vectorisation, and NLnet has an active project adding exactly this
(<https://nlnet.nl/project/curve25519-dalek/>). Expect 2–4x on the multiply if
it works.

- [ ] Re-measure and record the post-Step-1 breakdown in `ERRATA.md`
- [ ] **Do not start NEON yet.** Write the acceptance criteria first, below
- [ ] Check whether NLnet's implementation is published and usable before
      writing our own; a reviewed, benchmarked implementation beats a fresh
      hand-rolled one at identical cost

**Acceptance criteria for NEON, to be agreed before any code is written:**
1. Bit-identical to `curve25519-dalek` for 10,000 random scalars
2. Passes all 71 existing tests unchanged
3. `research/cross_check.py` still `ALL PASS`
4. Measured >1.5x on the multiply on this device, or it is not merged
5. Behind a feature flag, CPU fallback preserved, `main` unaffected until then

If NLnet's work is usable, criteria 1–4 are largely free. If we write our own,
budget 2–3 weeks and accept that it is the single riskiest thing in this plan.

---

### Step 3 — Only if Step 2 stalls: vendored dalek with a wider comb *(3–5 days)*

dalek 5.0 already implements radix-32/64/128/256 tables (52/43/37/33
additions against the default's 64). They are simply unreachable, because the
trait providing `create` is private.

Vendoring dalek to make one constructor public is a small diff against a large
maintenance and supply-chain commitment, and 480KB of table on a phone with a
small L2 may thrash anyway. That risk is why it is Step 3 and not Step 1.

- [ ] Only if Step 2 is abandoned: measure the radix-16 vs radix-64 tradeoff on
      this device *before* committing to the fork
- [ ] Reject if the table does not fit the L2 budget

---

## Files to modify

| File | Change | Step |
|---|---|---|
| `nano-keys/src/lib.rs` | y-only derivation, `batch_invert` normalisation, the doc that explains why | 1 |
| `nano-vanity/src/engine.rs` | batch-normalise per block; skip `compress()` in prefix mode | 1 |
| `nano-keys/examples/breakdown.rs` | keep, re-run after each step | all |
| `nano-keys/examples/dalek_ab.rs` | keep as the closed-question record | — |
| `nano-keys/examples/table_ab.rs` | keep as the closed-question record | — |
| `ERRATA.md` | new section: the CPU breakdown, with post-Step-1 numbers | 1, 2 |

## Reuse

| Need | Reuse | Where |
|---|---|---|
| Batch inversion | `AffineNielsPoint::batch_invert` | `curve25519-dalek`, already a dependency |
| Correct CPU reference for the new path | `private_scalar_to_public` | `nano-keys/src/lib.rs:128` |
| Bit-level prefix test | `Pattern::matches(&pk, &mut scratch)` | `nano-keys/src/lib.rs:1264` |
| Encoder ground truth | `Pattern::matches_reference(&pk)` | `nano-keys/src/lib.rs:1280` |
| Address encoding | `public_key_to_address` | `nano-keys/src/lib.rs:241` |
| Independent oracle | existing Python Ed25519 | `research/cross_check.py` |
| The 260-bit layout rationale | the prefix-offset fix | `ERRATA.md` §3 |
| Existing regression vectors | 38 + 33 tests | `nano-keys`, `nano-vanity` |

## Verification

**After Step 1:**
```sh
cargo test --workspace                      # 71 tests, must stay green
python3 research/cross_check.py             # must stay ALL PASS
cargo clippy --workspace --all-targets -- -D warnings
```

**Correctness of the y-only path specifically** — this is the part that could
be silently wrong, so it gets its own check: for every published vector and
all three `MatchMode`s, the y-only path and the existing `compress()` path must
produce identical *match decisions*, and identical addresses whenever a match
is reported. A `debug_assert!` in the engine, mirroring the existing one at
`engine.rs:254`, catches disagreement during the test suite rather than in
production.

**Throughput** — always the pair, same session:
```sh
nano-vanity 1fadizq -T 10 -t 8     # baseline: record this right now
# ... apply the change, rebuild ...
nano-vanity 1fadizq -T 10 -t 8     # after: compare against the line above
```
Also re-run `breakdown.rs` and commit the new per-operation numbers. A step
that does not beat its own baseline, measured in the same session, does not
merge.

**End-to-end sanity:** grind a real 5-character prefix, import the seed into
Nault, press "Add account", confirm the address matches what was printed.

## Notes carried forward

- The web UI, CLI, installer and releases keep working throughout. This plan
  changes no interface, only speed.
- `panic = "abort"` stays off; no measurable throughput was ever attributed to
  it, and the web server needs it off.
- Suffix and contains modes are **not** sped up by Step 1 and must not be
  reported as if they were. They keep `compress()`.
- `/tmp` does not exist in Termux. Scratch files go under the workspace.
