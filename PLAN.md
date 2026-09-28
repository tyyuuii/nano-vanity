# PLAN — GPU search mode for Android (Mali)

## Scope

This plan is **Android-only and Mali-specific**. The `gpu-test` branch exists
solely to explore GPU acceleration on mobile Mali GPUs; it is not a path
toward a cross-platform or desktop GPU backend, and it does not affect
`main`.

Consequences, settled up front:

- **No CI for the GPU path.** GitHub-hosted runners have no usable GPU, so
  every GPU test is manual, run on the phone. That is acceptable here because
  the target is one GPU family on one device.
- **`--gpu` is opt-in, never automatic.** An Android-only branch should not
  change default behaviour for anyone, and on an unknown device a silent
  fallback path is harder to reason about than an explicit flag.
- **Target is this device: Mali-G51 MP2** (Kirin 710). Field arithmetic that is
  subgroup-size-4 and `shader_int64`-free is written for it specifically.

## Context

`nano-vanity` currently derives roughly **64,000–67,500 addresses/s** on this
phone (measured, 8 threads). Profiling in `ERRATA.md` shows **~99.4% of that is
one operation**: the fixed-base Ed25519 scalar multiplication
(`scalar · B`) inside `private_scalar_to_public`.

That caps what the tool can do. At 67k/s a 5-character prefix takes ~31 s, a
6-character prefix ~17 minutes, and 7 characters ~9 hours. Anything longer is
impractical on a phone.

The goal is a GPU backend that does the scalar multiplication and nothing else,
so the per-candidate cost drops enough to make longer prefixes reachable.

**The hardware is the crux of this plan.** This is a Huawei Kirin 710
(`getprop ro.board.platform` → `kirin710`, board `STK-L21MDV`) with a
**dual-core Arm Mali-G51 MP2** (Bifrost, 2018), 4x Cortex-A73 @ 2.36 GHz plus
4x A53. Not a Snapdragon, and not a discrete GPU — there is no CUDA path.

A Mali-G51 MP2 is a plausible-but-unproven target: it has a 64-bit datapath per
core, subgroup size **4**, no guaranteed `shader_int64`, and a driver layer
where an integer-arithmetic bug produces *silently wrong but perfectly valid*
Nano addresses. That failure mode is the thing this plan is organised around.

Outcome: `--gpu` gives a real speedup, **or** we learn in one day that it cannot,
having spent one day.

---

## Approach

### The GPU boundary is one line of code

In `nano-vanity/src/engine.rs`, the inner loop currently does:

```rust
let private_key = nano_keys::derive_private_key(&wallet_seed, idx);  // Blake2b-256
let scalar      = expand_private_key(&private_key);                 // Blake2b-512 + clamp
let pk          = private_scalar_to_public(&scalar);                // <-- 99.4% of runtime
if pattern.matches(&pk, &mut scratch) { ... }
```

Only the third line moves to the GPU:

```
CPU                                        GPU
───                                        ───
wallet_seed, idx
private_key = Blake2b-256(...)         <1%  stays on CPU
scalar      = clamp(Blake2b-512(...))  <1%  stays on CPU
                                        scalar ──► scalar · B ──► compress y+sign
                                                  ◄── 32-byte public key
pattern.matches(&pk, &mut scratch)            stays on CPU
  └─ on match: enc52 + Blake2b-5 checksum, then re-derive on CPU
```

Everything above that — block claiming, the `Axis::Index`/`Axis::Seed` split,
`--grind`, `--max-index`, determinism, cancellation, result reporting — is
untouched. The GPU replaces a multiply, not the search.

### Non-negotiable correctness rule

> **Every GPU-produced public key is re-derived on the CPU with
> `curve25519-dalek` before it is ever compared or reported.**

This costs one scalar multiplication per *candidate examined*, which is
nothing — and it converts the worst possible failure (a wrong address that
looks valid) into a slower one. Combined with a bit-identical differential
gate in Phase 2, a driver bug becomes a loud test failure rather than a user's
lost funds.

### Sequencing: measure before building

The entire project is gated on a one-day measurement. Do not write the engine
until the number says the hardware is worth it.

---

## Files to modify

| File | Change | Phase |
|---|---|---|
| `nano-vanity/src/gpu/mod.rs` | **new** — Vulkan device, pipeline, dispatch | 3 |
| `nano-vanity/src/gpu/field.glsl` | **new** — 10-limb radix-2^25.5 field arithmetic | 2 |
| `nano-vanity/src/gpu/scalarmul.glsl` | **new** — fixed-base multiply + compress | 2 |
| `nano-vanity/src/gpu/spike.rs` | **new** — Phase 0 throughput benchmark | 0 |
| `nano-vanity/src/engine.rs` | add `--gpu` dispatch around `private_scalar_to_public` | 3 |
| `nano-vanity/src/main.rs` | add `--gpu`, `--gpu-selftest N` flags | 3 |
| `nano-vanity/Cargo.toml` | add `ash`, `naga`, `libc` (dev-gated) | 0 |
| `research/gpu_cross_check.py` | **new** — third-party oracle for GPU output | 4 |
| `README.md` | document `--gpu`, or record the negative result | 5 |

**`nano-keys/src/lib.rs` stays free of GPU code.** The derivation is verified
and shipped; this is a search-speed project, and mixing Vulkan into the crypto
crate would put an untestable dependency inside the part that must be trusted.

---

## Reuse

Everything needed already exists. No new crypto.

| Need | Reuse | Where |
|---|---|---|
| Field arithmetic reference | `clamp`, `expand_private_key` | `nano-keys/src/lib.rs:106,115` |
| Scalar → public key | `private_scalar_to_public` | `nano-keys/src/lib.rs:128` |
| Full CPU reference path | `private_key_to_public` | `nano-keys/src/lib.rs:136` |
| Seed → private key | `derive_private_key` | `nano-keys/src/lib.rs:78` |
| Bit-level prefix test | `Pattern::matches(&pk, &mut scratch)` | `nano-keys/src/lib.rs:1264` |
| **Ground truth for the encoder** | `Pattern::matches_reference(&pk)` | `nano-keys/src/lib.rs:1280` |
| Address encoding | `public_key_to_address` | `nano-keys/src/lib.rs:241` |
| 260-bit field rationale | the prefix offset fix | `ERRATA.md` §3 |
| Differential-test harness | existing structure | `research/cross_check.py` |
| Independent oracle | existing Python Ed25519 | `research/cross_check.py` (top of file) |

`matches_reference` is the important one. It recomputes the match against the
*encoded string* rather than raw bits, and the engine already uses it in a
`debug_assert!` at `engine.rs:254`. The GPU filter must be validated against
it, not against the bit comparison, because the bit comparison is the
optimised path and the encoded string is what users actually paste.

---

## Steps

### Phase 0 — Throughput spike *(1 day, gate)*

Answer one question: does this Mali-G51 have enough INT32 throughput to be
worth 3–5 weeks?

- [ ] `gpu/spike.rs`: Vulkan compute shader, branch-free INT32 FMA loop
      (`acc = acc * 1664525u + data[i]`) over a 64 KB buffer, known iteration
      count, no correctness requirement — pure throughput
- [ ] Same loop compiled for AArch64 NEON on the same phone, as the baseline
- [ ] `--gpu-selftest` reports both numbers and a ratio
- [ ] **Gate: GPU below ~5x one A73 core → stop.** A real field-arithmetic
      kernel will not close that gap. At ~20x or more → proceed.

This is the whole recommendation. It is cheap, and it converts a three-to-five
week bet into a one-day bet.

### Phase 1 — Field arithmetic on the GPU *(3–5 days, gate)*

- [ ] `field.glsl`: add, sub, mul, square in 10 limbs × 25.5 bits (dalek's
      representation, so the two can be diffed limb-for-limb)
- [ ] u32 splitting only — assume no `shader_int64`
- [ ] Validate the shader **offline on the laptop** via `naga`, against vectors
      exported from `nano-keys`, before the shader ever runs on the phone
- [ ] **Gate: field ops bit-identical to dalek**, including carry, borrow and
      top-limb edge cases

### Phase 2 — One scalar multiplication *(3–5 days, gate)*

- [ ] `scalarmul.glsl`: fixed-base comb table in a UBO, `workgroup_size = 64`
      (16 workgroups of a 4-wide subgroup)
- [ ] Compress to 32 bytes: y in little-endian, sign bit in the top bit
- [ ] **Gate: 10,000 random scalars, GPU output bit-identical to
      `curve25519-dalek`.** Not "close". Identical.
- [ ] **If this gate fails, abandon.** A sometimes-wrong GPU is worse than no
      GPU, because the wrongness is silent

### Phase 3 — Engine integration *(3–5 days)*

- [ ] `gpu/mod.rs`: `ash` device init, SPIR-V load via `naga`, descriptor
      sets, staging buffer, dispatch
- [ ] Buffer the batch: 10k–100k scalars in, 32 B each out (3.2 MB at 100k,
      negligible)
- [ ] `engine.rs`: replace the single `private_scalar_to_public` call
- [ ] Sweep workgroup size 32/64/128/256 and record the best
- [ ] `--gpu` opt-in, **automatic fallback to CPU** on any init/dispatch
      failure so a phone that cannot run it can still grind
- [ ] CPU re-derivation of every public key before comparison (the
      non-negotiable rule above)

### Phase 4 — Differential testing *(2–3 days, manual on-device)*

- [ ] `--gpu-selftest N`: N candidates on both backends, assert equality
- [ ] `research/gpu_cross_check.py`: third independent implementation, so a
      disagreement has three explanations rather than two
- [ ] Randomise seeds, indices, patterns, and all three `MatchMode`s
- [ ] Gate: matches on both backends agree over a long soak run
- [ ] All of it runs on the phone. No CI job: there is no GPU on the hosted
      runners, and adding one that never executes would be worse than none

### Phase 5 — Ship or record *(1 day)*

- [ ] If it works: document `--gpu` in `README.md` and `INSTALL.md` for
      Android, and rebuild the Termux release
- [ ] If it does not: record the **negative result** in `ERRATA.md` with the
      measured numbers. A measured "this GPU cannot do it" is a real result,
      and it stops the next person repeating the investigation

---

## Resolved decisions

| Question | Decision |
|---|---|
| Scope | Android-only, Mali-specific, on this branch. Not a route to a general GPU backend. |
| GPU testing | Manual, on the phone. No CI — hosted runners have no GPU. |
| Default behaviour | `--gpu` opt-in, never auto-detected. |
| Target | Mali-G51 MP2 (Kirin 710): subgroup size 4, no `shader_int64`. |
| Dependency budget | `ash` + `naga` allowed on this branch, behind `--gpu`. `main` keeps its three dependencies. |
| NEON alternative | Not now. Phase 0 measures a NEON baseline for the ratio, so the data decides whether NEON is the better follow-up. |

---

## Verification

**Phase 0 (the gate that matters):**
```sh
cargo run --release -- --gpu-selftest
# expect: GPU/A73 ratio printed; <5x means stop here
```

**Phase 2 (the gate that must not be soft):**
```sh
cargo run --release -- --gpu-selftest 10000
# expect: 10000/10000 public keys bit-identical to dalek
```

**End-to-end, once integrated:**
```sh
# same seed, --gpu and CPU, must return the same address
nano-vanity 1test --grind -s <seed> --gpu -q
nano-vanity 1test --grind -s <seed>        -q     # must be identical
```

**Throughput:**
```sh
nano-vanity 1fadizq -T 10 -t 8    # CPU baseline: ~64k addr/s
# compare against the same command with --gpu
```

**Correctness under the existing suite:**
- `cargo test --workspace` must stay green — it currently runs in ~3.3s
- `python3 research/cross_check.py` must stay `ALL PASS`
- A new CI job runs `--gpu-selftest` on a self-hosted ARM runner, or is
  documented as manual-only (GitHub's hosted runners have no usable GPU)

**GPU verification is manual, on the phone, by design.** `--gpu-selftest` is
run locally; no CI job is added, because a job that can never exercise a GPU
is theatre.

**Manual check on the phone:** run a real 5-character grind, import the
resulting seed into Nault, press "Add account", and confirm the account 0
address matches what was printed.

---

