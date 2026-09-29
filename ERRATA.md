# Errata & Verification Notes

Every non-obvious claim in `NANO_VANITY_PLAN.md` was re-derived and checked
against real data. This file records *how* each fact was established, so the
corrected spec is auditable rather than asserted.

The probes live in `research/` (throwaway Python, kept for provenance).
The final word is `nano-keys/src/lib.rs`, whose tests pin all of it.

---

## 1. The original plan's derivation is wrong

The plan specified:

```
Blake2b-512(seed || index) -> take first 32 bytes -> clamp -> scalar · G
```

Both the hash *and* the structural role of the 32-byte value are wrong.

**How it was caught.** Implemented the plan's pipeline from scratch in pure
Python (including an independent Edwards-curve implementation, so no library
could hide the mistake) and ran the plan's own advertised test vector. It failed
immediately. Sweeping digest size × endianness × "use directly / expand again"
produced 16 combinations, none of which matched:

```
d64 little direct  addr=nano_1de7zdobrjucifn4exsh94nxpmf4cgncugy85snga5y987cdhak4k4qa4tqh   addrok=False
d64 little expand  addr=nano_15x6kp5y3shqwjgbdydk6rdtdzzxqbrgwfqxj8wm8ha1hdmabsgtq4ud7cnk addrok=False
d32 little direct  addr=nano_1iab87u3k7h1qnjscjt953a1ck5rrhh69crwhpb8mxrcgqh4fd79i99sef3t   addrok=False
d32 little expand  addr=nano_3i1aq1cchnmbn9x5rsbap8b15akfh7wj7pwskuzi7ahz8oq6cobd71i4aaq1   addrok=False
```

**The actual facts**, each confirmed against published vectors:

| Step | Correct behaviour | Evidence |
|---|---|---|
| seed → private key | `Blake2b-**256**(seed ‖ index.to_be_bytes())` | Reproduced `1f6feb5d…794e3e` exactly at index 0, and `7027958b…ce5bb` at index 1 |
| private key → scalar | `clamp(Blake2b-**512**(private_key)[0..32])` | `clamp(Blake2b-512(prv))·B` matched the published pubkey; the other three variants did not |
| scalar → public key | `scalar · B`, Ed25519 base point | All three published triples reproduce |
| `Scalar` reduction | `from_bytes_mod_order` BEFORE multiply | A clamped scalar is ≥ 2^254 > ℓ, and `s·B == (s mod ℓ)·B` because `B` has order ℓ |

The private key is an **Ed25519 seed**, i.e. it is hashed *again* (Blake2b-512),
and only then clamped. The original plan named this function
`seed_to_private_scalar`, which was a misnomer — it returns a private key, not a
scalar. It is now `seed_to_private_key`.

## 2. The checksum is Blake2b-**5**, not truncated Blake2b-256

The plan said `Blake2b-256(pk)[..5]` reversed. That is wrong, and non-obviously
so: **Blake2b's digest length is part of its parameter block**, so a 5-byte
Blake2b digest is a different computation, not a prefix of the 32-byte one.

**How it was caught.** With the 52-character body already matching published
addresses exactly, only the checksum differed. Ten candidate constructions were
tested against two real addresses; exactly one matched both:

```
d32[0:5]rev    pujya3np   <- the plan's method
d5rev          9emk8y1d   <<<< MATCH
d64[0:5]rev    7aqk7dmu
```

`d5rev` = `Blake2b-5(pubkey)` then reversed. The library now encodes that
digest directly and a test (`blake2b5_is_not_blake2b32_truncated`) asserts the
two constructions genuinely differ.

## 3. The address body is a 260-bit field — this caused a real bug

The plan called the public key field a "260-bit number (256 bits + 4 leading
zero bits)" in prose but then wrote the encoder with a manual 4-bit offset while
the checker used a 256-bit shift. Those are inconsistent, and the inconsistency
reached the grinder.

**Symptom.** The grinder found addresses, but a prefix of `1` was reported as a
non-match. A probe showed `m1=false` for a key whose address began with `1`,
while `n >> 251` over the key equalled `2`.

**Cause.** A prefix of `L` characters occupies bits `[260-5L, 260)` of the body
field. The matcher used `256-5L`, i.e. it compared against the *second* group.

**Fix and guard.** `BODY_BITS = 260`. Verified against published encodings:

```
L=1 body='1'  string=0     off260=0     match260=True   off256=11    match256=False
L=2 body='1p' string=22    off260=22    match260=True   off256=365   match256=False
L=8 body='1pu7p5n3' string=24534257281  off260=24534257281 match260=True
```

The regression test `prefix_offset_is_260_bit_not_256_bit` fails if anyone
reverts to a 256-bit offset.

### Consequence the plan missed: attempts are not `32^n`

Because character 0 carries only the public key's **top bit**, it is `1` or `3`.
So a prefix's expected cost is `2^(5L-4)`, not `32^L`:

| Prefix | Plan implied | Actual |
|---|---|---|
| `1` | 32 | 2 |
| `1111` | ~1.05e6 | ~6.55e4 |
| `111111` | ~1.07e9 | ~6.7e7 |

The plan's "4 chars ≈ 1M attempts" is off by 16x. The tool now reports
`expected_tries()` from the real model, and rejects prefixes whose first
character is not `1` or `3` (no such address can exist) with exit code 2.

## 4. The plan's "zero seed" test vector is not a seed vector

`nano_1111111111111111111111111111111111111111111111111111hifc8npp` is the
encoding of a **zero public key** — the burn address. It is not the zero seed's
address. The plan wires it into a seed test.

Verified in the library: `public_key_to_address(&[0u8; 32])` reproduces it
exactly (`burn_address_is_zero_public_key`).

The zero seed *does* have a real, verified address under the corrected pipeline:

```
seed 0000…0000, index 0 -> nano_3i1aq1cchnmbn9x5rsbap8b15akfh7wj7pwskuzi7ahz8oq6cobd99d4r3b7
```

(Independently reproduced in Python at index 0 of the all-zero seed.)

## 5. Two published vector families, easily conflated

docs.nano.org lists two kinds of key material that look interchangeable but are not:

- **Wallet seed vectors** — `privkey = Blake2b-256(seed ‖ index)`. Seed
  `D56143E7…` gives `1f6feb5d…` at index 0.
- **SLIP-0010 vectors** — keys from BIP39 path `44'/165'/i'`. These have no
  wallet-seed relation; `ce7e429e…`, `d9f7762e…` and `3be4fc2e…` are in this family.

I initially mis-paired them, which made two tests fail for the wrong reason. The
tests now exercise each family for what it actually proves:

- family A pins **seed → private key**;
- family B pins **private key → public key → address** (all three fields exactly).

## 6. Encoding is independently round-trip verified

`decode_public_key` exists so the encoder is checked in both directions, and
`is_valid_address` re-validates checksums. Confirmed against published
addresses: decoding the 52-char body of both real vectors returns the published
public key bytes exactly.

`decode_public_key` also enforces that the leading 5-bit group is 0 or 1, so a
malformed address cannot silently lose bits in the accumulator.

---

## 6a. The expansion hash: check the vendored code, not `package.json`

A Nano private key is expanded into an Ed25519 signing scalar by hashing it and
clamping the first 32 bytes. The spec says **Blake2b-512**. Standard Ed25519 says
**SHA-512**. Both produce a valid curve point from a valid private key, so the
wrong one is completely invisible: the address is well-formed, the checksum is
correct, and the key is spendable — it is simply not the account the seed
derives.

This is where reading an actual shipping wallet earned its keep, and it nearly
went the other way. Nault lists `tweetnacl` in `package.json`, and
`tweetnacl`'s `sign.keyPair.fromSecretKey` is SHA-512. Taken at face value that
says Nault uses SHA-512, and therefore that Blake2b-512 is wrong.

That reading is a trap. Nault never imports the npm package — `util.service.ts`
resolves `const nacl = window['nacl']`, and `index.html` loads
`src/assets/lib/tweetnacl/nacl.js`, a vendored fork sitting in a directory named
`tweetnacl`. Inside it:

    var context = blake2bInit(64);
    blake2bUpdate(context, sk);
    d = blake2bFinal(context);
    d[0] &= 248;  d[31] &= 127;  d[31] |= 64;

It calls Blake2b, and the file contains no SHA-512 at all. The directory name and
the dependency list are both misleading; only the code is authoritative.

The general lesson, and the reason `research/cross_check.py` re-derives results
from a second implementation rather than restating the first: **a dependency
list describes intent, not behaviour.** Verify the code path that actually runs.

---

## 7. The account index is **big-endian**, and little-endian nearly shipped

`docs.nano.org` states the index is "a 32-bit big-endian unsigned integer".
`nanopy` uses `byteorder="big"`; `nanopyrs` uses `i.to_be_bytes()`. The first
implementation used `index.to_le_bytes()`.

Confirmed independently against a shipping wallet: Nault's
`generateAccountSecretKeyBytes` builds the suffix with
`hexToUint8(decToHex(accountIndex, 4))`, and `decToHex` pads on the **left**, so
Nault is big-endian too. See [`NOTICE`](NOTICE).

This bug survived unusually long because **every vector then in the repo used
index 0**, where both byte orders are identical — `0u32.to_be_bytes()` and
`0u32.to_le_bytes()` are both `[0,0,0,0]`. The suite was green and looked
convincing. It only surfaced when non-zero-index vectors were added, which
immediately disagreed.

It is the worst class of bug for this tool: the output is still a **valid Nano
account** with a correct checksum, so nothing about it looks broken. It just is
not the account your seed regenerates, so a user restoring from seed would get a
different, empty address and never learn why. The tool now carries regression
vectors for indices 0, 1, 2, 255, 256, and 65535, plus a test asserting the
little-endian variant must disagree.

## 8. Retracted: "a high account index is unreachable from a seed"

This tool once told users that an index above 1000 could not be restored, that
reaching it meant "adding 644595 accounts", and that they should import the
private key instead. That advice was **wrong**, and it was invented here rather
than inherited.

The premise was that a wallet materialises accounts 0..=N one at a time, so a
high index is unreachable. Nothing in Nano's derivation requires that. Nault's
own documentation says:

> "In many wallets, we are only interested in the first account (index 0) but
> Nault, for example, can access any index if you so want."

and its import flow takes the account index as a field, so `(seed, index)`
restores any address in the 2^32 space with none of the preceding accounts ever
existing. The retracted advice pushed users toward importing a private key —
a strictly worse and more fragile workflow — for no reason.

The constant `SEED_RESTORE_PLAUSIBLE_MAX` is retained but unused, marked as
retired, because deleting it would hide the correction. A test now sweeps the
CLI result output and the help text for the retracted wording, because the claim
had already been copy-pasted into four separate places and fixing them one at a
time is how the others survive.

## Performance: measured, not assumed

The plan asserted specific multipliers (2x for skipping ed25519-dalek, ~1.5x for
blake2b_simd, +10% for `target-cpu=native`). Those were **not** verified here and
should not be quoted. What was actually measured on this device:

### Thread scaling

```
threads=1    12,593 addr/s
threads=2    25,298 addr/s   (2.01x)
threads=4    49,242 addr/s   (3.91x)
threads=8    60,880 addr/s   (4.83x)   <- sublinear
```

**Cause: big.LITTLE.** This SoC has 4x 1.709 GHz and 4x 2.189 GHz cores:

```
cpu0..cpu3  cpuinfo_max_freq = 1709000
cpu4..cpu7  cpuinfo_max_freq = 2189000
```

The scaling curve flattens exactly where the slow cluster is saturated. This is
the dominant performance characteristic on a phone, and it is invisible on a
homogeneous desktop CPU.

### Thermal stability

40 seconds at 8 threads showed **no throttling** (64.3k → 60.0k addr/s, ~7% drift):

```
  5s   64290 addr/s
 20s   60153 addr/s
 40s   59897 addr/s
```

### Compiler flags on aarch64

`-C target-cpu=native` (unverified single run): ~64.6k vs ~62.0k addr/s baseline,
roughly +4%.

Explicitly forcing `-C target-feature=+sha3,+aes` was **measurably worse**
(47.4k addr/s, about -24%). SHA-3/AES instructions are irrelevant to Blake2b and
the extra feature selection appears to have perturbed codegen. The plan's
suggestion to add x86 `avx2` flags is simply inapplicable on aarch64, where NEON
is selected by the backend.

Benchmarking was stopped early by request once the scaling curve and the
big.LITTLE explanation were established.

### Honest takeaway

Random-seed grinding at ~60k addr/s on this phone is *not* competitive with the
plan's cited desktop/GPU figures (millions/s, 20M/s). Short prefixes only:

| Prefix | Expected tries | Realistic time here |
|---|---|---|
| `1111` | 6.6e4 | ~1 second |
| `11111` | 2.1e6 | ~35 seconds |
| `111111` | 6.7e7 | ~18 minutes |
| `1111111` | 2.1e9 | ~10 hours |

---

## Design decisions (deviations from the plan)

1. **Index-space search instead of random seeds.** The plan randomises 32-byte
   seeds. But only `Blake2b-256(seed ‖ index)` becomes an account, so a
   random 32-byte value is *not* importable as a private key unless it happens to
   be one of those hashes — which it never is. The grinder searches account
   indices under a wallet seed and prints `seed` + `index` + the derived
   `private key`, all three of which a wallet accepts.
2. **A fresh random seed per run, and no `rand` dependency.** The seed comes
   from `/dev/urandom`, so a run does not need a CSPRNG crate. Randomising per
   run is a security requirement, not a stylistic one: with a *fixed* seed the
   key is `Blake2b-256(seed ‖ index)`, so anyone knowing the prefix can recompute
   it, and two people grinding the same prefix would derive the *same* private
   key. `--seed <hex>` restores reproducibility for a specific seed. The
   *search* is separately deterministic (lowest matching indices), so thread
   count and scheduling never change a result.
3. **`rayon` removed.** Block-claiming with `std::thread::scope` plus an atomic
   counter replaced it, because `find_map_any` returns whichever thread finishes
   first and made every run non-reproducible. Fewer dependencies and a smaller
   build on a phone.
4. **Allocation-free matching.** A single masked `u64` compare replaces
   `format!`-ing an address per candidate.
5. **Three match modes.** The plan only ever asked for a prefix. Bitcoin's vanity
   tools also offer *suffix* and *contains*, and those are implemented here
   against the fully encoded address. A suffix cannot be tested on the public
   key alone: the last eight body characters are the checksum, so the real
   encoding is required. The cost is one Blake2b-5 plus a short base32 pass per
   candidate, measured at 1-2% of the loop.
6. **Prefixes are matched literally.** An earlier version stripped leading `1`s
   as "free" matches. That silently returns addresses that do *not* start with
   what the user typed (`111x` would return `x…`), which is unacceptable for a
   vanity tool, so it was removed even though it was faster.
7. **Reporting uses a condvar.** A plain `sleep(5s)` in the reporter kept
   `thread::scope` blocked, making every run take a full 5.00 s and corrupting
   the throughput figure. Fixed; runs now return as soon as a match is found.
## Upstream state: why the CPU ceiling is not going to move

Checked against the released crates, not pre-release notes, so the
path-forward decision rests on verified facts.

| Question | Finding | How verified |
|---|---|---|
| Does dalek vectorize on aarch64? | **No.** No aarch64/NEON backend in any release. | `grep -rli neon` over 4.1.3 and 5.0.0 sources: zero hits |
| Is the SIMD gate arch-specific? | Yes: `is_capable_simd` is `arch == "x86_64" && bits == Dalek64` | `build.rs` of both versions |
| Did 5.0.0 add NEON? | **No — it added AVX-512**, widening the x86/aarch64 gap. | 5.0.0 `CHANGELOG.md` |
| Is 5.0.0 actually released? | Yes, through `5.0.0-rc.1` to `5.0.0`. | crates.io index |
| Would a NEON backend help? | ~20-30% on the scalar multiply, per the PR author's benchmarks. | PR #457 description |
| Is NEON imminent? | Unlikely: PR #457 open since 2022-12-08, still unmerged. | GitHub API: `state: open` |

### Why batching compression does not work from outside dalek

A tempting idea is to amortise `compress()` (16.4 us of the 78.9 us loop,
~21%) using Montgomery's trick: N inversions become 1 inversion plus
3(N-1) multiplications.

It is not reachable as a small patch:

1. `curve25519_dalek::field` is `pub(crate)` in **both** 4.1.3 and 5.0.0, and
   `EdwardsPoint`'s `X/Y/Z/T` are `pub(crate)` too. Batching `compress()`
   needs the *field* inversions of the `Z` coordinates. `Scalar::batch_invert`
   (renamed `invert_batch`, const-generic, in 5.0.0) is inversion in the
   *scalar* field mod l and is irrelevant here. So the only route is vendoring
   or forking the crate, including its backend selection and `build.rs`.

2. The math does not compose. Batch-inverting `Z_i` gives `1/Z_i` for each
   candidate, producing N *independent* `y = Y/Z` byte strings — but an address
   encodes the single point `sum(s_i*B)`, not a block-diagonal sum, and
   `compress` is not linear in the points. So a batched inversion does not yield
   the address for `sum(s_i*B)`. The only sound batch form is "invert N Z's,
   form N y's, check N prefixes, stop early", which **defeats the early exit**
   the grinder relies on.

3. The ceiling is modest regardless: amortising `compress()` perfectly bounds
   the gain at ~1.26x, realistically ~2.5x with a large batch, against the cost
   of a security-critical fork on a money-handling path.

**Conclusion.** ~60k addr/s is the real ceiling for dalek 4.1.3 on this SoC.
The remaining levers are a NEON fork (blocked upstream for 3+ years) or
vendoring dalek to hand-roll batch compression. Neither is a small change.

---
## 9. GPU acceleration on this device: measured, and it loses

The `gpu-test` branch investigated a Vulkan compute backend. Phase 0 was a
one-day throughput gate, built specifically so that one day of measurement
would decide whether three to five weeks of kernel work was worth doing. It
was, and the answer was no. The project stopped at the gate.

### What was measured

Device: Huawei Kirin 710, Arm **Mali-G51 MP2** (Bifrost, 2018), paired with
4x Cortex-A73 @ 2.36 GHz and 4x Cortex-A53.

Both sides ran the same register-resident kernel -- `acc = acc * acc + b`,
across 16 independent chains -- counted in identical units of one 32-bit
multiply plus one 32-bit add. The GPU ran it as a Vulkan compute shader; the
CPU ran it as hand-written NEON.

| | lane-ops/s |
|---|---|
| Mali-G51, sustained peak (16 chains, workgroup 128) | 2.06e10 |
| 1x Cortex-A73, peak (8 lanes) | 3.26e9 |
| 8 CPU cores, generous assumption (all at A73 speed) | 2.61e10 |

Stable to within 2% across three full sweeps, so this is not a lucky run. The
GPU figure was also taken at four dispatch sizes up to 0.79 s to rule out a
clock-boost artifact: it plateaus at ~2.1e10 and does not improve under
sustained load, so that is its real sustained rate, not an idle-clock number.

### A methodology note, because it cut against the conclusion

The first version of this benchmark reported the GPU at **3.0x a core and
13x**, and a naive reading of that would have said "worth trying". It was
wrong, twice over:

1. The CPU side read a 256 KB buffer inside its inner loop while the GPU side
   did a large job, so it was comparing a big job against a small one. The
   loop is now register-resident on both sides, doing identical work.
2. After that fix the NEON baseline still looked slow, because it indexed a
   `Vec` and paid bounds checks in the hot loop. Removing that made the CPU
   **2x faster** (1.6e9 -> 3.3e9 lane-ops/s) and the GPU correspondingly
   **worse**.

Both corrections moved the result *against* the GPU. A negative result should
be reported from the strongest opponent, so the numbers below use the fast
NEON version, not the flattering one.

### Why 6.3x over one core is not a win

The GPU is 6.3x a single core, which sounds substantial. It is not, for two
reasons.

1. **The phone has 8 cores, not 1.** Against the whole CPU the GPU manages
   **0.79x** -- it is already *slower* than the existing 8-thread path on raw
   integer op rate, before any penalty at all. And that is deliberately
   generous, because 4 of the 8 cores are A53, which are substantially slower
   than A73.

2. **The GPU has no 64-bit integers.** `subgroup ops` reports `0x1` (BASIC
   only), and the device offers no `shader_int64`. A 64x64 field multiply must
   be decomposed into 32-bit pieces, costing roughly 2x to 4x more integer
   operations than the same multiply on the CPU.

Applying that penalty:

| Assumption | GPU vs 8-core CPU |
|---|---|
| no penalty (raw op rate) | 0.79x |
| 2x operation penalty (optimistic) | **0.39x** |
| 4x operation penalty | **0.20x** |

All of them are below break-even -- and that is *before* accounting for the
fact that a real field-arithmetic kernel typically reaches only 50-70% of the
rate of a synthetic multiply-accumulate loop, once register pressure, carry
chains and base-table lookups are in the picture. The realistic figure is
well under 0.2x.

### Conclusion

A Vulkan Ed25519 kernel on this GPU would be roughly **2.5x to 5x slower**
than the existing 8-thread CPU path. The 32-bit-only arithmetic model does not
merely cancel the parallelism advantage -- the raw op rate is already behind
before it is even applied.

The useful finding is not "GPUs are bad". It is that on a 2018 dual-core mobile
GPU, the absence of 64-bit integer support is not a detail to engineer around
-- it is the whole answer. What would change the result is `shader_int64` or
many more compute cores, and neither is reachable by writing better code.

This also retroactively justifies the CPU ceiling above: the alternative to
dalek's generic 64-bit code is a NEON implementation, not a GPU. The NEON path
reuses the same arithmetic, carries no driver layer, and keeps one
implementation to trust. It is now the only remaining lever, and this result
says it is the right one.

### Reproducing

```sh
cargo run --release --example gpu_probe    # device, limits, subgroup properties
sh nano-vanity/shaders/sweep.sh            # chain x workgroup sweep, both sides
```

All of it lives on the `gpu-test` branch. `main` is unchanged.

### Vulkan gotchas found along the way

Recorded because they are Android-specific and cost real time:

- Android ships `/system/lib64/libvulkan.so` but **not** `libvulkan.so.1`,
  which is what `ash::Entry::load()` tries by default. Load by absolute path.
- The `_khr` alias for `get_physical_device_properties2` is absent even though
  the device reports Vulkan 1.1. Using the KHR wrapper **aborts the process**,
  because ash resolves extern function pointers eagerly and cannot unwind out
  of them. The core 1.1 entry point works, but only when the instance is
  created with `api_version = 1.1`; asking for 1.0 leaves the pointer unloaded.
- `subgroup stages` is reported as `0x30`, which decodes to tessellation and
  geometry, not compute. The driver fills this struct nonsensically. Treat
  driver-reported properties as a hint, never as a fact.
- `timestampPeriod` is 0, so GPU-side timestamps are unusable. Throughput must
  be measured as wall clock around submit plus fence wait.

---

## 10. Why the CPU is slow: measured breakdown, and three ideas already closed

Section 9 closed the GPU. This section records what the CPU is actually
spending time on, so the next optimisation attempt starts from measurements
rather than from the assumption that hashing is the problem. It is not.

### The breakdown

`cargo run --release --example breakdown -p nano-keys`, 20,000 iterations:

| Operation | ns/op | share of the loop |
|---|---|---|
| `blake2b-512` (scalar expand) | 372.3 | 0.5% |
| `Scalar::from_bytes_mod_order` | 174.8 | 0.2% |
| **basepoint multiply** | **62,179.2** | **78.5%** |
| `compress()` + `to_bytes` | 16,482.8 | 20.8% |
| **total** | **79,209.1** | |

Hashing and scalar reduction are together **0.7%**. Any proposal to speed up
Blake2b, batch the hashing, or move it to another core is optimising something
that cannot matter.

### Three ideas, tested and closed

Recorded so nobody spends the effort again.

**1. Upgrade `curve25519-dalek` 4.1.3 -> 5.0.0. No win.**
`dalek_ab.rs`, 6,000 iterations each:

```
4.1.3  basepoint multiply      74798.4 ns/op
5.0.0  basepoint multiply      74809.3 ns/op
multiply speedup                    1.000x
compress speedup                    1.000x
```

Dalek's 5.0 changelog advertises "automatic serial backend selection between
u32 and u64" and "maximum available NAF window size in
VartimePrecomputedStraus". On aarch64 both are no-ops. The two versions were
also verified to agree bit-for-bit, so this is a performance no-op rather than
a silently different implementation.

**2. "The default 32-bit field backend must be the problem." Wrong.**
dalek 4.1.3 has no `radix_51` feature; the backend is chosen by
`--cfg curve25519_dalek_bits`, and `build.rs` already resolves 64-bit
targets to `DalekBits::Dalek64`. We were never on the 32-bit backend. Note
dalek's own `build.rs` carries a `TODO(Arm): needs tests + benchmarks to back
this up` -- `dalek_ab.rs` is that benchmark, for a six-year-old Cortex-A73.

**3. Wider basepoint comb tables. Real idea, unreachable API.**
dalek 5.0 ships tables trading bytes for point additions:

| table | size | additions |
|---|---|---|
| `EdwardsBasepointTable` (radix 16, default) | 30KB | 64 |
| `EdwardsBasepointTableRadix64` | 120KB | 43 |
| `EdwardsBasepointTableRadix128` | 240KB | 37 |
| `EdwardsBasepointTableRadix256` | 480KB | 33 |

Fewer additions is strictly less field multiplication, so this is the one
genuinely promising idea in this section. But `BasepointTable` and
`EdwardsPoint::mul_by_pow_2` are both `pub(crate)`, so the tables cannot be
constructed outside the crate, and a hand-rolled comb hits the same wall.
Reaching it means vendoring dalek, which is a large maintenance and
supply-chain commitment for an unknown payoff on a phone with a small L2.
Recorded as a step-3 option in `PLAN.md`, not as a recommendation.

The blocker is directly reproducible, which is why no benchmark script is
checked in for it. Attempting to construct any of these tables from outside
the crate fails to compile:

```
error[E0603]: trait `BasepointTable` is private
error[E0599]: no associated function or constant named `create` found for
              struct `EdwardsBasepointTableRadix64`
error[E0599]: no method named `basepoint` found for reference
              `&'static EdwardsBasepointTable`
```

A compile error is stronger evidence of a closed door than a script that
returns zero, so the benchmark that proved it was removed rather than kept in
a non-compiling state. `dalek_ab.rs`, which *does* compile, is kept.

### What is left

The multiply at 78.5% is the only thing worth attacking, and dalek's field
arithmetic is generic 64-bit limb code with no aarch64 vectorisation. That is
the remaining lever, and it is a real implementation job rather than a
configuration change. See `PLAN.md`.

One observation worth recording: `compress()` is 20.8%, and a **prefix** match
never needs it. The address body is 255 bits of y followed by 1 bit of the
sign of x, and that sign bit is the *last* bit, so it can only ever affect a
suffix. Skipping it for prefix mode, and amortising the normalisation with
`AffineNielsPoint::batch_invert`, is worth a measured **1.25x** with no new
dependency. Suffix and contains modes must keep `compress()` and gain nothing.

## 11. Qubic: three silent ways to get a valid-looking wrong answer

Qubic is a mode of this tool rather than a separate program, so the crypto
lives under `nano-keys/src/qubic/` and touches none of the Nano code. Three
bugs turned up while building it, and all three share a property worth naming:
**each produced output that looked completely reasonable.** None of them threw,
none of them produced an obviously malformed address, and in two cases the
implementation was internally self-consistent the whole time.

### 11.1 The identity encoding runs the other way

A Qubic identity reads the 32-byte public key as four **little-endian** u64
fragments and writes each as 14 base-26 digits with the **least significant
digit first**. The checksum is four more digits from 18 bits of K12 over the
public key.

So `identity[0]` depends on the *low* bits of the public key. This is the
opposite of Nano's `enc52`, which is emitted most-significant-first, and it is
the opposite of the intuition the rest of this document teaches. Carrying the
Nano model across produces a 60-character string that passes a length check, a
charset check and looks like an address, and belongs to nobody. The test
`leading_character_tracks_the_low_bytes_of_the_public_key` exists purely to
stop a future "optimisation" from flipping it.

Contract identities are the cheapest way to exercise the encoding without
touching the seed path at all: the identity of a small integer is just the
integer's public key, so index 1 must give `BAAA…`, index 2 `CAAA…`, index 4
`EAAA…` — and index 4 matches the QUTIL address quoted in Qubic's own
documentation.

### 11.2 Negating a point does not negate its coordinates

The reference's `r2Neg` **swaps** `addYX` with `subYX` and negates `dt2`. The
tempting reading — negate `x` and `y` and carry on — is wrong, and it is wrong
in a way that does not announce itself. The sign flip propagates through the
ladder, `Z` eventually reaches zero, and the only visible symptom is the
inversion in `to_affine` aborting on a zero element, long after the point had
been treated as a perfectly good group element.

### 11.3 A multi-precision borrow that is correct alone and wrong in a loop

`sub_div16` computes `(x − y) / 16` over a 320-bit value, with `y` sign-extended
into the upper limbs. The first cut composed `sign_ext + borrow` into a single
`overflowing_sub`. That is not equivalent to subtracting `y` and the borrow
separately:

```
sign_ext = 0xFFFF_FFFF_FFFF_FFFF,  borrow = 1  ->  sign_ext + borrow = 0
x − 0            reports "no borrow"
```

so every higher limb silently gained one. In isolation the function looked
perfect — it was correct for `y = 0`, and correct for any `y` that did not
overflow — and it was wrong for every signed `y`, which is most of them.

The only visible symptom was a recoded top digit falling outside the odd
multiple table, so the ladder selected a **zero** point, and the identity came
out wrong. The borrow is now taken from the comparison rather than from a
wrapped subtraction's overflow flag.

### Why these survived, and what caught them

Nothing internal would have caught any of the three. A self-consistent
implementation agrees with itself perfectly. Every one was caught by something
external:

| Bug | Found by |
|---|---|
| identity digit order | contract identities 1/2/4, checked against Qubic's docs |
| `r2Neg` | `to_affine` aborting on a zero inversion |
| `sub_div16` borrow | the six official golden vectors |
| seed search produced a plausible but wrong seed set | re-deriving a *found* seed through the official npm package |

That last row is the one worth keeping. The golden vectors use seeds chosen in
advance, so they would pass even if candidate generation were biased. Feeding a
seed the search *discovered* back through the official package closes that gap,
and it is now part of `research/qubic/cross_check.py`.

### And one that was mine, in the checker itself

Worth recording because the cross-check is the thing people trust, so a bug
there is the expensive kind. The Tonelli-Shanks square root used to check the
FourQ curve equation searched for a quadratic non-residue among elements of
`Fp`. It can never find one:

```
n^((p²−1)/2) = (n^(p−1))^((p+1)/2) = (±1)^(2^126) = 1
```

because `(p+1)/2 = 2^126` is even. **Every** non-zero element of `Fp` is already
a square in `Fq`, so that search is an infinite loop. It has to look at elements
with a non-zero imaginary part.

A second one in the same file: the sign bit of X lives in bit 127 of the
imaginary half of the public key, so it must be masked off before that half is
read as a field element. Reducing with `% P` instead wraps the bit into the low
bits, which yields a plausible Y that is not a curve point — and it made five of
the six golden keys look off-curve. Both are now documented at the function.

### What is not claimed

FourQ over `Fp = 2^127 − 1` is a different curve family from Ed25519 over
`2^255 − 19`. The two are unrelated despite both being twisted Edwards curves,
and nothing in this implementation is compatible with curve25519-dalek. The
reference files under `research/qubic/` belong to the Qubic project under its
own licence and are research material only: nothing there is compiled or
vendored.
