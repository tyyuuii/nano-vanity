# GPU mode for Nano vanity search (Android / Mali)

Status: **plan, not implementation.** Branch `gpu-test` carries this document
only. The `main` branch is untouched and remains the shipping, correct,
CPU-only tool.

---

## 1. Verdict up front

The plan is worth doing, but **only behind a measurement gate**, and I would
set expectations low. On this specific device the most likely outcome is a
project that proves interesting and ships nothing, for reasons in §5.

The single most valuable thing in this document is §7 Phase 0: roughly a day
of work that settles the question empirically, on this phone, before anyone
commits to the real engine.

---

## 2. The hardware, as actually measured

Not assumed — read off this device:

| Property | Value | Source |
|---|---|---|
| SoC | Huawei HiSilicon **Kirin 710** | `getprop ro.board.platform` → `kirin710` |
| Board | `STK-L21MDV` (Huawei nova 3i) | `getprop ro.product.board` |
| GPU | **Arm Mali-G51 MP2**, dual-core, Bifrost | Kirin 710 spec |
| Vulkan | `libvulkan.so` present (system HAL) | `ls /system/lib64/libvulkan.so` |
| CPU | 8 cores: 4x Cortex-A73 @ 2.36 GHz + 4x A53 | `/proc/cpuinfo`, `nproc` |
| Rust | 1.98.1, Termux, no proot | `cargo --version` |

**Correction:** earlier revisions of this repository described this device as
"Snapdragon-class". That was wrong and is fixed on this branch. It matters,
because Mali and Adreno differ in exactly the ways that decide this project.

### Current CPU baseline, measured on this phone

```
~64,000 – 67,500 addr/s   (8 threads, prefix mode)
~12,400 addr/s            (1 thread)
```

Scalar multiplication is **~99.4%** of that. Blake2b, encoding and
comparison are under 1% combined.

---

## 3. What is actually expensive

Per candidate the CPU does:

```
private_key = Blake2b-256(seed ‖ index_be)        <1% of time
scalar      = clamp(Blake2b-512(private_key)[0..32])
public_key  = scalar · B                         <99% of time
```

So a GPU only has to do **one thing well**: `scalar · B`, the fixed-base
Ed25519 scalar multiplication, for many scalars at once. It does **not** need
Blake2b, does not need the base-32 encoder, and does not need the checksum.

`curve25519-dalek` 4.1.3 is the CPU reference. It has no SIMD backend for
aarch64 — its vectorized path is gated to `x86_64` — so the current CPU number
is generic 64-bit limb code, not hand-tuned. That is what a GPU has to beat.

---

## 4. Why a GPU could win at all

The parallelism is genuinely there. Each candidate is independent: one scalar
in, one compressed public key out. Nothing in the loop is sequential across
candidates. A GPU that can hold ~50,000 scalars in flight should in principle
do far more work per second than 4 A73 cores.

Rough per-candidate cost, using the same 10-limb radix-2^25.5 representation
dalek uses:

- one fixed-base multiply: ~64 doublings + ~64 additions
- each field op: ~25–30 INT32 multiply-accumulates
- ≈ **4,000–8,000 INT32 ops per candidate**

A single scalar-multiply kernel is therefore arithmetic-bound, not
bandwidth-bound, which is the friendly case. Results are 32 bytes each and
only *matches* need to come back to the CPU, so memory traffic is negligible.

---

## 5. Why I expect this to disappoint on Mali-G51

This is the part that matters, and it is why Phase 0 exists.

**1. Mali-G51 MP2 is a 2018, dual-core, rasterisation-first GPU.** Bifrost
at this tier has a narrow 64-bit datapath per core and modest INT32 throughput.
It is designed to shade mobile pixels, not to run big integer kernels. Two
cores is very little parallelism for compute.

**2. Mali compute drivers have a long history of bugs.** Correct integer
64-bit accumulation, loop unrolling and shared-memory barriers are exactly
where vendor drivers get it wrong. A kernel that produces a *wrong* answer
silently is far worse than no kernel: it yields valid-looking Nano addresses
that no seed regenerates — the same failure class as the endianness bug in
`ERRATA.md` §7.

**3. `shader_int64` is not a given.** GLSL ES 3.1 has no native 64-bit
integer. 10-limb radix-2^25.5 arithmetic must be done with careful u32
splitting. This is the single hardest part of the implementation and it is
where driver bugs concentrate.

**4. Small shared memory, small subgroups.** Mali-G51 uses a **subgroup size
of 4**, not the 64/128 that GPU programming guides assume. Workgroup sizes
must be multiples of 4, occupancy maths changes completely, and hand-rolled
code tuned for a 64-wide warp will perform badly.

**5. The honest baseline.** 4x A73 @ 2.36 GHz running dalek is not weak. Beating
it needs a large margin, not a small one, to be worth 3–5 weeks of work.

**Realistic range if everything goes well:** 0.5M–3M addr/s, i.e. 8–45x the
CPU. **Realistic range including driver surprises:** possibly slower than CPU.

For context on what that would buy, at 1M addr/s:

| Prefix | Tries | Now (67k/s) | At 1M/s |
|---|---|---|---|
| `1test` (5) | 2.1e6 | 31 s | 2 s |
| `1testi` (6) | 6.7e7 | 17 min | 67 s |
| `1testio` (7) | 2.1e9 | 9 hours | 35 min |

The capability jump is real and worth wanting. Whether this GPU delivers it is
an empirical question, not a design question.

---

## 6. Architecture

### Where the split goes

```
CPU                                  GPU
────────                             ────
generate candidate seed / index
scalar = clamp(Blake2b-512(...))  ──►  scalar            (32 B per candidate)
                                      scalar · B
                                      compress y + sign
                              ◄──   32 B public key  (or nothing, see below)
compare top bits vs pattern
  ├─ no match → discard
  └─ match → full enc52 + Blake2b-5 checksum, verify with dalek
```

Two refinements, in increasing order of complexity and payoff:

**v1 — return every public key.** Trivial. 32 B x N candidates; a 100k
candidate batch is 3.2 MB. Fine, and it keeps the shader dead simple.

**v2 — filter on the GPU.** Upload the prefix mask and have the shader compare
the top bits of `y | (sign << 255)` as a big-endian integer, returning only
matches. The address body is a **260-bit** field (see `ERRATA.md` §3), so the
comparison is on the *top* bits of a 260-bit big-endian number, not on the
little-endian bytes. Getting this wrong reintroduces a silent-wrong-answer
bug, so it must be verified against `Pattern::matches_reference`, which
already exists in `nano-keys` and is the CPU ground truth.

Do **v1 first.** Only attempt v2 once v1 is proven bit-identical to dalek.

### Components

| Piece | Choice | Why |
|---|---|---|
| API | **Vulkan compute** | Only portable option here. No CUDA (no NVIDIA), and OpenCL support on Mali is less consistent than Vulkan. |
| Rust binding | `ash` | Low-level, no runtime, no async, smallest build. `vulkano` is safer but we want control over workgroup and subgroup sizing. |
| Shader language | GLSL ES 3.10 → SPIR-V via `naga` | Lets us validate the shader offline on the laptop, before touching the phone. |
| Field representation | 10 limbs x 25.5 bits, radix 2^25.5 | Same as dalek, so the two implementations can be diffed limb-for-limb when debugging. |
| Base point table | Precomputed comb table uploaded as a UBO | dalek's `ED25519_BASEPOINT_TABLE` is 64 points. ~2–8 KB. Makes the kernel a fixed-base multiply instead of generic double-and-add. |

### How it fits the existing engine

`engine::search()` already has the right shape: workers claim blocks of
`BLOCK = 2048` candidate indices and return matches. The GPU backend should
replace the *inner* candidate loop only, keeping block claiming, the
`(seed, index)` determinism guarantee, `--grind`, and all result reporting
exactly as they are.

Introduce a trait so the CPU and GPU paths are genuinely interchangeable:

```rust
pub trait Derive {
    /// Public keys for candidates [start, end) at a fixed account index.
    fn batch(&self, start: u64, end: u64, index: u32) -> Vec<[u8; 32]>;
    fn close(&self) {}
}
```

`--gpu` selects the Vulkan implementation; the default stays `std::thread`-based
CPU. **Automatic fallback to CPU on any GPU initialisation failure**, because
a phone that cannot run it must still be able to grind.

---

## 7. Phased plan

Each phase ends in a gate. If the gate fails, stop; do not proceed.

### Phase 0 — Measurement spike  *(~1 day, highest value)*

The question is only: **does this GPU do integer compute fast enough to be
worth building on?**

Write one throwaway Vulkan compute shader that does nothing but a tight,
branch-free INT32 multiply-accumulate loop, e.g. repeated
`acc = acc * 1664525u + data[i]` over a 64 KB buffer, over a known number of
iterations. Measure ops/second. Compare against the same loop compiled for
AArch64 NEON on the same phone.

- If GPU INT32 throughput is **below roughly 5x** a single A73 core, stop.
  A complex field-arithmetic kernel will not close that gap, and the project
  is dead. This is a one-day answer to a question worth weeks.
- If it is **20x or more**, proceed.

Run it with `cargo run --release` in Termux, no root, no proot. Add
`--gpu-selftest` so it is a permanent, honest benchmark rather than a
throwaway.

**This phase is the whole recommendation. Do it first and let the number
decide.**

### Phase 1 — Correct field arithmetic  *(3–5 days)*

- 10-limb radix-2^25.5 add, sub, mul, square in GLSL
- Write them with u32 splitting only; no `shader_int64`
- Validate the **shaders** offline on the laptop: export a handful of
  known field inputs/outputs from `nano-keys`, and check the SPIR-V-translated
  logic against them before ever running on the GPU
- Gate: field ops agree with dalek bit-for-bit on vectors covering carries,
  borrows, and the top limb

### Phase 2 — One scalar multiplication  *(3–5 days)*

- Fixed-base comb table in a UBO
- One `scalar → 32-byte compressed point` kernel, `workgroup_size = 64`
  (16 workgroups of a 4-wide subgroup)
- Gate: for 10,000 random scalars, GPU output is **bit-identical** to
  `curve25519-dalek`. Not "close". Identical.

**If Phase 2 cannot be made bit-identical, abandon the project.** A GPU that
is occasionally wrong is worse than no GPU, because the failure is silent and
produces plausible addresses.

### Phase 3 — Throughput and integration  *(3–5 days)*

- Tune workgroup size: 32 / 64 / 128 / 256
- Batch 10k–100k candidates per dispatch
- Early-exit via atomics on first match
- Wire into `engine::search()` behind `--gpu`
- Benchmark against the 67k/s CPU baseline on this device

### Phase 4 — Differential testing  *(2–3 days)*

- `--gpu-selftest N`: derive N candidates on both backends, assert equality
- Extend `research/cross_check.py` with a GPU mode, so CI can arbitrate
  between Rust and Python
- Randomise seeds, indices, patterns and match modes
- Soak test: run a long grind and verify every returned match, on CPU, before
  it is ever shown to a user

### Phase 5 — On-device reliability  *(ongoing)*

- Test across the Mali-G51's driver versions
- Handle `device lost`, mid-dispatch, and out-of-memory by falling back to CPU
  mid-search without losing progress
- Document the driver-specific findings, especially any that are
  Mali-G51-specific

---

## 8. Testing strategy

The bar is higher than for the CPU path, because the failure mode is silent.

1. **Offline shader validation.** Field arithmetic and the point compressor
   are validated against `nano-keys` on the laptop, before the shader ever
   runs on the phone. `naga` makes this possible.
2. **Differential, always.** Every GPU run is checked against dalek. A result
   is trusted only after a CPU recomputation. This is the same discipline
   `research/cross_check.py` already enforces for the derivation itself, and
   it is what caught the endianness bug.
3. **Independent oracle.** Extend the Python implementation to GPU mode so a
   disagreement has three possible explanations, not two.
4. **Never GPU-trusted end to end.** A match found on the GPU is re-derived on
   the CPU with dalek before it is printed. Cost: one scalar mult per *match*,
   which is free.

---

## 9. Alternatives, ranked by expected value per unit of effort

| Option | Expected gain | Effort | Risk |
|---|---|---|---|
| **Phase 0 measurement spike** | Decides the project | 1 day | None |
| AArch64 NEON scalar mult (hand-written, no dalek) | 2–4x | 2–3 weeks | Medium — same class of silent-wrong-answer risk, but no driver layer |
| GPU filter (v2) after v1 works | 2–5x over GPU v1 | 2–3 days | Low, once v1 is proven |
| **GPU mode (this document)** | **8–45x, or nothing** | **3–5 weeks** | **High — driver bugs, and Mali-G51 is a weak, old GPU** |
| Wider CPU parallelism / tuning | ~0 | 1 day | None — already using 8 threads |

The honest summary: **the NEON option is the better bet if the goal is a faster
phone grinder**, because it removes the driver layer, keeps a single
implementation to trust, and the same 10-limb arithmetic is reused. The GPU
only wins if Phase 0 shows this particular Mali has the integer throughput.

Both should share the field-arithmetic work. If Phase 0 says "no", the NEON
implementation still needs it, and it is most of the hard part.

---

## 10. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Mali-G51 integer throughput is too low | Project dead | Phase 0, before any commitment |
| Driver produces silently wrong results | **Users get valid-looking, unrestorable addresses** | Bit-identical differential gate at Phase 2; CPU re-derivation of every match before display |
| `shader_int64` absent | Rework of all field arithmetic | Design for u32 splitting from the start |
| Subgroup size 4 defies tuning assumptions | Poor performance | Sweep workgroup sizes; measure, don't assume |
| Android kills the process mid-grind | Lost work | Already restartable; report partial results |
| Scope creep into a general Nano crypto library | Never finishes | Keep `nano-keys` free of GPU code; isolate in one module |

The silent-wrong-answer risk deserves emphasis. This tool prints wallet seeds
and keys. A GPU backend that is 99.99% correct still produces a wrong address
once in ten thousand, and the user has no way to notice. Every design decision
above is subordinate to that.

---

## 11. What is not changing

- `main` stays CPU-only and correct. No GPU flag, no `ash` dependency, no
  Vulkan requirement for existing users.
- The published releases for Termux, Ubuntu and Windows are unaffected.
- The derivation is untouched. This is a search-speed project only.
