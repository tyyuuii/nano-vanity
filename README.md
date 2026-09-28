# nano-vanity

**A fast Nano (XNO) vanity address generator written in Rust** — find a Nano
address that starts, ends, or contains any pattern you like, and get back the
**wallet seed** that produces it, not just a private key nothing can restore
from.

[![CI](https://github.com/tyyuuii/nano-vanity/actions/workflows/ci.yml/badge.svg)](https://github.com/tyyuuii/nano-vanity/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/tyyuuii/nano-vanity?label=release)](https://github.com/tyyuuii/nano-vanity/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org)
[![Platforms](https://img.shields.io/badge/Termux%20%7C%20Linux%20%7C%20Windows-informational.svg)](INSTALL.md)

```sh
# the whole workflow: a 5-character prefix on account 0, in your wallet's seed
nano-vanity 1test --grind
```

### Why not just grind a private key?

A Nano account is defined by `Blake2b-256(seed ‖ index)`, so a random 32-byte
value is almost never an account at all — it is a standalone key that no seed
phrase can bring back. This grinder reports `(seed, index)` for every hit, so
the address is restorable, and with `--grind` the vanity address lands on
**account 0**, which means importing the seed is the entire job.

### Features

- **Account 0 vanity** — search candidate *seeds* so the vanity address is your
  wallet's first account, not account 40,000.
- **Prefix, suffix, or contains** matching, plus `--skip-first` to accept both
  `nano_1…` and `nano_3…` for half the work.
- **Reproducible** — the same seed and pattern always return the same result.
- **Collect several addresses at once** from one seed with `-n`.
- **Verified derivation** — big-endian account index, Blake2b-512 expansion,
  and a 260-bit prefix field, each pinned by regression tests and checked
  against an independent Python implementation on every commit. See
  [`ERRATA.md`](ERRATA.md) for what the commonly-copied recipe gets wrong.
- **Runs natively on Android** in Termux, no proot and no root. Prebuilt
  binaries for Termux (aarch64), Ubuntu/Debian (x86_64) and Windows x64, with
  releases built automatically on a version tag.
- **Local web UI** using only `std::net` — no axum, no tokio, no async runtime.
- **Optional `--derive`** to check any seed and account index against a wallet
  that disagrees with you.

> ⚠️ The web UI displays wallet seeds and private keys in plain text. It binds
> to `127.0.0.1` by default for that reason. Read
> [the warning in `INSTALL.md`](INSTALL.md#web-ui-and-seeds--please-read)
> before binding it anywhere else.

## Quick reference

| Goal | Command |
|---|---|
| Vanity address on **account 0** (import the seed, done) | `nano-vanity 1test --grind` |
| Vanity address in a chosen seed, lowest account index | `nano-vanity 1test -s <seed>` |
| Match the **end** of the address | `nano-vanity xyz -m suffix` |
| Match **anywhere** in the address | `nano-vanity xyz -m contains` |
| Accept both `nano_1…` and `nano_3…` | `nano-vanity 1test -F` |
| Collect **N** addresses from one seed | `nano-vanity 1111 -n 5` |
| Reproduce an earlier run | `nano-vanity 1111 -s <the printed seed>` |
| Check a seed against a wallet | `nano-vanity --derive <SEED> --index 0` |
| Local web UI | `nano-vanity --web` (or `Nanvin` on Termux) |

## Install

See **[`INSTALL.md`](INSTALL.md)** for Termux, Ubuntu and Windows, prebuilt or
from source.

```sh
# Termux
wget https://github.com/tyyuuii/nano-vanity/releases/latest/download/nano-vanity-android-arm64
mv nano-vanity-android-arm64 $PREFIX/bin/nano-vanity && chmod +x $PREFIX/bin/nano-vanity

# Ubuntu / Debian
sudo install -m 755 nano-vanity-linux-amd64 /usr/local/bin/nano-vanity
```

## Acknowledgements

The derivation in [`nano-keys`](nano-keys/src/lib.rs) is written in Rust from
the published Nano specification and validated against the published test
vectors. No code was copied from another project — but **[Nault](https://nault.cc)**
([source](https://github.com/Nault/Nault)) was the decisive reference while
checking it, and this project would have shipped a wrong answer without it.

Specifically, reading Nault settled two things the specification alone could
not:

- **The expansion hash is Blake2b-512, not SHA-512.** Standard Ed25519, and so
  `tweetnacl` — which Nault's `package.json` lists as a dependency — uses
  SHA-512. But the `nacl` Nault actually uses is not that package: it is
  `window['nacl']`, loaded from a vendored fork whose
  `derivePublicFromSecret` does `blake2b(sk, 64)` plus a clamp, and which
  contains no SHA-512 at all. Trusting the dependency list over the code would
  have produced entirely different, equally plausible-looking addresses.
- **The account index is big-endian.** `generateAccountSecretKeyBytes` builds
  the index with `decToHex(accountIndex, 4)`, which pads on the left.

Nault also explained why importing a seed that holds a brand-new empty account
appears to do nothing: `scanAccounts` keeps only accounts already used on the
ledger.

Nault is MIT licensed, © 2020 The Nano Community. Full attribution is in
[`NOTICE`](NOTICE).

## Crates

| Crate | Kind | Purpose |
|---|---|---|
| [`nano-keys`](nano-keys/src/lib.rs) | library | seed → private key → public key → address, plus address validation |
| [`nano-vanity`](nano-vanity/src/main.rs) | binary | multi-threaded grinder (seed index space or seed space) |

## Build

```sh
cargo build --release            # add -j 2 on Termux; see INSTALL.md
```

Prefer building under `$HOME` on Termux. `/sdcard` is slower and has
permission quirks.

## Test

```sh
cargo test --workspace           # 71 tests
python3 research/cross_check.py  # independent re-derivation, in CI too
```

71 tests: 38 in the library and 33 in the binary, covering CLI parsing, the
engine end-to-end, cancellation, determinism across thread counts, seed
handling, account-0 grinding, JSON output validity, and multi-result output.
They include the published vectors from
<https://docs.nano.org/integration-guides/key-management/>, and pin the traps
described in the errata — including the big-endian account index and the
260-bit prefix offset.

## Use

```sh
nano-vanity 1111                        # search one seed's index space
nano-vanity 1test --grind               # search seeds so account 0 is the vanity address
nano-vanity nano_111111 -t 4            # 4 threads
nano-vanity 11111 -T 60                 # give up after 60s, report rate
nano-vanity 1111 -n 4                   # collect 4 addresses from one seed
nano-vanity --derive <SEED> --index 0   # check a seed against a wallet
nano-vanity --web                       # local web UI
```

```
FOUND 1 address after 38345 tries in 0.67s (56933 addr/s)

  account idx : 36353
  private key : 0F26875C79F7DA0885D569C7601E7E0BADEF38F1139896A6014A398BD8BBBC9E
  address     : nano_1111h7a31k6ih5b4etrzejem33agm6muct861xf1d79szk6b3c6syzrm3tr4
  wallet seed : 1DA5C8E0592B7A20CC8D4C3FEB717B58645174926EB20C78AA4045279265F5CF
```

**Keep the seed, not just the private key.** The private key is one account and
nothing more; the seed derives every account at every index. Either will import
the address, but only the seed lets you add accounts later.

Import with the private key, or restore the seed and set the account index to
the printed **index**. Verify the address in a wallet before receiving funds,
and note that a new account must be opened with a small send before it can
receive directly.

### Using it with Nault

If the match came from `--grind` it is account 0, which is the simplest case:
import the seed and press **"Add account"** once. Nault's seed import scans the
first 20 indices and keeps only accounts that are *already used on the ledger*,
so a brand-new empty account is discarded and the import looks empty. That is
expected — pressing "Add account" with no accounts present derives index 0,
which is the vanity address.

**Pick the right import type.** Nault offers several, and pasting a 64-hex
value into the wrong one gives a valid but unrelated address. Use **Import
Seed** (the panel that says *"64 hex character secret recovery seed"*), which is
the legacy `Blake2b-256(seed ‖ index)` scheme this tool implements. Do **not**
use *BIP39 Mnemonic* or *BIP39 Seed*: those are HD-wallet paths
(`m/44'/165'/…`) and produce a completely different account from the same 64
characters. Importing the **private key** also works and skips the seed scan
entirely.

A Nano account must also be *opened* before it can receive directly: send it a
small amount from another account once.

### Web UI

For point-and-click use, the same engine is served over a small local web page:

```sh
nano-vanity --web
# then open http://127.0.0.1:8787/ in a browser on the same device
```

It gives you a prefix box, live progress (tries, speed, ETA), a cancel button,
and the result with copy buttons. Pick a custom port with
`--web --bind 127.0.0.1:9000`.

Notes:

- The server is **dependency-free** (`std::net` only). No tokio/axum, so the
  build stays light enough for a phone with `-j 2` and no OOM risk.
- It binds **loopback only** by default, on purpose. Anyone who can reach the
  port can start jobs and read the seeds and private keys they produce, so
  `--bind 0.0.0.0:8787` prints a warning and should be a deliberate choice on a
  trusted network.
- Both front-ends share one engine (`nano-vanity/src/engine.rs`), so the CLI and
  the web UI cannot drift apart in how keys map to addresses. A test asserts the
  returned address, the private key, and the seed/index path all agree.

### Match modes

The pattern can be applied in three ways, the same set Bitcoin's vanity tools
offer. Pick one with *Match* in the UI, or `--mode`:

| mode | CLI | matches | cost for 3 chars |
|---|---|---|---|
| starts with | `--mode prefix` (default) | `nano_1fa…` | 2¹¹ |
| ends with | `--mode suffix` | `…1fa` | 2¹⁵ |
| contains | `--mode contains` | anywhere | 2¹⁵/60 |

```sh
nano-vanity 1fa                  # nano_1fa...
nano-vanity 1fa --mode suffix    # ...1fa
nano-vanity 1fa --mode contains  # 1fa anywhere
```

**Suffix and contains are checked against the real address**, checksum included,
because the last eight characters are the checksum rather than key material.
Matching the low bits of the public key instead would be faster but would
quietly return addresses that do not actually end in your pattern.

That does cost a little: each candidate has to be encoded. Measured on this
phone, single-threaded, with a pattern long enough never to complete:

| mode | addr/s | vs prefix |
|---|---|---|
| prefix | 12,422 | — |
| suffix | 12,301 | −1% |
| contains | 12,195 | −2% |

The scalar multiply dominates the loop, so the extra hash and base32 pass barely
register. (Multi-threaded figures swing by ±10% from thermals, so the
single-threaded comparison is the meaningful one.)

`contains` is the cheapest per character, since there are 60 positions for the
pattern to land in rather than one.

### Cost per character

Each extra character costs ~32x. Because character 0 carries only the public
key's top bit, a literal run of `1`s is ~16x cheaper than `32^L` suggests:

| Prefix | Expected tries | On this phone (~60k addr/s) |
|---|---|---|
| `1111` | 6.6e4 | ~1 second |
| `11111` | 2.1e6 | ~35 seconds |
| `111111` | 6.7e7 | ~18 minutes |
| `1111111` | 2.1e9 | ~10 hours |

Only `1` and `3` can begin an address; other leads are rejected up front.

Expected work is `2^(5L-4)` for a run of `L` leading `1`s. Note the `2^32` index
ceiling: prefixes at or beyond ~7 characters exceed the searchable space per
seed and would need multiple seeds.

### Seeds, reproducibility, and finding several at once

**Every run generates a fresh random seed** (32 bytes from `/dev/urandom`). Two
presses of Generate with the same prefix therefore give **different addresses**.

That is deliberate. The private key is `Blake2b-256(seed ‖ index)`, so with a
*fixed* seed anyone who knows the prefix can recompute every matching key — and
two people grinding the same prefix would derive the **same private key**, each
believing they owned the address. A random seed per run makes the key
underivable from the prefix.

The search itself is deterministic: it always returns the **lowest** matching
account indices, so results never depend on thread count or scheduling. The
seed is what makes the result unreproducible, not the search.

| | same prefix, new run | same prefix + same seed |
|---|---|---|
| address | different | identical |
| index | different | identical |
| private key | different, underivable | identical |

**To reproduce an address**, paste the seed from the earlier result into the
*Seed* box (Advanced) or pass `--seed`:

```sh
nano-vanity 1111 --seed 5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A
```

**To collect several addresses at once**, set *How many* (or `-n/--count N`).
The search continues past the first hit and returns the N lowest matching
indices from the same seed, so all of them restore from that one seed phrase:

```sh
nano-vanity 1111 -n 5
```

This is the cross-device workflow: find five addresses from one seed, then
restore that seed on any phone or desktop and set each account index to the
printed values. Nault can reach any index directly, so there is nothing to
create first. Count is capped at 1000; if a time limit or cancel cuts the search
short you get what was found, and the UI says so.

## How it works

The hot loop allocates nothing. Per candidate:

1. `Blake2b-256(seed ‖ index_be_u32)` → private key
2. `Blake2b-512(private_key)` → clamp first 32 bytes → scalar
3. one fixed-base scalar multiplication (`curve25519-dalek`)
4. one masked `u64` compare against the target prefix

Only a match is formatted into a string.

### Two ways to search, and why both exist

Every 32-byte value is a valid Ed25519 seed, so a grinder that fills 32 bytes
from a CSPRNG and hashes *that* produces real, spendable private keys. What it
cannot produce is an **account**. A Nano account is defined by
`Blake2b-256(seed ‖ index)` for `index < 2^32`; a random 32-byte private key is
(almost surely) not in that image, so there is no seed and no index that
regenerates it. That is the whole reason this tool reports a seed and index
rather than just a key: the seed-relative form is what wallets, backups, and
address↔account tooling all assume.

Which of the two you want depends on where you want the vanity address to sit.

**Default: search one seed's index space.** Every hit is reported as
`(seed, index)` plus the private key. The seed is fixed, the search walks
indices upward, and the results are the lowest matching indices — reproducible,
and cheap for short prefixes.

```sh
nano-vanity 1111
```

**`--grind`: search candidate seeds at a fixed index.** A seed has exactly one
account at index 0, so capping the index can never move a match onto account 0 —
the only way to do that is to change the seed itself. `--grind` makes a fresh
candidate seed the variable and holds the index at 0, which is what makes
"import the seed and the vanity address is your first account" true.

```sh
nano-vanity 1test --grind
```

Both modes print the wallet seed with the result, so either workflow ends with
something you can write down and restore.

The cost is a hard `2^32` ceiling on distinct candidates per seed (fine up to
about 7 characters, where expected work is `2^31`) and one extra Blake2b-256 per
candidate. That hash is 0.5% of the loop (see below), so the search space choice
is effectively free at this scale; the only real limitation is that exhausting
2^32 candidates on a phone takes ~20 hours.

### Correctness

Design choices that make the output verifiable:

- The **exact private key is printed**, so any wallet can import it directly.
- Cross-checked end-to-end against an **independent pure-Python
  implementation** of Edwards-curve arithmetic and Blake2b
  (`research/cross_check.py` reproduces the binary's private key and address
  from the printed index).
- Addresses are re-validated by a checksum-checking decoder, and the encoder is
  verified in both directions.

## Performance (measured on a Huawei Kirin 710, 8-core)

| Threads | addr/s | Scaling |
|---|---|---|
| 1 | 12,593 | — |
| 2 | 25,298 | 2.01x |
| 4 | 49,242 | 3.91x |
| 8 | 60,880 | 4.83x |

Scaling goes sublinear at 8 threads because the SoC is **big.LITTLE** (4x
1.709 GHz + 4x 2.189 GHz); the slow cluster saturates. Sustained 40s runs showed
no thermal throttling (~7% drift).

Wall-clock per address is ~79 us single-threaded. A micro-profile of the hot
loop shows where it goes:

| Stage | ns/op | share |
|---|---|---|
| `Blake2b-256(seed ‖ idx)` | 374 | 0.5% |
| `Blake2b-512(priv)` | 369 | 0.5% |
| `scalar · B` (precomputed tables) | 62,007 | 79% |
| `compress()` (field inversion) | 16,434 | 21% |
| **full loop** | **78,915** | 100% |

The scalar multiply dominates, so **hashing is not worth optimizing** — swapping
`blake2` for `blake2b_simd` would move total throughput by under 1%. Fixed-base
precomputed tables *are* active (`curve25519-dalek` 4.1.3 enables
`precomputed-tables` by default, and `ED25519_BASEPOINT_TABLE` is feature-gated
on it, so the code would not compile otherwise). The remaining cost is ~1.3x
above what a desktop-class core achieves for the same operations, which is
expected for an in-order/low-clock mobile core.

Note that dalek 4.1.3 has **no NEON/SIMD backend for aarch64** — its vectorized
backend is gated to `x86_64` only, so `-C target-feature` tuning cannot reach the
field arithmetic here.

**This is not desktop/GPU-class throughput.** Expect ~60k addr/s here versus
millions per second on a desktop CPU or ~20M/s on a discrete GPU, so
multi-character prefixes are impractical on a phone.

Benchmarks live in [`ERRATA.md`](ERRATA.md#performance-measured-not-assumed),
including why forcing `-C target-feature=+sha3,+aes` made things ~24% *slower*.

## Termux notes

- `pkg install rust` only — `rustup` has no aarch64-linux-android toolchain.
- Use `cargo build --release -j 2`; Android's low-memory killer can otherwise
  kill `rustc`. This is deliberately *not* committed, because it would halve
  build time for everyone else. On Termux, create it locally:
  ```sh
  mkdir -p .cargo
  printf '[build]\njobs = 2\n' > .cargo/config.toml
  ```
- Avoid crates needing glibc (e.g. `openssl-sys`); they will not link against
  Bionic.
- For long grinds: plug in and run `termux-wake-lock`.
- All dependencies are pure Rust and build cleanly on aarch64.

## Continuous integration and releases

`.github/workflows/ci.yml` runs the test suite on Linux, macOS and Windows, plus
`cargo fmt --check`, `cargo clippy -D warnings`, and the independent Python
cross-check on every push and pull request.

`.github/workflows/release.yml` publishes binaries automatically when a version
tag is pushed:

```sh
git tag v0.1.0
git push origin v0.1.0
```

That produces a GitHub release with `nano-vanity-android-arm64`,
`nano-vanity-linux-amd64`, `nano-vanity-windows-amd64.exe`, and a
`SHA256SUMS` file. The Android target is cross-compiled with the Android NDK
(needed only for the linker — every dependency is pure Rust); Windows is built
natively on `windows-latest` rather than cross-compiled.

## Layout

```
nano-vanity/
├── .github/workflows/    # CI, and tag-triggered releases for 3 targets
├── Cargo.toml            # workspace
├── README.md             # usage, cost table, measured performance
├── INSTALL.md            # install guides: Termux, Ubuntu, Windows
├── LICENSE               # MIT
├── NOTICE                # third-party attribution: Nault
├── NANO_VANITY_PLAN.md   # corrected project plan
├── ERRATA.md             # what the common recipe gets wrong, and the evidence
├── nano-keys/            # library: seed -> key -> public key -> address
│   └── examples/profile.rs   # micro-profile of the hot loop
├── nano-vanity/          # binary
│   └── src/
│       ├── engine.rs     # shared search engine (CLI + web)
│       ├── main.rs       # CLI front-end
│       └── web.rs        # dependency-free local web UI
└── research/             # independent Python cross-checks
    ├── cross_check.py    # re-derives the binary's results from scratch
    └── checksum.py       # shows why the checksum is Blake2b-5 reversed
```

Run the independent cross-check after any change to the crypto:

```sh
python3 research/cross_check.py
```

It re-implements the derivation in Python, checks a published docs.nano.org
vector, then re-derives four live results from the seeds the binary printed.
It exits non-zero on any disagreement.

## License

MIT. See [`LICENSE`](LICENSE).