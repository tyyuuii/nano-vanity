# Nano Vanity Address Generator in Rust — Corrected Plan (Termux, no proot)

> **Status: implemented and verified.** See [`README.md`](README.md) for usage and
> [`ERRATA.md`](ERRATA.md) for the evidence behind every correction below.
> 20 tests pass, cross-checked against an independent implementation.

## ⚠️ Errata — the original plan is wrong in three places

Every claim below was re-derived and verified against **real vectors from
docs.nano.org**. See `research/` for the throwaway probes and
`nano-keys/src/lib.rs` for the authoritative implementation.

| # | Original plan said | Reality (verified) |
|---|---|---|
| 1 | `privkey = Blake2b-**512**(seed‖idx)[..32]` then clamp | `privkey = Blake2b-**256**(seed‖idx_le_u32)`. **No clamping here.** |
| 2 | `private_scalar_to_public(scalar)` multiplies the seed hash directly | The 32-byte privkey is an *Ed25519 seed*: `h = Blake2b-512(privkey)`, `scalar = clamp(h[..32])`, then `scalar·B`. |
| 3 | checksum = `Blake2b-**256**(pk)[..5]` reversed | checksum = `Blake2b-**5**(pk)` reversed. Blake2b's output length is part of its parameter block, so a 5-byte digest ≠ the first 5 bytes of a 32-byte digest. |

Also: the "zero seed" test vector in the plan is bogus. Its address
`nano_1111…hifc8npp` is the **burn address**, i.e. the encoding of a zero
**public key**, which is not the zero seed's public key. It is a fine test —
for `public_key_to_address([0u8;32])`, not for seed derivation.

### The actual Nano key-derivation pipeline

```
Seed (32 B) ── Blake2b-256(seed ‖ index_le_u32) ──► privkey (32 B)          "the seed" per account
privkey     ── Blake2b-512 ──► h (64 B)
                            scalar = clamp(h[0..32])                        scalar[0]&=248; scalar[31]&=127; scalar[31]|=64
                            pubkey = scalar · B  (Ed25519 base point)
pubkey      ──► "nano_" + enc52(pubkey) + enc8(reverse(Blake2b-5(pubkey)))
```

`enc52` treats the pubkey as a **260-bit big-endian integer (4 leading zero
bits)** → 52 chars. `enc8` treats 5 bytes as a 40-bit BE integer → 8 chars.
Alphabet: `13456789abcdefghijkmnopqrstuwxyz`.

### Verified vectors (docs.nano.org/integration-guides/key-management)

| Seed | Index | Private key | Address |
|---|---|---|---|
| `D56143E7…E8BE4E5` | 0 | `1F6FEB5D…794E3E` | `nano_16odwi933gpzmkgdcy9tt5zef5ka3jcfubc97fwypsokg7sji4mb9n6qtbme` |
| `D56143E7…E8BE4E5` | 1 | `CE7E429E…CB1A83` | `nano_3phqgrqbso99xojkb1bijmfryo7dy1k38ep1o3k3yrhb7rqu1h1k47yu78gz` |
| (pubkey all zeros) | — | — | `nano_1111111111111111111111111111111111111111111111111111hifc8npp` |

Encoding is independently confirmed by 52-char round-trip decode.

## Environment (measured)

- Termux aarch64-linux-android, `rustc 1.98.1` from `pkg install rust` (no rustup), 8 CPUs, ~5.7 GB RAM.

## Layout

```
nan/
├── NANO_VANITY_PLAN.md      # this file
├── README.md                # usage
├── ERRATA.md                # deeper notes + how each fact was verified
├── Cargo.toml               # workspace
├── nano-keys/               # library: seed → address
└── nano-vanity/             # binary: multi-threaded prefix grinder
```

## Performance: measured, not asserted

The original plan's "2× / 1.5× / +10%" multipliers were **not** verified on ARM
and are not quoted here. Measured on this device instead:

| Threads | addr/s | Scaling |
|---|---|---|
| 1 | 12,593 | — |
| 2 | 25,298 | 2.01× |
| 4 | 49,242 | 3.91× |
| 8 | 60,880 | 4.83× |

Scaling goes sublinear at 8 threads because the SoC is big.LITTLE
(4× 1.709 GHz + 4× 2.189 GHz); the slow cluster saturates. No thermal throttling
over a sustained 40 s run (~7% drift).

Also: forcing `-C target-feature=+sha3,+aes` measured ~24% **slower**. SHA-3/AES
are irrelevant to Blake2b, and the plan's x86 `avx2` advice does not apply on
aarch64 (NEON is selected by the backend).

## What the plan got wrong (summary)

1. `privkey = Blake2b-**256**(seed ‖ index)`, not `Blake2b-512(…)[..32]`, and it is **not** clamped here.
2. The private key is an Ed25519 seed: hash it **again** with Blake2b-512, then clamp, then multiply.
3. The checksum is a dedicated `Blake2b-**5**(pubkey)` reversed — not a truncated 32-byte digest.
4. `nano_1111…hifc8npp` is the **burn address** (zero *public key*), not the zero seed's address.
5. A 4-char prefix is ~6.6e4 tries, not ~1e6: character 0 is only ever `1` or `3`.
6. A random 32-byte seed + index is **not** importable as a private key; the tool prints an importable seed/index pair instead.