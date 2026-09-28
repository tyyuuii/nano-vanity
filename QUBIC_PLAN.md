# Qubic crypto research + plan

Branch `Qubic-test`. **Research is complete and sourced; implementation has
not started.** Everything below was read out of the reference implementations,
not inferred from blog posts.

Sources, all fetched into `research/qubic/`:

| File | What it gave us |
|---|---|
| `key_utils.cpp` (qubic-cli, C++) | The authoritative C derivation chain |
| `k12_and_key_utils.h` (qubic-cli, C++) | KangarooTwelve implementation, 177KB |
| `identity.ts`, `fourq.ts`, `fq.ts`, `fp.ts`, `k12.ts` (qubic-typescript) | Pure-TS port, the most readable form of the same algorithm |
| `__tests__/*.test.ts` | Official test vectors |
| `vectors/qubic_vectors.json` | Golden vectors we generated with the official npm package |

---

## 1. The derivation, end to end

Verified against `@qubic.org/crypto` (`qubic-typescript`, the official port of
the C++ reference).

```
seed: 55 lowercase ASCII letters
  │
  ├─ each char c  →  byte (c - 'a'), so 55 bytes each in [0, 25]
  │
  ├─ subseed     = K12(55 bytes)                     [32 bytes]
  │
  ├─ privateKey  = K12(subseed)                      [32 bytes]
  │                (raw — NO clamping; reduction happens inside the curve)
  │
  ├─ publicKey   = FourQ scalarBaseMult(privateKey)  → compress  [32 bytes]
  │
  └─ identity    = 60 uppercase letters
                   56 from the public key, 4 from a K12 checksum
```

**That is the whole thing.** Two K12 hashes and one FourQ scalar multiply.
Everything else in this document is a consequence of those two facts.

### 1.1 Subseed and private key

From `key_utils.cpp`:

```cpp
for (int i = 0; i < 55; i++) {
    if (seed[i] < 'a' || seed[i] > 'z') return false;
    seedBytes[i] = seed[i] - 'a';
}
KangarooTwelve(seedBytes, sizeof(seedBytes), subseed, 32);   // 55 -> 32
```

```cpp
void getPrivateKeyFromSubSeed(const uint8_t* seed, uint8_t* privateKey)
{ KangarooTwelve(seed, 32, privateKey, 32); }                 // 32 -> 32
```

The Qubic blog calls this "K12 hashed twice". Confirmed in the source.

**No clamping, and that is not an omission.** The private key is a raw 32-byte
value. `recodeScalar` in `fourq.ts` begins with `condAddOrderN(m)`, which
conditionally adds the group order to bring the scalar into range before
recoding. Same situation as Nano: a clamped scalar can exceed the order, and
`s·B = (s mod n)·B` because the generator has order n.

### 1.2 The identity encoding — this is the part that will bite

From `identity.ts`, confirmed line-for-line against the C++:

```ts
for (let fragmentIndex = 0; fragmentIndex < 4; fragmentIndex++) {
  let fragment = view.getBigUint64(fragmentIndex * 8, true)   // little-endian!
  for (let digitIndex = 0; digitIndex < 14; digitIndex++) {
    identity[fragmentIndex * 14 + digitIndex] = Number(fragment % 26n) + 65
    fragment /= 26n
  }
}
```

Three things here, and each one is a way to get it wrong:

1. **The 32-byte public key is read as four 8-byte fragments, little-endian.**
   Fragment 0 is `pk[0..8]`, fragment 1 is `pk[8..16]`, and so on.

2. **Each fragment becomes 14 base-26 digits written least-significant first.**
   `identity[0]` is `fragment % 26` — the *lowest* digits of the *lowest* bytes.

3. **4 × 14 = 56 characters**, then 4 checksum characters. Total 60.

**So a Qubic identity's first character depends on the LOW bits of the public
key, not the high bits.** This is the exact opposite of Nano, where `enc52`
emits most-significant-digit first. Any mental model carried over from the
Nano side of this repo will produce valid-looking, permanently wrong addresses.

The reason 14 digits suffice: 26¹³ ≈ 2.48e18 < 1.8e19 = 2⁶⁴, so all 14 digits
are actually used.

### 1.3 The checksum

```ts
const checksumBytes = k12(publicKey, 3)          // 3 bytes
let checksum = b0 | (b1 << 8) | (b2 << 16)        // little-endian
checksum &= 0x3ffffn                             // 18 bits
for (let i = 0; i < 4; i++) { out[i] = checksum % 26n + 65; checksum /= 26n }
```

18 bits into 4 base-26 digits (26⁴ = 456,976 > 262,144 ✓). Identical
structure to Nano's Blake2b-5 checksum, but a different hash, a different
mask, and — crucially — placed at the **end**.

### 1.4 K12

`k12.ts` in its entirety:

```ts
import { kt128 } from '@noble/hashes/sha3-addons.js'
export function k12(input: Uint8Array, outputLength = 32): Uint8Array {
  return kt128(input, { dkLen: outputLength })
}
```

KangarooTwelve — a Keccak-256-based tree hash with variable output length.
**Not** NIST SHA3 (different padding) and **not** Blake2b.

Confirmed against the official KangarooTwelve spec vector, which we now hold:

```
K12(empty, 32) = 1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e5
```

### 1.5 The curve: FourQ, not Ed25519

Both are twisted Edwards curves, which makes it tempting to reuse dalek. **Do
not.** From `fp.ts` and `fq.ts`:

- `P = (1n << 127n) - 1n` — the base field is **Fp = 2¹²⁷ − 1**, a 127-bit
  prime. Not 2²⁵⁵ − 19.
- `Fq` is a **quadratic extension**: every Fq element is two Fp elements,
  `SIZE_FP * 2 = 32` bytes.
- `fpToBytes` is little-endian, and `fqToBytes` writes the real part first,
  then the imaginary part.
- Compression: `out = LE(Y)`, then `out[31] |= ((1 - sign(X)) >> 1) << 7`.

So the compressed public key is 32 bytes = Re(Y) ‖ Im(Y), little-endian, with
the sign of X in bit 7 of the last byte. Structurally similar to a compressed
Edwards point; arithmetically unrelated to it.

---

## 2. What we have verified, and how

Six golden vectors in `research/qubic/vectors/qubic_vectors.json`, generated by
running the **official** `@qubic.org/crypto` package under node — not by our
own port, which is the whole point. Each one records subseed, private key,
public key and identity, and each round-trips through
`identityToPublicKey` with a valid checksum.

```
aaaa…aaaa (55 a's)  BZBQFLLBNCXEMGLOBHUVFTLUPLVCPQUASSILFABOFFBCADQSSUPNWLZBQEXK
zzzz…zzzz (55 z's)  ZSDAHLHNHVWTEDYXRTTDWNKGRVPAFQKNTOUXPOXSCDGOPTMUJFWPVATFXHPG
abab…abab           ORDJDHAOLGPLDCDFRSHAMZAERVDBPAENYMBVGUTDKHHLCLMAULIVHCQEQCVK
lcehvbv…ufnkkuf     EPYWDREDNLHXOFYVGQUKPHJGOMPBSLDDGZDPKVQUMFXAIQYMZGEHPZTAAWON
qqqq…qqqq (55 q's)  BZVYNEUTPXQBUEDENLWEXKSCTBECIAQOWPOETKHDIFNCXJEDIENYWHFBAZPM
mmmm…mmmm (55 m's)  AFRXCAJVXLETZBTWTCJREEXDLCLARUTUXAHKHVKREHTCJKUMDGKWIQLGDNKO
```

**The strongest single check is the contract vector.** A contract address is
just the identity of a tiny public key — a little-endian integer with the
index in the first bytes:

```
contract 1 → BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARMID
contract 2 → CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACNKL
contract 4 → EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAVWRF
```

Index 1 → `B`, index 2 → `C`, index 4 → `E`. That is base-26 LSB-first with
`A`=0 confirmed by the official docs' own QUTIL address for index 4, which
matches character for character. **This validates the fragment split, the
endianness, and the digit order in one shot**, using a completely different
derivation path than the seed path.

### Things we are deliberately *not* claiming

- No real-network round trip has been done. We have not sent a transaction or
  queried a node. Never use a funded seed for testing.
- The vectors are from the npm package, not from a mainnet node. If the network
  ever forks from that, we would not know. `identityToPublicKey` validates the
  checksum only, not that a key has an on-chain balance.
- `schnorrq.ts` and the vault format are **out of scope**. This is a search
  tool, not a wallet.

---

## 3. The structural difference that drives the whole design

### Qubic has no seed index. Nano has one.

Nano's derivation is `Blake2b-256(seed ‖ index_be)`, so one seed yields
2³² distinct accounts and a vanity search grinds *indices* — the seed is fixed
and the user keeps it.

Qubic's `deriveKeys(seed)` takes **no index parameter**. One 55-letter seed
maps to exactly one identity, permanently. The only way to get a different
identity is a different seed.

Consequences:

- **There is no "search indices" mode.** Every search is a seed search.
- The seed is the private key material. Publishing a winning seed *is*
  publishing the wallet, exactly as with Nano's `--grind` mode.
- Search space is 26⁵⁵ ≈ 10⁷⁷, uniformly sampled by K12, so the difficulty
  curve is identical to Nano's: an L-character prefix needs 26ᴸ tries on
  average, i.e. 2^(5.02·L).

The user-facing story is therefore *different* from Nano even though the
search cost is the same: a Qubic vanity seed is the wallet.

### Performance will be worse than Nano, and the plan says so up front

The reference `scalarBaseMult` is a Montgomery ladder with **no precomputed
base table**:

```ts
const tabQ = oddMultiples(Q)      // recomputed on every call
for (let i = 64; i >= 0; i--) { P = pointDouble(P); P = pointDouble(P); ... }
```

That is 64 rounds × (2 doublings + 1 conditional add) ≈ **192 point
operations**, over a 32-byte quadratic extension field. Nano's dalek path is
**64 point additions** with a precomputed table, over a 32-byte prime field.

So the naive port should land somewhere around **20–30k addr/s** on this
phone, i.e. roughly a third of Nano's rate, before any optimisation.

---

## 4. Plan

### Step 0 — K12 in Rust, verified first *(1–2 days, gate)*

Everything else depends on this and it is the one piece with no obvious Rust
equivalent.

- [ ] Implement K12 (Keccak-p sponge + K12 finalisation) — `tiny-keccak` gives
      the permutation and the original-padding Keccak, so this is a few
      hundred lines, not a research project
- [ ] **Gate: `K12(empty, 32) == 1ac2d450…f39e5`**, the official spec vector
- [ ] Cross-check every K12 call the derivation makes against node

### Step 1 — FourQ field and point arithmetic *(3–5 days, gate)*

- [ ] Fp = 2¹²⁷−1 arithmetic, then the quadratic extension Fq
- [ ] `pointDouble`, `pointAdd`, `toAffine`, `fqToBytes`/`fqSgn`
- [ ] `recodeScalar` with `condAddOrderN`, and the 65-digit radix-16 recoding
- [ ] **Gate: all six golden vectors reproduce byte-for-byte**, including
      `subseed` and `privateKey`, not just the final identity
- [ ] Gate: contract 1/2/4 produce the `BAAA…`/`CAAA…`/`EAAA…` identities

### Step 2 — A correct, boring engine first

- [ ] `--derive <SEED>` mirroring Nano's, printing subseed/private/public/identity
- [ ] `research/qubic_cross_check.py` — an independent Python implementation,
      in the same spirit as the existing `cross_check.py`, arbitrating Rust
      against Python against the npm package
- [ ] Ship this before optimising anything. A slow correct tool beats a fast
      wrong one, and that ordering is the lesson of §1.2

### Step 3 — Speed, in the order the evidence supports

- [ ] **Measure the split first.** Hash vs ladder vs `toAffine`, with a
      `breakdown` example modelled on the existing one. Do not guess
- [ ] **Replace the ladder with a precomputed fixed-base comb.** This is the
      single biggest available win: ~192 point ops → ~64 additions, the same
      3x that made dalek's table worthwhile on the Nano side
- [ ] **Batch the `toAffine` inversions** with Montgomery's trick, one
      inversion per block instead of one per candidate
- [ ] Compare only the identity characters actually being matched

### Step 4 — Search, GUI, and the seed-safety problem

- [ ] Prefix / suffix / contains over the 60-char identity
- [ ] Since only seeds can be searched, the tool must make the implication
      unmissable: a found seed **is** the wallet
- [ ] `--web` GUI, if the existing one is generalised rather than duplicated
- [ ] The web server already defaults to loopback "because it exposes seeds and
      private keys". That reasoning applies more strongly here, not less

### Deliberately out of scope

`SchnorrQ` signatures, the AES-GCM vault (`qvault`), transaction building,
node RPC, and anything that touches a funded seed.

---

## 5. Open questions to resolve during Step 1

1. **Is there a seed index after all?** The npm docs for `@qubic-labs/core`
   mention `privateKeyFromSeed(seed, index?)`, but the official
   `qubic-typescript` `deriveKeys(seed)` has no such parameter. The former is
   likely a different or older API. **Resolve this before designing the search
   engine**, because it decides whether a seed can yield more than one identity.
2. **What is the exact group order `n`?** Needed for `condAddOrderN`. It is in
   `fourq-constants.ts`; read it from there rather than transcribing it from
   this document.
3. **Are there hidden constraints on the seed alphabet?** The C++ rejects any
   non-lowercase character. Whether the on-chain genesis has further
   constraints is not answered by the client libraries.

## 6. A note on scope

This is a second blockchain in a repository that currently has exactly one, and
it shares **no cryptography** with it: different hash (K12 vs Blake2b), different
curve (FourQ vs Ed25519), different encoding (base-26 LSB-first vs base-32
MSB-first), different search model (seed-only vs seed+index).

The reusable part is the *harness* — the engine's block claiming, the web GUI,
the CLI shape, the cross-check discipline — not a single line of crypto. The
honest structure is a new `qubic-keys` crate beside `nano-keys`, and it must not
be folded into `nano-keys` "because the shape is similar". The shape is
similar; the arithmetic is not, and §1.2 is exactly the trap that similarity
sets.
