//! # nano-keys
//!
//! Nano (XNO) key derivation, verified against real vectors from
//! <https://docs.nano.org/integration-guides/key-management/>.
//!
//! ## Pipeline
//!
//! ```text
//! Seed (32 B) ── Blake2b-256(seed ‖ index_le_u32) ──► private key (32 B)
//! private key ── Blake2b-512 ──► h (64 B)
//!                             scalar = clamp(h[0..32])
//!                             public key = scalar · B   (Ed25519 base point)
//! public key  ──► "nano_" + enc52(pubkey) + enc8(reverse(Blake2b-5(pubkey)))
//! ```
//!
//! ### Three traps this crate deliberately avoids
//!
//! 1. The private key is `Blake2b-**256**(seed ‖ index)`, *not* `Blake2b-512`.
//! 2. The 32-byte private key is an **Ed25519 seed**: it is hashed *again* with
//!    Blake2b-512 and the first half is clamped. It is not used as a scalar directly.
//! 3. The address checksum is a **dedicated Blake2b-5** digest. Blake2b's output
//!    length is part of its parameter block, so `Blake2b-5(pk)` is *not* the first
//!    5 bytes of `Blake2b-32(pk)`.

use blake2::digest::consts::{U32, U5};
use blake2::{Blake2b, Blake2b512, Digest};
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;

/// Nano's custom Base32 alphabet (RFC 4648 without `0`, `2`, `l`, `v`).
pub const ALPHABET: &[u8; 32] = b"13456789abcdefghijkmnopqrstuwxyz";

/// Length of the address body (public key + checksum) in characters.
pub const BODY_LEN: usize = 60;
/// Length of the encoded public key in characters.
pub const PUBLIC_KEY_CHARS: usize = 52;
/// Length of the encoded checksum in characters.
pub const CHECKSUM_CHARS: usize = 8;
/// Full address length including the `nano_` prefix.
pub const ADDRESS_LEN: usize = 65;

/// Reverse lookup table: ASCII byte -> base32 value (`0xff` = invalid).
const fn build_decode_table() -> [u8; 256] {
    let mut t = [0xffu8; 256];
    let mut i = 0;
    while i < 32 {
        t[ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    t
}
static DECODE: [u8; 256] = build_decode_table();

#[inline]
fn decode_char(c: u8) -> Option<u8> {
    match DECODE[c as usize] {
        0xff => None,
        v => Some(v),
    }
}

// ---------------------------------------------------------------------------
// Step 1: seed + index -> private key
// ---------------------------------------------------------------------------

/// Derives the account private key for `index` from a 32-byte wallet seed.
///
/// This is `Blake2b-256(seed ‖ index.to_be_bytes())`. Note the 256-bit output:
/// the widely-copied `Blake2b-512(...)[..32]` variant yields a *different*,
/// incorrect key.
///
/// The index is **big-endian**. This is stated by docs.nano.org ("i is a 32-bit
/// big-endian unsigned integer") and matches every reference implementation:
/// nanopy's `index.to_bytes(4, byteorder="big")` and nanopyrs's
/// `i.to_be_bytes()`. The choice only becomes visible for a non-zero index, so
/// an index-0 test vector cannot detect the wrong byte order — see
/// `index_is_big_endian` below.
pub mod qubic;

pub fn derive_private_key(seed: &[u8; 32], index: u32) -> [u8; 32] {
    let mut h = Blake2b::<U32>::new();
    h.update(seed);
    h.update(index.to_be_bytes());
    let out = h.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out);
    key
}

/// Derives the **private key** (an Ed25519 seed) for `(seed, index)`.
///
/// This is `Blake2b-256(seed ‖ index_le_u32)`. It is *not* a clamped scalar:
/// clamping happens later, inside [`expand_private_key`].
///
/// The old plan called this `seed_to_private_scalar`, which was a misnomer —
/// see `ERRATA.md`.
#[inline]
pub fn seed_to_private_key(seed: &[u8; 32], index: u32) -> [u8; 32] {
    derive_private_key(seed, index)
}

// ---------------------------------------------------------------------------
// Step 2: private key -> public key
// ---------------------------------------------------------------------------

/// Ed25519 clamping, as used by Nano.
#[inline]
pub fn clamp(scalar: &mut [u8; 32]) {
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;
}

/// Expands a private key into the clamped 32-byte scalar used for multiplication.
///
/// This is `clamp(Blake2b-512(private_key)[0..32])`.
pub fn expand_private_key(private_key: &[u8; 32]) -> [u8; 32] {
    let h = Blake2b512::digest(private_key);
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&h[..32]);
    clamp(&mut scalar);
    scalar
}

/// Multiplies the Ed25519 base point by an already-clamped scalar.
///
/// The scalar is reduced modulo the group order ℓ internally, which is exactly
/// what Ed25519 does: a clamped scalar is ≥ 2^254 > ℓ, and `s·B = (s mod ℓ)·B`
/// because `B` has order ℓ.
pub fn private_scalar_to_public(scalar_bytes: &[u8; 32]) -> [u8; 32] {
    let scalar = Scalar::from_bytes_mod_order(*scalar_bytes);
    let point = ED25519_BASEPOINT_TABLE * &scalar;
    point.compress().to_bytes()
}

/// Full private key -> public key conversion (expand, then multiply).
#[inline]
pub fn private_key_to_public(private_key: &[u8; 32]) -> [u8; 32] {
    private_scalar_to_public(&expand_private_key(private_key))
}

/// Returns the clamped scalar for a private key as a `Scalar`.
#[inline]
pub fn private_key_to_scalar(private_key: &[u8; 32]) -> Scalar {
    Scalar::from_bytes_mod_order(expand_private_key(private_key))
}

// ---------------------------------------------------------------------------
// Step 3: public key -> address
// ---------------------------------------------------------------------------

/// `reverse(Blake2b-5(public_key))`.
///
/// Blake2b-5 is a real 5-byte-output Blake2b, not a truncated 32-byte digest.
pub fn checksum(public_key: &[u8; 32]) -> [u8; 5] {
    let mut h = Blake2b::<U5>::new();
    h.update(public_key);
    let out = h.finalize();
    let mut c = [0u8; 5];
    c.copy_from_slice(&out);
    c.reverse();
    c
}

/// Encodes `n` bytes (n*8 must be a multiple of 5) as big-endian base32.
#[inline]
fn encode_base32_exact(bytes: &[u8], out: &mut [u8]) {
    debug_assert_eq!(bytes.len() * 8, out.len() * 5);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut o = 0usize;
    for &b in bytes {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out[o] = ALPHABET[((acc >> bits) & 0x1f) as usize];
            o += 1;
        }
    }
    debug_assert_eq!(o, out.len());
}

/// Encodes a public key as 52 base32 characters.
///
/// The key is treated as a **260-bit** big-endian number (4 leading zero bits),
/// which is why the first character is always `1` or `3`.
pub fn encode_public_key(public_key: &[u8; 32]) -> String {
    let n = U256::from_be_bytes(public_key);
    let mut out = [0u8; PUBLIC_KEY_CHARS];
    for (i, slot) in out.iter_mut().enumerate() {
        let shift = 255 - 5 * i as u32;
        *slot = ALPHABET[n.shr(shift).low32() as usize & 0x1f];
    }
    // Safe: every byte came from ALPHABET.
    String::from_utf8(out.to_vec()).expect("alphabet is ASCII")
}

/// Decodes 52 base32 characters back into a public key.
pub fn decode_public_key(s: &str) -> Option<[u8; 32]> {
    if s.len() != PUBLIC_KEY_CHARS {
        return None;
    }
    let mut n = U256::ZERO;
    for (i, c) in s.bytes().enumerate() {
        let v = decode_char(c)?;
        // The 52 chars encode 260 bits, but the top 4 must be zero: the leading
        // 5-bit group is just bit 255 of the public key, so it is 0 or 1.
        // Anything else would silently lose bits in the U256 accumulator.
        if i == 0 && v > 1 {
            return None;
        }
        n = n.shl5().or_low(v);
    }
    Some(n.low_256_be())
}

/// Encodes a public key directly into a 60-byte address body buffer.
#[inline]
pub fn encode_address_body(public_key: &[u8; 32], out: &mut [u8; BODY_LEN]) {
    let n = U256::from_be_bytes(public_key);
    for (i, slot) in out.iter_mut().enumerate().take(PUBLIC_KEY_CHARS) {
        let shift = 255 - 5 * i as u32;
        *slot = ALPHABET[n.shr(shift).low32() as usize & 0x1f];
    }
    encode_base32_exact(&checksum(public_key), &mut out[PUBLIC_KEY_CHARS..]);
}

/// The full 60-character address body (52 key characters + 8 checksum
/// characters), without the `nano_` prefix.
///
/// Distinct from [`encode_public_key`], which returns only the 52 key
/// characters. Anything matching the *end* of an address must use this, because
/// the last 8 characters are the checksum and not key material.
pub fn encode_body_string(public_key: &[u8; 32]) -> String {
    let mut body = [0u8; BODY_LEN];
    encode_address_body(public_key, &mut body);
    // Safe: every byte came from ALPHABET.
    String::from_utf8(body.to_vec()).expect("alphabet is ASCII")
}

/// Encodes a full `nano_…` address.
pub fn public_key_to_address(public_key: &[u8; 32]) -> String {
    let mut body = [0u8; BODY_LEN];
    encode_address_body(public_key, &mut body);
    let mut s = String::with_capacity(ADDRESS_LEN);
    s.push_str("nano_");
    // Safe: every byte came from ALPHABET.
    s.push_str(std::str::from_utf8(&body).expect("alphabet is ASCII"));
    s
}

// ---------------------------------------------------------------------------
// Convenience / full pipeline
// ---------------------------------------------------------------------------

/// Derives the address for `(seed, index)`.
pub fn seed_to_address(seed: &[u8; 32], index: u32) -> String {
    public_key_to_address(&private_key_to_public(&derive_private_key(seed, index)))
}

/// Parses a 64-character hex seed.
pub fn parse_seed(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = (s.as_bytes()[2 * i] as char).to_digit(16)?;
        let lo = (s.as_bytes()[2 * i + 1] as char).to_digit(16)?;
        *slot = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

/// Validates a full address, including its checksum.
pub fn is_valid_address(address: &str) -> bool {
    let body = match address
        .strip_prefix("nano_")
        .or_else(|| address.strip_prefix("xrb_"))
    {
        Some(b) => b,
        None => return false,
    };
    if body.len() != BODY_LEN {
        return false;
    }
    let pk = match decode_public_key(&body[..PUBLIC_KEY_CHARS]) {
        Some(pk) => pk,
        None => return false,
    };
    if body[PUBLIC_KEY_CHARS..]
        .bytes()
        .any(|c| decode_char(c).is_none())
    {
        return false;
    }
    let mut expected = [0u8; CHECKSUM_CHARS];
    encode_base32_exact(&checksum(&pk), &mut expected);
    expected[..] == body.as_bytes()[PUBLIC_KEY_CHARS..]
}

// ---------------------------------------------------------------------------
// Fast prefix matching (allocation-free)
// ---------------------------------------------------------------------------

/// Maximum prefix length supported by the fast matcher (60 bits of mask).
pub const MAX_FAST_PREFIX: usize = 12;

/// Bits in the address body: the public key field is 260 bits (256 + 4 offset).
const BODY_BITS: u32 = 260;

/// Matches address-body prefixes against a public key without allocating.
///
/// The prefix is compared literally starting at character 0. Note that the
/// address body is a **260-bit** field (4 leading zero bits), so a prefix of
/// `L` characters occupies bits `[260-5L, 260)` of that field.
#[derive(Debug, Clone)]
pub struct PrefixMatcher {
    expected: u64,
    mask: u64,
    /// `260 - 5*len`; in `200..=255` for `len <= 12`. Lower by 5 when
    /// [`skip_first`](Self::skip_first) is set, so the comparison starts at body
    /// character 1.
    shift: u32,
    len: u8,
    /// When set, the first body character is a wildcard and the prefix is
    /// matched from character 1 onwards.
    skip_first: bool,
}

impl PrefixMatcher {
    /// Builds a matcher for a base32 prefix (without the `nano_` prefix),
    /// anchored at body character 0.
    ///
    /// Returns `None` if the prefix is empty, longer than [`MAX_FAST_PREFIX`],
    /// or contains a character outside [`ALPHABET`].
    pub fn new(prefix: &str) -> Option<Self> {
        Self::build(prefix, false)
    }

    /// Builds a matcher that ignores the leading `1`/`3` and matches the prefix
    /// against body characters 1..len.
    ///
    /// The first body character carries only the public key's most significant
    /// bit, so it is always `1` or `3` — a property of every key, not a choice.
    /// Pinning it to one value therefore costs a factor of ~2 and buys nothing,
    /// whereas leaving it free matches both. A prefix of `len` characters costs
    /// `2^(5*len)` here versus `2^(5*len - 4)` when anchored, so skipping the
    /// first character is both more general and about twice as cheap.
    pub fn new_skipping_first(prefix: &str) -> Option<Self> {
        Self::build(prefix, true)
    }

    fn build(prefix: &str, skip_first: bool) -> Option<Self> {
        let bytes = prefix.as_bytes();
        let len = bytes.len();
        if len == 0 || len > MAX_FAST_PREFIX {
            return None;
        }
        let mut expected: u64 = 0;
        for &c in bytes {
            expected = (expected << 5) | decode_char(c)? as u64;
        }
        let bits = 5 * len as u32;
        // The skipped character sits above the compared range. `len <= 12` keeps
        // this well inside the field, so the subtraction cannot underflow.
        let shift = BODY_BITS - bits - if skip_first { 5 } else { 0 };
        Some(Self {
            expected,
            mask: (1u64 << bits) - 1,
            shift,
            len: len as u8,
            skip_first,
        })
    }

    /// True when the leading `1`/`3` is ignored and matching starts at body
    /// character 1.
    #[inline]
    pub const fn skip_first(&self) -> bool {
        self.skip_first
    }

    /// Number of characters compared.
    #[inline]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// True when the prefix is empty (never, for a valid matcher).
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// True when this prefix can occur at all.
    ///
    /// Character 0 encodes the public key's most significant bit, so the first
    /// character is always `1` (bit 0) or `3` (bit 1). Any other first
    /// character describes an address that cannot exist.
    ///
    /// With [`skip_first`](Self::skip_first) the first typed character lands on
    /// body character 1, which is unconstrained, so every prefix is satisfiable.
    pub fn is_satisfiable(&self) -> bool {
        if self.skip_first {
            return true;
        }
        self.expected >> (5 * (self.len as u32 - 1)) <= 1
    }

    /// Expected number of random public keys tried before a match.
    ///
    /// Anchored: character 0 is uniform over 2 values and every later character
    /// over 32, giving `2^(5*len - 4)`.
    ///
    /// Skipping the first character drops the factor-2 constraint, giving
    /// `2^(5*len)`.
    pub fn expected_tries(&self) -> f64 {
        if self.skip_first {
            2f64.powi(5 * self.len as i32)
        } else {
            2f64.powi(5 * self.len as i32 - 4)
        }
    }

    /// True when an encoded `nano_` address body satisfies this prefix.
    ///
    /// This is the check the hot loop cannot do cheaply, so it is used in
    /// `debug_assert` and in tests. Honouring `skip_first` matters: an anchored
    /// prefix must match from character 0, while a skipping one leaves
    /// character 0 free and requires only that it is `1` or `3`.
    pub fn encoded_matches(&self, body: &str) -> bool {
        let prefix = self.prefix();
        if self.skip_first {
            // Byte indexing rather than `split_first`, which is still unstable.
            match body.as_bytes().split_first() {
                Some((&first, rest)) => {
                    (first == b'1' || first == b'3') && rest.starts_with(prefix.as_bytes())
                }
                None => false,
            }
        } else {
            body.starts_with(&prefix)
        }
    }

    /// Tests a public key against the prefix.
    #[inline(always)]
    pub fn matches(&self, public_key: &[u8; 32]) -> bool {
        let n = U256::from_be_bytes(public_key);
        let top = n.shr(self.shift).low64();
        (top & self.mask) == self.expected
    }

    /// Slow reference implementation, used to validate the fast path in tests.
    pub fn matches_reference(&self, public_key: &[u8; 32]) -> bool {
        self.encoded_matches(&encode_body_string(public_key))
    }

    fn as_prefix_string(&self) -> String {
        let mut s = String::with_capacity(self.len as usize);
        for i in (0..self.len as u32).rev() {
            s.push(ALPHABET[((self.expected >> (5 * i)) & 0x1f) as usize] as char);
        }
        s
    }

    /// The canonical prefix string.
    pub fn prefix(&self) -> String {
        self.as_prefix_string()
    }
}

// ---------------------------------------------------------------------------
// Minimal 256-bit big-endian helper (avoids a bigint dependency)
// ---------------------------------------------------------------------------

/// A 256-bit unsigned integer stored as two `u128` halves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct U256 {
    hi: u128,
    lo: u128,
}

impl U256 {
    pub const ZERO: Self = Self { hi: 0, lo: 0 };

    #[inline]
    pub const fn from_be_bytes(b: &[u8; 32]) -> Self {
        let mut hi_b = [0u8; 16];
        let mut lo_b = [0u8; 16];
        let mut i = 0;
        while i < 16 {
            hi_b[i] = b[i];
            lo_b[i] = b[16 + i];
            i += 1;
        }
        Self {
            hi: u128::from_be_bytes(hi_b),
            lo: u128::from_be_bytes(lo_b),
        }
    }

    /// Logical right shift by `shift` bits (`shift <= 255`).
    #[inline(always)]
    pub const fn shr(self, shift: u32) -> Self {
        if shift == 0 {
            return self;
        }
        if shift >= 256 {
            return Self::ZERO;
        }
        if shift >= 128 {
            Self {
                hi: 0,
                lo: self.hi >> (shift - 128),
            }
        } else {
            Self {
                hi: self.hi >> shift,
                lo: (self.lo >> shift) | (self.hi << (128 - shift)),
            }
        }
    }

    #[inline(always)]
    pub const fn low32(self) -> u32 {
        self.lo as u32
    }

    #[inline(always)]
    pub const fn low64(self) -> u64 {
        self.lo as u64
    }

    /// `(self << 5) | v` where `v < 32`.
    #[inline(always)]
    pub const fn shl5(self) -> Self {
        Self {
            hi: (self.hi << 5) | (self.lo >> 123),
            lo: self.lo << 5,
        }
    }

    /// Logical left shift by `shift` bits (`shift < 256`), discarding overflow.
    #[inline(always)]
    pub const fn shl(self, shift: u32) -> Self {
        if shift == 0 {
            return self;
        }
        if shift >= 128 {
            Self {
                hi: self.lo << (shift - 128),
                lo: 0,
            }
        } else {
            Self {
                hi: (self.hi << shift) | (self.lo >> (128 - shift)),
                lo: self.lo << shift,
            }
        }
    }

    #[inline(always)]
    pub const fn or_low(self, v: u8) -> Self {
        Self {
            hi: self.hi,
            lo: self.lo | v as u128,
        }
    }

    /// Low 256 bits as big-endian bytes.
    #[inline]
    pub const fn low_256_be(self) -> [u8; 32] {
        let hi_b = self.hi.to_be_bytes();
        let lo_b = self.lo.to_be_bytes();
        let mut out = [0u8; 32];
        let mut i = 0;
        while i < 16 {
            out[i] = hi_b[i];
            out[16 + i] = lo_b[i];
            i += 1;
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Vector family A — Nano wallet seed (`Blake2b-256(seed ‖ index)`).
    /// From docs.nano.org/integration-guides/key-management ("Seed: D56143E7…”).
    const VEC_SEED: &str = "D56143E7561D71C1AF4D563C6AF79EECE93E82479818AD8ED88BED1AAE8BE4E5";
    const VEC_SEED0_PRIV: &str = "1f6feb5d1e05c10b904e1112f430c3fa93acc7067206b63ad155199501794e3e";
    const VEC_SEED0_PUB: &str = "12abe40e10badf9c9cb578fad0fec68e480c54dda5472b79eb66b27173180a69";
    const VEC_SEED0_ADDR: &str =
        "nano_16odwi933gpzmkgdcy9tt5zef5ka3jcfubc97fwypsokg7sji4mb9n6qtbme";

    /// Vector family B — SLIP-0010 Ed25519 keys (path 44'/165'/i').
    ///
    /// The *private key* here is produced by SLIP-0010, not by hashing a wallet
    /// seed, so only the privkey -> pubkey -> address half is exercised here.
    /// It still pins the Ed25519 expansion, clamping, and encoding exactly.
    /// These three rows are an exact privkey/pubkey/address triple from
    /// docs.nano.org/integration-guides/key-management.
    const SLIP10: [(&str, &str, &str); 3] = [
        (
            "3be4fc2ef3f3b7374e6fc4fb6e7bb153f8a2998b3b3dab50853eabe128024143",
            "5b65b0e8173ee0802c2c3e6c9080d1a16b06de1176c938a924f58670904e82c4",
            "nano_1pu7p5n3ghq1i1p4rhmek41f5add1uh34xpb94nkbxe8g4a6x1p69emk8y1d",
        ),
        (
            "ce7e429e683d652446261c17a96da9ed1897aea96c8046f2b8036f6b05cb1a83",
            "d9f7762e9cd4e7ed632481308cdb8f54abf0241332c0a8641f61e92e2fb03c12",
            "nano_3phqgrqbso99xojkb1bijmfryo7dy1k38ep1o3k3yrhb7rqu1h1k47yu78gz",
        ),
        (
            "1f6feb5d1e05c10b904e1112f430c3fa93acc7067206b63ad155199501794e3e",
            "12abe40e10badf9c9cb578fad0fec68e480c54dda5472b79eb66b27173180a69",
            "nano_16odwi933gpzmkgdcy9tt5zef5ka3jcfubc97fwypsokg7sji4mb9n6qtbme",
        ),
    ];

    fn hex_to_32(s: &str) -> [u8; 32] {
        let v = hex::decode(s).unwrap();
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        a
    }

    #[test]
    fn vector_seed0_private_key() {
        let seed = parse_seed(VEC_SEED).unwrap();
        assert_eq!(hex::encode(derive_private_key(&seed, 0)), VEC_SEED0_PRIV);
    }

    #[test]
    fn vector_seed0_public_key() {
        let pk = private_key_to_public(&hex_to_32(VEC_SEED0_PRIV));
        assert_eq!(hex::encode(pk), VEC_SEED0_PUB);
    }

    #[test]
    fn vector_seed0_address() {
        let seed = parse_seed(VEC_SEED).unwrap();
        assert_eq!(seed_to_address(&seed, 0), VEC_SEED0_ADDR);
    }

    /// The full privkey -> pubkey -> address chain for all published triples.
    #[test]
    fn slip10_triples_derive_their_documented_addresses() {
        for (priv_hex, pub_hex, addr) in SLIP10 {
            let priv_key = hex_to_32(priv_hex);
            let pub_key = private_key_to_public(&priv_key);
            assert_eq!(hex::encode(pub_key), pub_hex, "pubkey for {priv_hex}");
            assert_eq!(public_key_to_address(&pub_key), addr);
        }
    }

    /// `nano_1111…hifc8npp` is the burn address: the encoding of a **zero public
    /// key**, not of the zero seed. The original plan conflated the two.
    #[test]
    fn burn_address_is_zero_public_key() {
        assert_eq!(
            public_key_to_address(&[0u8; 32]),
            "nano_1111111111111111111111111111111111111111111111111111hifc8npp"
        );
    }

    #[test]
    fn checksum_uses_dedicated_blake2b5() {
        // If this were a truncated Blake2b-32 digest it would not match.
        let pk = hex_to_32(VEC_SEED0_PUB);
        let mut expected = [0u8; 8];
        encode_base32_exact(&checksum(&pk), &mut expected);
        assert_eq!(&expected, &VEC_SEED0_ADDR.as_bytes()[57..]);
    }

    /// Pins the exact distinction that the original plan got wrong: a dedicated
    /// Blake2b-5 digest differs from the first five bytes of Blake2b-32.
    #[test]
    fn blake2b5_is_not_blake2b32_truncated() {
        use blake2::digest::consts::U32 as U;
        let pk = hex_to_32(VEC_SEED0_PUB);
        let mut h32 = Blake2b::<U>::new();
        h32.update(pk);
        let d32 = h32.finalize();
        let c = checksum(&pk);
        let c_rev: Vec<u8> = c.iter().rev().copied().collect();
        assert_ne!(
            &d32[..5],
            &c_rev[..],
            "Blake2b-5 must differ from truncated Blake2b-32"
        );
    }

    /// The zero seed's real index-0 account, independently reproduced.
    /// This is *not* the burn address — see `burn_address_is_zero_public_key`.
    #[test]
    fn zero_seed_index_0_vector() {
        let seed = [0u8; 32];
        assert_eq!(
            hex::encode(derive_private_key(&seed, 0)),
            "9f0e444c69f77a49bd0be89db92c38fe713e0963165cca12faf5712d7657120f"
        );
        assert_eq!(
            seed_to_address(&seed, 0),
            "nano_3i1aq1cchnmbn9x5rsbap8b15akfh7wj7pwskuzi7ahz8oq6cobd99d4r3b7"
        );
    }

    /// Regression test for a real bug: the account index was encoded
    /// little-endian when the protocol specifies **big-endian**.
    ///
    /// docs.nano.org states "i is a 32-bit big-endian unsigned integer", and
    /// both reference implementations agree: nanopy uses
    /// `index.to_bytes(4, byteorder="big")` and nanopyrs uses
    /// `i.to_be_bytes()`.
    ///
    /// The bug survived because every other vector here used index 0, and for
    /// index 0 the two byte orders are byte-for-byte identical. Only a
    /// non-zero index can tell them apart, so these cases pin the order.
    ///
    /// Vectors generated with Python's hashlib, independent of this crate:
    /// `blake2b(seed + i.to_bytes(4, "big"), digest_size=32)`.
    #[test]
    fn index_is_big_endian() {
        let seed = parse_seed("D56143E7561D71C1AF4D563C6AF79EECE93E82479818AD8ED88BED1AAE8BE4E5")
            .expect("valid seed");
        let vectors: &[(u32, &str)] = &[
            (
                0,
                "1f6feb5d1e05c10b904e1112f430c3fa93acc7067206b63ad155199501794e3e",
            ),
            (
                1,
                "7027958b0570df456cb47ff455b3dab6838576557b8fcfa6a33d0d882a2ce5bb",
            ),
            (
                2,
                "07c191ad68beab4ad07cbf324615a2529db16cef0b5f002d97005f8d7931a32d",
            ),
            (
                255,
                "e414dbc68c1430b9a448a7b036ebb17e0917de65e5e50b802847d215da305850",
            ),
            (
                256,
                "0048e0b42a443b1967dce8ffd5679190cbdde015cffee8d3057109b2b7f4add2",
            ),
            (
                65535,
                "7a0d9ba85c8e06226d48598fbae7758c28648a23bb3c89d9d71027d1fef8d170",
            ),
        ];
        for &(index, expected) in vectors {
            assert_eq!(
                hex::encode(derive_private_key(&seed, index)),
                expected,
                "index {index} did not match the big-endian vector"
            );
        }
    }

    /// A test that would have caught the bug before it shipped. Kept separate
    /// because it asserts the *failure* mode directly: little-endian must not
    /// agree for any index above 0.
    #[test]
    fn little_endian_would_be_wrong_for_every_nonzero_index() {
        let seed = parse_seed("D56143E7561D71C1AF4D563C6AF79EECE93E82479818AD8ED88BED1AAE8BE4E5")
            .expect("valid seed");
        for index in [1u32, 2, 255, 256, 65535, 72879] {
            let mut h = Blake2b::<U32>::new();
            h.update(seed);
            h.update(index.to_le_bytes());
            let mut wrong = [0u8; 32];
            wrong.copy_from_slice(&h.finalize());
            assert_ne!(
                derive_private_key(&seed, index),
                wrong,
                "index {index}: little-endian unexpectedly matched, so the test \
                 vector above is not actually distinguishing the byte order"
            );
        }
    }

    #[test]
    fn encode_decode_round_trip() {
        let seed = parse_seed(VEC_SEED).unwrap();
        for index in 0..64 {
            let pk = private_key_to_public(&derive_private_key(&seed, index));
            let encoded = encode_public_key(&pk);
            assert_eq!(encoded.len(), PUBLIC_KEY_CHARS);
            assert_eq!(decode_public_key(&encoded).unwrap(), pk);
        }
    }

    #[test]
    fn address_round_trip_and_validation() {
        let seed = parse_seed(VEC_SEED).unwrap();
        for index in 0..64 {
            let addr = seed_to_address(&seed, index);
            assert_eq!(addr.len(), ADDRESS_LEN);
            assert!(is_valid_address(&addr), "invalid: {addr}");
        }
    }

    #[test]
    fn tampered_address_is_rejected() {
        let seed = parse_seed(VEC_SEED).unwrap();
        let mut addr = seed_to_address(&seed, 0);
        // Flip one body character to a different valid alphabet character.
        let last = addr.pop().unwrap();
        addr.push(if last == '1' { '3' } else { '1' });
        assert!(!is_valid_address(&addr));
    }

    #[test]
    fn first_char_is_one_or_three() {
        let seed = parse_seed(VEC_SEED).unwrap();
        for index in 0..256 {
            let addr = seed_to_address(&seed, index);
            let c = addr.as_bytes()[5];
            assert!(
                c == b'1' || c == b'3',
                "unexpected first char {}",
                c as char
            );
        }
    }

    /// The address-body prefix starts at bit 255 of the key, i.e. bit 259 of the
    /// 260-bit field. Regressing to a 256-bit offset would silently match the
    /// wrong addresses, so pin it against the published encodings.
    #[test]
    fn prefix_offset_is_260_bit_not_256_bit() {
        for (_, pub_hex, addr) in SLIP10 {
            let pk = hex_to_32(pub_hex);
            let body = &addr[5..57];
            for len in 1..=8usize {
                let m = PrefixMatcher::new(&body[..len]).unwrap();
                assert!(m.matches(&pk), "{pub_hex} should match {:?}", &body[..len]);
            }
            // A 256-bit offset would require the key's top bit to be 0 for '1'.
            let m = PrefixMatcher::new("3").unwrap();
            if body.starts_with('3') {
                assert!(m.matches(&pk));
            }
        }
    }

    #[test]
    fn prefix_matcher_agrees_with_strings() {
        let seed = parse_seed(VEC_SEED).unwrap();
        let prefixes = ["1", "3", "1111", "16", "1pu7p5n3", "11111111"];
        let keys: Vec<[u8; 32]> = (0..512)
            .map(|i| private_key_to_public(&derive_private_key(&seed, i)))
            .collect();

        for p in prefixes {
            let m = PrefixMatcher::new(p).unwrap();
            for pk in &keys {
                let expect = encode_public_key(pk).starts_with(p);
                assert_eq!(m.matches(pk), expect, "prefix {p} mismatch");
                assert_eq!(m.matches_reference(pk), expect, "reference {p} mismatch");
            }
        }
    }

    /// '2' is not in the alphabet; '7'..'9' and 'b'..'z' can never lead an
    /// address because character 0 carries the key's top bit only.
    #[test]
    fn unsatisfiable_prefixes_are_flagged_and_never_match() {
        let seed = parse_seed(VEC_SEED).unwrap();
        let keys: Vec<[u8; 32]> = (0..512)
            .map(|i| private_key_to_public(&derive_private_key(&seed, i)))
            .collect();

        for lead in ["7", "9", "a", "z", "b"] {
            let m = PrefixMatcher::new(lead).unwrap();
            assert!(!m.is_satisfiable(), "{lead} should be unsatisfiable");
            assert!(keys.iter().all(|pk| !m.matches(pk)), "{lead} matched");
        }
        for lead in ["1", "3"] {
            let m = PrefixMatcher::new(lead).unwrap();
            assert!(m.is_satisfiable(), "{lead} should be satisfiable");
            assert!(keys.iter().filter(|pk| m.matches(pk)).count() > 100);
        }
    }

    #[test]
    fn expected_tries_matches_the_260_bit_field() {
        // '1' and '3' each appear ~half the time: 2^(5*1-4) = 2.
        assert_eq!(PrefixMatcher::new("1").unwrap().expected_tries(), 2.0);
        // Four characters: 2^16 ~ 65k, not 32^4 ~ 1.05M.
        assert_eq!(
            PrefixMatcher::new("1111").unwrap().expected_tries(),
            65536.0
        );
        assert_eq!(
            PrefixMatcher::new("16odwi93").unwrap().expected_tries(),
            2f64.powi(36)
        );
    }

    #[test]
    fn prefix_matcher_finds_planted_match() {
        let seed = parse_seed(VEC_SEED).unwrap();
        let pk = private_key_to_public(&derive_private_key(&seed, 0));
        let enc = encode_public_key(&pk);
        for len in 1..=MAX_FAST_PREFIX {
            let m = PrefixMatcher::new(&enc[..len]).unwrap();
            assert!(m.matches(&pk), "len {len}");
            // And the matcher must reject a key whose prefix differs.
            let mut other = pk;
            other[0] ^= 0x80;
            let other_enc = encode_public_key(&other);
            if !other_enc.starts_with(&enc[..len]) {
                assert!(!m.matches(&other), "len {len} false positive");
            }
        }
    }

    #[test]
    fn prefix_matcher_rejects_bad_input() {
        assert!(PrefixMatcher::new("").is_none());
        assert!(PrefixMatcher::new("0").is_none()); // '0' is not in the alphabet
        assert!(PrefixMatcher::new(&"1".repeat(MAX_FAST_PREFIX + 1)).is_none());
    }

    #[test]
    fn u256_shift_matches_bigint_semantics() {
        let bytes: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
        let n = U256::from_be_bytes(&bytes);

        // Independent reference: bit `b` (0 = least significant) of the result is
        // bit `b + shift` of the input. In a big-endian array, bit `b` lives in
        // byte `31 - b/8` at position `b%8`.
        let get_bit = |b: usize| -> u8 { (bytes[31 - b / 8] >> (b % 8)) & 1 };
        let reference = |shift: usize| -> [u8; 32] {
            let mut out = [0u8; 32];
            for b in 0..256usize {
                let src = b + shift;
                if src >= 256 {
                    break;
                }
                out[31 - b / 8] |= get_bit(src) << (b % 8);
            }
            out
        };

        // shl(k): bit b of the result is bit (b - k) of the input, and bits
        // below k are zero. Overflow above bit 255 is discarded.
        let reference_shl = |k: usize| -> [u8; 32] {
            let mut out = [0u8; 32];
            for b in k..256usize {
                out[31 - b / 8] |= get_bit(b - k) << (b % 8);
            }
            out
        };

        for shift in 0..=255u32 {
            assert_eq!(
                n.shr(shift).low_256_be(),
                reference(shift as usize),
                "shr {shift}"
            );
            assert_eq!(
                n.shl(shift).low_256_be(),
                reference_shl(shift as usize),
                "shl {shift}"
            );
        }
    }

    #[test]
    fn many_random_like_keys_do_not_panic() {
        for i in 0..10_000u32 {
            let mut seed = [0u8; 32];
            let mut x = i.wrapping_mul(2654435761);
            for b in seed.iter_mut() {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                *b = x as u8;
            }
            let addr = seed_to_address(&seed, i);
            assert!(is_valid_address(&addr));
        }
    }
}
#[cfg(test)]
mod skip_first_tests {
    use super::*;

    /// The skipping matcher must agree with the encoded address, not just with
    /// itself. This is the check that catches an off-by-one in `shift`: the fast
    /// path and the reference are computed completely differently, so agreement
    /// is real evidence.
    #[test]
    fn skipping_matches_agree_with_the_encoded_address() {
        let mut seed = [7u8; 32];
        for len in 1..=4usize {
            for skip in [false, true] {
                for _ in 0..200 {
                    seed[0] = seed[0].wrapping_add(1);
                    let pk = derive_public_key_for_test(&seed);
                    let body = encode_public_key(&pk);
                    // Take the first `len` characters after the leading 1/3.
                    let tail: String = body[1..].chars().take(len).collect();
                    let m = if skip {
                        PrefixMatcher::new_skipping_first(&tail).unwrap()
                    } else {
                        let head: String = body.chars().take(len).collect();
                        PrefixMatcher::new(&head).unwrap()
                    };
                    assert!(
                        m.matches(&pk),
                        "skip={skip} len={len} tail={tail} body={body}"
                    );
                    assert!(m.matches_reference(&pk), "reference disagrees");
                    assert!(m.encoded_matches(&body), "encoded_matches disagrees");
                }
            }
        }
    }

    /// A skipping matcher must be *equivalent* to the union of the two anchored
    /// prefixes it stands in for, and must reject the leading character.
    #[test]
    fn skipping_equals_the_union_of_both_anchored_prefixes() {
        let mut seed = [11u8; 32];
        for _ in 0..300 {
            seed[0] = seed[0].wrapping_add(1);
            let pk = derive_public_key_for_test(&seed);
            let body = encode_public_key(&pk);
            let tail: String = body[1..4].to_string();
            let skip = PrefixMatcher::new_skipping_first(&tail).unwrap();
            let one = PrefixMatcher::new(&format!("1{tail}")).unwrap();
            let three = PrefixMatcher::new(&format!("3{tail}")).unwrap();
            assert_eq!(
                skip.matches(&pk),
                one.matches(&pk) || three.matches(&pk),
                "skipping matcher is not the union of the two anchored ones"
            );
        }
    }

    /// Cost: dropping the leading character must halve the work, and the
    /// reported expectation must say so.
    #[test]
    fn skipping_is_twice_as_cheap() {
        // Anchored "1test" costs 2^(5*5 - 4) = 2^21.
        assert_eq!(
            PrefixMatcher::new("1test").unwrap().expected_tries(),
            2f64.powi(21)
        );
        // Skipping "test" costs 2^(5*4) = 2^20, and covers 3test as well.
        assert_eq!(
            PrefixMatcher::new_skipping_first("test")
                .unwrap()
                .expected_tries(),
            2f64.powi(20)
        );
    }

    /// With the first character skipped, every alphabet character is a legal
    /// first *typed* character, because it lands on body character 1.
    #[test]
    fn skipping_accepts_any_first_character() {
        for c in ALPHABET.iter() {
            let p = format!("{}z", *c as char);
            let m = PrefixMatcher::new_skipping_first(&p).unwrap();
            assert!(
                m.is_satisfiable(),
                "{p} should be satisfiable when skipping"
            );
        }
        // Anchored, the same prefixes are mostly impossible.
        assert!(!PrefixMatcher::new("9z").unwrap().is_satisfiable());
        assert!(PrefixMatcher::new("1z").unwrap().is_satisfiable());
        assert!(PrefixMatcher::new("3z").unwrap().is_satisfiable());
    }

    /// A single skipped character must not match the leading character itself.
    /// This is the subtle case: with len == 1, `body[1..2]`, not `body[0..1]`.
    #[test]
    fn single_skipped_character_ignores_the_lead() {
        let mut seed = [3u8; 32];
        for _ in 0..200 {
            seed[0] = seed[0].wrapping_add(1);
            let pk = derive_public_key_for_test(&seed);
            let body = encode_public_key(&pk);
            for c in ALPHABET.iter() {
                let m = PrefixMatcher::new_skipping_first(&(*c as char).to_string()).unwrap();
                let expected = body.as_bytes()[1] as char == *c as char;
                assert_eq!(m.matches(&pk), expected, "body={body} c={c}");
            }
        }
    }

    fn derive_public_key_for_test(seed: &[u8; 32]) -> [u8; 32] {
        let private = derive_private_key(seed, 0);
        private_key_to_public(&private)
    }
}

// ---------------------------------------------------------------------------
// Match patterns: prefix, suffix, contains
// ---------------------------------------------------------------------------

/// How a user's pattern is applied to the 60-character address body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MatchMode {
    /// The address starts with the pattern.
    Prefix,
    /// The address ends with the pattern.
    Suffix,
    /// The address contains the pattern anywhere.
    Contains,
}

impl MatchMode {
    /// Parses the spelling used by the CLI and the web UI.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "prefix" | "starts" | "start" | "p" => Some(Self::Prefix),
            "suffix" | "ends" | "end" => Some(Self::Suffix),
            "contains" | "anywhere" | "middle" => Some(Self::Contains),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prefix => "prefix",
            Self::Suffix => "suffix",
            Self::Contains => "contains",
        }
    }
}

/// A search pattern over the address body.
///
/// The three modes differ sharply in cost, and the difference is deliberate:
///
/// - [`Prefix`](Self::Prefix) is decided entirely by bits of the public key,
///   so it is tested against raw `u64`s and never encodes an address. This is
///   the fast path the whole grinder is built around.
/// - [`Suffix`](Self::Suffix) and [`Contains`](Self::Contains) depend on the
///   checksum, which only exists once the address has been encoded, so those
///   modes encode every candidate. That costs one extra Blake2b-5 plus a short
///   base32 pass — under 1% of the loop, since the scalar multiply dominates.
///
/// The alternative (matching a suffix on the low bits of the public key) would
/// be much faster but would be a lie: the last eight body characters are the
/// checksum, not key material, so a pattern aimed at them has to be checked
/// against the real encoding.
#[derive(Clone, Debug)]
pub struct Pattern {
    needle: String,
    mode: MatchMode,
    prefix: Option<PrefixMatcher>,
}

impl Pattern {
    /// Builds a pattern, validating the characters and length.
    ///
    /// `skip_first` only applies to [`MatchMode::Prefix`]; in the other modes it
    /// is meaningless, so it is rejected rather than silently ignored.
    pub fn new(needle: &str, mode: MatchMode, skip_first: bool) -> Result<Self, String> {
        let needle = needle.trim().to_ascii_lowercase();
        if needle.is_empty() {
            return Err("pattern must not be empty".into());
        }
        if needle.len() > MAX_FAST_PREFIX {
            return Err(format!(
                "pattern has {} characters; the limit is {MAX_FAST_PREFIX}",
                needle.len()
            ));
        }
        for c in needle.chars() {
            if !ALPHABET.contains(&(c as u8)) {
                return Err(format!(
                    "invalid character {c:?} — the Nano alphabet excludes 0, 2, l and v"
                ));
            }
        }
        if skip_first && mode != MatchMode::Prefix {
            return Err("ignoring the first character only applies to prefix mode".into());
        }

        let prefix = match mode {
            MatchMode::Prefix => Some(
                if skip_first {
                    PrefixMatcher::new_skipping_first(&needle)
                } else {
                    PrefixMatcher::new(&needle)
                }
                .ok_or("pattern is too long")?,
            ),
            _ => None,
        };

        Ok(Self {
            needle,
            mode,
            prefix,
        })
    }

    pub fn needle(&self) -> &str {
        &self.needle
    }

    pub fn mode(&self) -> MatchMode {
        self.mode
    }

    /// True when this pattern can occur at all. Only anchored prefixes can be
    /// impossible, because character 0 is always `1` or `3`.
    pub fn is_satisfiable(&self) -> bool {
        self.prefix.as_ref().is_none_or(|p| p.is_satisfiable())
    }

    /// Explains an unsatisfiable pattern, or `None` when it is fine.
    pub fn unsatisfiable_reason(&self) -> Option<String> {
        if self.is_satisfiable() {
            return None;
        }
        let c = self.needle.chars().next().unwrap_or('?');
        Some(format!(
            "no address can start with {c:?} — the first character encodes only the \
             public key's top bit, so it is always '1' or '3'. Use --skip-first to ignore \
             that character, or a suffix/contains pattern."
        ))
    }

    /// Expected candidates before a match.
    ///
    /// A prefix is constrained by the key's bits, hence `2^(5L-4)` (or `2^5L`
    /// when the first character is skipped). A suffix of `L` characters is
    /// uniform over the checksum's 32^L values. A substring can sit in any of
    /// the 60 positions, so it is that much likelier.
    pub fn expected_tries(&self) -> f64 {
        let n = self.needle.len() as i32;
        match self.mode {
            MatchMode::Prefix => self.prefix.as_ref().map_or(0.0, |p| p.expected_tries()),
            MatchMode::Suffix => 2f64.powi(5 * n),
            MatchMode::Contains => 2f64.powi(5 * n) / BODY_LEN as f64,
        }
    }

    /// Tests a public key.
    ///
    /// `scratch` is reused across candidates to keep the suffix and contains
    /// modes allocation-free; it is ignored by the prefix fast path.
    #[inline]
    pub fn matches(&self, public_key: &[u8; 32], scratch: &mut [u8; BODY_LEN]) -> bool {
        match &self.prefix {
            // The whole point of the fast path: no encoding, no hashing.
            Some(p) => p.matches(public_key),
            None => {
                encode_address_body(public_key, scratch);
                match self.mode {
                    MatchMode::Suffix => scratch.ends_with(self.needle.as_bytes()),
                    MatchMode::Contains => contains_bytes(scratch, self.needle.as_bytes()),
                    MatchMode::Prefix => unreachable!("prefix always builds a matcher"),
                }
            }
        }
    }

    /// Slow reference used by tests: builds the address and checks the string.
    pub fn matches_reference(&self, public_key: &[u8; 32]) -> bool {
        // The full 60-character body, not the 52-character key encoding: a
        // suffix pattern reaches into the checksum.
        let body = encode_body_string(public_key);
        match self.mode {
            MatchMode::Prefix => self
                .prefix
                .as_ref()
                .is_some_and(|p| p.encoded_matches(&body)),
            MatchMode::Suffix => body.ends_with(&self.needle),
            MatchMode::Contains => body.contains(&self.needle),
        }
    }
}

/// Naive substring search over ASCII bytes. The needle is short (at most
/// [`MAX_FAST_PREFIX`]), so a straightforward scan is faster than pulling in a
/// substring-search dependency.
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod pattern_tests {
    use super::*;

    /// The 60-character body every pattern is checked against.
    fn body_of(public_key: &[u8; 32]) -> String {
        encode_body_string(public_key)
    }

    fn sample_keys(n: usize) -> Vec<[u8; 32]> {
        let mut seed = [9u8; 32];
        (0..n)
            .map(|i| {
                seed[0] = (i + 1) as u8;
                seed[1] = (i >> 8) as u8;
                private_key_to_public(&derive_private_key(&seed, i as u32))
            })
            .collect()
    }

    /// The fast path and the string-based reference must agree for every mode.
    /// They are computed completely differently — bit masking versus encoded
    /// string search — so agreement is real evidence, and a silent off-by-one in
    /// either one shows up here.
    #[test]
    fn fast_path_agrees_with_reference_in_every_mode() {
        let keys = sample_keys(400);
        for mode in [MatchMode::Prefix, MatchMode::Suffix, MatchMode::Contains] {
            for len in 1..=3usize {
                for skip in [false, true] {
                    if skip && mode != MatchMode::Prefix {
                        continue;
                    }
                    for k in keys.iter().take(40) {
                        let body = body_of(k);
                        let needle: String = match mode {
                            MatchMode::Prefix => body.chars().take(len).collect(),
                            MatchMode::Suffix => body[body.len() - len..].to_string(),
                            MatchMode::Contains => body[len - 1..len - 1 + len].to_string(),
                        };
                        let p = Pattern::new(&needle, mode, skip).unwrap();
                        assert_eq!(
                            p.matches(k, &mut [0u8; BODY_LEN]),
                            p.matches_reference(k),
                            "mode={} len={len} skip={skip} needle={needle} body={body}",
                            mode.as_str()
                        );
                    }
                }
            }
        }
    }

    /// A pattern built from the address itself must match that address, in every
    /// mode. Without this, a systematically wrong needle could still pass the
    /// agreement test above by being wrong in both paths.
    #[test]
    fn a_pattern_taken_from_an_address_always_matches_it() {
        for k in sample_keys(300) {
            let body = body_of(&k);
            let pre: String = body.chars().take(3).collect();
            let suf: String = body[body.len() - 3..].to_string();
            let mid: String = body[20..23].to_string();
            let mut scratch = [0u8; BODY_LEN];
            assert!(Pattern::new(&pre, MatchMode::Prefix, false)
                .unwrap()
                .matches(&k, &mut scratch));
            assert!(Pattern::new(&suf, MatchMode::Suffix, false)
                .unwrap()
                .matches(&k, &mut scratch));
            assert!(Pattern::new(&mid, MatchMode::Contains, false)
                .unwrap()
                .matches(&k, &mut scratch));
        }
    }

    /// A suffix must not accidentally match a pattern taken from the *start* of
    /// the address, and vice versa. This catches the two modes being swapped or
    /// silently sharing a code path.
    #[test]
    fn modes_do_not_bleed_into_each_other() {
        for k in sample_keys(200) {
            let body = body_of(&k);
            let pre: String = body.chars().take(3).collect();
            let suf: String = body[body.len() - 3..].to_string();
            if pre != suf {
                let mut scratch = [0u8; BODY_LEN];
                assert!(
                    !Pattern::new(&suf, MatchMode::Prefix, false)
                        .unwrap()
                        .matches(&k, &mut scratch)
                        || body.starts_with(&suf)
                );
                assert!(
                    !Pattern::new(&pre, MatchMode::Suffix, false)
                        .unwrap()
                        .matches(&k, &mut scratch)
                        || body.ends_with(&pre)
                );
            }
        }
    }

    /// Cost model: 32^n for a suffix, that divided by the body length for a
    /// substring, and the key-derived figure for a prefix.
    #[test]
    fn expected_tries_per_mode() {
        assert_eq!(
            Pattern::new("abcd", MatchMode::Suffix, false)
                .unwrap()
                .expected_tries(),
            2f64.powi(20)
        );
        assert_eq!(
            Pattern::new("abcd", MatchMode::Contains, false)
                .unwrap()
                .expected_tries(),
            2f64.powi(20) / BODY_LEN as f64
        );
        assert_eq!(
            Pattern::new("1abcd", MatchMode::Prefix, false)
                .unwrap()
                .expected_tries(),
            2f64.powi(21)
        );
        assert_eq!(
            Pattern::new("abcd", MatchMode::Prefix, true)
                .unwrap()
                .expected_tries(),
            2f64.powi(20)
        );
    }

    /// Validation must reject the same junk in every mode, and must refuse the
    /// leading-character trick outside prefix mode rather than ignoring it.
    #[test]
    fn pattern_validation_is_mode_aware() {
        for mode in [MatchMode::Prefix, MatchMode::Suffix, MatchMode::Contains] {
            assert!(Pattern::new("", mode, false).is_err(), "{mode:?} empty");
            assert!(
                Pattern::new("10", mode, false).is_err(),
                "{mode:?} bad char 0"
            );
            assert!(
                Pattern::new("1l", mode, false).is_err(),
                "{mode:?} bad char l"
            );
            assert!(
                Pattern::new("1v", mode, false).is_err(),
                "{mode:?} bad char v"
            );
            assert!(
                Pattern::new(&"1".repeat(MAX_FAST_PREFIX + 1), mode, false).is_err(),
                "{mode:?} too long"
            );
            assert!(
                Pattern::new("1o", mode, false).is_ok(),
                "{mode:?} 'o' is valid"
            );
        }
        // Ignoring the first character is meaningless for the other modes.
        assert!(Pattern::new("1test", MatchMode::Prefix, true).is_ok());
        assert!(Pattern::new("test", MatchMode::Suffix, true).is_err());
        assert!(Pattern::new("test", MatchMode::Contains, true).is_err());
    }

    /// Only an anchored prefix can be impossible to satisfy.
    #[test]
    fn satisfiability_only_restricts_anchored_prefixes() {
        let bad = Pattern::new("9test", MatchMode::Prefix, false).unwrap();
        assert!(!bad.is_satisfiable());
        assert!(bad.unsatisfiable_reason().is_some());
        for good in [
            ("1test", MatchMode::Prefix, false),
            ("3test", MatchMode::Prefix, false),
            ("9test", MatchMode::Prefix, true),
            ("9test", MatchMode::Suffix, false),
            ("9test", MatchMode::Contains, false),
        ] {
            let p = Pattern::new(good.0, good.1, good.2).unwrap();
            assert!(p.is_satisfiable(), "{good:?} should be satisfiable");
            assert!(p.unsatisfiable_reason().is_none());
        }
    }

    /// Uppercase input must behave like lowercase, since Nano addresses are
    /// usually pasted in mixed case.
    #[test]
    fn patterns_are_case_insensitive() {
        let k = sample_keys(1)[0];
        let body = body_of(&k);
        let needle = body[..3].to_ascii_uppercase();
        let mut scratch = [0u8; BODY_LEN];
        assert!(Pattern::new(&needle, MatchMode::Prefix, false)
            .unwrap()
            .matches(&k, &mut scratch));
        // Stored lowercase, so a pasted mixed-case address still matches.
        let stored = Pattern::new(&needle, MatchMode::Prefix, false).unwrap();
        assert!(
            stored.needle().chars().all(|c| !c.is_ascii_uppercase()),
            "pattern should be stored lowercase, got {:?}",
            stored.needle()
        );
    }

    #[test]
    fn match_mode_parsing_accepts_common_spellings() {
        assert_eq!(MatchMode::parse("prefix"), Some(MatchMode::Prefix));
        assert_eq!(MatchMode::parse("START"), Some(MatchMode::Prefix));
        assert_eq!(MatchMode::parse(" suffix "), Some(MatchMode::Suffix));
        assert_eq!(MatchMode::parse("ends"), Some(MatchMode::Suffix));
        assert_eq!(MatchMode::parse("contains"), Some(MatchMode::Contains));
        assert_eq!(MatchMode::parse("anywhere"), Some(MatchMode::Contains));
        assert_eq!(MatchMode::parse("regex"), None);
        assert_eq!(MatchMode::parse(""), None);
    }

    /// `contains` must find a needle that spans the public-key/checksum
    /// boundary, which is where a naive split would go wrong.
    #[test]
    fn contains_spans_the_checksum_boundary() {
        for k in sample_keys(200) {
            let body = body_of(&k);
            let needle: String = body[49..55].to_string(); // crosses char 52
            let mut scratch = [0u8; BODY_LEN];
            assert!(
                Pattern::new(&needle, MatchMode::Contains, false)
                    .unwrap()
                    .matches(&k, &mut scratch),
                "needle spanning the boundary was missed: {needle}"
            );
        }
    }
}

#[cfg(test)]
mod external_vector_tests {
    use super::*;

    /// A real (private key, address) pair supplied from outside, checked with
    /// this crate's pipeline rather than an external one.
    ///
    /// The pair as given does **not** hold: the private key derives
    /// `nano_1qzi3mt9…`, not the address quoted. The key and the address come
    /// from different accounts. Both facts are pinned here so the expected
    /// behaviour is explicit rather than a silent mismatch.
    #[test]
    fn supplied_private_key_does_not_produce_the_supplied_address() {
        let priv_hex = "CC24F63A64F5920043E03BAE36CD986D2D3D4691427DCEDEBF362E5418BE50CA";
        let quoted = "nano_3w3w1h9jeytt6hguqfib3jjyb5c1bsbho3yqyk837gmpenxo14x5re3nu8g3";

        // A private key must be expanded to its public key first; feeding the
        // private key straight to `public_key_to_address` would typecheck (both
        // are 32 bytes) and silently produce a different, meaningless address.
        let private = parse_seed(priv_hex).expect("valid 32-byte key");
        let public = private_key_to_public(&private);
        let derived = public_key_to_address(&public);

        // The pipeline is self-consistent...
        assert_eq!(
            derived,
            "nano_1qzi3mt9ppfz3ze5q3un87aig99y9mo8t3gr1osw9tw7hnx4cb99ygshdeu9"
        );
        // ...and the two supplied values genuinely disagree.
        assert_ne!(
            derived, quoted,
            "expected the supplied key and address to disagree"
        );
    }

    /// The quoted address is nonetheless a well-formed Nano address, so it is a
    /// real account — just not one controlled by that key.
    #[test]
    fn quoted_address_is_itself_valid() {
        let quoted = "nano_3w3w1h9jeytt6hguqfib3jjyb5c1bsbho3yqyk837gmpenxo14x5re3nu8g3";
        assert_eq!(quoted.len(), ADDRESS_LEN);
        assert!(is_valid_address(quoted), "quoted address failed validation");
    }
}
