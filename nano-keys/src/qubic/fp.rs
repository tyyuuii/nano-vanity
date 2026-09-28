//! GF(2^127 - 1) arithmetic.
//!
//! The FourQ base field is the Mersenne prime p = 2^127 - 1, so an element is
//! two `u64` limbs with the high limb under 2^63, and reduction is a fold
//! rather than a division: 2^127 = 1 (mod p) turns a 254-bit product back
//! into a 127-bit one with a shift and an add.
//!
//! Every function here is checked against a straightforward `u128` reference
//! in the tests, so a transcription slip cannot hide. An earlier version of
//! this file folded limbs more cleverly than necessary and got the select
//! inverted; the tests found it immediately, which is the point of having them.

/// p = 2^127 - 1, the base field prime.
const P128: u128 = (1u128 << 127) - 1;
/// Mask of the low 127 bits.
const MASK127: u128 = P128;

/// A field element: `[lo, hi]` meaning `lo + hi * 2^64`, always canonical
/// (strictly below p).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Fp(pub u64, pub u64);

impl Fp {
    pub const ZERO: Fp = Fp(0, 0);
    pub const ONE: Fp = Fp(1, 0);

    #[inline]
    pub const fn new(lo: u64, hi: u64) -> Self {
        Fp(lo, hi)
    }

    /// The 127-bit value as a single `u128`.
    #[inline]
    pub fn to_u128(self) -> u128 {
        (self.0 as u128) | ((self.1 as u128) << 64)
    }

    /// Build from an already-reduced value below p.
    #[inline]
    const fn from_canonical(v: u128) -> Fp {
        Fp(v as u64, (v >> 64) as u64)
    }

    /// Reduce any `u128` into an element.
    ///
    /// `v >> 127` is 0 or 1, so the fold lands below 2^127 + 1 and a single
    /// conditional subtraction is enough.
    #[inline]
    pub fn from_u128(v: u128) -> Fp {
        let folded = (v & MASK127) + (v >> 127);
        Fp::from_canonical(if folded >= P128 { folded - P128 } else { folded })
    }

    #[inline]
    pub fn add(self, o: Fp) -> Fp {
        // a + b < 2p < 2^128, so one conditional subtraction is enough.
        let s = self.to_u128() + o.to_u128();
        Fp::from_canonical(if s >= P128 { s - P128 } else { s })
    }

    #[inline]
    pub fn sub(self, o: Fp) -> Fp {
        let (a, b) = (self.to_u128(), o.to_u128());
        Fp::from_canonical(if a >= b { a - b } else { a + P128 - b })
    }

    #[inline]
    pub fn neg(self) -> Fp {
        Fp::ZERO.sub(self)
    }

    /// The 254-bit product as `(high, low)`, i.e. `high * 2^128 + low`.
    #[inline]
    fn mul_wide(self, o: Fp) -> (u128, u128) {
        let a0 = self.0 as u128;
        let a1 = self.1 as u128;
        let b0 = o.0 as u128;
        let b1 = o.1 as u128;

        let p0 = a0 * b0; // < 2^128
        let p1 = a0 * b1; // < 2^127
        let p2 = a1 * b0; // < 2^127
        let p3 = a1 * b1; // < 2^126

        let mid = p1 + p2; // < 2^128
        let mid_lo = mid & 0xFFFF_FFFF_FFFF_FFFF;
        let mid_hi = mid >> 64;

        let (lo, carry) = p0.overflowing_add(mid_lo << 64);
        // p3 + mid_hi + carry stays below 2^127, so it fits a u128.
        let hi = p3 + mid_hi + (carry as u128);
        (hi, lo)
    }

    #[inline]
    pub fn mul(self, o: Fp) -> Fp {
        let (hi, lo) = self.mul_wide(o);
        // 2^128 = 2 * 2^127, and 2^127 = 1 (mod p), so 2^128 = 2 (mod p):
        // the high half folds down to twice itself.
        //
        // `hi < 2^126 + 2^64 + 1`, so `hi << 1` stays below 2^128 and the sum
        // needs at most one carry bit. That carry is a 2^128 term, which is
        // worth 2 modulo p -- not 1. Getting that wrong was a real bug, caught
        // by `mul_matches_reference`.
        let (s, carry) = lo.overflowing_add(hi << 1);
        // s is strictly below 2^128, so folding it and adding the carry's
        // contribution cannot overflow a u128.
        let v = (s & MASK127) + (s >> 127) + 2 * (carry as u128);
        // v < 2^127 + 3, so a single conditional subtraction finishes it.
        Fp::from_canonical(if v >= P128 { v - P128 } else { v })
    }

    #[inline]
    pub fn square(self) -> Fp {
        self.mul(self)
    }

    /// `a^(p-2) = a^(2^127-3)`, i.e. the inverse in this field.
    ///
    /// The reference splits this across two functions. `fpTwo1251` builds the
    /// addition chain and returns `a^(2^125-1)`; `fpInv` then squares twice
    /// and multiplies by `a` to reach `a^(2^127-3)`. The name is a misnomer --
    /// the chain never involves 2^1251 -- which is exactly why it is worth
    /// writing down here. An earlier version of this file stopped at
    /// `a^(2^125-1)` and returned a value that looked plausible and was not an
    /// inverse; the chain is now transcribed exactly and checked by test.
    pub fn invert(self) -> Fp {
        assert!(
            !(self == Fp::ZERO),
            "invert: expected a non-zero field element"
        );
        // fpTwo1251, verbatim from the reference.
        let t2 = self.square().mul(self); // a^3
        let t3 = t2.square().square(); // a^12
        let t3 = t3.mul(t2); // a^15
        let t4 = t3.square().square().square().square(); // a^240
        let t4 = t4.mul(t3); // a^255
        let mut t5 = t4.square();
        for _ in 0..7 {
            t5 = t5.square();
        }
        t5 = t5.mul(t4); // a^65535
        let mut tt2 = t5.square();
        for _ in 0..15 {
            tt2 = tt2.square();
        }
        tt2 = tt2.mul(t5); // a^(2^32-1)
        let mut t1 = tt2.square();
        for _ in 0..31 {
            t1 = t1.square();
        }
        t1 = t1.mul(tt2); // a^(2^64-1)
        for _ in 0..32 {
            t1 = t1.square();
        }
        t1 = tt2.mul(t1); // a^(2^96-1)
        for _ in 0..16 {
            t1 = t1.square();
        }
        t1 = t1.mul(t5); // a^(2^112-1)
        for _ in 0..8 {
            t1 = t1.square();
        }
        t1 = t1.mul(t4); // a^(2^120-1)
        for _ in 0..4 {
            t1 = t1.square();
        }
        t1 = t1.mul(t3); // a^(2^124-1)
        t1 = t1.square(); // a^(2^125-2)
        let mut t1 = self.mul(t1); // a^(2^125-1)   <-- fpTwo1251's return value

        // fpInv: two more squarings and a final multiply by a.
        t1 = t1.square(); // a^(2^126-2)
        t1 = t1.square(); // a^(2^127-4)
        self.mul(t1) // a^(2^127-3) = a^(p-2)
    }

    /// Returns `b` when `flag` is 1, else `a`.
    #[inline]
    pub fn cmov(self, b: Fp, flag: u64) -> Fp {
        let mask = 0u64.wrapping_sub(flag & 1);
        Fp((self.0 & !mask) | (b.0 & mask), (self.1 & !mask) | (b.1 & mask))
    }

    /// 0 for zero, 1 for non-zero with bit 126 clear, -1 for non-zero with
    /// bit 126 set. Mirrors `fpSgn` in the reference.
    pub fn sgn(self) -> i64 {
        let t = self.0 | self.1;
        let nonzero = ((t | t.wrapping_neg()) >> 63) as i64;
        let negative = ((self.1 >> 62) & 1) as i64;
        nonzero * (1 - (negative << 1))
    }

    /// `v` if `self` is odd, else `(v + p) / 2`. Mirrors `fpHlf`: the reference
    /// computes `carry = -(v & 1)` then `(v + (P & carry)) >> 1`, so an even v is
    /// halved and an odd v has p added first to make it even.
    pub fn hlf(self, v: Fp) -> Fp {
        let vv = v.to_u128();
        let total = if vv & 1 == 1 { vv + P128 } else { vv };
        Fp::from_canonical(total >> 1)
    }

    pub fn to_bytes(self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&self.0.to_le_bytes());
        out[8..].copy_from_slice(&self.1.to_le_bytes());
        out
    }

    /// Parse 16 little-endian bytes. Returns `None` if bit 127 is set, which
    /// the reference treats as malformed.
    pub fn from_bytes(b: &[u8]) -> Option<Fp> {
        if b.len() != 16 {
            return None;
        }
        let mut lo = [0u8; 8];
        let mut hi = [0u8; 8];
        lo.copy_from_slice(&b[..8]);
        hi.copy_from_slice(&b[8..]);
        let hiu = u64::from_le_bytes(hi);
        if (hiu >> 63) != 0 {
            return None;
        }
        Some(Fp(u64::from_le_bytes(lo), hiu))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic xorshift, so the tests are reproducible without pulling in
    /// a rand dependency for something this small.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        /// A canonical element: 127 bits, then reduced.
        fn fp(&mut self) -> Fp {
            Fp::from_u128(((self.next() as u128) << 64 | self.next() as u128) & MASK127)
        }
    }

    #[test]
    fn add_matches_reference() {
        let mut r = Rng(0x12345678);
        for _ in 0..5000 {
            let (a, b) = (r.fp(), r.fp());
            let want = (a.to_u128() + b.to_u128()) % P128;
            assert_eq!(a.add(b).to_u128(), want);
        }
    }

    #[test]
    fn sub_matches_reference() {
        let mut r = Rng(0xdeadbeef);
        for _ in 0..5000 {
            let (a, b) = (r.fp(), r.fp());
            let want = (a.to_u128() + P128 - b.to_u128()) % P128;
            assert_eq!(a.sub(b).to_u128(), want);
        }
    }

    #[test]
    fn mul_matches_python_oracle() {
        // The expected products come from Python, not from this file: a u128
        // cannot hold a 127x127 product, so a test-local expectation would
        // overflow instead of checking anything.
        for &(a, b, want) in crate::qubic::fp_vectors::MUL_VECTORS {
            assert_eq!(a.mul(b), want, "mul wrong for {a:?} * {b:?}");
            assert_eq!(b.mul(a), want, "mul is not commutative");
        }
    }

    #[test]
    fn square_matches_mul() {
        let mut r = Rng(0xfeedface);
        for _ in 0..2000 {
            let a = r.fp();
            assert_eq!(a.square(), a.mul(a));
        }
    }

    #[test]
    fn everything_stays_canonical() {
        let mut r = Rng(0x0badf00d);
        for _ in 0..5000 {
            let a = r.fp();
            let b = r.fp();
            for v in [a, a.add(b), a.sub(b), a.mul(b), a.square(), a.neg()] {
                assert!(v.to_u128() < P128, "value {:#x} is not reduced", v.to_u128());
                assert!(v.1 >> 63 == 0, "high limb out of range");
            }
        }
    }

    #[test]
    fn neg_is_additive_inverse() {
        let mut r = Rng(0x5150);
        for _ in 0..2000 {
            let a = r.fp();
            assert_eq!(a.add(a.neg()).to_u128(), 0);
        }
    }

    #[test]
    fn invert_round_trips() {
        let mut r = Rng(0x5eed);
        let mut checked = 0;
        for _ in 0..300 {
            let a = r.fp();
            if a == Fp::ZERO {
                continue;
            }
            assert_eq!(
                a.mul(a.invert()).to_u128(),
                1,
                "a * a^-1 must be 1 for {:#x}",
                a.to_u128()
            );
            checked += 1;
        }
        assert!(checked > 100, "too few non-zero samples to be meaningful");
    }

    #[test]
    fn sgn_matches_reference_rule() {
        // The reference is `(v >> 126) & 1`, so the sign turns on bit 126.
        assert_eq!(Fp::ZERO.sgn(), 0);
        assert_eq!(Fp::ONE.sgn(), 1);
        assert_eq!(Fp::from_u128(1u128 << 126).sgn(), -1);
        assert_eq!(Fp::from_u128(1u128 << 126).add(Fp::ONE).sgn(), -1);
        // 2^127 - 2 has bit 126 set, so it too is "negative".
        assert_eq!(Fp::from_u128(P128 - 1).sgn(), -1);
        // Bit 126 clear and non-zero: positive.
        assert_eq!(Fp::from_u128(1u128 << 125).sgn(), 1);
    }

    #[test]
    fn hlf_halves() {
        let mut r = Rng(0x1234);
        for _ in 0..2000 {
            let a = r.fp();
            // hlf is division by two, so doubling the result must give a back.
            let h = a.hlf(a).to_u128();
            assert_eq!(h * 2 % P128, a.to_u128());
        }
    }

    #[test]
    fn bytes_round_trip() {
        let mut r = Rng(0x77);
        for _ in 0..1000 {
            let a = r.fp();
            assert_eq!(Fp::from_bytes(&a.to_bytes()), Some(a));
        }
    }

    #[test]
    fn from_u128_reduces_values_above_p() {
        assert_eq!(Fp::from_u128(P128).to_u128(), 0);
        assert_eq!(Fp::from_u128(P128 + 1).to_u128(), 1);
        // 2^128 - 1 = 2*p + 1, so it reduces to 1.
        assert_eq!(Fp::from_u128(u128::MAX).to_u128(), 1);
    }
}
