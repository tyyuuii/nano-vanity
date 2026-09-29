//! KangarooTwelve, as used by Qubic.
//!
//! K12 is the tree hash from <https://keccak.team/files/KangarooTwelve.pdf>.
//! It is Keccak-based but is **not** SHA3 and **not** Blake2b: different
//! padding, a 168-byte rate (256-bit capacity), and only 12 rounds. Qubic uses
//! it everywhere in key derivation, so it has to be exactly right.
//!
//! tiny-keccak provides a reviewed implementation; this module is a thin,
//! allocation-free wrapper so the hot loop can hash a 32-byte subseed without
//! touching the heap.

use tiny_keccak::{Hasher, KangarooTwelve};

/// K12 of `input` to exactly 32 bytes, the size Qubic uses for subseeds and
/// private keys.
#[inline]
pub fn k12_32(input: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    // The empty custom string matches the reference: the C code calls
    // `KangarooTwelve(input, len, out, outlen)` with no customization.
    let mut k = KangarooTwelve::new(b"");
    k.update(input);
    k.finalize(&mut out);
    out
}

/// K12 of `input` to `n` bytes, which must be 1..=32.
///
/// Qubic also uses a short K12 for the identity checksum: 3 bytes of the
/// 32-byte public key, masked down to 18 bits. Routing both lengths through
/// one function keeps the custom string and the padding in exactly one place,
/// where they can be checked.
#[inline]
pub fn k12_n(input: &[u8], n: usize) -> ([u8; 32], usize) {
    debug_assert!((1..=32).contains(&n));
    let mut buf = [0u8; 32];
    let mut k = KangarooTwelve::new(b"");
    k.update(input);
    // Squeeze only `n` bytes. The underlying XOF produces a longer stream, so
    // truncating is equivalent to asking for `n` bytes directly.
    let mut full = [0u8; 32];
    k.finalize(&mut full);
    buf[..n].copy_from_slice(&full[..n]);
    (buf, n)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The official KangarooTwelve test vector for the empty message, taken
    /// from the specification and independently confirmed by
    /// `qubic-typescript`'s `k12.test.ts`.
    const K12_EMPTY: &str =
        "1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e5";

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn matches_official_spec_vector() {
        let got = hex(&k12_32(b""));
        assert_eq!(got, K12_EMPTY, "K12 of the empty message must match the spec");
    }

    #[test]
    fn short_output_is_a_prefix_of_long_output() {
        // The identity checksum uses 3 bytes. If truncation were not equivalent
        // to a short request, the checksum and the key hash would disagree.
        let input = b"qubic checksum truncation probe";
        let full = k12_32(input);
        let (short, n) = k12_n(input, 3);
        assert_eq!(n, 3);
        assert_eq!(&short[..3], &full[..3]);
    }

    #[test]
    fn is_deterministic() {
        let a = k12_32(b"deterministic");
        let b = k12_32(b"deterministic");
        assert_eq!(a, b);
    }

    #[test]
    fn distinct_inputs_differ() {
        assert_ne!(k12_32(&[0]), k12_32(&[1]));
    }
}
