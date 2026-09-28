//! Qubic seed -> identity derivation and the 60-character identity encoding.
//!
//! # Why the encoding is not like Nano's
//!
//! Nano's address body is `enc52(y)` plus a checksum, emitted
//! **most-significant digit first**. A Qubic identity reads the 32-byte public
//! key as four **little-endian** u64 fragments and writes each as 14 base-26
//! digits **least-significant first**. So `identity[0]` depends on the *low*
//! bits of the public key, and it is the exact opposite of the intuition the
//! rest of this repository teaches. Carrying the Nano mental model over here
//! produces addresses that look valid and belong to nobody -- the same failure
//! class as the account-index endianness bug recorded in `ERRATA.md` §7.
//!
//! # Why a Qubic vanity seed is the wallet
//!
//! Qubic has no seed index. `derive_keys` takes only a seed, so one 55-letter
//! seed maps to exactly one identity, permanently. Every search is therefore a
//! seed search, and a found seed is the whole wallet rather than one account of
//! several. That is a materially different risk from the Nano side, where the
//! seed can be shared across indices.

use super::fourq::{point_marshal, scalar_base_mult};
use super::k12::k12_32;

/// A Qubic seed is exactly this many lowercase letters.
pub const SEED_LENGTH: usize = 55;
/// A Qubic identity is exactly this many uppercase letters.
pub const IDENTITY_LENGTH: usize = 60;

#[derive(Debug, PartialEq, Eq)]
pub enum SeedError {
    WrongLength(usize),
    NotLowercaseAscii,
}

impl std::fmt::Display for SeedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SeedError::WrongLength(n) => write!(
                f,
                "a Qubic seed is exactly {SEED_LENGTH} lowercase letters, got {n}"
            ),
            SeedError::NotLowercaseAscii => {
                write!(f, "a Qubic seed uses only the letters a-z, with no digits")
            }
        }
    }
}

impl std::error::Error for SeedError {}

/// Everything the derivation produces. All three are returned because being
/// able to see the subseed and private key is what makes a wrong result
/// diagnosable rather than mysterious.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedKeys {
    pub subseed: [u8; 32],
    pub private_key: [u8; 32],
    pub public_key: [u8; 32],
    pub identity: String,
}

/// Validate a seed and convert its letters to the 55 bytes K12 consumes.
pub fn seed_to_bytes(seed: &str) -> Result<[u8; 55], SeedError> {
    if seed.len() != SEED_LENGTH {
        return Err(SeedError::WrongLength(seed.len()));
    }
    let mut out = [0u8; SEED_LENGTH];
    for (i, b) in seed.bytes().enumerate() {
        if !b.is_ascii_lowercase() {
            return Err(SeedError::NotLowercaseAscii);
        }
        out[i] = b - b'a';
    }
    Ok(out)
}

/// The full derivation: seed -> subseed -> private key -> public key -> identity.
pub fn derive_keys(seed: &str) -> Result<DerivedKeys, SeedError> {
    let seed_bytes = seed_to_bytes(seed)?;
    let subseed = k12_32(&seed_bytes);
    // The private key is a raw 32-byte value. Qubic does not clamp it; the
    // scalar recoder inside the curve adds the group order when needed.
    let private_key = k12_32(&subseed);
    let public_key = point_marshal(&scalar_base_mult(&private_key));
    let identity = public_key_to_identity(&public_key);
    Ok(DerivedKeys {
        subseed,
        private_key,
        public_key,
        identity,
    })
}

pub fn seed_to_identity(seed: &str) -> Result<String, SeedError> {
    Ok(derive_keys(seed)?.identity)
}

/// Encode a 32-byte public key as the 60-character identity.
///
/// 56 characters come from four little-endian u64 fragments in base 26, written
/// least-significant digit first; the last 4 are a K12 checksum over the public
/// key, masked to 18 bits.
pub fn public_key_to_identity(public_key: &[u8; 32]) -> String {
    let mut id = [b'A'; IDENTITY_LENGTH];

    for frag in 0..4 {
        let mut f = u64::from_le_bytes(public_key[frag * 8..frag * 8 + 8].try_into().unwrap());
        for j in 0..14 {
            id[frag * 14 + j] = b'A' + (f % 26) as u8;
            f /= 26;
        }
    }

    // 4 checksum characters from 18 bits of K12(publicKey, 3).
    let ck = k12_32(public_key);
    let mut c = (ck[0] as u32) | ((ck[1] as u32) << 8) | ((ck[2] as u32) << 16);
    c &= 0x3FFFF;
    for (i, slot) in id[56..60].iter_mut().enumerate() {
        *slot = b'A' + (c % 26) as u8;
        c /= 26;
    }

    String::from_utf8(id.to_vec()).expect("identity is ASCII by construction")
}

/// Decode the 56 data characters back into a public key.
///
/// The checksum characters are not read; use `is_valid_identity` to check them.
pub fn identity_to_public_key(identity: &str) -> Option<[u8; 32]> {
    let b = identity.as_bytes();
    if b.len() != IDENTITY_LENGTH {
        return None;
    }
    let mut pk = [0u8; 32];
    for frag in 0..4 {
        let mut f: u64 = 0;
        // Walk the digits most-significant first to rebuild the integer, which
        // is the inverse of writing them least-significant first.
        for j in (0..14).rev() {
            let c = b[frag * 14 + j];
            if !c.is_ascii_uppercase() {
                return None;
            }
            f = f * 26 + (c - b'A') as u64;
        }
        pk[frag * 8..frag * 8 + 8].copy_from_slice(&f.to_le_bytes());
    }
    Some(pk)
}

/// True when the identity is well formed and its checksum matches.
///
/// This validates the checksum only. It does not mean the address exists on the
/// network or holds a balance -- nothing here talks to a node, by design.
pub fn is_valid_identity(identity: &str) -> bool {
    let Some(pk) = identity_to_public_key(identity) else {
        return false;
    };
    let expected = public_key_to_identity(&pk);
    expected == identity
}

/// The identity of a smart contract, which is just the identity of a small
/// little-endian integer.
///
/// Present because it validates the encoding through a path that never touches
/// the seed derivation: index 1 must give `BAAA...`, index 2 `CAAA...`, index 4
/// `EAAA...`.
pub fn contract_index_to_identity(index: u32) -> String {
    let mut pk = [0u8; 32];
    pk[..4].copy_from_slice(&index.to_le_bytes());
    public_key_to_identity(&pk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qubic::tests_vectors::GOLDEN;

    fn hx(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn every_golden_vector_reproduces_exactly() {
        for g in GOLDEN {
            let d = derive_keys(g.seed).unwrap_or_else(|e| panic!("seed {} rejected: {e}", g.seed));
            assert_eq!(hx(&d.subseed), g.subseed, "subseed for {}", g.seed);
            assert_eq!(hx(&d.private_key), g.private_key, "private key for {}", g.seed);
            assert_eq!(hx(&d.public_key), g.public_key, "public key for {}", g.seed);
            assert_eq!(d.identity, g.identity, "identity for {}", g.seed);
        }
    }

    #[test]
    fn golden_identities_round_trip_through_the_public_key() {
        for g in GOLDEN {
            let pk = identity_to_public_key(&g.identity)
                .unwrap_or_else(|| panic!("could not decode {}", g.identity));
            assert_eq!(hx(&pk), g.public_key, "decode of {} lost data", g.identity);
            assert_eq!(public_key_to_identity(&pk), g.identity);
            assert!(is_valid_identity(&g.identity));
        }
    }

    #[test]
    fn checksum_catches_a_single_flipped_character() {
        let g = &GOLDEN[0];
        let mut id: Vec<char> = g.identity.chars().collect();
        let last = id.len() - 1;
        id[last] = if id[last] == 'A' { 'B' } else { 'A' };
        let corrupted: String = id.into_iter().collect();
        assert!(!is_valid_identity(&corrupted));
    }

    /// The single most valuable check in this module: contract addresses are
    /// the identity of a tiny integer, so they exercise the fragment split, the
    /// endianness and the digit order without touching the seed path at all.
    /// Index 1 must start with 'B', index 2 with 'C', index 4 with 'E'.
    #[test]
    fn contract_identities_match_the_official_documentation() {
        assert!(contract_index_to_identity(1).starts_with('B'));
        assert!(contract_index_to_identity(2).starts_with('C'));
        // The QUTIL contract, index 4, quoted in Qubic's own docs.
        assert_eq!(
            contract_index_to_identity(4),
            "EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAVWRF"
        );
    }

    #[test]
    fn identity_is_exactly_sixty_uppercase_letters() {
        let id = seed_to_identity(&"a".repeat(55)).unwrap();
        assert_eq!(id.len(), IDENTITY_LENGTH);
        assert!(id.chars().all(|c| c.is_ascii_uppercase()));
    }

    #[test]
    fn rejects_malformed_seeds() {
        assert!(matches!(
            seed_to_identity("abc"),
            Err(SeedError::WrongLength(3))
        ));
        assert!(matches!(
            seed_to_identity(&"A".repeat(55)),
            Err(SeedError::NotLowercaseAscii)
        ));
        // Digits are not allowed, even 55 of them.
        assert!(matches!(
            seed_to_identity(&"1".repeat(55)),
            Err(SeedError::NotLowercaseAscii)
        ));
    }

    #[test]
    fn rejects_malformed_identities() {
        assert!(!is_valid_identity("ABCDEF"));
        assert!(!is_valid_identity(&"a".repeat(60)));
        assert!(!is_valid_identity(&"A".repeat(59)));
    }

    /// A prefix match on the identity depends on the LOW bits of the public
    /// key, which is the opposite of Nano. Pin that down so a future "optimisation"
    /// cannot quietly flip it.
    #[test]
    fn leading_character_tracks_the_low_bytes_of_the_public_key() {
        let g = &GOLDEN[0];
        let pk = identity_to_public_key(&g.identity).unwrap();
        // identity[0] is the least significant base-26 digit of pk[0..8] read
        // as a little-endian u64.
        let frag = u64::from_le_bytes(pk[0..8].try_into().unwrap());
        let expected = b'A' + (frag % 26) as u8;
        assert_eq!(g.identity.as_bytes()[0], expected);
    }
}
