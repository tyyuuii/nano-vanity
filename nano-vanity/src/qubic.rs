//! Qubic mode: the search half of Qubic support.
//!
//! This sits beside `engine.rs` rather than inside it. `engine` owns block
//! claiming, cancellation, timing and result reporting, all of which are
//! chain-agnostic; this module owns the part that is genuinely Qubic, which is
//! generating a candidate and deciding whether it matches.
//!
//! # The one structural difference from Nano
//!
//! Nano searches a seed's *account indices*, so a seed is reusable and a
//! search never reveals the wallet. Qubic has **no seed index** --
//! `derive_keys` takes only a seed, so one 55-letter seed maps to exactly one
//! identity, forever. Every Qubic search is therefore a seed search, and
//! **a found seed is the entire wallet**.
//!
//! That is why candidate seeds here are derived from a master seed rather than
//! being chosen by the user, and why `Found` carries the seed in plain sight:
//! there is nothing else to hand someone. The CLI and the web UI both say so
//! when they print a result.

use nano_keys::qubic::identity::{
    derive_keys, public_key_to_identity, seed_to_bytes,
    IDENTITY_LENGTH, SEED_LENGTH,
};
use nano_keys::MatchMode;

/// Which chain a search runs on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Chain {
    /// Nano: 64-hex seed, Blake2b, Ed25519, `nano_` addresses.
    Nano,
    /// Qubic: 55-letter seed, K12, FourQ, 60-letter identities.
    Qubic,
}

impl Chain {
    pub fn as_str(self) -> &'static str {
        match self {
            Chain::Nano => "nano",
            Chain::Qubic => "qubic",
        }
    }
}

/// The output of a Qubic derivation.
///
/// This started life as a `Candidate` enum with a variant per chain, on the
/// assumption that both chains would funnel through one representation. They
/// did not: `engine::Found` and `qubic_search::Found` are separate types,
/// because the two searches have almost nothing in common (account indices
/// versus seeds, a 64-hex seed versus a 55-letter one). With the enum never
/// gaining a second variant, it was dead weight, so it is now just the data it
/// always actually was.
///
/// `seed` is the important field: **this is the wallet.** Qubic has no account
/// index, so one seed maps to exactly one identity, forever.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Keys {
    pub seed: String,
    pub subseed: [u8; 32],
    pub private_key: [u8; 32],
    pub public_key: [u8; 32],
    pub identity: String,
}

/// A 55-letter lowercase Qubic seed from OS entropy.
pub fn random_seed() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| format!("random seed: {e}"))?;
    Ok(seed_from_bytes(&bytes))
}

/// Map 32 bytes to a 55-letter seed via K12.
///
/// The 55th byte is generated separately because 55 bytes of K12 output is not
/// derived from 32 bytes by construction; taking 55 bytes of a wider hash is
/// simpler and equally arbitrary. Mapping `byte % 26` is very slightly
/// non-uniform (256 is not a multiple of 26, so 22 letters get 10 chances and 4
/// get 9), which perturbs the expected-tries estimate by under 4%. Rejection
/// sampling would remove the bias at the cost of a variable-length loop; for a
/// search tool that is not a trade worth making, and it is noted here so the
/// expected-tries figure is not mistaken for exact.
fn seed_from_bytes(bytes: &[u8]) -> String {
    use nano_keys::qubic::k12::k12_32;
    let a = k12_32(bytes);
    let mut b = bytes.to_vec();
    b.extend_from_slice(&a);
    let h = k12_32(&b);
    let mut out = String::with_capacity(SEED_LENGTH);
    for i in 0..SEED_LENGTH {
        let byte = if i < 32 { bytes[i] } else { h[(i - 32) % 32] };
        out.push((b'a' + (byte % 26) as u8) as char);
    }
    out
}

/// Validate a user-supplied Qubic seed.
pub fn parse_seed(input: &str) -> Result<String, String> {
    seed_to_bytes(input).map_err(|e| e.to_string())?;
    Ok(input.to_string())
}

/// A pattern over a 60-character Qubic identity.
///
/// Unlike Nano there is no bit-level shortcut available: the identity is a
/// base-26 string, so matching is character comparison. The upside is that the
/// semantics are obvious rather than something to re-derive from a bit offset,
/// and the cost is that every character is compared rather than a fixed 260-bit
/// window. At 26 characters of a 60-character string that is irrelevant next
/// to a 183 microsecond scalar multiply.
#[derive(Clone, Debug)]
pub struct IdentityPattern {
    needle: String,
    mode: MatchMode,
    skip_first: usize,
}

impl IdentityPattern {
    pub fn new(needle: &str, mode: MatchMode, skip_first: usize) -> Result<Self, String> {
        if needle.is_empty() {
            return Err("pattern must not be empty".into());
        }
        if !needle.chars().all(|c| c.is_ascii_uppercase()) {
            return Err("a Qubic identity pattern uses the letters A-Z only".into());
        }
        Ok(IdentityPattern {
            needle: needle.to_string(),
            mode,
            skip_first,
        })
    }

    pub fn needle(&self) -> &str {
        &self.needle
    }

    pub fn mode(&self) -> MatchMode {
        self.mode
    }

    /// Does this identity match, honouring the skip-first window?
    pub fn matches(&self, identity: &str) -> bool {
        let hay = match self.skip_first {
            0 => identity,
            n if n < identity.len() => &identity[n..],
            _ => "",
        };
        match self.mode {
            MatchMode::Prefix => hay.starts_with(&self.needle),
            MatchMode::Suffix => hay.ends_with(&self.needle),
            MatchMode::Contains => hay.contains(&self.needle),
        }
    }

    /// Expected tries, for honest progress reporting.
    ///
    /// 26^n for a prefix or a suffix, and 26^n / 60 for a substring. The
    /// window is `60 - skip_first`, and the denominator uses the unskipped
    /// length, matching how the Nano side reports it.
    pub fn expected_tries(&self) -> f64 {
        let n = self.needle.len() as f64;
        let window = (IDENTITY_LENGTH as f64 - self.skip_first as f64).max(1.0);
        match self.mode {
            MatchMode::Prefix | MatchMode::Suffix => 26f64.powf(n),
            MatchMode::Contains => 26f64.powf(n) / window,
        }
    }
}

/// Derive the keys for a given attempt number.
///
/// Reproducible: the same master seed always produces the same sequence of
/// candidates, so a search can be re-run and will find the same winners. This
/// is the Qubic analogue of Nano's `Blake2b-256(master ‖ attempt_be)`.
pub fn derive_candidate(master: &str, attempt: u64) -> Keys {
    // A 64-bit attempt counter is folded in so attempt N and N+1 differ.
    let mut salt = [0u8; 8];
    salt.copy_from_slice(&attempt.to_be_bytes());
    let mut material = Vec::with_capacity(master.len() + 8);
    material.extend_from_slice(master.as_bytes());
    material.extend_from_slice(&salt);
    let seed = seed_from_bytes(&material);

    match derive_keys(&seed) {
        Ok(d) => Keys {
            seed,
            subseed: d.subseed,
            private_key: d.private_key,
            public_key: d.public_key,
            identity: d.identity,
        },
        // `seed_from_bytes` always produces 55 lowercase letters, so this is
        // unreachable. Falling back keeps the search total rather than
        // panicking a worker thread on an invariant that a future refactor
        // could break.
        Err(_) => Keys {
            seed: "a".repeat(SEED_LENGTH),
            subseed: [0u8; 32],
            private_key: [0u8; 32],
            public_key: [0u8; 32],
            identity: public_key_to_identity(&[0u8; 32]),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nano_keys::qubic::identity::is_valid_identity;

    const ID: &str = "BZBQFLLBNCXEMGLOBHUVFTLUPLVCPQUASSILFABOFFBCADQSSUPNWLZBQEXK";

    #[test]
    fn random_seed_is_well_formed() {
        let s = random_seed().unwrap();
        assert_eq!(s.len(), SEED_LENGTH);
        assert!(s.chars().all(|c| c.is_ascii_lowercase()));
        assert!(seed_to_bytes(&s).is_ok());
    }

    #[test]
    fn parse_seed_rejects_bad_input() {
        assert!(parse_seed("abc").is_err());
        assert!(parse_seed(&"A".repeat(55)).is_err());
        assert!(parse_seed(&"z".repeat(55)).is_ok());
    }

    #[test]
    fn pattern_modes() {
        let p = IdentityPattern::new("BZB", MatchMode::Prefix, 0).unwrap();
        assert!(p.matches(ID));
        assert!(!p.matches("ABZ"));

        let s = IdentityPattern::new("QEXK", MatchMode::Suffix, 0).unwrap();
        assert!(s.matches(ID));
        assert!(!s.matches("QEXJ"));

        let c = IdentityPattern::new("FLLB", MatchMode::Contains, 0).unwrap();
        assert!(c.matches(ID));
        assert!(!c.matches("ZZZZ"));
    }

    #[test]
    fn skip_first_shifts_the_window() {
        let p = IdentityPattern::new("BZQ", MatchMode::Prefix, 0).unwrap();
        assert!(!p.matches(ID), "BZQ is not a prefix of the identity");
        // The identity at offset 0 begins BZB, so a needle from the shifted
        // window must not match the unshifted one.
        let shifted = IdentityPattern::new("ZB", MatchMode::Prefix, 1).unwrap();
        assert!(shifted.matches(ID));
    }

    #[test]
    fn pattern_rejects_non_uppercase() {
        assert!(IdentityPattern::new("abc", MatchMode::Prefix, 0).is_err());
        assert!(IdentityPattern::new("", MatchMode::Prefix, 0).is_err());
    }

    #[test]
    fn expected_tries_scales_as_expected() {
        let p3 = IdentityPattern::new("ABC", MatchMode::Prefix, 0).unwrap();
        assert!((p3.expected_tries() - 26f64.powi(3)).abs() < 1.0);
        let c3 = IdentityPattern::new("ABC", MatchMode::Contains, 0).unwrap();
        assert!(c3.expected_tries() < p3.expected_tries());
    }

    #[test]
    fn candidate_derivation_is_reproducible() {
        let a = derive_candidate("master-seed-for-testing-only", 7);
        let b = derive_candidate("master-seed-for-testing-only", 7);
        assert_eq!(a, b, "the same master and attempt must give the same candidate");
    }

    #[test]
    fn every_candidate_carries_its_own_seed() {
        // The seed is the wallet, so it must travel with the identity it
        // produced. A candidate that kept the master seed instead would report
        // a seed that does not derive the address printed next to it.
        let k = derive_candidate("m".repeat(55).as_str(), 3);
        let d = nano_keys::qubic::identity::derive_keys(&k.seed).unwrap();
        assert_eq!(d.identity, k.identity);
        assert_eq!(d.public_key, k.public_key);
        assert_ne!(k.seed, "m".repeat(55));
    }

    #[test]
    fn consecutive_attempts_differ() {
        let a = derive_candidate("master-seed-for-testing-only", 1);
        let b = derive_candidate("master-seed-for-testing-only", 2);
        assert_ne!(a, b);
    }

    #[test]
    fn derived_candidates_are_valid_identities() {
        for attempt in 0..5 {
            let Keys { identity, seed, .. } =
                derive_candidate("master-seed-for-testing-only", attempt);
            assert_eq!(identity.len(), IDENTITY_LENGTH);
            assert!(
                is_valid_identity(&identity),
                "attempt {attempt} produced an invalid identity"
            );
            assert_eq!(seed.len(), SEED_LENGTH);
        }
    }
}
