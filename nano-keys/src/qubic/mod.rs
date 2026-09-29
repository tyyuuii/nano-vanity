//! Qubic (Q) key derivation: seed -> subseed -> private key -> public key -> identity.
//!
//! Everything Qubic lives under this module, and nothing here reaches back into
//! the Nano code. That separation is deliberate: FourQ over `Fp = 2^127 - 1` is
//! a different curve family from Ed25519 over `2^255 - 19`, and the two are
//! unrelated despite both being twisted Edwards curves. Sharing a "curve module"
//! between them would invite exactly the kind of plausible-but-wrong output
//! that `ERRATA.md` §7 records.
//!
//! The modules run in dependency order:
//!
//! | module | role |
//! |---|---|
//! | [`k12`] | KangarooTwelve, the seed and checksum hash |
//! | [`fp`] | the base field `Fp = 2^127 - 1` |
//! | [`fourq`] | the `Fq = Fp[i]` extension, the curve, and scalar multiplication |
//! | [`identity`] | the public API: seed to identity, and back |

// The field layers keep the reference names `add`, `sub`, `mul` and `neg`
// rather than implementing `std::ops::{Add,Sub,Mul,Neg}`. That is deliberate:
// `fpAdd`/`fqAdd` and friends are what the Qubic reference calls these
// operations, and a line-for-line read against the reference is worth more
// than trait ergonomics. The trait methods would also read as `a + b` in code
// that is otherwise a direct transcription, which invites "simplifications"
// that break the correspondence with the source being verified.
#![allow(clippy::should_implement_trait)]

pub mod fp;
pub mod fourq;
pub mod identity;
pub mod k12;

/// Python-oracle field multiplication triples, used by the `fp` tests.
#[cfg(test)]
mod fp_vectors;

/// Golden derivation vectors from the official Qubic package.
#[cfg(test)]
mod tests_vectors;
