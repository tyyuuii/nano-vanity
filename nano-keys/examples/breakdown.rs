//! Where does the CPU hot loop actually spend its time?
//!
//! `private_scalar_to_public` does two very different pieces of work: an
//! elliptic-curve scalar multiply, and a point *compression* that needs a
//! modular inversion (a ~254-step exponentiation) followed by a square root
//! (another exponentiation). The existing profile.rs measured them together,
//! so it could not tell us which one to attack.
//!
//! This differs them: measure the multiply with the point black_boxed but not
//! compressed, measure compress alone on a fixed point, and subtract.
//!
//! Run: cargo run --release --example breakdown -p nano-keys

use std::hint::black_box;
use std::time::Instant;

use blake2::{Blake2b512, Digest};
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;

fn bench<T>(name: &str, iters: u32, mut f: impl FnMut(u32) -> T) -> f64 {
    for i in 0..(iters / 10).max(1) {
        black_box(f(i));
    }
    let mut best = f64::INFINITY;
    for _ in 0..5 {
        let t = Instant::now();
        let mut acc = None::<T>;
        for i in 0..iters {
            acc = Some(black_box(f(i)));
        }
        black_box(&acc);
        best = best.min(t.elapsed().as_secs_f64() / iters as f64);
    }
    let ns = best * 1e9;
    println!("  {name:<38} {ns:9.1} ns/op");
    ns
}

fn main() {
    let iters: u32 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(20_000);

    println!("CPU hot-loop breakdown on this device ({iters} iters each)\n");

    let seed = [7u8; 32];
    let mut priv_bytes = [0u8; 32];
    priv_bytes.copy_from_slice(&Blake2b512::digest(seed)[..32]);
    let h = Blake2b512::digest(priv_bytes);
    let mut clamped = [0u8; 32];
    clamped.copy_from_slice(&h[..32]);
    clamped[0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;

    // --- hashing -------------------------------------------------------------
    let ns_hash512 = bench("blake2b-512 (scalar expand)", iters, |i| {
        let mut p = priv_bytes;
        p[0] ^= i as u8;
        Blake2b512::digest(p)[0]
    });

    // --- reduction -----------------------------------------------------------
    let ns_reduce = bench("Scalar::from_bytes_mod_order", iters, |i| {
        let mut c = clamped;
        c[1] ^= (i & 0x7f) as u8;
        Scalar::from_bytes_mod_order(c).to_bytes()[0]
    });

    // --- the two halves of private_scalar_to_public -------------------------
    // Multiply only: the point is black_boxed so it must be materialised, but
    // never compressed.
    let ns_mul = bench("basepoint multiply (no compress)", iters, |i| {
        let mut c = clamped;
        c[2] ^= (i & 0x7f) as u8;
        let s = Scalar::from_bytes_mod_order(c);
        black_box(ED25519_BASEPOINT_TABLE * &s)
    });

    // Compress on one fixed point: pure inversion + sqrt + serialise, i.e.
    // exactly the tail of the hot loop after the multiply.
    let fixed = ED25519_BASEPOINT_TABLE * &Scalar::from_bytes_mod_order(clamped);
    let ns_compress_bytes = bench("compress + to_bytes", iters, |_i| {
        fixed.compress().to_bytes()[0]
    });

    // --- whole operation -----------------------------------------------------
    let ns_full = bench("FULL private_scalar_to_public", iters, |i| {
        let mut c = clamped;
        c[3] ^= (i & 0x7f) as u8;
        let s = Scalar::from_bytes_mod_order(c);
        (ED25519_BASEPOINT_TABLE * &s).compress().to_bytes()[0]
    });

    // --- the ratio that decides everything -----------------------------------
    let ns_compress_true = ns_compress_bytes;
    let mult_pct = ns_mul / ns_full * 100.0;
    let comp_pct = ns_compress_true / ns_full * 100.0;
    let rest_pct = 100.0 - mult_pct - comp_pct;

    println!("\n  inside private_scalar_to_public:");
    println!("    multiply            {mult_pct:5.1}%");
    println!("    compress            {comp_pct:5.1}%");
    println!("    overhead/other      {rest_pct:5.1}%");

    println!("\n  whole-loop budget (hash512 + reduce + mul + compress):");
    let total = ns_hash512 + ns_reduce + ns_mul + ns_compress_bytes;
    println!("    blake2b-512         {:5.1}%", ns_hash512 / total * 100.0);
    println!("    reduce              {:5.1}%", ns_reduce / total * 100.0);
    println!("    multiply            {:5.1}%", ns_mul / total * 100.0);
    println!("    compress            {:5.1}%", ns_compress_bytes / total * 100.0);
    println!("    total               {total:.1} ns/candidate");

    // --- what skipping compression would buy ---------------------------------
    //
    // For PREFIX matching we never need the x coordinate: the address body is
    // [y in 255 bits][sign of x in 1 bit], and the sign bit is the LAST bit of
    // the 260-bit value, so it only ever affects a suffix. A prefix is
    // determined entirely by the top bits of y.
    //
    // compress() = invert (a ~254-step exponentiation) + sqrt (another one).
    // Skipping the sqrt alone removes about half of it; batching the remaining
    // inversion across a whole block of candidates with Montgomery's trick
    // amortises it to ~3 multiplies per point.
    let after_skip_sqrt = total - ns_compress_bytes * 0.5;
    let after_batch_inv = total - ns_compress_bytes * 0.95;
    println!("\n  if prefix mode never compresses:");
    println!("    skip sqrt only     {total:.0} -> {after_skip_sqrt:.0} ns  ({:.2}x)", total / after_skip_sqrt);
    println!("    + batch inversion  {total:.0} -> {after_batch_inv:.0} ns  ({:.2}x)", total / after_batch_inv);
    println!("\n    (suffix/contains mode still needs the sign bit, so it keeps compress.)");
}
