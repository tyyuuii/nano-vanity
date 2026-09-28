//! Micro-profile of the grinder's hot loop, to find where time actually goes.
//!
//! Run with: cargo run --release --example profile -p nano-keys

use std::hint::black_box;
use std::time::Instant;

use blake2::digest::consts::U32;
use blake2::{Blake2b, Blake2b512, Digest};
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;

fn bench(name: &str, iters: u32, mut f: impl FnMut(u32) -> u8) {
    // Warm up so the first measurement is not penalised by cold caches.
    for i in 0..iters / 10 {
        black_box(f(i));
    }
    let t = Instant::now();
    let mut acc = 0u8;
    for i in 0..iters {
        acc ^= black_box(f(i));
    }
    let el = t.elapsed();
    let ns = el.as_nanos() as f64 / iters as f64;
    println!("  {name:<34} {ns:8.1} ns/op   ({} acc)", acc);
}

fn main() {
    let iters = 15_000;
    let seed = [0u8; 32];

    println!("Per-operation cost on this device ({iters} iters each)\n");

    bench("blake2b-256(seed||idx)", iters, |i| {
        let mut h = Blake2b::<U32>::new();
        h.update(seed);
        h.update((i).to_le_bytes());
        h.finalize()[0]
    });

    let priv_bytes: [u8; 32] = Blake2b::<U32>::digest(seed).into();

    bench("blake2b-512(priv)", iters, |i| {
        let mut p = priv_bytes;
        p[0] ^= i as u8;
        Blake2b512::digest(p)[0]
    });

    // Clamped scalar from an unreduced 32-byte value.
    let mut clamped = [0u8; 32];
    clamped.copy_from_slice(&Blake2b512::digest(priv_bytes)[..32]);
    clamped[0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;

    bench("Scalar::from_bytes_mod_order", iters, |i| {
        let mut c = clamped;
        c[1] ^= i as u8;
        Scalar::from_bytes_mod_order(c).to_bytes()[0]
    });

    let scalar = Scalar::from_bytes_mod_order(clamped);
    let scalar_bytes = scalar.to_bytes();

    bench("ED25519_BASEPOINT_TABLE * scalar", iters, |i| {
        let mut b = scalar_bytes;
        b[0] ^= i as u8;
        let s = Scalar::from_bytes_mod_order(b);
        let p = ED25519_BASEPOINT_TABLE * &s;
        p.compress().to_bytes()[0]
    });

    // dalek's clamped entry point: builds the unreduced Scalar internally, so it
    // skips canonical reduction. Result is identical because B has order l.
    bench("EdwardsPoint::mul_base_clamped", iters, |i| {
        let mut c = clamped;
        c[2] ^= i as u8;
        EdwardsPoint::mul_base_clamped(c).compress().to_bytes()[0]
    });

    // Whole hot loop, exactly as the grinder runs it.
    bench("FULL hot loop (hash+hash+mul)", iters, |i| {
        let mut key = [0u8; 32];
        key[..4].copy_from_slice(&i.to_le_bytes());
        let scalar_bytes = {
            let h = Blake2b512::digest(key);
            let mut s = [0u8; 32];
            s.copy_from_slice(&h[..32]);
            s[0] &= 248;
            s[31] &= 127;
            s[31] |= 64;
            s
        };
        let sc = Scalar::from_bytes_mod_order(scalar_bytes);
        (ED25519_BASEPOINT_TABLE * &sc).compress().to_bytes()[0]
    });

    // Same loop via the clamped entry point, to see if it is cheaper.
    bench("FULL hot loop (mul_base_clamped)", iters, |i| {
        let mut key = [0u8; 32];
        key[..4].copy_from_slice(&i.to_le_bytes());
        let scalar_bytes = {
            let h = Blake2b512::digest(key);
            let mut s = [0u8; 32];
            s.copy_from_slice(&h[..32]);
            s[0] &= 248;
            s[31] &= 127;
            s[31] |= 64;
            s
        };
        EdwardsPoint::mul_base_clamped(scalar_bytes)
            .compress()
            .to_bytes()[0]
    });

    // Isolate the cost of `compress()`, which needs a full field inversion
    // (~250 squarings). black_box forces the point to be materialised without
    // calling compress() on it.
    bench("mul WITHOUT compress (isolate)", iters, |i| {
        let mut b = scalar_bytes;
        b[0] ^= i as u8;
        let s = Scalar::from_bytes_mod_order(b);
        let p = ED25519_BASEPOINT_TABLE * &s;
        black_box(&p);
        0
    });

    bench("mul WITH compress only", iters, |i| {
        let mut b = scalar_bytes;
        b[0] ^= i as u8;
        let s = Scalar::from_bytes_mod_order(b);
        let p = ED25519_BASEPOINT_TABLE * &s;
        p.compress().to_bytes()[0]
    });

    // Note: curve25519_dalek::field is pub(crate), so a standalone inversion
    // cannot be timed from outside. The mul-with/without delta below bounds it.
}
