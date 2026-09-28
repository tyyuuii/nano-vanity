//! A/B the two dalek majors on this exact device.
//!
//! We ship on curve25519-dalek 4.1.3. 5.0.0 claims "automatic serial backend
//! selection between u32 and u64" and "maximum available NAF window size in
//! VartimePrecomputedStraus". dalek's own build.rs carries a "TODO(Arm): needs
//! tests + benchmarks to back this up" -- this is that benchmark, on a
//! six-year-old Cortex-A73.
//!
//! The multiply is measured without compression, so the delta is arithmetic
//! only. The point is passed through `black_box` rather than `.compress()`
//! because compressing would re-add the 21% inversion+sqrt cost and hide the
//! effect being measured.
//!
//! Run: cargo run --release --example dalek_ab -p nano-keys

use std::hint::black_box;
use std::time::Instant;

fn bench<T>(name: &str, iters: u32, mut f: impl FnMut(u32) -> T) -> f64 {
    for i in 0..(iters / 10).max(1) {
        black_box(f(i));
    }
    let mut best = f64::INFINITY;
    for _ in 0..5 {
        let t = Instant::now();
        for i in 0..iters {
            black_box(f(i));
        }
        best = best.min(t.elapsed().as_secs_f64() / iters as f64);
    }
    let ns = best * 1e9;
    println!("  {name:<38} {ns:9.1} ns/op");
    ns
}

fn scalar_bytes(i: u32) -> [u8; 32] {
    let mut b = [0u8; 32];
    for (k, x) in b.iter_mut().enumerate() {
        *x = (k as u8).wrapping_mul(37) | 1;
    }
    b[0] &= 248;
    b[31] &= 127;
    b[31] |= 64;
    b[2] ^= (i & 0x3f) as u8;
    b
}

fn main() {
    let iters: u32 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(6_000);

    println!("dalek 4.1.3 vs 5.0.0 on this device ({iters} iters each)\n");
    println!("  multiply measured alone; compression excluded\n");

    // --- 4.1.3 multiply, as shipped -----------------------------------------
    use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE as T4;
    use curve25519_dalek::scalar::Scalar as S4;
    let mul4 = bench("4.1.3  basepoint multiply", iters, |i| {
        let s = S4::from_bytes_mod_order(scalar_bytes(i));
        black_box(T4 * &s)
    });

    // --- 5.0.0 multiply -----------------------------------------------------
    use dalek5::constants::ED25519_BASEPOINT_TABLE as T5;
    use dalek5::scalar::Scalar as S5;
    let mul5 = bench("5.0.0  basepoint multiply", iters, |i| {
        let s = S5::from_bytes_mod_order(scalar_bytes(i));
        black_box(T5 * &s)
    });

    // --- correctness: the two majors must agree bit for bit -----------------
    let v4 = (T4 * &S4::from_bytes_mod_order(scalar_bytes(0))).compress().to_bytes();
    let v5 = (T5 * &S5::from_bytes_mod_order(scalar_bytes(0))).compress().to_bytes();
    println!("\n  agreement 4.1.3 == 5.0.0:  {}", v4 == v5);
    println!("  multiply speedup:            {:.3}x", mul4 / mul5);

    // --- compression, for completeness --------------------------------------
    let p4 = T4 * &S4::from_bytes_mod_order(scalar_bytes(0));
    let p5 = T5 * &S5::from_bytes_mod_order(scalar_bytes(0));
    let cmp4 = bench("4.1.3  compress", iters, |_| black_box(&p4).compress().to_bytes()[0]);
    let cmp5 = bench("5.0.0  compress", iters, |_| black_box(&p5).compress().to_bytes()[0]);
    println!("\n  compress speedup:             {:.3}x", cmp4 / cmp5);

    let end4 = mul4 + cmp4;
    let end5 = mul5 + cmp5;
    println!("  end-to-end mul+compress:      {:.3}x", end4 / end5);
    println!(
        "  implied address rate:         {:.0}/s single core (was {:.0}/s)",
        1e9 / end5,
        1e9 / end4
    );
}
