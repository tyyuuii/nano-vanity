//! Where does a Qubic candidate cost its time?
//!
//! Mirrors `breakdown.rs` for Nano, because the shape of the work is different:
//! K12 twice, a FourQ fixed-base scalar multiply, and a point compression. The
//! reference `scalar_baseMult` is a 65-round Montgomery ladder with no
//! precomputed base table, so the multiply is expected to dominate by a wide
//! margin and to be much more expensive relative to the hashing than Nano's.
//
//! Run: cargo run --release --example qubic_breakdown -p nano-keys

use std::hint::black_box;
use std::time::Instant;

use nano_keys::qubic::fourq::{point_marshal, scalar_base_mult, to_affine, GENERATOR};
use nano_keys::qubic::k12::k12_32;

fn bench<T>(name: &str, iters: u32, mut f: impl FnMut(u32) -> T) -> f64 {
    for i in 0..(iters / 10).max(1) {
        black_box(f(i));
    }
    let mut best = f64::INFINITY;
    for _ in 0..3 {
        let t = Instant::now();
        for i in 0..iters {
            black_box(f(i));
        }
        best = best.min(t.elapsed().as_secs_f64() / iters as f64);
    }
    let ns = best * 1e9;
    println!("  {name:<40} {ns:10.1} ns/op");
    ns
}

fn main() {
    let iters: u32 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(200);
    let seed_bytes: [u8; 55] = std::array::from_fn(|i| (i % 26) as u8);

    println!("Qubic per-candidate cost on this device ({iters} iters each)\n");

    let k12_a = bench("K12(55 bytes)", iters, |i| {
        let mut s = seed_bytes;
        s[0] = (s[0] + i as u8) % 26;
        k12_32(&s)
    });
    let subseed = k12_32(&seed_bytes);
    let k12_b = bench("K12(32 bytes) = private key", iters, |i| {
        let mut s = subseed;
        s[0] = s[0].wrapping_add(i as u8);
        k12_32(&s)
    });
    let priv_key = k12_32(&subseed);
    let mul = bench("FourQ scalar_base_mult", iters, |i| {
        let mut k = priv_key;
        k[0] = k[0].wrapping_add(i as u8);
        black_box(scalar_base_mult(&k))
    });
    let pt = scalar_base_mult(&priv_key);
    let affine = bench("to_affine (one Fq inversion)", iters, |_i| black_box(&pt).pipe_affine());
    let compress = bench("point_marshal", iters, |_i| black_box(&pt).pipe_marshal());

    let total = k12_a + k12_b + mul + compress;
    println!("\n  breakdown of a full candidate:");
    println!("    K12 seed        {:5.1}%", k12_a / total * 100.0);
    println!("    K12 private key {:5.1}%", k12_b / total * 100.0);
    println!("    scalar multiply {:5.1}%", mul / total * 100.0);
    println!("    to_affine       {:5.1}%", affine / total * 100.0);
    println!("    total           {total:.1} ns/candidate");
    println!("\n  single-core address rate: {:.0}/s", 1e9 / total);
    println!("  (to_affine is inside point_marshal; shown for context)");
    let _ = GENERATOR;
}

trait Pipe {
    fn pipe_affine(&self) -> (nano_keys::qubic::fourq::Fq, nano_keys::qubic::fourq::Fq);
    fn pipe_marshal(&self) -> [u8; 32];
}
impl Pipe for nano_keys::qubic::fourq::PointR1 {
    fn pipe_affine(&self) -> (nano_keys::qubic::fourq::Fq, nano_keys::qubic::fourq::Fq) {
        to_affine(self)
    }
    fn pipe_marshal(&self) -> [u8; 32] {
        point_marshal(self)
    }
}
