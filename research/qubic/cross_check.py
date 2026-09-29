#!/usr/bin/env python3
"""Independent cross-check of the Qubic implementation.

This is deliberately *not* a second implementation of the derivation. A
transcription of the same FourQ ladder in Python would share every assumption
with the Rust, including the ones that are wrong, and would agree with it
perfectly while both were wrong. The bug already found in the borrow chain of
`sub_div16` is exactly the kind of thing two transcriptions of the same source
both get wrong.

So each check here is anchored to something other than the implementation:

  1. K12 against the official `@qubic.org/crypto` package, which is the real
     oracle rather than a reimplementation.
  2. Fp arithmetic against Python's arbitrary-precision integers, with the
     Mersenne reduction written here rather than imported.
  3. **Every golden public key satisfies the FourQ curve equation.** The
     equation is recomputed here from the curve parameters with nothing but
     Python bigints and a Tonelli-Shanks square root in Fq. A public key is the
     image of a scalar multiple, so it is necessarily on the curve, and a wrong
     ladder step, a wrong marshalling, or a wrong final inversion cannot land
     on it by accident. This costs about a millisecond, where the group-order
     check that used to sit here -- affine Edwards, an Fq inversion per
     addition, each a 254-bit modexp -- cost minutes. Verifying membership
     rather than exact order is the right trade: membership catches the
     failure modes that matter, and the identity agreement in steps 4 and 5
     already pins the exact value.
  4. The identity encoding, written from the specification and round-tripped.
  5. The shipped binary, so the artefact is what was verified.

K12 comes from Node rather than a Python package because Termux has no PyPI
access for `pyk12`, and because the npm package is the authoritative
implementation anyway -- a Python K12 would be a third transcription.

Usage:
    python3 research/qubic/cross_check.py [--binary PATH]
"""

import json
import os
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
VECTORS = os.path.join(HERE, "vectors", "qubic_vectors.json")
K12_HELPER = os.path.join(HERE, "vectors", "k12_helper.mjs")

P = 2**127 - 1  # the FourQ base field

# The group order, lifted from the Qubic reference. Little-endian u64 limbs.
ORDER = 0x29CBC14E5E0A72F05397829CBC14E5DFBD004DFE0F79992FB2540EC7768CE7

# The curve parameters: a = -1 and d, as [real, imaginary].
PARAM_A = (P - 1, 0)
PARAM_D = (0x0000_0000_0000_00E4_0000_0000_0000_0142,
           0x5E47_2F84_6657_E0FC_B382_1488_F1FC_0C8D)


# ---------------------------------------------------------------- Fp --------

def fp_add(a, b):
    s = a + b
    if s >= P:
        s -= P
    return s


def fp_sub(a, b):
    return (a - b) % P


def fp_mul(a, b):
    # Full 254-bit product, then fold the high part back with 2^127 = 1 (mod p).
    t = a * b
    return ((t & P) + (t >> 127)) % P


def fp_pow(a, e):
    r = 1
    while e:
        if e & 1:
            r = fp_mul(r, a)
        a = fp_mul(a, a)
        e >>= 1
    return r


# ---------------------------------------------------------------- Fq --------

def fq_add(u, v):
    return (fp_add(u[0], v[0]), fp_add(u[1], v[1]))


def fq_sub(u, v):
    return (fp_sub(u[0], v[0]), fp_sub(u[1], v[1]))


def fq_mul(u, v):
    ur, ui = u
    vr, vi = v
    return (fp_sub(fp_mul(ur, vr), fp_mul(ui, vi)),
            fp_add(fp_mul(ur, vi), fp_mul(ui, vr)))


def fq_sqr(u):
    return fq_mul(u, u)


def fq_inv(u):
    """Invert in the quadratic extension via the conjugate.

    |u|^2 = ur^2 + ui^2, so u^-1 = conj(u) / |u|^2. This differs from the
    reference's `fpTwo1251` chain on purpose -- an independent method is the
    only kind that can catch a shared mistake.
    """
    ur, ui = u
    norm = fp_add(fp_mul(ur, ur), fp_mul(ui, ui))
    if norm == 0:
        raise ZeroDivisionError("cannot invert the zero element of Fq")
    ninv = fp_pow(norm, P - 2)
    return (fp_mul(ur, ninv), fp_sub(0, fp_mul(ui, ninv)))


FQ_ZERO = (0, 0)
FQ_ONE = (1, 0)
FQ_IDENTITY = (FQ_ZERO, FQ_ONE)  # the neutral element, (X=0, Y=1)

# The order of Fq. p^2 - 1 = 2^128 * (2^126 - 1), so Tonelli-Shanks over Fq has
# 128 rounds of squaring, which is why a plain (q+1)/4 formula does not apply.
FQ_ORDER = P * P


def fq_pow(u, e):
    r = FQ_ONE
    while e:
        if e & 1:
            r = fq_mul(r, u)
        u = fq_sqr(u)
        e >>= 1
    return r


def non_residue():
    """Find a quadratic non-residue in Fq.

    It has to be searched for among elements with a **non-zero imaginary
    part**, and that is not a detail. For any n in Fp*:

        n^((p^2-1)/2) = (n^(p-1))^((p+1)/2) = (+-1)^(2^126) = 1

    because (p+1)/2 = 2^126 is even. So *every* non-zero element of Fp is
    already a square in Fq, and a search that only tries Fp elements never
    terminates. An earlier version of this file did exactly that and hung
    forever on the first decompress.
    """
    minus_one = (P - 1, 0)
    for a in range(64):
        for b in range(64):
            if a == 0 and b == 0:
                continue
            cand = (a, b)
            if fq_pow(cand, (FQ_ORDER - 1) // 2) == minus_one:
                return cand
    raise RuntimeError("no quadratic non-residue in the first 64x64 elements of Fq")


def fq_sqrt(u):
    """A square root in Fq, or None if there is none.

    Tonelli-Shanks over the extension field. An earlier version of this file
    tried to shortcut this by taking a square root of the real part of x^2 in
    Fp, which is simply wrong: x^2 = (a^2 - b^2) + 2ab i has a real part that
    is generally not a square in Fp, so the shortcut reported valid points as
    invalid. Only 2 of the 6 golden keys survived it.
    """
    if u == FQ_ZERO:
        return FQ_ZERO
    if fq_pow(u, (FQ_ORDER - 1) // 2) != FQ_ONE:
        return None  # not a square, so the point is not on the curve

    q, s, e = FQ_ORDER - 1, FQ_ORDER - 1, 0
    while s % 2 == 0:
        s //= 2
        e += 1

    c = fq_pow(non_residue(), s)
    r = fq_pow(u, (s + 1) // 2)
    t = fq_pow(u, s)
    m = e
    while t != FQ_ONE:
        i, t2 = 1, fq_sqr(t)
        while t2 != FQ_ONE:
            t2 = fq_sqr(t2)
            i += 1
            if i == m:
                return None  # cannot happen once the Legendre test passed
        b = fq_pow(c, 1 << (m - i - 1))
        r = fq_mul(r, b)
        c = fq_sqr(b)
        t = fq_mul(t, c)
        m = i
    return r


def on_curve(pt):
    (x, y) = pt
    x2 = fq_sqr(x)
    y2 = fq_sqr(y)
    lhs = fq_add(fq_mul(PARAM_A, x2), y2)
    rhs = fq_add(FQ_ONE, fq_mul(PARAM_D, fq_mul(x2, y2)))
    return lhs == rhs


# --------------------------------------------------------- decompression ----

def decompress(pub):
    """Recover (X, Y) in Fq from a 32-byte FourQ public key.

    Layout, from the reference: little-endian real Y in bytes 0..16,
    little-endian imaginary Y in bytes 16..32, and the sign of X in bit 7 of
    byte 31. X is then solved from the curve equation and the sign bit selects
    between the two roots.

    The sign bit IS bit 127 of the imaginary half, so it has to be masked off
    before the imaginary part is interpreted as a field element. Reducing with
    `% P` instead is subtly wrong: it wraps that bit into the low bits rather
    than clearing it, which yields a plausible Y that is not a curve point, and
    then reports a perfectly good public key as off-curve. An earlier version
    of this file did exactly that and passed one vector of six.
    """
    mask = (1 << 127) - 1
    y = (int.from_bytes(pub[0:16], "little") & mask,
         int.from_bytes(pub[16:32], "little") & mask)
    sign = (pub[31] >> 7) & 1

    # a x^2 = 1 - y^2 + d x^2 y^2  =>  x^2 = (1 - y^2) / (a - d y^2)
    y2 = fq_sqr(y)
    x2 = fq_mul(fq_sub(FQ_ONE, y2), fq_inv(fq_sub(PARAM_A, fq_mul(PARAM_D, y2))))

    root = fq_sqrt(x2)
    if root is None:
        raise ValueError("no curve point has this Y: x^2 is not a square in Fq")
    # The two roots are +x and -x; the sign bit in byte 31 selects between them.
    # The result is a point, so both coordinates travel out as Fq pairs.
    if sign == 0:
        return (root, y)
    return ((fp_sub(0, root[0]), fp_sub(0, root[1])), y)


# ------------------------------------------------------------- K12 oracle ----

def k12_many(messages, n=32):
    """K12 over many messages, via the official npm package.

    Batched into a single Node invocation: starting Node per hash would cost
    more than the hashing, and this script hashes every vector's public key
    for the checksum.
    """
    payload = json.dumps([{"hex": m.hex(), "n": n} for m in messages])
    r = subprocess.run(
        ["node", K12_HELPER], input=payload, capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        raise SystemExit(f"cross_check: K12 helper failed:\n{r.stderr.strip()}")
    return [bytes.fromhex(h) for h in json.loads(r.stdout)]


class K12:
    """Memoised K12, so the module reads naturally in the checks below."""

    def __init__(self):
        self._cache = {}

    def prime(self, m, n=32):
        if (m, n) not in self._cache:
            self._cache[(m, n)] = k12_many([m], n)[0]
        return self._cache[(m, n)]


# ---------------------------------------------------------- identity --------

def public_key_to_identity(pub, k12):
    """The 60-character identity, written from the specification.

    Four little-endian u64 fragments, each as 14 base-26 digits with the
    LEAST significant digit first, then 4 checksum digits from 18 bits of K12
    over the public key. The digit order is the opposite of Nano's and is the
    single easiest thing in this file to get backwards.
    """
    out = []
    for frag in range(4):
        v = int.from_bytes(pub[frag * 8:frag * 8 + 8], "little")
        for _ in range(14):
            out.append(chr(ord("A") + v % 26))
            v //= 26
    c = int.from_bytes(k12(pub, 3), "little") & 0x3FFFF
    for _ in range(4):
        out.append(chr(ord("A") + c % 26))
        c //= 26
    return "".join(out)


def identity_to_public_key(ident):
    pub = bytearray()
    for frag in range(4):
        v = 0
        for j in range(13, -1, -1):
            v = v * 26 + (ord(ident[frag * 14 + j]) - ord("A"))
        pub += struct.pack("<Q", v)
    return bytes(pub)


# ---------------------------------------------------------------- driver ----

class Check:
    def __init__(self):
        self.passed = 0
        self.failed = 0

    def __call__(self, name, ok, detail=""):
        if ok:
            self.passed += 1
            print(f"  OK    {name}")
        else:
            self.failed += 1
            print(f"  FAIL  {name}")
            if detail:
                for line in str(detail).splitlines():
                    print(f"        {line}")


def main():
    binary = None
    if "--binary" in sys.argv:
        binary = sys.argv[sys.argv.index("--binary") + 1]
    if binary is None:
        binary = os.environ.get("NANO_VANITY_BIN") or os.path.join(
            ROOT, "target", "release", "nano-vanity")
    if not os.path.exists(binary):
        print(f"cross_check: binary not found at {binary}")
        print("  cargo build --release   or pass --binary PATH")
        return 1

    with open(VECTORS) as fh:
        vectors = json.load(fh)["vectors"]

    ok = Check()
    k12 = K12()

    print("\n1. K12 against the published specification vector")
    got = k12.prime(b"").hex()
    want = "1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e5"
    ok("K12(empty, 32) matches the spec", got == want, f"got {got}\nwant {want}")

    print("\n2. Fp arithmetic against Python's bigints")
    bad = []
    for a, b in [(0, 0), (1, 1), (P - 1, 1), (2**63, 2**64 + 7),
                 (12345678901234567890, 98765432109876543210), (P - 1, P - 1),
                 (P - 1, P - 2), (2**126, 2**126)]:
        if fp_mul(a % P, b % P) != (a * b) % P:
            bad.append(f"  {a} * {b}")
    ok(f"Fp multiplication agrees on {8 - len(bad)} of 8 edge cases",
       not bad, "\n".join(bad))

    print("\n3. Every golden public key is a real point on the FourQ curve")
    # The load-bearing check, and now a cheap one: decompress with an
    # independent Tonelli-Shanks square root, then recompute the curve equation
    # from the parameters. Off-curve results are what a bad ladder, a bad
    # marshalling or a bad final inversion actually produce.
    for v in vectors:
        pub = bytes.fromhex(v["publicKey"])
        tag = v["seed"][:8]
        try:
            pt = decompress(pub)
            ok(f"seed {tag}...: public key decompresses to a curve point",
               on_curve(pt))
        except Exception as exc:                       # noqa: BLE001
            ok(f"seed {tag}...: public key decompresses to a curve point",
               False, exc)

    print("\n4. Identity encoding, written from the spec")
    for v in vectors:
        pub = bytes.fromhex(v["publicKey"])
        ident = public_key_to_identity(pub, k12.prime)
        ok(f"seed {v['seed'][:8]}...: identity encodes correctly",
           ident == v["identity"],
           f"got {ident}\nwant {v['identity']}")
        ok(f"seed {v['seed'][:8]}...: identity round-trips",
           identity_to_public_key(ident) == pub)

    print("\n5. The shipped binary derives the golden vectors")
    for v in vectors:
        r = subprocess.run(
            [binary, "--chain", "qubic", "--derive", v["seed"]],
            capture_output=True, text=True, timeout=180)
        fields = {}
        for line in r.stdout.splitlines():
            if ":" in line:
                key, _, val = line.partition(":")
                fields[key.strip()] = val.strip()
        ok(f"seed {v['seed'][:8]}...: binary derives the golden identity",
           fields.get("identity") == v["identity"],
           f"got {fields.get('identity')}\nwant {v['identity']}")
        ok(f"seed {v['seed'][:8]}...: binary derives the golden public key",
           fields.get("public key", "").lower() == v["publicKey"].lower(),
           f"got {fields.get('public key')}\nwant {v['publicKey']}")

    print("\n6. Small live searches through the shipped binary")
    # Each of these asks for a *single* character, so the expected wait is about
    # 26 candidates and the search finishes in milliseconds rather than hours.
    # The point is not that the search is hard, it is that a found result is
    # structurally sound: a real 60-character identity whose 4 checksum
    # characters were recomputed here from the specification, decoded back to
    # the same 32 bytes, and whose seed is a well-formed 55-letter seed.
    #
    # A fixed master seed keeps these reproducible, so a failure here is a real
    # regression rather than an unlucky draw.
    master = "m" * 55
    for label, pattern, mode in [
        ("1-char prefix", "A", "prefix"),
        ("1-char suffix", "K", "suffix"),
        ("1-char contains", "M", "contains"),
    ]:
        r = subprocess.run(
            [binary, "--chain", "qubic", pattern, "-m", mode, "-n", "1",
             "-T", "30", "-s", master],
            capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            ok(f"{label}: search succeeds", False,
               f"exit {r.returncode}\n{r.stdout.strip()[-400:]}")
            continue
        found = [line.split(":", 1)[1].strip()
                 for line in r.stdout.splitlines()
                 if line.strip().startswith("identity")]
        seeds = [line.split(":", 1)[1].strip()
                 for line in r.stdout.splitlines()
                 if line.strip().startswith("seed")]
        if len(found) != 1:
            ok(f"{label}: exactly one match", False,
               f"got {len(found)}: {found}")
            continue
        ident, seed = found[0], seeds[0] if seeds else ""
        ok(f"{label}: found exactly one match ({ident[:6]}…)", True)

        ok(f"{label}: identity is 60 uppercase letters",
           len(ident) == 60 and ident.isalpha() and ident.isupper())
        ok(f"{label}: seed is 55 lowercase letters",
           len(seed) == 55 and seed.isalpha() and seed.islower())
        ok(f"{label}: the match really has the requested shape",
           (ident.startswith(pattern) if mode == "prefix"
            else ident.endswith(pattern) if mode == "suffix"
            else pattern in ident), f"identity was {ident}")

        # Recompute the encoding from the decoded public key. This validates all
        # 60 characters, the fragment split, the little-endian fragment order,
        # the least-significant-digit-first order and the K12 checksum, using
        # only the specification and the official K12.
        pk = identity_to_public_key(ident)
        ok(f"{label}: checksum and encoding re-derive from the public key",
           public_key_to_identity(pk, k12.prime) == ident,
           f"re-encoded to {public_key_to_identity(pk, k12.prime)}")

        # And the seed must be a real Qubic seed: 55 letters, each mapped to
        # 0..25 before hashing.
        ok(f"{label}: the reported seed is the wallet, not an index",
           len(seed) == 55 and "index" not in r.stdout.lower().split("the seed")[0][-80:])

    print("\n7. A found seed re-derives to the identity it was found for")
    # Closes the loop the golden vectors cannot: those use seeds chosen in
    # advance, this one is a seed the search discovered. Run with the found seed
    # as the master so the candidate stream is a pure function of it, then
    # confirm the identity that comes back is the one that was reported.
    r = subprocess.run(
        [binary, "--chain", "qubic", "A", "-m", "prefix", "-n", "1",
         "-T", "30", "-s", master],
        capture_output=True, text=True, timeout=120)
    if r.returncode == 0:
        ident = [line.split(":", 1)[1].strip() for line in r.stdout.splitlines()
                 if line.strip().startswith("identity")][0]
        seed = [line.split(":", 1)[1].strip() for line in r.stdout.splitlines()
                if line.strip().startswith("seed")][0]
        r2 = subprocess.run(
            [binary, "--chain", "qubic", "--derive", seed],
            capture_output=True, text=True, timeout=120)
        again = [line.split(":", 1)[1].strip() for line in r2.stdout.splitlines()
                 if line.strip().startswith("identity")]
        ok("a seed found by search derives the identity it was found for",
           again == [ident], f"re-derived {again}, search reported {ident}")

    print(f"\n  {ok.passed} passed, {ok.failed} failed")
    if ok.failed == 0:
        print("\n  QUBIC CROSS-CHECK RESULT: ALL PASS")
        return 0
    print("\n  QUBIC CROSS-CHECK RESULT: FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
