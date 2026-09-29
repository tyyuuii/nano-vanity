# Qubic reference material

Fetched from the official Qubic repositories to research key derivation.
Not compiled, not vendored, not depended on — these are reference copies kept
so the derivation in `QUBIC_PLAN.md` can be re-checked against primary source.

| File | Origin | Role |
|---|---|---|
| `key_utils.cpp` | `qubic/qubic-cli` | **Authoritative** C derivation chain: subseed, private key, identity encode/decode, checksum |
| `key_utils.h` | `qubic/qubic-cli` | Declarations |
| `k12_and_key_utils.h` | `qubic/qubic-cli` | KangarooTwelve + FourQ tables (177KB) |
| `wallet_utils.cpp` / `.h` | `qubic/qubic-cli` | Callers of the above |
| `identity.ts` | `qubic/qubic-typescript` | Most readable form of the same algorithm |
| `fourq.ts` | `qubic/qubic-typescript` | FourQ point arithmetic, `scalarBaseMult`, `recodeScalar`, `pointMarshal` |
| `fq.ts`, `fp.ts` | `qubic/qubic-typescript` | Fp = 2^127-1 and the quadratic extension |
| `fourq-constants.ts` | `qubic/qubic-typescript` | Generator, group order, precomputed constants |
| `k12.ts` | `qubic/qubic-typescript` | K12 is `kt128` from `@noble/hashes` |
| `brands.ts`, `errors.ts` | `qubic/qubic-typescript` | Type branding, error types |
| `*.test.ts` | `qubic/qubic-typescript` | Official tests, incl. the K12 spec vector |
| `vectors/qubic_vectors.json` | generated here | Golden vectors from the official npm package |

## Regenerating the golden vectors

`node` is required. The official package is the oracle, so the vectors are not
produced by our own code.

```sh
cd research/qubic/vectors
npm install
node gen.mjs > qubic_vectors.json
```

Requires network. Never use a funded or real seed here — the seeds are all
synthetic constants like `"a".repeat(55)`.

## Licensing

These files belong to the Qubic project under its own licence. They are
reference material for research, not vendored source, and none of them is
compiled into anything this repository ships. If any Qubic code is ever
vendored rather than reimplemented, its licence must be reviewed first.
