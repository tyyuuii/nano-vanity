// Independent verification of an identity THIS implementation found.
//
// The golden vectors prove the pipeline agrees with the official package on
// inputs chosen in advance. This checks the other direction: a seed the search
// discovered, fed to the official package, must give the identity the tool
// printed. A search bug that biased candidate generation would pass the golden
// vectors and fail here.
import { deriveKeys, publicKeyToIdentity, identityToPublicKey, isValidIdentityChecksum } from "@qubic.org/crypto";

const cases = [
  ["drtlrmhztabbwivylupsnbqqpuotqrjmqvgwodpinjglvafakqlwtca",
   "ABNKVXTHBPEUMARJDMYMPIICDNAAWYNGXZTQDMPWECJRFTSGSFPKKAMBJAFI"],
  ["drtlrmhztabbwivylupsnbqqpuotqrjmgrddbbfclkuxonrncouqgtb",
   "ABZHUNDYFKEPRAFRYTOKDRSPRHVBQERJJBYGNOSPEENGUGAHYUIULQEDQRQM"],
];

let fail = 0;
for (const [seed, claimed] of cases) {
  const d = deriveKeys(seed);
  const identity = publicKeyToIdentity(d.publicKey);
  const ok = identity === claimed;
  if (!ok) fail++;
  console.log(`  ${ok ? "OK  " : "FAIL"} ${seed.slice(0,12)}... -> ${identity}`);
  const pk = identityToPublicKey(identity);
  const pkOk = Buffer.from(pk).toString("hex").toUpperCase() === Buffer.from(d.publicKey).toString("hex").toUpperCase();
  const ckOk = isValidIdentityChecksum(identity);
  if (!pkOk) { console.log("       FAIL public key round-trip"); fail++; }
  if (!ckOk) { console.log("       FAIL checksum"); fail++; }
  if (!ok) console.log(`       tool said: ${claimed}`);
  // Round-trip: the identity must decode back to the same public key.
  if (identity.length !== 60) { console.log("       FAIL length " + identity.length); fail++; }
}
console.log(fail === 0 ? "\n  FOUND-SEED VERIFICATION: ALL PASS" : `\n  FOUND-SEED VERIFICATION: ${fail} FAILED`);
process.exit(fail === 0 ? 0 : 1);
