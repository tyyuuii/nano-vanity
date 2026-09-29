import { deriveKeys, publicKeyToIdentity, identityToPublicKey,
         isValidIdentityChecksum, contractIndexToIdentity }
  from '@qubic.org/crypto'

const hex = (u) => Array.from(u, b => b.toString(16).padStart(2, '0')).join('')
const seeds = [
  'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz',
  'abababababababababababababababababababababababababababa',
  'lcehvbvddggkjfnokduyjuiyvkklrvrmsaozwbvjlzvgvfipqpnkkuf',
  'qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq',
  'mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm',
]
const out = []
for (const s of seeds) {
  if (s.length !== 55) { console.error('bad seed length', s.length); continue }
  const { subseed, privateKey, publicKey } = deriveKeys(s)
  const identity = publicKeyToIdentity(publicKey)
  const back = identityToPublicKey(identity)
  out.push({
    seed: s,
    subseed: hex(subseed),
    privateKey: hex(privateKey),
    publicKey: hex(publicKey),
    identity,
    roundTrip: hex(back) === hex(publicKey),
    checksumOk: isValidIdentityChecksum(identity),
    identityLen: identity.length,
  })
}
// contract identities, same encoding path with a tiny public key
const contracts = [1, 2, 4].map(i => ({ index: i, identity: contractIndexToIdentity(i) }))
console.log(JSON.stringify({ vectors: out, contracts }, null, 2))
