// The vendored MLS crypto, checked against something other than itself.
//
// `src/vendor/mls/crypto/implementation/noble/hpke.ts` replaces @hpke/core
// with an implementation of RFC 9180 written for biset's single ciphersuite.
// That is exactly the kind of change that passes every functional test while
// being subtly wrong — every party would agree with every other party because
// they all run the same wrong code. So it is checked two ways here, neither of
// which can be satisfied by self-consistency:
//
//   1. **RFC 9420's own crypto-basics test vectors** (test/vectors/, taken
//      from ts-mls's `test_vectors/crypto-basics.json`, cipher suite 1 only).
//      Fixed inputs, fixed expected outputs, written by the working group.
//   2. **Differentially against @hpke/core**, which is kept as a devDependency
//      for this one purpose: seal here and open there, seal there and open
//      here, and compare exported secrets. An independent implementation of
//      the same RFC disagreeing is the signal.
import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256, Aes128Gcm } from '@hpke/core'
import vectors from './vectors/rfc9420-crypto-basics.json' with { type: 'json' }
import { mlsSuite } from '../src/vendor/mls/suite.ts'
import { expandWithLabel, deriveSecret, deriveTreeSecret } from '../src/vendor/mls/crypto/kdf.ts'
import { encryptWithLabel, decryptWithLabel } from '../src/vendor/mls/crypto/hpke.ts'
import { verifyWithLabel, signWithLabel } from '../src/vendor/mls/crypto/signature.ts'

let fails = 0
const ok = (name: string, cond: boolean, detail = '') => {
  console.log(`  ${cond ? 'ok  ' : 'FAIL'}  ${name}${cond || !detail ? '' : '\n          → ' + detail}`)
  if (!cond) fails++
}
const hex = (b: Uint8Array) => Array.from(b, x => x.toString(16).padStart(2, '0')).join('')
const unhex = (s: string) => new Uint8Array(s.match(/../g)!.map(h => parseInt(h, 16)))
const enc = new TextEncoder()

const suite = await mlsSuite()

console.log('\n=== RFC 9420 crypto-basics vectors (cipher suite 1) ===')
const v = vectors[0]!
ok('the vector file is the suite biset speaks', v.cipher_suite === 1)

// KDF: expand_with_label / derive_secret / derive_tree_secret.
const expanded = await expandWithLabel(unhex(v.expand_with_label.secret), v.expand_with_label.label, unhex(v.expand_with_label.context), v.expand_with_label.length, suite.kdf)
ok('expand_with_label', hex(expanded) === v.expand_with_label.out, `${hex(expanded)} != ${v.expand_with_label.out}`)

const derived = await deriveSecret(unhex(v.derive_secret.secret), v.derive_secret.label, suite.kdf)
ok('derive_secret', hex(derived) === v.derive_secret.out, `${hex(derived)} != ${v.derive_secret.out}`)

const treeSecret = await deriveTreeSecret(unhex(v.derive_tree_secret.secret), v.derive_tree_secret.label, v.derive_tree_secret.generation, v.derive_tree_secret.length, suite.kdf)
ok('derive_tree_secret', hex(treeSecret) === v.derive_tree_secret.out, `${hex(treeSecret)} != ${v.derive_tree_secret.out}`)

// Signature: verify the vector's signature, then check our own round trip.
const sigValid = await verifyWithLabel(unhex(v.sign_with_label.pub), v.sign_with_label.label, unhex(v.sign_with_label.content), unhex(v.sign_with_label.signature), suite.signature)
ok('sign_with_label verifies the vector signature', sigValid)
const ownSig = await signWithLabel(unhex(v.sign_with_label.priv), v.sign_with_label.label, unhex(v.sign_with_label.content), suite.signature)
ok('and our own signature verifies', await verifyWithLabel(unhex(v.sign_with_label.pub), v.sign_with_label.label, unhex(v.sign_with_label.content), ownSig, suite.signature))
ok('a tampered message does not verify', !(await verifyWithLabel(unhex(v.sign_with_label.pub), v.sign_with_label.label, enc.encode('not the content'), unhex(v.sign_with_label.signature), suite.signature)))

// HPKE: decrypt the vector's own ciphertext. This is the strongest single
// assertion here — the KEM, the key schedule and the AEAD must ALL match the
// working group's implementation, against bytes we did not produce.
const decrypted = await decryptWithLabel(
  await suite.hpke.importPrivateKey(unhex(v.encrypt_with_label.priv)),
  v.encrypt_with_label.label,
  unhex(v.encrypt_with_label.context),
  unhex(v.encrypt_with_label.kem_output),
  unhex(v.encrypt_with_label.ciphertext),
  suite.hpke,
)
ok('encrypt_with_label: the vector ciphertext decrypts', hex(decrypted) === v.encrypt_with_label.plaintext, hex(decrypted))

// And the reverse direction against the vector's public key, since sealing is
// randomized and cannot be compared byte for byte.
const sealed = await encryptWithLabel(
  await suite.hpke.importPublicKey(unhex(v.encrypt_with_label.pub)),
  v.encrypt_with_label.label,
  unhex(v.encrypt_with_label.context),
  unhex(v.encrypt_with_label.plaintext),
  suite.hpke,
)
const roundTrip = await decryptWithLabel(
  await suite.hpke.importPrivateKey(unhex(v.encrypt_with_label.priv)),
  v.encrypt_with_label.label, unhex(v.encrypt_with_label.context), sealed.enc, sealed.ct, suite.hpke,
)
ok('and our own ciphertext round trips to the same key', hex(roundTrip) === v.encrypt_with_label.plaintext)

console.log('\n=== Differential against @hpke/core ===')
const theirs = new CipherSuite({ kem: new DhkemX25519HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm() })
const info = enc.encode('biset differential test')
const aad = enc.encode('aad')
const plaintext = enc.encode('the same bytes must come back')

// Their key pair, our seal, their open.
const theirKeys = await theirs.kem.generateKeyPair()
const ourSeal = await suite.hpke.seal(
  await suite.hpke.importPublicKey(new Uint8Array(await theirs.kem.serializePublicKey(theirKeys.publicKey))),
  plaintext, info, aad,
)
const theyOpened = await theirs.open(
  { recipientKey: theirKeys.privateKey, enc: ourSeal.enc.buffer as ArrayBuffer, info: info.buffer as ArrayBuffer },
  ourSeal.ct.buffer as ArrayBuffer,
  aad.buffer as ArrayBuffer,
)
ok('@hpke/core opens what we sealed', hex(new Uint8Array(theyOpened)) === hex(plaintext))

// Our key pair, their seal, our open.
const ourKeys = await suite.hpke.generateKeyPair()
const theirSeal = await theirs.seal(
  {
    recipientPublicKey: await theirs.kem.deserializePublicKey((await suite.hpke.exportPublicKey(ourKeys.publicKey)).buffer as ArrayBuffer),
    info: info.buffer as ArrayBuffer,
  },
  plaintext.buffer as ArrayBuffer,
  aad.buffer as ArrayBuffer,
)
const weOpened = await suite.hpke.open(ourKeys.privateKey, new Uint8Array(theirSeal.enc), new Uint8Array(theirSeal.ct), info, aad)
ok('we open what @hpke/core sealed', hex(weOpened) === hex(plaintext))

// Exported secrets must agree too — MLS's Welcome path uses export, not seal.
const exporterContext = enc.encode('exporter context')
const ourExport = await suite.hpke.exportSecret(
  await suite.hpke.importPublicKey(new Uint8Array(await theirs.kem.serializePublicKey(theirKeys.publicKey))),
  exporterContext, 32, info,
)
const theirRecipientCtx = await theirs.createRecipientContext({
  recipientKey: theirKeys.privateKey, enc: ourExport.enc.buffer as ArrayBuffer, info: info.buffer as ArrayBuffer,
})
const theirExport = new Uint8Array(await theirRecipientCtx.export(exporterContext.buffer as ArrayBuffer, 32))
ok('exported secrets match across implementations', hex(ourExport.secret) === hex(theirExport), `${hex(ourExport.secret)} != ${hex(theirExport)}`)

// DeriveKeyPair must be deterministic and agree — MLS derives leaf keys from
// path secrets this way, so a mismatch would split the tree silently.
const ikm = new Uint8Array(32).fill(7)
const ourDerived = await suite.hpke.deriveKeyPair(ikm)
const theirDerived = await theirs.kem.deriveKeyPair(ikm.buffer as ArrayBuffer)
ok('deriveKeyPair agrees with @hpke/core', hex(await suite.hpke.exportPublicKey(ourDerived.publicKey)) === hex(new Uint8Array(await theirs.kem.serializePublicKey(theirDerived.publicKey))))

// A wrong key must fail, not silently return garbage.
let openFailed = false
try {
  const other = await suite.hpke.generateKeyPair()
  await suite.hpke.open(other.privateKey, ourSeal.enc, ourSeal.ct, info, aad)
} catch { openFailed = true }
ok('opening with the wrong key throws', openFailed)

console.log(fails === 0 ? '\nall ok' : `\n${fails} failed`)
process.exit(fails === 0 ? 0 : 1)
