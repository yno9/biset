// Interop check: src/did/didcomm/crypto.ts (pure TS) <-> didcomm-node (real
// Rust/wasm reference implementation, the same library ~/didmediator runs).
// This is the strongest possible verification of wire compatibility — not
// just internal self-consistency, but round-tripping through the actual
// library our own mediator/counterparties speak.
import * as didcomm from 'didcomm-node'
import { generatePeerIdentity, decodePeerDid2 } from './src/did/peer.ts'
import { packAuthcrypt, packAnoncrypt, unpackAuthcrypt, unpackAnoncrypt } from './src/did/didcomm/crypto.ts'

const alice = generatePeerIdentity()
const bob = generatePeerIdentity()

// didcomm-node needs a DIDResolver + SecretsResolver over both identities.
const known = { [alice.did]: alice.doc, [bob.did]: bob.doc }
const didResolver = {
  async resolve(did) { return known[did] ?? null },
}
const allSecrets = { ...alice.secrets, ...bob.secrets }
const secretsResolver = {
  async get_secret(id) { return allSecrets[id] ?? null },
  async find_secrets(ids) { return ids.filter(id => allSecrets[id]) },
}

function b64urlToBytes(s) {
  const pad = (4 - (s.length % 4)) % 4
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat(pad)
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0))
}

// ── 1. pack with crypto.ts (authcrypt), unpack with real didcomm-node ──────
{
  const plaintext = JSON.stringify({ id: 'test-1', type: 'test/1.0', body: { hello: 'from pure-TS authcrypt' }, from: alice.edKid, to: [bob.xKid] })
  const jwe = packAuthcrypt(new TextEncoder().encode(plaintext), { kid: alice.xKid, privateKey: alice.xPriv }, { kid: bob.xKid, publicKey: bob.xPub })
  const wireJson = JSON.stringify(jwe)

  const [unpacked, meta] = await didcomm.Message.unpack(wireJson, didResolver, secretsResolver, {})
  const msg = unpacked.as_value()
  if (msg.body.hello !== 'from pure-TS authcrypt') throw new Error('FAIL: didcomm-node did not recover plaintext body')
  if (!meta.authenticated) throw new Error('FAIL: didcomm-node did not mark message authenticated')
  console.log('ok   pure-TS authcrypt -> didcomm-node unpack:', JSON.stringify(msg.body), 'authenticated:', meta.authenticated)
}

// ── 2. pack with real didcomm-node (authcrypt), unpack with crypto.ts ──────
{
  const msg = new didcomm.Message({
    id: 'test-2', typ: 'application/didcomm-plain+json', type: 'test/1.0',
    body: { hello: 'from didcomm-node authcrypt' }, from: alice.did, to: [bob.did],
  })
  const [packed] = await msg.pack_encrypted(bob.xKid, alice.xKid, null, didResolver, secretsResolver, { forward: false })
  const jwe = JSON.parse(packed)

  const resolveSenderKey = async (senderKid) => {
    const doc = known[senderKid.split('#')[0] + ''] ?? decodePeerDid2(senderKid.split('#')[0])
    const vm = doc.verificationMethod.find(v => v.id === senderKid)
    return b64urlToBytes(vm.publicKeyJwk.x)
  }
  const { plaintext, senderKid } = await unpackAuthcrypt(jwe, { kid: bob.xKid, privateKey: bob.xPriv }, resolveSenderKey)
  const body = JSON.parse(new TextDecoder().decode(plaintext))
  if (body.body.hello !== 'from didcomm-node authcrypt') throw new Error('FAIL: crypto.ts did not recover plaintext body')
  if (senderKid !== alice.xKid) throw new Error(`FAIL: senderKid mismatch: ${senderKid} !== ${alice.xKid}`)
  console.log('ok   didcomm-node authcrypt -> pure-TS unpack:', JSON.stringify(body.body), 'senderKid matches:', senderKid === alice.xKid)
}

// ── 3. anoncrypt round-trip, both directions ───────────────────────────────
{
  const plaintext = JSON.stringify({ id: 'test-3', type: 'test/1.0', body: { next: bob.xKid } })
  const jwe = packAnoncrypt(new TextEncoder().encode(plaintext), { kid: bob.xKid, publicKey: bob.xPub })
  const [unpacked, meta] = await didcomm.Message.unpack(JSON.stringify(jwe), didResolver, secretsResolver, {})
  const msg = unpacked.as_value()
  if (msg.body.next !== bob.xKid) throw new Error('FAIL: anoncrypt pure-TS -> didcomm-node mismatch')
  console.log('ok   pure-TS anoncrypt -> didcomm-node unpack:', JSON.stringify(msg.body), 'authenticated (should be false):', meta.authenticated)
}
{
  const msg = new didcomm.Message({ id: 'test-4', typ: 'application/didcomm-plain+json', type: 'test/1.0', body: { next: bob.xKid } })
  // NB: didcomm-node's PackEncryptedOptions default enc_alg_anon is XC20P, not
  // A256CBC-HS512 — crypto.ts only implements A256CBC-HS512 (the only variant
  // biset itself ever needs to produce or consume), so this must be forced
  // explicitly for this cross-library check.
  const [packed] = await msg.pack_encrypted(bob.xKid, null, null, didResolver, secretsResolver, { forward: false, enc_alg_anon: 'A256cbcHs512EcdhEsA256kw' })
  const jwe = JSON.parse(packed)
  const plaintext = await unpackAnoncrypt(jwe, { kid: bob.xKid, privateKey: bob.xPriv })
  const body = JSON.parse(new TextDecoder().decode(plaintext))
  if (body.body.next !== bob.xKid) throw new Error('FAIL: anoncrypt didcomm-node -> pure-TS mismatch')
  console.log('ok   didcomm-node anoncrypt -> pure-TS unpack:', JSON.stringify(body.body))
}

console.log('\nAll interop checks passed — crypto.ts is wire-compatible with didcomm-node.')
