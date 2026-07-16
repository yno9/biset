// Full did:dht <-> did:dht send/pickup flow, against the real public Pkarr
// gateways and the real running ~/didmediator — the same shape the /didcomm
// debug UI now drives, exercised here without a browser first.
//
// src/did/resolver.ts's rollback-defense (freshness.ts) uses localStorage,
// a browser-only API this Bun script doesn't have — the real /didcomm UI
// runs in an actual browser where this is a non-issue; shim it here purely
// so this verification script can run standalone (test-only, not a product
// change).
const _store = new Map()
globalThis.localStorage = {
  getItem: (k) => _store.get(k) ?? null,
  setItem: (k, v) => _store.set(k, String(v)),
}

import { deriveRootKey, deriveDidCommKey, didFromRootPublicKey } from './src/did/keys.ts'
import { buildBisetDocument } from './src/did/document.ts'
import { registerDidCommViaDht } from './src/did/didcomm/register.ts'
import { sendDidComm } from './src/did/didcomm/send.ts'
import { pickupStatus, pickupDeliver } from './src/did/didcomm/pickup.ts'
import { resolveDidCommDoc, resolveSenderPublicKey } from './src/did/didcomm/resolve.ts'
import { PUBLIC_PKARR_FALLBACKS } from './src/did/resolver.ts'

const MEDIATOR_URL = 'http://localhost:4100'

async function registerFreshDhtIdentity() {
  const seed = crypto.getRandomValues(new Uint8Array(32))
  const root = deriveRootKey(seed)
  const didComm = deriveDidCommKey(seed)
  const did = didFromRootPublicKey(root.publicKey)
  const existingDoc = buildBisetDocument(did, root.publicKey, [], [])
  const result = await registerDidCommViaDht(didComm.privateKey, root.privateKey, existingDoc, MEDIATOR_URL, PUBLIC_PKARR_FALLBACKS)
  return { did, own: result.own, mediator: result.mediator }
}

console.log('registering Alice (did:dht)...')
const alice = await registerFreshDhtIdentity()
console.log('alice:', alice.did)

console.log('registering Bob (did:dht)...')
const bob = await registerFreshDhtIdentity()
console.log('bob:', bob.did)

console.log('\nresolving bob via resolveDidCommDoc (public Pkarr gateways)...')
const bobDoc = await resolveDidCommDoc(bob.did)
if (!bobDoc) throw new Error('FAIL: could not resolve bob')

console.log('alice sending to bob...')
await sendDidComm(alice.own, bob.did, bobDoc, {
  type: 'https://didcomm.org/basicmessage/2.0/message',
  body: { content: 'hello bob, from alice, entirely over did:dht' },
})
console.log('ok   sent (forward-wrapped through the mediator)')

const count = await pickupStatus(bob.mediator, bob.own)
console.log('bob status message_count:', count)
if (count !== 1) throw new Error(`FAIL: expected 1 queued message, got ${count}`)

const delivered = await pickupDeliver(bob.mediator, bob.own, resolveSenderPublicKey)
if (delivered.length !== 1) throw new Error(`FAIL: expected 1 delivered message, got ${delivered.length}`)
console.log('\n*** bob decrypted alice\'s message, entirely via did:dht (no did:peer anywhere) ***')
console.log('senderKid:', delivered[0].senderKid)
console.log('body:', JSON.stringify(delivered[0].plaintext.body))
if (delivered[0].plaintext.body.content !== 'hello bob, from alice, entirely over did:dht') throw new Error('FAIL: content mismatch')

console.log('\ndid:dht <-> did:dht full flow verified.')
