// Full end-to-end check of biset's own DIDComm client code (src/did/peer.ts +
// src/did/didcomm/*) against a real, running ~/didmediator — no mocks, no
// didcomm-node on biset's side. This is the exact scenario the human wants
// to verify: Alice -> (real mediator) -> Bob, entirely through biset's new
// pure-TS code.
import { generatePeerIdentity, decodePeerDid2 } from './src/did/peer.ts'
import { fetchMediatorInfo, requestMediation, updateKeylist } from './src/did/didcomm/coordinate.ts'
import { sendDidComm } from './src/did/didcomm/send.ts'
import { pickupStatus, pickupDeliver } from './src/did/didcomm/pickup.ts'

const MEDIATOR_URL = 'http://localhost:4100'

// ── Bob registers with the mediator and gets a "public" did:peer ──────────
const mediator = await fetchMediatorInfo(MEDIATOR_URL)
const mediatorXKid = mediator.doc.keyAgreement[0]
const bob = generatePeerIdentity({ uri: mediator.url, routingKeys: [mediatorXKid] })
console.log('bob (public) did:', bob.did)

await requestMediation(mediator, bob)
await updateKeylist(mediator, bob, bob.xKid, 'add')
console.log('ok   bob registered + keylist-update accepted')

// ── Alice resolves Bob's DID (self-decode, did:peer is self-certifying) ───
const alice = generatePeerIdentity()
const bobDoc = decodePeerDid2(bob.did)

await sendDidComm(alice, bob.did, bobDoc, { type: 'https://didcomm.org/basicmessage/2.0/message', body: { content: 'hello from biset Alice, via didmediator' } })
console.log('ok   alice sent, forward-wrapped through the mediator')

// ── Bob checks status, then picks up ───────────────────────────────────────
const count = await pickupStatus(mediator, bob)
console.log('status message_count:', count)
if (count !== 1) throw new Error(`FAIL: expected 1 queued message, got ${count}`)

const resolveSenderKey = (senderKid) => {
  const doc = decodePeerDid2(senderKid.split('#')[0])
  const vm = doc.verificationMethod.find(v => v.id === senderKid)
  const b64urlToBytes = (s) => {
    const pad = (4 - (s.length % 4)) % 4
    const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat(pad)
    return Uint8Array.from(atob(b64), c => c.charCodeAt(0))
  }
  return b64urlToBytes(vm.publicKeyJwk.x)
}

const delivered = await pickupDeliver(mediator, bob, resolveSenderKey)
if (delivered.length !== 1) throw new Error(`FAIL: expected 1 delivered message, got ${delivered.length}`)
console.log('*** Bob decrypted Alice\'s message via didmediator, using only biset\'s own pure-TS client code ***')
console.log('body:', JSON.stringify(delivered[0].plaintext.body))
console.log('senderKid matches alice:', delivered[0].senderKid === alice.xKid)
if (delivered[0].senderKid !== alice.xKid) throw new Error('FAIL: senderKid mismatch')
if (delivered[0].plaintext.body.content !== 'hello from biset Alice, via didmediator') throw new Error('FAIL: content mismatch')

console.log('\nEnd-to-end check passed.')
