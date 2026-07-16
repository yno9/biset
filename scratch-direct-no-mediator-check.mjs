// Verifies goal 1 from the very start of this effort: can a biset identity
// send DIRECTLY, with no mediator at all? sendDidComm already branches on
// this (routing_keys empty -> no Forward wrapping, POST straight to the
// recipient's service uri) — this just proves that branch actually works,
// using a minimal throwaway HTTP listener standing in for "a directly
// reachable recipient" (something a real biset browser tab can't be, but
// nothing else in the DIDComm layer prevents it).
import { generatePeerIdentity, decodePeerDid2 } from './src/did/peer.ts'
import { sendDidComm } from './src/did/didcomm/send.ts'
import { unpackAuthcrypt, b64urlToBytes } from './src/did/didcomm/crypto.ts'

let received = null
const bob = generatePeerIdentity({ uri: 'http://localhost:4321' }) // no routingKeys -> direct
const server = Bun.serve({
  port: 4321,
  async fetch(req) {
    const jwe = await req.json()
    const resolveSenderKey = (senderKid) => {
      // self-decode, same interop-fallback assumption as everywhere else
      const doc = decodePeerDid2(senderKid.split('#')[0])
      const vm = doc.verificationMethod.find(v => v.id === senderKid)
      return b64urlToBytes(vm.publicKeyJwk.x)
    }
    const { plaintext, senderKid } = await unpackAuthcrypt(jwe, { kid: bob.xKid, privateKey: bob.xPriv }, resolveSenderKey)
    received = { senderKid, body: JSON.parse(new TextDecoder().decode(plaintext)) }
    return new Response(null, { status: 202 })
  },
})

const alice = generatePeerIdentity()
await sendDidComm(alice, bob.did, bob.doc, { type: 'https://didcomm.org/basicmessage/2.0/message', body: { content: 'direct, no mediator at all' } })

// give the listener a tick to finish handling
await new Promise(r => setTimeout(r, 100))
server.stop()

if (!received) throw new Error('FAIL: nothing arrived at the "direct" listener')
console.log('received directly (no mediator involved):')
console.log('  from:', received.senderKid)
console.log('  body:', JSON.stringify(received.body))
console.log('\nDirect (no-mediator) send works — same sendDidComm() code, just no routing_keys on the recipient side.')
