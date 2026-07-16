// Sends one message to the did:peer the human just registered via the real
// browser UI (/didcomm page) — closes the loop: browser registers -> script
// sends -> browser picks up via the same UI.
import { generatePeerIdentity, decodePeerDid2 } from './src/did/peer.ts'
import { sendDidComm } from './src/did/didcomm/send.ts'

const BOB_DID = process.argv[2]
if (!BOB_DID) throw new Error('usage: bun run scratch-send-to-browser-bob.mjs <did:peer:2...>')

const alice = generatePeerIdentity()
const bobDoc = decodePeerDid2(BOB_DID)

await sendDidComm(alice, BOB_DID, bobDoc, {
  type: 'https://didcomm.org/basicmessage/2.0/message',
  body: { content: 'hello from a script, sent to the DID you registered in the browser' },
})
console.log('sent — click "Check for messages" in the browser now')
