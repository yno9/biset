// Registers a second, reachable (mediator-registered) identity — "Charlie" —
// so the human can test the BROWSER's own send path (not just receive) by
// pasting this DID into /didcomm's Recipient field.
import { generatePeerIdentity } from './src/did/peer.ts'
import { fetchMediatorInfo, requestMediation, updateKeylist } from './src/did/didcomm/coordinate.ts'
import { pickupDeliver } from './src/did/didcomm/pickup.ts'
import { writeFileSync } from 'node:fs'

const MEDIATOR_URL = 'http://localhost:4100'

const mediator = await fetchMediatorInfo(MEDIATOR_URL)
const mediatorXKid = mediator.doc.keyAgreement[0]
const charlie = generatePeerIdentity({ uri: mediator.url, routingKeys: [mediatorXKid] })

await requestMediation(mediator, charlie)
await updateKeylist(mediator, charlie, charlie.xKid, 'add')

writeFileSync('/tmp/charlie-identity.json', JSON.stringify({
  xPriv: Buffer.from(charlie.xPriv).toString('base64url'),
  edPriv: Buffer.from(charlie.edPriv).toString('base64url'),
}))

console.log('Charlie registered. Paste this DID into /didcomm\'s Recipient field:')
console.log(charlie.did)
