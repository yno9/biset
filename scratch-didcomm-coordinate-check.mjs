// Verifies src/did/didcomm/coordinate.ts against a real, running ~/didmediator
// instance (not a mock) — mediate-request/grant + keylist-update.
import { generatePeerIdentity } from './src/did/peer.ts'
import { fetchMediatorInfo, requestMediation, updateKeylist } from './src/did/didcomm/coordinate.ts'

const MEDIATOR_URL = 'http://localhost:4100'

const bob = generatePeerIdentity()
console.log('bob did:', bob.did)

const mediator = await fetchMediatorInfo(MEDIATOR_URL)
console.log('mediator did:', mediator.did)

const routingDid = await requestMediation(mediator, bob)
console.log('routing_did:', routingDid)
if (routingDid !== mediator.did) throw new Error('FAIL: routing_did should equal mediator DID')

await updateKeylist(mediator, bob, bob.xKid, 'add')
console.log('ok   keylist-update accepted for', bob.xKid)

console.log('\nCoordination client works against the real running didmediator.')
