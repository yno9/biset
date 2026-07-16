import { readFileSync } from 'node:fs'
import { identityFromKeys, decodePeerDid2 } from './src/did/peer.ts'
import { fetchMediatorInfo } from './src/did/didcomm/coordinate.ts'
import { pickupDeliver } from './src/did/didcomm/pickup.ts'

const MEDIATOR_URL = 'http://localhost:4100'
const { xPriv, edPriv } = JSON.parse(readFileSync('/tmp/charlie-identity.json', 'utf-8'))
const toBytes = (b64url) => Uint8Array.from(Buffer.from(b64url, 'base64url'))

const mediator = await fetchMediatorInfo(MEDIATOR_URL)
const mediatorXKid = mediator.doc.keyAgreement[0]
const charlie = identityFromKeys(toBytes(xPriv), toBytes(edPriv), { uri: mediator.url, routingKeys: [mediatorXKid] })

const resolveSenderKey = (senderKid) => {
  const doc = decodePeerDid2(senderKid.split('#')[0])
  const vm = doc.verificationMethod.find(v => v.id === senderKid)
  return Uint8Array.from(atob(vm.publicKeyJwk.x.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - vm.publicKeyJwk.x.length % 4) % 4)), c => c.charCodeAt(0))
}

const delivered = await pickupDeliver(mediator, charlie, resolveSenderKey)
console.log(`${delivered.length} message(s):\n`)
for (const d of delivered) {
  console.log('from:', d.senderKid)
  console.log(JSON.stringify(d.plaintext, null, 2))
  console.log('---')
}
