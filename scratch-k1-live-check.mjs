const _store = new Map()
globalThis.localStorage = { getItem: (k) => _store.get(k) ?? null, setItem: (k, v) => _store.set(k, String(v)) }

import { documentToRecords } from './src/did/document.ts'
import { resolve as resolveDidDht, PUBLIC_PKARR_FALLBACKS } from './src/did/resolver.ts'
import { fetchMediatorInfo } from './src/did/didcomm/coordinate.ts'

const DID = 'did:dht:6oien8gcebk6zdy49sj9319wg13zaid1sdpkamb7jp6bw31pkdxo'

// crude DNS-packet size estimate: reuse the same encoder biset actually uses
async function packetSize(doc) {
  const { encodePacket } = await import('./src/did/dns.ts')
  return encodePacket(documentToRecords(doc)).length
}

const doc = await resolveDidDht(DID, PUBLIC_PKARR_FALLBACKS)
if (!doc) throw new Error('could not resolve — check gateways/network')
console.log('current document:')
console.log(JSON.stringify(doc, (k, v) => v instanceof Uint8Array ? `<${v.length} bytes>` : v, 2))
console.log('\ncurrent DNS packet size:', await packetSize(doc), 'bytes')

const mediator = await fetchMediatorInfo('http://localhost:4100')
const mediatorXKid = mediator.doc.keyAgreement[0]
console.log('\nmediator kid length:', mediatorXKid.length, 'chars:', mediatorXKid)

const withK1 = { ...doc, keyAgreementKey: new Uint8Array(32) }
const withService = {
  ...withK1,
  service: [...withK1.service, { id: 'didcomm', type: 'DIDCommMessaging', serviceEndpoint: [mediator.url], accept: ['didcomm/v2'], routingKeys: [mediatorXKid] }],
}
console.log('\nsize with _k1 only:', await packetSize(withK1), 'bytes')
console.log('size with _k1 + DIDCommMessaging service:', await packetSize(withService), 'bytes')
