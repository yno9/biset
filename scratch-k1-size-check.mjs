// Does a REAL biset account's document (mail + AP relays) still fit in
// BEP44's 1000-byte cap once _k1 + a DIDCommMessaging service are added?
import { buildBisetDocument, documentToRecords } from './src/did/document.ts'
import { encodePacket } from './src/did/dns.ts'
import { fetchMediatorInfo } from './src/did/didcomm/coordinate.ts'

const DID = 'did:dht:6oien8gcebk6zdy49sj9319wg13zaid1sdpkamb7jp6bw31pkdxo'
const size = (doc) => encodePacket(documentToRecords(doc)).length

const mediator = await fetchMediatorInfo('http://localhost:4100')
const mediatorXKid = mediator.doc.keyAgreement[0]

// A realistic biset account: mail + AP relays, as publish.ts builds it.
const base = buildBisetDocument(
  DID, new Uint8Array(32),
  [
    { id: 'mail', serverUrl: 'https://mail.biset.md', protocol: 'mail', address: 'y@biset.md' },
    { id: 'ap', serverUrl: 'https://ap.biset.md', protocol: 'activitypub', address: 'y@biset.md' },
  ],
  ['y@biset.md'],
)
console.log('base (2 relays, no _k1):        ', size(base), 'bytes')

const withK1 = { ...base, keyAgreementKey: new Uint8Array(32) }
console.log('+ _k1:                          ', size(withK1), 'bytes')

const withDidcomm = {
  ...withK1,
  service: [...withK1.service, { id: 'didcomm', type: 'DIDCommMessaging', serviceEndpoint: [mediator.url], accept: ['didcomm/v2'], routingKeys: [mediatorXKid] }],
}
console.log('+ DIDCommMessaging (did:peer kid):', size(withDidcomm), 'bytes', size(withDidcomm) > 1000 ? '*** OVER 1000 CAP ***' : '(fits)')

console.log('\nbreakdown of the didcomm service record:')
for (const r of documentToRecords(withDidcomm)) {
  console.log(' ', r.name.padEnd(12), r.rdata.join('').length, 'bytes')
}

// What if the mediator were addressed by a did:dht instead of a 236-char did:peer?
const shortKid = 'did:dht:qxoigfu9unz98g15nr85kbbd9x9khup7ccijmypkn51m68yib3ey#k1'
const withShort = {
  ...withK1,
  service: [...withK1.service, { id: 'didcomm', type: 'DIDCommMessaging', serviceEndpoint: [mediator.url], accept: ['didcomm/v2'], routingKeys: [shortKid] }],
}
console.log('\nif the mediator had a did:dht kid instead:', size(withShort), 'bytes', size(withShort) > 1000 ? '(still over)' : '(fits)')
