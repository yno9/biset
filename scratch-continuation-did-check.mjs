// Continuation-DID chaining: can a did:dht document point at ANOTHER
// did:dht that holds more relays? Pure did:dht, no protocol extension,
// works through any public Pkarr gateway. Measures the real capacity.
import { buildBisetDocument, documentToRecords } from './src/did/document.ts'
import { encodePacket } from './src/did/dns.ts'

const DID = 'did:dht:6oien8gcebk6zdy49sj9319wg13zaid1sdpkamb7jp6bw31pkdxo'
const NEXT = 'did:dht:qxoigfu9unz98g15nr85kbbd9x9khup7ccijmypkn51m68yib3ey'
const size = (doc) => encodePacket(documentToRecords(doc)).length

function build(relayCount, { withExt = false, withDidcomm = false } = {}) {
  const relays = []
  for (let i = 0; i < relayCount; i++) {
    relays.push({ id: `r${i}`, serverUrl: `https://relay${i}.biset.md`, protocol: 'mail', address: 'y@biset.md' })
  }
  const doc = buildBisetDocument(DID, new Uint8Array(32), relays, ['y@biset.md'], 'y')
  if (withDidcomm) {
    doc.keyAgreementKey = new Uint8Array(32)
    doc.service.push({ id: 'didcomm', type: 'DIDCommMessaging', serviceEndpoint: ['https://didmediator.biset.md'], accept: ['didcomm/v2'], routingKeys: [`${NEXT}#k1`] })
  }
  // The continuation pointer: just a service whose endpoint is another DID.
  if (withExt) doc.service.push({ id: 'ext', type: 'DIDDocExtension', serviceEndpoint: [NEXT] })
  return doc
}

console.log('cost of one continuation pointer:', size(build(2, { withExt: true })) - size(build(2)), 'bytes')

// How many relays fit in a ROOT record that also carries _k1 + didcomm + a pointer?
let rootMax = 0
for (let n = 0; n <= 30; n++) {
  if (size(build(n, { withExt: true, withDidcomm: true })) <= 1000) rootMax = n
  else break
}
console.log('root record (with _k1 + didcomm svc + ext pointer): fits', rootMax, 'relays')

// How many fit in a CONTINUATION record (no _k1/didcomm — just relays + next pointer)?
let contMax = 0
for (let n = 0; n <= 30; n++) {
  if (size(build(n, { withExt: true })) <= 1000) contMax = n
  else break
}
console.log('continuation record (relays + next pointer):        fits', contMax, 'relays')

// And a terminal continuation (no further pointer)?
let termMax = 0
for (let n = 0; n <= 30; n++) {
  if (size(build(n)) <= 1000) termMax = n
  else break
}
console.log('terminal record (relays only, no pointer):          fits', termMax, 'relays')

console.log('\n--- what a 1000-relay identity costs ---')
const perLink = contMax
const needed = Math.ceil((1000 - rootMax) / perLink)
console.log(`root holds ${rootMax}, each continuation holds ${perLink}`)
console.log(`1000 relays => ~${needed} continuation records => ~${needed + 1} sequential DHT lookups`)
console.log(`20 relays   => ~${Math.ceil((20 - rootMax) / perLink)} continuation record(s) => ~${Math.ceil((20 - rootMax) / perLink) + 1} lookups`)
