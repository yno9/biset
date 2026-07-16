// How many relays actually fit in a did:dht document before BEP44's
// 1000-byte cap? Measures the real encoder rather than estimating.
import { buildBisetDocument, documentToRecords } from './src/did/document.ts'
import { encodePacket } from './src/did/dns.ts'

const DID = 'did:dht:6oien8gcebk6zdy49sj9319wg13zaid1sdpkamb7jp6bw31pkdxo'
const size = (doc) => encodePacket(documentToRecords(doc)).length

const PEER_KID = 'did:peer:2.Ez6LSojJcQNBZuGSMwSAHKHJbHdwmLALNZDqzVT5WGhcia24n.Vz6MkgEKVq1yAUpijCp41rg2hnJnvniDvHdtZB8xfn5XtHsgz.SeyJpZCI6IiNkaWRjb21tIiwidCI6ImRtIiwicyI6eyJ1cmkiOiJodHRwOi8vbG9jYWxob3N0OjQxMDAiLCJhIjpbImRpZGNvbW0vdjIiXSwiciI6W119fQ#key-1'
const DHT_KID = 'did:dht:qxoigfu9unz98g15nr85kbbd9x9khup7ccijmypkn51m68yib3ey#k1'

function build(relayCount, routingKid, mediatorUrl = 'https://didmediator.biset.md') {
  const relays = []
  for (let i = 0; i < relayCount; i++) {
    relays.push({ id: `r${i}`, serverUrl: `https://relay${i}.biset.md`, protocol: 'mail', address: 'y@biset.md' })
  }
  const doc = buildBisetDocument(DID, new Uint8Array(32), relays, ['y@biset.md'], 'y')
  doc.keyAgreementKey = new Uint8Array(32)
  if (routingKid) {
    doc.service.push({ id: 'didcomm', type: 'DIDCommMessaging', serviceEndpoint: [mediatorUrl], accept: ['didcomm/v2'], routingKeys: [routingKid] })
  }
  return doc
}

for (const [label, kid] of [['did:peer mediator', PEER_KID], ['did:dht mediator', DHT_KID], ['no mediator', null]]) {
  let max = 0
  for (let n = 1; n <= 20; n++) {
    if (size(build(n, kid)) <= 1000) max = n
    else break
  }
  const at2 = size(build(2, kid))
  console.log(`${label.padEnd(20)} 2 relays: ${String(at2).padStart(4)}B | max relays that fit: ${max}`)
}

console.log('\nper-item cost:')
console.log('  each extra relay:  ', size(build(3, PEER_KID)) - size(build(2, PEER_KID)), 'bytes')
console.log('  didcomm svc (peer):', size(build(2, PEER_KID)) - size(build(2, null)), 'bytes')
console.log('  didcomm svc (dht): ', size(build(2, DHT_KID)) - size(build(2, null)), 'bytes')
