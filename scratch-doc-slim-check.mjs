// Where does a real biset did:dht document's space actually go, and what is
// safely removable? Measures each candidate against the real encoder.
import { buildBisetDocument, documentToRecords } from './src/did/document.ts'
import { encodePacket } from './src/did/dns.ts'

const DID = 'did:dht:6oien8gcebk6zdy49sj9319wg13zaid1sdpkamb7jp6bw31pkdxo'
const PEER_KID = 'did:peer:2.Ez6LSojJcQNBZuGSMwSAHKHJbHdwmLALNZDqzVT5WGhcia24n.Vz6MkgEKVq1yAUpijCp41rg2hnJnvniDvHdtZB8xfn5XtHsgz.SeyJpZCI6IiNkaWRjb21tIiwidCI6ImRtIiwicyI6eyJ1cmkiOiJodHRwOi8vbG9jYWxob3N0OjQxMDAiLCJhIjpbImRpZGNvbW0vdjIiXSwiciI6W119fQ#key-1'
const DHT_KID = 'did:dht:qxoigfu9unz98g15nr85kbbd9x9khup7ccijmypkn51m68yib3ey#k1'
const size = (d) => encodePacket(documentToRecords(d)).length

// The real thing: y@biset.md as it stands today.
function real({ addr = true, aka = true, name = true, https = true, kid = PEER_KID } = {}) {
  const url = (u) => (https ? u : u.replace(/^https:\/\//, ''))
  const d = buildBisetDocument(
    DID, new Uint8Array(32),
    [
      { id: 'mail', serverUrl: url('https://mail.biset.md'), protocol: 'mail', address: addr ? 'y@biset.md' : undefined },
      { id: 'ap', serverUrl: url('https://ap.biset.md'), protocol: 'activitypub', address: addr ? 'y@biset.md' : undefined },
    ],
    aka ? ['y@biset.md'] : [],
    name ? 'y' : undefined,
  )
  d.keyAgreementKey = new Uint8Array(32)
  d.service.push({ id: 'didcomm', type: 'DIDCommMessaging', serviceEndpoint: ['http://localhost:4100'], accept: ['didcomm/v2'], routingKeys: [kid] })
  return d
}

const base = size(real())
console.log('current real document:', base, 'bytes\n')
console.log('per-record breakdown:')
for (const r of documentToRecords(real())) console.log(' ', r.name.padEnd(14), String(r.rdata.join('').length).padStart(4), 'B')

console.log('\n--- what each candidate would save ---')
const opt = (label, doc) => console.log(`  ${label.padEnd(46)} ${String(size(doc)).padStart(4)}B  (saves ${String(base - size(doc)).padStart(3)}B)`)
opt('drop addr= when it equals alsoKnownAs[0]', real({ addr: false }))
opt('drop alsoKnownAs (keep addr=)', real({ aka: false }))
opt('drop the display name', real({ name: false }))
opt('drop "https://" from service endpoints', real({ https: false }))
opt('mediator kid: did:peer -> did:dht', real({ kid: DHT_KID }))
opt('BOTH: drop addr= AND did:dht mediator', real({ addr: false, kid: DHT_KID }))

console.log('\nfor reference: one more relay costs ~91B, cap is 996B')
