// Does "put my own did:peer in the did:dht doc, do all DIDComm over
// did:peer" (did:dht as a pure router) actually save bytes vs the current
// "_k1 + DIDCommMessaging service" layout?
import { buildBisetDocument, documentToRecords } from './src/did/document.ts'
import { encodePacket } from './src/did/dns.ts'
import { generatePeerIdentity } from './src/did/peer.ts'
import { fetchMediatorInfo } from './src/did/didcomm/coordinate.ts'

const DID = 'did:dht:6oien8gcebk6zdy49sj9319wg13zaid1sdpkamb7jp6bw31pkdxo'
const size = (doc) => encodePacket(documentToRecords(doc)).length

const relays = [
  { id: 'mail', serverUrl: 'https://mail.biset.md', protocol: 'mail', address: 'y@biset.md' },
  { id: 'ap', serverUrl: 'https://ap.biset.md', protocol: 'activitypub', address: 'y@biset.md' },
]
const base = () => buildBisetDocument(DID, new Uint8Array(32), relays, ['y@biset.md'], 'y')

const mediator = await fetchMediatorInfo('http://localhost:4100')
const mediatorXKid = mediator.doc.keyAgreement[0]
console.log('mediator did:peer kid length:', mediatorXKid.length, 'chars')

// --- A: current layout (_k1 + DIDCommMessaging service) ---
const a = base()
a.keyAgreementKey = new Uint8Array(32)
a.service.push({ id: 'didcomm', type: 'DIDCommMessaging', serviceEndpoint: [mediator.url], accept: ['didcomm/v2'], routingKeys: [mediatorXKid] })
console.log('\nA) current (_k1 + DIDCommMessaging svc): ', size(a), 'bytes')

// --- B: proposed — my own did:peer as a pointer, did:dht as pure router ---
// This is what biset actually generates today when registering: the mediator's
// endpoint + routing key are embedded IN the did:peer string.
const myPeer = generatePeerIdentity({ uri: mediator.url, routingKeys: [mediatorXKid] })
console.log('\nmy own did:peer length:', myPeer.did.length, 'chars')
console.log('  (it embeds the mediator\'s', mediatorXKid.length, 'char did:peer, base64-inflated)')

const b = base()
b.service.push({ id: 'didcomm', type: 'DIDCommMessaging', serviceEndpoint: [myPeer.did], accept: ['didcomm/v2'] })
console.log('\nB) proposed (my did:peer as pointer):    ', size(b), 'bytes', size(b) > 1000 ? '*** OVER 1000 CAP ***' : '')

console.log('\ndifference:', size(b) - size(a), 'bytes', size(b) > size(a) ? '(proposal is WORSE)' : '(proposal is better)')

// --- C: what if the mediator itself were did:dht? then my did:peer is small ---
const dhtKid = 'did:dht:qxoigfu9unz98g15nr85kbbd9x9khup7ccijmypkn51m68yib3ey#k1'
const myPeerSmall = generatePeerIdentity({ uri: mediator.url, routingKeys: [dhtKid] })
console.log('\nif the mediator had a did:dht kid, my did:peer would be:', myPeerSmall.did.length, 'chars')
const c = base()
c.service.push({ id: 'didcomm', type: 'DIDCommMessaging', serviceEndpoint: [myPeerSmall.did], accept: ['didcomm/v2'] })
console.log('C) my did:peer (mediator=did:dht):      ', size(c), 'bytes')

// --- D: mediator did:dht, current layout (for comparison) ---
const d = base()
d.keyAgreementKey = new Uint8Array(32)
d.service.push({ id: 'didcomm', type: 'DIDCommMessaging', serviceEndpoint: [mediator.url], accept: ['didcomm/v2'], routingKeys: [dhtKid] })
console.log('D) current layout (mediator=did:dht):   ', size(d), 'bytes  <- cheapest?')
