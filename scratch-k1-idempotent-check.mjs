// The exact bug that broke a real account: registering more than once must
// not stack duplicate DIDCommMessaging services (each ~330 bytes; two of
// them plus relays blows past BEP44's 1000-byte cap and the identity can no
// longer publish at all).
const _store = new Map()
globalThis.localStorage = { getItem: (k) => _store.get(k) ?? null, setItem: (k, v) => _store.set(k, String(v)) }

import { deriveRootKey, deriveDidCommKey, didFromRootPublicKey } from './src/did/keys.ts'
import { buildBisetDocument, documentToRecords } from './src/did/document.ts'
import { encodePacket } from './src/did/dns.ts'
import { registerDidCommViaDht } from './src/did/didcomm/register.ts'
import { PUBLIC_PKARR_FALLBACKS } from './src/did/resolver.ts'

const size = (doc) => encodePacket(documentToRecords(doc)).length
const seed = crypto.getRandomValues(new Uint8Array(32))
const root = deriveRootKey(seed)
const didComm = deriveDidCommKey(seed)
const did = didFromRootPublicKey(root.publicKey)

// A realistic account: mail + AP relays, exactly as publish.ts builds it.
const base = buildBisetDocument(
  did, root.publicKey,
  [
    { id: 'mail', serverUrl: 'https://mail.biset.md', protocol: 'mail', address: 'y@biset.md' },
    { id: 'ap', serverUrl: 'https://ap.biset.md', protocol: 'activitypub', address: 'y@biset.md' },
  ],
  ['y@biset.md'],
)

console.log('registering (1st time)...')
const r1 = await registerDidCommViaDht(didComm.privateKey, root.privateKey, base, 'http://localhost:4100', PUBLIC_PKARR_FALLBACKS)
console.log('  services:', JSON.stringify(r1.doc.service.map(s => s.type)), '| size:', size(r1.doc), 'bytes')

// Second registration, feeding back the already-registered document — this
// is what a retry / a second device / publish.ts's rebuilt doc looks like.
console.log('registering (2nd time, feeding back the registered doc)...')
const r2 = await registerDidCommViaDht(didComm.privateKey, root.privateKey, r1.doc, 'http://localhost:4100', PUBLIC_PKARR_FALLBACKS)
console.log('  services:', JSON.stringify(r2.doc.service.map(s => s.type)), '| size:', size(r2.doc), 'bytes')

const didcommCount = r2.doc.service.filter(s => s.type === 'DIDCommMessaging').length
if (didcommCount !== 1) throw new Error(`FAIL: ${didcommCount} DIDCommMessaging services after re-registering — should be exactly 1`)
if (r2.doc.service.filter(s => s.type === 'JMAPRelay').length !== 2) throw new Error('FAIL: JMAPRelay services lost')
if (size(r2.doc) !== size(r1.doc)) throw new Error(`FAIL: size grew on re-register (${size(r1.doc)} -> ${size(r2.doc)})`)
if (size(r2.doc) > 1000) throw new Error(`FAIL: ${size(r2.doc)} bytes exceeds the BEP44 1000-byte cap`)

console.log('\nok — re-registering is idempotent: 1 DIDCommMessaging service, relays intact, size stable and under the cap.')
