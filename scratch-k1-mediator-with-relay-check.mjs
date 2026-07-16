// Reproduces the exact live bug report: a did:dht identity that already has
// a non-DIDCommMessaging service (JMAPRelay, like a real biset account)
// registering _k1 with a mediator. Before the fix, didcomm-node's Rust
// deserializer threw "unknown variant `JMAPRelay`" trying to resolve the
// sender did for mediate-grant.
const _store = new Map()
globalThis.localStorage = { getItem: (k) => _store.get(k) ?? null, setItem: (k, v) => _store.set(k, String(v)) }

import { deriveRootKey, deriveDidCommKey, didFromRootPublicKey } from './src/did/keys.ts'
import { buildBisetDocument } from './src/did/document.ts'
import { registerDidCommViaDht } from './src/did/didcomm/register.ts'
import { PUBLIC_PKARR_FALLBACKS } from './src/did/resolver.ts'

const seed = crypto.getRandomValues(new Uint8Array(32))
const root = deriveRootKey(seed)
const didComm = deriveDidCommKey(seed)
const did = didFromRootPublicKey(root.publicKey)

// A real biset-shaped document: a JMAPRelay service, like an actual account.
const existingDoc = buildBisetDocument(
  did, root.publicKey,
  [{ id: 'mail', serverUrl: 'https://mail.biset.md', protocol: 'mail', address: 'test@biset.md' }],
  'test@biset.md',
)
console.log('identity:', did)
console.log('pre-existing service:', JSON.stringify(existingDoc.service))

const result = await registerDidCommViaDht(didComm.privateKey, root.privateKey, existingDoc, 'http://localhost:4100', PUBLIC_PKARR_FALLBACKS)
console.log('\nok — mediate-request/keylist-update succeeded with a JMAPRelay service present')
console.log('final service list:', JSON.stringify(result.doc.service.map(s => s.type)))
