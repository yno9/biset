// Publishes a fresh did:dht identity to the REAL public Pkarr gateways (not
// localhost — actual Mainline DHT infra), then verifies ~/didmediator's
// newly-wired did:dht resolver can find and parse it back correctly.
import { deriveRootKey, didFromRootPublicKey, deriveDidCommKey } from './src/did/keys.ts'
import { buildBisetDocument } from './src/did/document.ts'
import { publishDocument, PUBLIC_PKARR_FALLBACKS } from './src/did/resolver.ts'

const seed = crypto.getRandomValues(new Uint8Array(32))
const root = deriveRootKey(seed)
const did = didFromRootPublicKey(root.publicKey)
console.log('identity:', did)

const doc = buildBisetDocument(did, root.publicKey, [], 'y@biset.md')
console.log('publishing to public Pkarr gateways:', PUBLIC_PKARR_FALLBACKS.join(', '))
const t0 = Date.now()
const publishedTo = await publishDocument(root.privateKey, doc, PUBLIC_PKARR_FALLBACKS)
console.log(`publish: ${publishedTo}/${PUBLIC_PKARR_FALLBACKS.length} gateways accepted, ${Date.now() - t0}ms`)
if (publishedTo === 0) throw new Error('FAIL: no gateway accepted the publish — cannot proceed with resolve test')

console.log('\nnow registering DIDComm (_k1) via didmediator...')
const { registerDidCommViaDht } = await import('./src/did/didcomm/register.ts')
const t1 = Date.now()
const didComm = deriveDidCommKey(seed)
const result = await registerDidCommViaDht(didComm.privateKey, root.privateKey, doc, 'http://localhost:4100', PUBLIC_PKARR_FALLBACKS)
console.log(`registerDidCommViaDht succeeded in ${Date.now() - t1}ms`)
console.log('published updated doc to', result.publishedTo, 'gateways')
console.log('keyAgreementKey present:', !!result.doc.keyAgreementKey)
console.log('DIDCommMessaging service:', JSON.stringify(result.doc.service.find(s => s.type === 'DIDCommMessaging')))
