// The user's scenario, for real: an identity with 20 relays, published to
// and resolved from the actual public Pkarr gateways / Mainline DHT.
// Before chaining this threw "DNS packet 2097B exceeds BEP44 1000B limit"
// and publishOne swallowed it into a silent no-op.
const _store = new Map()
globalThis.localStorage = { getItem: (k) => _store.get(k) ?? null, setItem: (k, v) => _store.set(k, String(v)) }

import { buildBisetDocument } from './src/did/document.ts'
import { deriveRootKey, didFromRootPublicKey } from './src/did/keys.ts'
import { publishDocument, resolve, PUBLIC_PKARR_FALLBACKS } from './src/did/resolver.ts'

const N = 20
const seed = crypto.getRandomValues(new Uint8Array(32))
const root = deriveRootKey(seed)
const did = didFromRootPublicKey(root.publicKey)

const relays = []
for (let i = 0; i < N; i++) relays.push({ id: `r${i}`, serverUrl: `https://relay${i}.biset.md`, protocol: 'mail', address: `y${i}@biset.md` })
const doc = buildBisetDocument(did, root.publicKey, relays, ['y@biset.md'], 'y')
doc.keyAgreementKey = new Uint8Array(32).fill(7)

console.log(`identity: ${did}`)
console.log(`publishing ${N} relays to the real DHT via ${PUBLIC_PKARR_FALLBACKS.join(', ')}...`)
const t0 = Date.now()
const accepted = await publishDocument(root.privateKey, doc, PUBLIC_PKARR_FALLBACKS)
console.log(`published: root accepted by ${accepted}/${PUBLIC_PKARR_FALLBACKS.length} gateways, ${Date.now() - t0}ms total`)
if (accepted === 0) throw new Error('FAIL: root not accepted')

console.log('\nresolving back from the DHT (follows the chain)...')
const t1 = Date.now()
const got = await resolve(did, PUBLIC_PKARR_FALLBACKS)
console.log(`resolved in ${Date.now() - t1}ms`)
if (!got) throw new Error('FAIL: could not resolve')

console.log('services recovered:', got.service.length, '/', N)
if (got.service.length !== N) throw new Error(`FAIL: expected ${N} services, got ${got.service.length}`)
for (let i = 0; i < N; i++) {
  if (got.service[i].id !== `r${i}`) throw new Error(`FAIL: order broken at ${i}: ${got.service[i].id}`)
  if (got.service[i].address !== `y${i}@biset.md`) throw new Error(`FAIL: address lost at ${i}`)
}
if (!got.keyAgreementKey) throw new Error('FAIL: _k1 lost')
if (got.name !== 'y') throw new Error('FAIL: name lost')
if (got.ext) throw new Error('FAIL: ext leaked to the caller')

console.log('first/last service:', got.service[0].serviceEndpoint[0], '...', got.service[N - 1].serviceEndpoint[0])
console.log('_k1 present:', !!got.keyAgreementKey, '| name:', got.name, '| aka:', JSON.stringify(got.alsoKnownAs))
console.log(`\n*** ${N} relays published to and resolved from the real public DHT, in order, all signatures verified ***`)
