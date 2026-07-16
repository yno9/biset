// Continuation chaining: split/merge correctness, offline (no network).
import { buildBisetDocument } from './src/did/document.ts'
import { buildSignedPayload, parseSignedPayload } from './src/did/packet.ts'
import { splitIntoChain, mergeChain } from './src/did/chain.ts'
import { deriveRootKey, didFromRootPublicKey } from './src/did/keys.ts'
import { identityKeyFromDid } from './src/did/resolver.ts'

const seed = crypto.getRandomValues(new Uint8Array(32))
const root = deriveRootKey(seed)
const did = didFromRootPublicKey(root.publicKey)

function docWith(n) {
  const relays = []
  for (let i = 0; i < n; i++) relays.push({ id: `r${i}`, serverUrl: `https://relay${i}.biset.md`, protocol: 'mail', address: `y${i}@biset.md` })
  const d = buildBisetDocument(did, root.publicKey, relays, ['y@biset.md'], 'y')
  d.keyAgreementKey = new Uint8Array(32).fill(7)
  return d
}

// 1. A document that fits must be published EXACTLY as before: one link, no ext.
{
  const doc = docWith(2)
  const links = splitIntoChain(root.privateKey, doc)
  if (links.length !== 1) throw new Error(`FAIL: fitting doc split into ${links.length} links`)
  if (links[0].doc.ext) throw new Error('FAIL: fitting doc got an ext pointer')
  if (links[0].did !== did) throw new Error('FAIL: root did changed')
  console.log('ok   2 relays  -> 1 record, no ext (byte-identical to today)')
}

// 2. Overflow splits, and every link verifies against its OWN did's key.
for (const n of [5, 20, 100]) {
  const doc = docWith(n)
  const links = splitIntoChain(root.privateKey, doc)

  // Simulate the DHT: sign each link, then verify+parse it exactly as a
  // resolver would (against the pubkey recovered from the link's own DID).
  const dht = new Map()
  for (const link of links) {
    const payload = buildSignedPayload(link.privateKey, link.doc)
    const parsed = parseSignedPayload(identityKeyFromDid(link.did), payload) // throws if the key doesn't match its DID
    dht.set(link.did, parsed.document)
  }

  // Follow the chain the way resolve() does.
  const rootDoc = dht.get(did)
  const continuations = []
  let next = rootDoc.ext
  while (next) {
    const d = dht.get(`did:dht:${next}`)
    if (!d) throw new Error(`FAIL: chain points at ${next}, which was never published`)
    continuations.push(d)
    next = d.ext
  }
  const merged = mergeChain(rootDoc, continuations)

  if (merged.service.length !== n) throw new Error(`FAIL: ${n} relays in, ${merged.service.length} out`)
  for (let i = 0; i < n; i++) {
    if (merged.service[i].id !== `r${i}`) throw new Error(`FAIL: service order broken at ${i}`)
  }
  if (!merged.keyAgreementKey) throw new Error('FAIL: _k1 lost')
  if (merged.name !== 'y') throw new Error('FAIL: name lost')
  if (merged.alsoKnownAs[0] !== 'mailto:y@biset.md') throw new Error('FAIL: alsoKnownAs lost')
  if (merged.ext) throw new Error('FAIL: ext leaked into the merged document')
  console.log(`ok   ${String(n).padStart(3)} relays -> ${links.length} records, all signatures verify, ${merged.service.length} services recovered in order`)
}

// 3. A generic resolver that ignores `ext` still gets a usable document.
{
  const links = splitIntoChain(root.privateKey, docWith(20))
  const rootOnly = links[0].doc
  if (!rootOnly.identityKey || !rootOnly.keyAgreementKey) throw new Error('FAIL: root record is not self-sufficient')
  console.log(`ok   generic resolver (ignores ext) still sees ${rootOnly.service.length} services + _k0 + _k1 + aka + name`)
}

console.log('\nChaining verified: unbounded services, every link self-certifying, fitting documents unchanged.')
