// publishDocument must distinguish "nothing/nobody accepted it" (benign, 0)
// from "this document cannot be published" (a real fault, throws) — the
// conflation of those is what let a broken account sit silently unpublished.
const _store = new Map()
globalThis.localStorage = { getItem: (k) => _store.get(k) ?? null, setItem: (k, v) => _store.set(k, String(v)) }

import { buildBisetDocument } from './src/did/document.ts'
import { deriveRootKey, didFromRootPublicKey } from './src/did/keys.ts'
import { publishDocument } from './src/did/resolver.ts'

const seed = crypto.getRandomValues(new Uint8Array(32))
const root = deriveRootKey(seed)
const did = didFromRootPublicKey(root.publicKey)
const doc = buildBisetDocument(did, root.publicKey, [{ id: 'mail', serverUrl: 'https://mail.biset.md', protocol: 'mail', address: 'y@biset.md' }], ['y@biset.md'], 'y')

// 1. Unreachable gateway = benign. Must return 0, NOT throw: this is the
//    everyday transient case and must never be mistaken for a fault.
{
  const n = await publishDocument(root.privateKey, doc, ['http://127.0.0.1:9/nope'])
  if (n !== 0) throw new Error(`FAIL: expected 0, got ${n}`)
  console.log('ok   unreachable gateway -> 0 (benign, no throw)')
}

// 2. A single service too big to ever fit = a real fault. Must throw, and the
//    message must name the actual problem.
{
  const huge = buildBisetDocument(did, root.publicKey, [
    { id: 'mail', serverUrl: 'https://' + 'x'.repeat(1200) + '.biset.md', protocol: 'mail', address: 'y@biset.md' },
  ], ['y@biset.md'], 'y')
  try {
    await publishDocument(root.privateKey, huge, ['http://127.0.0.1:9/nope'])
    throw new Error('FAIL: an unpublishable document did not throw')
  } catch (e) {
    if (String(e).includes('FAIL:')) throw e
    console.log('ok   unpublishable document -> throws:', e.message.slice(0, 80))
  }
}

// 3. A chained document whose continuations can't be placed = a real fault
//    (refusing to publish a root that points at a link nobody has).
{
  const relays = []
  for (let i = 0; i < 20; i++) relays.push({ id: `r${i}`, serverUrl: `https://relay${i}.biset.md`, protocol: 'mail', address: `y${i}@biset.md` })
  const chained = buildBisetDocument(did, root.publicKey, relays, ['y@biset.md'], 'y')
  try {
    await publishDocument(root.privateKey, chained, ['http://127.0.0.1:9/nope'])
    throw new Error('FAIL: a chain with unplaceable continuations did not throw')
  } catch (e) {
    if (String(e).includes('FAIL:')) throw e
    console.log('ok   chain w/ unplaceable continuation -> throws:', e.message.slice(0, 70))
  }
}

console.log('\nBenign vs. fault are now distinguishable — the UI can stop reporting every failure as "no gateway reachable".')
