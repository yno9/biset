// What ACTUALLY happens when an identity has too many relays to fit in
// BEP44's 1000 bytes? Does it error, or fail silently?
import { buildBisetDocument } from './src/did/document.ts'
import { buildSignedPayload } from './src/did/packet.ts'
import { publishDocument } from './src/did/resolver.ts'
import { deriveRootKey, didFromRootPublicKey } from './src/did/keys.ts'

const seed = crypto.getRandomValues(new Uint8Array(32))
const root = deriveRootKey(seed)
const did = didFromRootPublicKey(root.publicKey)

function docWith(n) {
  const relays = []
  for (let i = 0; i < n; i++) relays.push({ id: `r${i}`, serverUrl: `https://relay${i}.biset.md`, protocol: 'mail', address: 'y@biset.md' })
  return buildBisetDocument(did, root.publicKey, relays, ['y@biset.md'], 'y')
}

// 1. What does the low-level signer do?
console.log('--- buildSignedPayload (the signer) with 20 relays ---')
try {
  buildSignedPayload(root.privateKey, docWith(20))
  console.log('  no error?!')
} catch (e) {
  console.log('  throws:', e.message)
}

// 2. What does publishDocument (what publishOne calls) do?
console.log('\n--- publishDocument with 20 relays ---')
try {
  const n = await publishDocument(root.privateKey, docWith(20), ['https://relay.pkarr.org'])
  console.log('  returned:', n, '(no throw)')
} catch (e) {
  console.log('  throws:', e.message)
}

// 3. And what does publishOne's shape do? (it wraps the above in try/catch → 0)
console.log('\n--- simulating publishOne\'s try/catch wrapper ---')
async function publishOneLike() {
  try {
    return await publishDocument(root.privateKey, docWith(20), ['https://relay.pkarr.org'])
  } catch { return 0 }
}
console.log('  returns:', await publishOneLike(), '— indistinguishable from "gateway unreachable"')
