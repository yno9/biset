// NOTE: superseded by scratch-k1-live-dht-fullflow.mjs — this originally
// proved didmediator's did:dht resolver gap before it was implemented. Kept
// only as a historical record; the "expected failure" it checks for no
// longer occurs (resolver.ts now resolves did:dht for real).
import { deriveRootKey, deriveDidCommKey, didFromRootPublicKey } from './src/did/keys.ts'
import { buildBisetDocument } from './src/did/document.ts'
import { registerDidCommViaDht } from './src/did/didcomm/register.ts'

const seed = crypto.getRandomValues(new Uint8Array(32))
const root = deriveRootKey(seed)
const didComm = deriveDidCommKey(seed)
const did = didFromRootPublicKey(root.publicKey)
const existingDoc = buildBisetDocument(did, root.publicKey, [], 'y@biset.md')

console.log('attempting did:dht mediator registration for', did)
try {
  const result = await registerDidCommViaDht(didComm.privateKey, root.privateKey, existingDoc, 'http://localhost:4100', [])
  console.log('now succeeds (resolver.ts implemented since this script was written):', JSON.stringify({ publishedTo: result.publishedTo }, null, 2))
} catch (e) {
  console.log('failed:', e.message)
}
