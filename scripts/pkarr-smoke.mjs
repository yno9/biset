// Live Pkarr/did:dht gateway smoke test.
//
// Exercises the full deployed chain against a running relay gateway:
//   client builds a signed DID document  →  PUT /pkarr/<key>  →  gateway → DHT
//   →  GET /pkarr/<key>  →  gateway → DHT  →  client verifies signature + payload
//
// Run AFTER a relay has been (re)deployed with the pkarr package and started
// with PKARR_GATEWAY=1:
//
//   bun scripts/pkarr-smoke.mjs https://mail.non.md
//   bun scripts/pkarr-smoke.mjs https://ap.non.md
//
// A pass means the gateway can talk to the live mainline DHT and round-trip a
// self-signed record. Uses an ephemeral throwaway identity — it publishes a
// short-lived test record under a random key, nothing tied to a real account.
import { deriveRootKey, didFromRootPublicKey } from '../src/did/keys.ts'
import { buildBisetDocument } from '../src/did/document.ts'
import { buildSignedPayload, parseSignedPayload } from '../src/did/packet.ts'
import { identityKeyFromDid } from '../src/did/resolver.ts'

const gw = (process.argv[2] || 'http://127.0.0.1:8790').replace(/\/$/, '')

const master = crypto.getRandomValues(new Uint8Array(32))
const root = deriveRootKey(master)
const did = didFromRootPublicKey(root.publicKey)
const suffix = did.replace('did:dht:', '')
const doc = buildBisetDocument(did, root.publicKey, [{ id: 'mail', serverUrl: 'https://mail.example' }], 'smoke@example')
const payload = buildSignedPayload(root.privateKey, doc, Math.floor(Date.now() / 1000))

console.log('gateway:', gw)
console.log('DID    :', did)

process.stdout.write('PUT ... ')
const put = await fetch(`${gw}/pkarr/${suffix}`, {
  method: 'PUT', headers: { 'Content-Type': 'application/octet-stream' }, body: payload,
})
console.log(put.status, put.ok ? 'OK' : 'FAIL')
if (!put.ok) { console.log('PUT failed — gateway not reachable or DHT/UDP blocked'); process.exit(1) }

let got = null
for (let i = 1; i <= 6; i++) {
  process.stdout.write(`GET attempt ${i} ... `)
  const g = await fetch(`${gw}/pkarr/${suffix}`, { headers: { Accept: 'application/octet-stream' } })
  if (g.ok) { got = new Uint8Array(await g.arrayBuffer()); console.log('200 OK'); break }
  console.log(g.status)
  await new Promise(r => setTimeout(r, 4000))
}
if (!got) { console.log('GET never succeeded — DHT propagation/coverage issue'); process.exit(1) }

const parsed = parseSignedPayload(identityKeyFromDid(did), got)
const relay = parsed.document.service[0]?.serviceEndpoint[0]
const okRelay = relay === 'https://mail.example'
console.log(`verify: signature OK, seq=${parsed.seq}, relay=${relay} ${okRelay ? '✓' : '✗'}`)
if (okRelay) console.log('\nGATEWAY SMOKE TEST PASSED (client→HTTP→DHT→HTTP→client)')
else { console.log('\nFAIL: round-trip payload mismatch'); process.exit(1) }
