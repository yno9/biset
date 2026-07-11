// Client-side "keep my DID record alive" — build each identity's did:dht
// document (relay list + address) from its stored root key and publish it to
// that identity's own relays' gateways. Called best-effort on app start and
// after account creation: DHT records expire in hours, and the client re-put is
// the backstop that keeps a DID resolvable even if every relay is down when the
// owner next opens biset (DID.md republish rules). No-op when a gateway is
// disabled (PKARR_GATEWAY off) — the PUT just fails and is swallowed.
import { identities, relaysFor } from '../context.ts'
import { getDidRecord } from './store.ts'
import { buildBisetDocument } from './document.ts'
import { publishDocument } from './resolver.ts'

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}

function relayId(serverUrl: string): string {
  try { return new URL(serverUrl).hostname.split('.')[0] } catch { return 'relay' }
}

function gatewayUrl(serverUrl: string): string {
  return serverUrl.replace(/\/$/, '') + '/pkarr'
}

async function publishOne(email: string): Promise<void> {
  const rec = await getDidRecord(email)
  if (!rec) return
  const relaySessions = relaysFor(email)
  if (!relaySessions.length) return
  const services = relaySessions.map(s => ({ id: relayId(s.account.serverUrl), serverUrl: s.account.serverUrl }))
  const gateways = relaySessions.map(s => gatewayUrl(s.account.serverUrl))
  const doc = buildBisetDocument(rec.did, hexToBytes(rec.rootPublicKey), services, email)
  try {
    await publishDocument(hexToBytes(rec.rootPrivateKey), doc, gateways)
  } catch { /* best-effort */ }
}

export async function publishOwnDids(): Promise<void> {
  for (const email of identities()) {
    try { await publishOne(email) } catch { /* best-effort, per-identity */ }
  }
}
