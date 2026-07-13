// Client-side "keep my DID record alive" — build each identity's did:dht
// document (relay list + address) from its stored root key and publish it to
// that identity's own relays' gateways. Called best-effort on app start and
// after account creation: DHT records expire in hours, and the client re-put is
// the backstop that keeps a DID resolvable even if every relay is down when the
// owner next opens biset (DID.md republish rules). No-op when a gateway is
// disabled (PKARR_GATEWAY off) — the PUT just fails and is swallowed.
import { identities, relaysFor, isApRelay } from '../context.ts'
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

// Build this identity's current document from its stored key + live relay set,
// publish it to those relays' gateways, and return how many accepted it. Shared
// by the automatic and manual paths. Returns 0 (never throws) when there's no
// DID record / no relay / all gateways unreachable.
async function publishOne(email: string): Promise<number> {
  try {
    const rec = await getDidRecord(email)
    if (!rec) return 0
    const relaySessions = relaysFor(email)
    if (!relaySessions.length) return 0
    // Each endpoint carries its own protocol + address, so an AP relay and an
    // SMTP relay of one DID can advertise different addresses (see DidService).
    const services = relaySessions.map(s => ({
      id: relayId(s.account.serverUrl),
      serverUrl: s.account.serverUrl,
      protocol: isApRelay(s.account.serverUrl) ? 'activitypub' : 'mail',
      address: s.account.email,
    }))
    const gateways = relaySessions.map(s => gatewayUrl(s.account.serverUrl))
    // All addresses of this identity (a moved identity spans several), the
    // representative `email` first as the primary a contact should deliver to.
    const addresses = [email, ...new Set(relaySessions.map(s => s.account.email))].filter((a, i, arr) => arr.indexOf(a) === i)
    const doc = buildBisetDocument(rec.did, hexToBytes(rec.rootPublicKey), services, addresses)
    return await publishDocument(hexToBytes(rec.rootPrivateKey), doc, gateways)
  } catch { return 0 }
}

export async function publishOwnDids(): Promise<void> {
  for (const email of identities()) await publishOne(email)
}

// Manual "Republish to DHT" action: true if at least one gateway accepted it.
export async function publishOneVisible(email: string): Promise<boolean> {
  return (await publishOne(email)) > 0
}
