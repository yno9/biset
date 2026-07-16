// Client-side "keep my DID record alive" — build each identity's did:dht
// document (relay list + address) from its stored root key and publish it to
// that identity's own relays' gateways. Called best-effort on app start and
// after account creation: DHT records expire in hours, and the client re-put is
// the backstop that keeps a DID resolvable even if every relay is down when the
// owner next opens biset (DID.md republish rules). No-op when a gateway is
// disabled (PKARR_GATEWAY off) — the PUT just fails and is swallowed.
import { identities, relaysFor, isApRelay } from '../context.ts'
import * as identityStore from '../store/identities.ts'
import { getDidRecord } from './store.ts'
import { buildBisetDocument } from './document.ts'
import { publishDocument } from './resolver.ts'
import { hexToBytes } from '../utils.ts'

// The display name to publish in the DID document (biset extension, see
// document.ts) — reuses the same JMAP Identity.name the "Change display
// name" modal already sets (left-pane.ts), rather than inventing a separate
// DID-specific name to manage. An identity can span several relays/addresses;
// take the first one that has a name set at all.
function displayNameFor(relaySessions: Array<{ account: { email: string } }>): string | undefined {
  for (const s of relaySessions) {
    const name = identityStore.all().find(i => i.email === s.account.email)?.name
    if (name) return name
  }
  return undefined
}


function relayId(serverUrl: string): string {
  try { return new URL(serverUrl).hostname.split('.')[0] } catch { return 'relay' }
}

export function gatewayUrl(serverUrl: string): string {
  return serverUrl.replace(/\/$/, '') + '/pkarr'
}

export interface OwnDocument {
  doc: ReturnType<typeof buildBisetDocument>
  gateways: string[]
  rootPrivateKey: Uint8Array
}

// Build this identity's current document from its stored key + LIVE relay set
// — the live sessions are the source of truth for "which relays serve me
// right now", never whatever happens to be published on the DHT already.
// Anything wanting to publish a variant of this document (e.g. adding a
// DIDComm _k1 + service, didcomm/register.ts) must start here rather than
// resolve-and-append: a resolve can transiently fail, and treating that as
// "no relays" would republish a document that erases the identity's real
// relay/address list — which is exactly what happened to a real account
// before this was unified (PLAN.md).
export async function buildOwnDocument(email: string): Promise<OwnDocument | null> {
  const rec = await getDidRecord(email)
  if (!rec) return null
  const relaySessions = relaysFor(email)
  if (!relaySessions.length) return null
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
  const doc = buildBisetDocument(rec.did, hexToBytes(rec.rootPublicKey), services, addresses, displayNameFor(relaySessions))

  // Carry the DIDComm layer (_k1 + the mediator it's registered with, both
  // from the local record) into every publish. This function is the ONLY
  // builder — publishOwnDids runs it on every app start — so anything it
  // omits gets republished away: without this, registering with a mediator
  // would silently un-register itself the next time biset opened.
  if (rec.didCommPublicKey) doc.keyAgreementKey = hexToBytes(rec.didCommPublicKey)
  if (rec.didCommMediatorUrl && rec.didCommRoutingKey) {
    doc.service.push({
      id: 'didcomm', type: 'DIDCommMessaging',
      serviceEndpoint: [rec.didCommMediatorUrl],
      accept: ['didcomm/v2'],
      routingKeys: [rec.didCommRoutingKey],
    })
  }
  return { doc, gateways, rootPrivateKey: hexToBytes(rec.rootPrivateKey) }
}

// Build + publish, returning how many gateways accepted it. Shared by the
// automatic and manual paths. Returns 0 (never throws) when there's no DID
// record / no relay / all gateways unreachable.
async function publishOne(email: string): Promise<number> {
  try {
    const own = await buildOwnDocument(email)
    if (!own) return 0
    return await publishDocument(own.rootPrivateKey, own.doc, own.gateways)
  } catch { return 0 }
}

export async function publishOwnDids(): Promise<void> {
  for (const email of identities()) await publishOne(email)
}

// Manual "Republish to DHT" action: true if at least one gateway accepted it.
export async function publishOneVisible(email: string): Promise<boolean> {
  return (await publishOne(email)) > 0
}
