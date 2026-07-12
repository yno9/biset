// Invisible DID-backed contact discovery (DID.md option A): keep a contact's
// reachable address/relays fresh from their signed DID document, so that if they
// move relays or domains, outgoing mail still reaches them — with no UI, exactly
// as did:plc is invisible to Bluesky users.
//
// Chain: address ──anchor──> DID ──gateway/DHT──> signed document (relay list +
// current address in alsoKnownAs). The document is signature-verified against
// the key the DID names (resolve()), and the address→DID binding is TOFU at the
// anchor. Everything here is best-effort and fully guarded: with gateways
// disabled or a contact that never published a DID, every call is a silent
// no-op and delivery falls back to the address as typed.
import { sessions } from '../context.ts'
import { resolve, PUBLIC_PKARR_FALLBACKS } from './resolver.ts'
import type { DidDocument } from './document.ts'

interface ContactCache {
  did: string
  address: string // current address from the document's alsoKnownAs (mailto:)
  relays: string[] // service endpoints from the document
}

const DID_KEY = 'biset_did_addr:' // address → did (TOFU binding)
const CONTACT_KEY = 'biset_did_contact:' // address → ContactCache (last resolved)

function getJSON<T>(key: string): T | null {
  try { const v = localStorage.getItem(key); return v ? JSON.parse(v) as T : null } catch { return null }
}
function setJSON(key: string, val: unknown): void {
  try { localStorage.setItem(key, JSON.stringify(val)) } catch { /* quota / private mode */ }
}

function domainOf(address: string): string { return address.slice(address.lastIndexOf('@') + 1) }
function localpartOf(address: string): string { return address.slice(0, address.lastIndexOf('@')) }

// The anchor (address→DID registry) is served by the domain's apex jmapap.
function anchorUrlFor(address: string): string {
  return `https://${domainOf(address)}/identity/${encodeURIComponent(localpartOf(address))}`
}

// The user's own relays double as resolution gateways (DID.md: query through a
// relay that already sees your traffic, not a stranger's).
function ownGateways(): string[] {
  return [...new Set(sessions.map(s => s.account.serverUrl.replace(/\/$/, '') + '/pkarr'))]
}

function akaMailAddress(doc: DidDocument): string | null {
  for (const aka of doc.alsoKnownAs) if (aka.startsWith('mailto:')) return aka.slice('mailto:'.length)
  return null
}

// address → DID via the anchor (cached; TOFU on first success).
async function addressToDid(address: string): Promise<string | null> {
  const cached = localStorage.getItem(DID_KEY + address)
  if (cached) return cached
  try {
    const resp = await fetch(anchorUrlFor(address))
    if (!resp.ok) return null
    const body = await resp.json() as { did?: string }
    if (!body.did) return null
    localStorage.setItem(DID_KEY + address, body.did)
    return body.did
  } catch { return null }
}

// Best-effort: resolve a contact's current document and cache their address +
// relays. Safe to fire-and-forget; never throws.
export async function refreshContact(address: string): Promise<void> {
  try {
    const did = await addressToDid(address)
    if (!did) return
    const prev = getJSON<ContactCache>(CONTACT_KEY + address)
    // Gateways: own relays first, then the contact's last-known relays, then
    // public fallbacks — so a contact whose own relays moved is still findable.
    const gateways = [
      ...ownGateways(),
      ...(prev?.relays ?? []).map(u => u.replace(/\/$/, '') + '/pkarr'),
      ...PUBLIC_PKARR_FALLBACKS,
    ]
    const doc = await resolve(did, [...new Set(gateways)]) // applies signature + freshness (rollback) checks
    if (!doc) return
    setJSON(CONTACT_KEY + address, {
      did,
      address: akaMailAddress(doc) ?? address,
      relays: doc.service.flatMap(s => s.serviceEndpoint),
    })
  } catch { /* best-effort */ }
}

// The freshest verified address to deliver to. Returns the input unchanged
// unless a signature-verified DID document gave a different current address.
export function freshestAddressFor(address: string): string {
  return getJSON<ContactCache>(CONTACT_KEY + address)?.address ?? address
}
