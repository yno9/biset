// Invisible DID-backed contact discovery (DID.md option A): keep a contact's
// reachable address/relays fresh from their signed DID document, so that if they
// move relays or domains, outgoing mail still reaches them — with no UI, exactly
// as did:plc is invisible to Bluesky users.
//
// Chain: address ──anchor(DNS TXT)──> DID ──gateway/DHT──> signed document
// (relay list + current address in alsoKnownAs). The document is
// signature-verified against the key the DID names (resolve()), and the
// address→DID binding is TOFU at the anchor. Everything here is best-effort
// and fully guarded: with gateways disabled or a contact that never published
// a DID, every call is a silent no-op and delivery falls back to the address
// as typed.
//
// Anchor = DNS, not a relay-hosted endpoint (DID.md "biset verse"): the
// address→DID binding lives in a `_did.<localpart>.<domain>` TXT record
// (`did=<did>`), resolved via DNS-over-HTTPS since browsers can't issue raw
// DNS queries — mirrors ATProto's `_atproto.<handle>` handle resolution. This
// decouples "who answers for this address" from "who runs the JMAP relay
// behind it": DNS is a commodity, swappable, and self-hostable by whoever owns
// the domain, unlike a bespoke relay endpoint only that relay's software can
// serve.
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

// DNS label for the anchor TXT record. Lowercased — DNS labels are
// case-insensitive and biset usernames are conventionally lowercase already.
function didTxtName(address: string): string {
  return `_did.${localpartOf(address).toLowerCase()}.${domainOf(address)}`
}

// DNS-over-HTTPS TXT lookup (JSON API), Cloudflare first, Google as a
// fallback so no single DoH provider is a hard dependency. Returns the decoded
// TXT string values (quotes stripped) or [] on any failure/empty result.
async function resolveTxt(name: string): Promise<string[]> {
  const providers = [
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=TXT`,
    `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=TXT`,
  ]
  for (const url of providers) {
    try {
      const resp = await fetch(url, { headers: { Accept: 'application/dns-json' } })
      if (!resp.ok) continue
      const body = await resp.json() as { Answer?: Array<{ type: number; data: string }> }
      const txts = (body.Answer ?? []).filter(a => a.type === 16).map(a => a.data.replace(/^"|"$/g, ''))
      if (txts.length) return txts
    } catch { /* try next provider */ }
  }
  return []
}

function parseDidTxt(txts: string[]): string | null {
  for (const t of txts) if (t.startsWith('did=')) return t.slice('did='.length)
  return null
}

function akaMailAddress(doc: DidDocument): string | null {
  for (const aka of doc.alsoKnownAs) if (aka.startsWith('mailto:')) return aka.slice('mailto:'.length)
  return null
}

// The user's own relays double as resolution gateways (DID.md: query through a
// relay that already sees your traffic, not a stranger's).
function ownGateways(): string[] {
  return [...new Set(sessions.map(s => s.account.serverUrl.replace(/\/$/, '') + '/pkarr'))]
}

// address → DID via the DNS anchor (cached; TOFU on first success).
async function addressToDid(address: string): Promise<string | null> {
  const cached = localStorage.getItem(DID_KEY + address)
  if (cached) return cached
  const did = parseDidTxt(await resolveTxt(didTxtName(address)))
  if (!did) return null
  localStorage.setItem(DID_KEY + address, did)
  return did
}

// Fresh (uncached) reverse-binding check: does `address`'s own DNS anchor
// attest that it belongs to `did`? A DID document is self-signed, so it can
// *claim* any address (even someone else's); a claim is only trustworthy when
// the claimed address points BACK to the same DID (bidirectional verification —
// see the two-DIDs-claim-one-account problem). Fails closed: no record / no
// match → not verified → we don't redirect delivery there.
async function verifyBinding(address: string, did: string): Promise<boolean> {
  const claimed = parseDidTxt(await resolveTxt(didTxtName(address)))
  return claimed === did
}

// Best-effort: resolve a contact's current document and cache their (verified)
// address + relays. Safe to fire-and-forget; never throws.
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
    // The document may claim a moved-to primary address (DID → address). Only
    // adopt it as the delivery target if the claimed address's relay attests the
    // reverse (address → same DID). Otherwise keep the address we already know
    // (which came from its own anchor via addressToDid) — never redirect on an
    // unverified unilateral claim.
    const claimed = akaMailAddress(doc)
    let verifiedAddress = address
    if (claimed && claimed !== address && await verifyBinding(claimed, did)) {
      verifiedAddress = claimed
    }
    setJSON(CONTACT_KEY + address, {
      did,
      address: verifiedAddress,
      relays: doc.service.flatMap(s => s.serviceEndpoint),
    })
  } catch { /* best-effort */ }
}

// The freshest verified address to deliver to. Returns the input unchanged
// unless a signature-verified DID document gave a different current address.
export function freshestAddressFor(address: string): string {
  return getJSON<ContactCache>(CONTACT_KEY + address)?.address ?? address
}
