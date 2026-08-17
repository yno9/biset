// Invisible DID-backed contact discovery (DID.md option A): keep a contact's
// reachable address/relays fresh from their signed DID document, so that if they
// move relays or domains, outgoing mail still reaches them — with no UI, exactly
// as did:plc is invisible to Bluesky users.
//
// Chain: address ──did:webvh's own convention──> DID ──gateway/DHT──> signed
// document (relay list + current address in alsoKnownAs). The document is
// signature-verified against the key the DID names (resolve()), and the
// address→DID binding is TOFU (the did.jsonl fetch below is unauthenticated —
// resolveAny's own signature/chain verification is what actually vouches for
// the document once the DID is known). Everything here is best-effort and
// fully guarded: with gateways disabled or a contact that never published a
// DID, every call is a silent no-op and delivery falls back to the address as
// typed.
//
// Anchor = the DID's own trailing path segment (2026-08-17, replacing both a
// DNS TXT anchor and a brief WebFinger detour): biset's own DID.md
// convention commits to `did:webvh:{SCID}:{domain}:{localpart}` always
// naming the SAME localpart the mail address at that domain uses — so
// `user@domain`'s DID is always at `https://domain/user/did.jsonl`, no
// separate address→DID binding record needed at all. Both DNS TXT and
// WebFinger existed to answer a question that, under this convention, the
// URL itself already answers.
import { sessions, isDidCommRelay } from '../context.ts'
import { resolveAny } from './resolver.ts'
import type { WebvhDidDocument } from './webvh/document.ts'
import { firstServiceEndpoint } from '../utils.ts'
import { buildCardForDid, type Card } from './contacts.ts'
import { buildBisetWebvhDid } from './webvh/identifier.ts'
import * as contactsStore from '../store/contacts.ts'
import * as persist from '../vault/persist.ts'

interface ContactCache {
  did: string
  address: string // current address from the document's alsoKnownAs (mailto:)
  relays: string[] // service endpoints from the document
  protocol?: string // 'mail' | 'activitypub' — the transport this address's matching service entry carries (DidService.protocol)
  name?: string // self-asserted display name from the document (biset extension, see document.ts) — a UX label only, not verified
  lastChecked?: number // ms epoch — throttles refreshContact's DHT round-trip
}

// How often refreshContact actually re-resolves against the DHT, once a
// contact is known. First contact always resolves (no cache yet); after
// that, re-checking on literally every send is wasted network/gateway load
// for a fact that changes rarely (a contact migrating relays mid-conversation
// is the whole point of periodic re-checks — but "periodic" isn't "every
// message").
const REFRESH_TTL_MS = 60 * 60 * 1000

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

// GET https://<domain>/<localpart>/did.jsonl directly — biset's own
// convention (this file's header) means the address's localpart IS the
// did:webvh path segment, so there is nothing to look up beyond the log
// itself. Reads the SCID out of the genesis entry's parameters (same
// computation buildBisetWebvhDid does for a fresh create) rather than
// parsing/verifying the whole log — this is a lookup, not a resolution;
// resolveAny's own chain verification is what a caller actually trusts.
// Anything else (network error, no did.jsonl at that path, malformed log) is
// null, same "silent no-op" contract the old DNS TXT / WebFinger lookups had.
async function resolveWebvhDid(address: string): Promise<string | null> {
  const domain = domainOf(address)
  const localpart = localpartOf(address).toLowerCase()
  try {
    const resp = await fetch(`https://${domain}/${encodeURIComponent(localpart)}/did.jsonl`)
    if (!resp.ok) return null
    const firstLine = (await resp.text()).split('\n').find(l => l.trim())
    if (!firstLine) return null
    const scid = (JSON.parse(firstLine) as { parameters?: { scid?: string } }).parameters?.scid
    return scid ? buildBisetWebvhDid(scid, domain, localpart) : null
  } catch {
    return null
  }
}

// Every address this document claims — every `mailto:` entry in
// alsoKnownAs, not just the first, PLUS every service[].address (a second+
// address never surfaced there before, e.g. the mail/AP split identities
// project_biset_identity_split describes). Generalizes what used to be a
// single-slot check (only alsoKnownAs[0]) to the "claim ≠ ownership"
// principle applying uniformly to anything the document asserts.
function claimedAddresses(doc: WebvhDidDocument): string[] {
  const out = new Set<string>()
  for (const aka of doc.alsoKnownAs) if (aka.startsWith('mailto:')) out.add(aka.slice('mailto:'.length))
  for (const svc of doc.service) if (svc.address) out.add(svc.address)
  return [...out]
}

// address → DID via the convention's own did.jsonl path (cached; TOFU on first success).
async function addressToDid(address: string): Promise<string | null> {
  const cached = localStorage.getItem(DID_KEY + address)
  if (cached) return cached
  const did = await resolveWebvhDid(address)
  if (!did) return null
  localStorage.setItem(DID_KEY + address, did)
  return did
}

// Public wrapper for UI callers that just want to know "does this address
// have a DID anchor at all" (e.g. compose's To-field protocol pills offering
// a [DID] option next to [Mail]/[AP] for an address that publishes one) —
// no reverse-binding check needed here, since (unlike a document's *claimed*
// address) this direction is already anchored by the address's own domain.
export const discoverDidForAddress = addressToDid

/** Same question, asked FRESH: does `address` publish a DID right now?
 *
 * Uncached on purpose, unlike discoverDidForAddress — the signup form asks
 * this to decide whether a typed username is an existing identity (offer
 * "Log in") or a free name (offer "Start"), and the TOFU cache would keep
 * answering "taken" for an address whose account has since been deleted.
 * Shares this file's one lookup implementation rather than adding a
 * second. */
export async function lookupDidForAddressFresh(address: string): Promise<string | null> {
  return resolveWebvhDid(address)
}

// Fresh (uncached) reverse-binding check: does `address`'s own anchor attest
// that it belongs to `did`? A DID document is self-signed, so it can *claim*
// any address (even someone else's); a claim is only trustworthy when the
// claimed address points BACK to the same DID (bidirectional verification —
// see the two-DIDs-claim-one-account problem). Fails closed: no record / no
// match → not verified → we don't redirect delivery there.
async function verifyBinding(address: string, did: string): Promise<boolean> {
  return (await resolveWebvhDid(address)) === did
}

// Picks which of the document's claimed addresses (if any) to actually
// deliver to instead of `known` — `known` itself needs no check (its own
// anchor is how this DID was found in the first place, addressToDid). Every
// OTHER address the document claims is verified independently (claimedAddresses,
// generalized from checking only alsoKnownAs[0]); among the ones that verify,
// one sharing `known`'s own protocol wins (a same-protocol move), otherwise
// whichever verified first. No verified claim at all → keep `known` unchanged,
// same fail-closed default as before.
async function resolveVerifiedAddress(
  doc: WebvhDidDocument, did: string, known: string,
): Promise<{ address: string; protocol?: string }> {
  const knownProtocol = doc.service.find(s => s.address === known)?.protocol
  let fallback: { address: string; protocol?: string } | undefined
  for (const candidate of claimedAddresses(doc)) {
    if (candidate === known) continue
    if (!(await verifyBinding(candidate, did))) continue
    const protocol = doc.service.find(s => s.address === candidate)?.protocol
    if (knownProtocol && protocol === knownProtocol) return { address: candidate, protocol }
    if (!fallback) fallback = { address: candidate, protocol }
  }
  return fallback ?? { address: known, protocol: knownProtocol }
}

// Best-effort: resolve a contact's current document and cache their (verified)
// address + relays. Safe to fire-and-forget; never throws.
export async function refreshContact(address: string): Promise<void> {
  try {
    const did = await addressToDid(address)
    if (!did) return
    const prev = getJSON<ContactCache>(CONTACT_KEY + address)
    if (prev?.lastChecked && Date.now() - prev.lastChecked < REFRESH_TTL_MS) return
    const doc = await resolveAny(did) // applies signature + chain verification
    if (!doc) return
    // The document may claim other addresses (a moved-to primary, a second
    // mail/AP-split address, …). Only adopt one as the delivery target if
    // that address's own relay attests the reverse (address → same DID) —
    // resolveVerifiedAddress checks every claim, not just one privileged
    // slot. Otherwise keep the address we already know (which came from its
    // own anchor via addressToDid) — never redirect on an unverified
    // unilateral claim.
    const { address: verifiedAddress, protocol } = await resolveVerifiedAddress(doc, did, address)
    setJSON(CONTACT_KEY + address, {
      did,
      address: verifiedAddress,
      relays: doc.service.map(s => firstServiceEndpoint(s.serviceEndpoint)),
      protocol,
      name: doc.name,
      lastChecked: Date.now(),
    })
    await syncContactCard(did)
  } catch { /* best-effort */ }
}

// Resolves a DID typed directly (shared via QR code, profile link, etc. —
// without knowing any current address) to its verified current address. The
// entry point for composing to someone by DID alone, complementing
// refreshContact (which starts from a known address instead). Same
// reverse-binding rule applies: a document's self-claimed address is only
// trusted once that address's own anchor points back to this DID — with no
// previously-known address to fall back to here, failure to verify means no
// usable address at all (returns null), not a guess.
export async function resolveDidDirect(did: string): Promise<{ address: string; relays: string[] } | null> {
  try {
    const doc = await resolveAny(did)
    if (!doc) return null
    // No prior known address to compare against here (cold start) — check
    // every claim the document makes (claimedAddresses, not just
    // alsoKnownAs[0]) and take the first that verifies. Still no guessing:
    // nothing verifies → no usable address at all.
    let claimed: string | undefined
    for (const candidate of claimedAddresses(doc)) {
      if (await verifyBinding(candidate, did)) { claimed = candidate; break }
    }
    if (!claimed) return null
    const relays = doc.service.map(s => firstServiceEndpoint(s.serviceEndpoint))
    const protocol = doc.service.find(s => s.address === claimed)?.protocol
    setJSON(CONTACT_KEY + claimed, { did, address: claimed, relays, protocol, name: doc.name, lastChecked: Date.now() })
    localStorage.setItem(DID_KEY + claimed, did) // seed the TOFU cache so a later refreshContact(claimed) skips the DNS round-trip
    await syncContactCard(did)
    return { address: claimed, relays }
  } catch { return null }
}

// The freshest verified address to deliver to. Returns the input unchanged
// unless a signature-verified DID document gave a different current address.
export function freshestAddressFor(address: string): string {
  return getJSON<ContactCache>(CONTACT_KEY + address)?.address ?? address
}

// The transport ('mail' | 'activitypub') `address`'s freshest verified
// binding uses, per the contact's DID document. Undefined if unresolved or
// the document didn't tag a protocol for it — callers should treat that as
// "unknown, don't second-guess the conversation's established relay".
export function protocolForContact(address: string): string | undefined {
  return getJSON<ContactCache>(CONTACT_KEY + address)?.protocol
}

// ── DID-rooted contact cache sync (server write-through + fresh-device pull) ──
// Consolidates every locally-known address for `did` into one JSContact Card
// (buildCardForDid) and write-throughs it: to the in-memory/idb/vault store
// (survives this browser's localStorage being cleared) and, best-effort, to
// every one of the user's own relays (survives a device change — the vault
// needs Chromium's File System Access API, so this is the fallback that works
// on every browser). Neither is the ground truth — the contact's own DID
// document is — this only makes what's already been resolved durable.
function allContactCacheEntries(): { did: string; address: string; relays: string[]; name?: string }[] {
  const out: { did: string; address: string; relays: string[]; name?: string }[] = []
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i)
    if (!key || !key.startsWith(CONTACT_KEY)) continue
    const entry = getJSON<ContactCache>(key)
    if (entry) out.push(entry)
  }
  return out
}

async function syncContactCard(did: string): Promise<void> {
  try {
    const card = buildCardForDid(did, allContactCacheEntries())
    contactsStore.put(card)
    await persist.flushContacts()
    const uid = encodeURIComponent(card.uid)
    await Promise.all(sessions.filter(s => !isDidCommRelay(s.account.serverUrl)).map(s =>
      fetch(`${s.account.serverUrl.replace(/\/$/, '')}/contacts/${uid}`, {
        method: 'PUT',
        headers: {
          Authorization: 'Basic ' + btoa(s.account.email + ':' + s.account.password),
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(card),
      }).catch(() => {})
    ))
  } catch { /* best-effort */ }
}

// Pulls every Card from every one of the user's own relays and merges them
// into the local store — the counterpart to syncContactCard's push, run once
// at session start so a fresh device/browser (empty localStorage/idb) inherits
// previously-resolved contacts instead of starting blind.
export async function pullOwnContacts(): Promise<void> {
  try {
    for (const s of sessions) {
      if (isDidCommRelay(s.account.serverUrl)) continue // no JMAP endpoint behind the synthetic DIDComm session
      try {
        const resp = await fetch(`${s.account.serverUrl.replace(/\/$/, '')}/contacts`, {
          headers: { Authorization: 'Basic ' + btoa(s.account.email + ':' + s.account.password) },
        })
        if (!resp.ok) continue
        const body = await resp.json() as { cards?: Card[] }
        for (const card of body.cards ?? []) contactsStore.put(card)
      } catch { /* try next relay */ }
    }
    await persist.flushContacts()
  } catch { /* best-effort */ }
}
