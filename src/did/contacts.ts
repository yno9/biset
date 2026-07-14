// DID-rooted contact cache (DID.md): a JSContact (RFC 9553) Card per resolved
// contact, built from discovery.ts's per-address ContactCache entries. One
// Card per DID (not per address) — mirrors the identity-by-DID grouping
// (`identityKey = did || email`) used everywhere else in the client, so a
// contact known under two addresses (mail + AP) collapses into one entry
// rather than reproducing the email/DID split this design has been avoiding
// all along.
//
// This is the client-side building block; persistence (vault + own-relay
// write-through) lives in store/contacts.ts and discovery.ts respectively.
import { sha1 } from '@noble/hashes/legacy.js'
import * as contactsStore from '../store/contacts.ts'

export interface JSContactEmail { address: string }
export interface JSContactCryptoKey { uri: string }
export interface JSContactLink { uri: string }
// RFC 9553 Name object: "full MUST be set if components is not set" — biset
// only ever has an unstructured display name, so full is the only field used.
export interface JSContactName { full: string }

export interface Card {
  '@type': 'Card'
  version: '1.0'
  uid: string
  name?: JSContactName
  emails?: Record<string, JSContactEmail>
  cryptoKeys?: Record<string, JSContactCryptoKey>
  links?: Record<string, JSContactLink>
  'biset.md:verifiedAt'?: number
}

// Fixed, arbitrary namespace UUID for deriving Card uids from a DID (RFC 4122
// §4.3, UUIDv5). Any fixed 16 bytes work as a namespace; this one has no
// meaning beyond being constant across the codebase.
const NAMESPACE = '9b7c9f3a-9e2b-4b7e-9a3c-6b6a2f6b3d10'

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/-/g, '')
  const out = new Uint8Array(clean.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16)
  return out
}

function bytesToUuid(b: Uint8Array): string {
  const hex = [...b].map(x => x.toString(16).padStart(2, '0')).join('')
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
}

// uuidv5(name) — deterministic: the same `name` (here, a DID string) always
// produces the same uid, so "does this DID already have a Card" reduces to a
// uid lookup instead of a separate DID→uid index.
export function uuidv5(name: string): string {
  const ns = hexToBytes(NAMESPACE)
  const nameBytes = new TextEncoder().encode(name)
  const buf = new Uint8Array(ns.length + nameBytes.length)
  buf.set(ns, 0)
  buf.set(nameBytes, ns.length)
  const digest = sha1(buf).slice(0, 16)
  digest[6] = (digest[6] & 0x0f) | 0x50 // version 5
  digest[8] = (digest[8] & 0x3f) | 0x80 // variant RFC 4122
  return bytesToUuid(digest)
}

interface ContactCacheEntry { did: string; address: string; relays: string[]; name?: string }

// Builds one Card consolidating every locally-cached ContactCache entry that
// resolves to `did` — regardless of how many different addresses biset has
// separately resolved it under.
export function buildCardForDid(did: string, entries: ContactCacheEntry[]): Card {
  const emails: Record<string, JSContactEmail> = {}
  const links: Record<string, JSContactLink> = {}
  const seenAddr = new Set<string>()
  const seenRelay = new Set<string>()
  let i = 0, r = 0
  let name: string | undefined
  for (const e of entries) {
    if (e.did !== did) continue
    if (!seenAddr.has(e.address)) { seenAddr.add(e.address); emails[`e${++i}`] = { address: e.address } }
    for (const relay of e.relays) {
      if (!seenRelay.has(relay)) { seenRelay.add(relay); links[`r${++r}`] = { uri: relay } }
    }
    if (e.name && !name) name = e.name
  }
  return {
    '@type': 'Card',
    version: '1.0',
    uid: `urn:uuid:${uuidv5(did)}`,
    name: name ? { full: name } : undefined,
    emails,
    cryptoKeys: { did1: { uri: did } },
    links,
    'biset.md:verifiedAt': Math.floor(Date.now() / 1000),
  }
}

// ── Inbox grouping by contact-DID (organization only, not message merging —
// same principle as go-jmapserver/didindex.go and context.ts's identityKey,
// applied to correspondents instead of the user's own accounts) ─────────────
//
// A contact known under two addresses (they migrated relays/domains mid-
// conversation) would otherwise fork into two separate inbox rows, since
// app.ts's loadInboxSummaries keys purely on the literal address. These two
// helpers let it key on the contact's DID instead, when contacts.json has
// already learned one — falling back to the address unchanged otherwise,
// exactly today's behavior.

// The grouping key for `address`: its DID if some locally-known Card lists
// it under `emails`, else the address itself.
export function contactIdentityKey(address: string): string {
  for (const card of contactsStore.all()) {
    if (Object.values(card.emails ?? {}).some(e => e.address === address)) {
      const did = Object.values(card.cryptoKeys ?? {})[0]?.uri
      if (did) return did
    }
  }
  return address
}

// The inverse of contactIdentityKey: every address grouped under `key` (all
// addresses on the Card whose DID matches, if `key` is one) — used to widen
// message filtering so a merged inbox row surfaces messages from every
// address the contact has used, not just the literal one a given row was
// keyed on.
function addressesForContactKey(key: string): string[] {
  if (key.startsWith('did:')) {
    for (const card of contactsStore.all()) {
      if (Object.values(card.cryptoKeys ?? {}).some(k => k.uri === key)) {
        const addrs = Object.values(card.emails ?? {}).map(e => e.address)
        if (addrs.length) return addrs
      }
    }
  }
  return [key]
}

// All addresses biset currently associates with `address`'s owner.
export function allKnownAddressesFor(address: string): string[] {
  return addressesForContactKey(contactIdentityKey(address))
}

// One representative address for `did` (the first one on its locally-known
// Card, if any) — the reverse of contactIdentityKey. Used to resolve a
// DID-keyed hash segment (see main.ts's matchInboxForHash) back into
// something getInboxEmails can actually filter real data on. Unlike
// addressesForContactKey, returns undefined (not the DID itself) when no
// Card is known yet — callers need to tell "unresolved" apart from "found".
export function representativeAddressForDid(did: string): string | undefined {
  for (const card of contactsStore.all()) {
    if (Object.values(card.cryptoKeys ?? {}).some(k => k.uri === did)) {
      return Object.values(card.emails ?? {})[0]?.address
    }
  }
  return undefined
}

// A DID is unreadable as a label — `did~xxxx` (last 4 chars) is the compact
// form shown when a contact is DID-mediated but hasn't set a display name.
export function shortDid(did: string): string {
  return 'did~' + did.slice(-4)
}

// The full display-label fallback chain for a contact: (1) their
// self-asserted name if known, (2) a shortened DID if one is known but no
// name is, (3) the literal address — never the raw DID in full.
export function displayLabelFor(address: string): string {
  const name = nameForContact(address)
  if (name) return name
  const key = contactIdentityKey(address)
  if (key.startsWith('did:')) return shortDid(key)
  return address
}

// The contact's self-asserted display name (see document.ts's `name` field),
// if a locally-known Card for their DID has one. Purely a UX label — same
// trust level as any social profile's display name, never verified.
export function nameForContact(address: string): string | undefined {
  const key = contactIdentityKey(address)
  if (!key.startsWith('did:')) return undefined
  for (const card of contactsStore.all()) {
    if (Object.values(card.cryptoKeys ?? {}).some(k => k.uri === key)) return card.name?.full
  }
  return undefined
}
