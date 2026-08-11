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
import { stableIdKey, isDidIdentityKey } from './idkey.ts'
import { bisetWebvhUsername } from './webvh/identifier.ts'

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
    // Derived from the STABLE key, not the raw DID string (PLANWEBVH.md
    // §3.1): a correspondent who moves their did:webvh to another domain
    // keeps the same Card rather than getting a second one under a new uid,
    // and every reference to them (inbox grouping, message filtering) keeps
    // resolving. `cryptoKeys` below still records the full CURRENT DID —
    // that's the value the wire needs, and the reverse lookup
    // currentDidForKey reads.
    uid: `urn:uuid:${uuidv5(stableIdKey(did))}`,
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
// it under `emails`, else the address itself — in both cases normalized
// through stableIdKey (did/idkey.ts, PLANWEBVH.md §3.1), so a correspondent
// who moves their did:webvh to another domain stays ONE contact instead of
// forking into a second one keyed on the new string. Identity-function for
// did:dht and for plain addresses.
//
// `address` may itself already be a raw DID (DIDComm conversations address
// the DID directly, never an email) — normalizing the fallback return covers
// that case, which is the common one for DIDComm.
export function contactIdentityKey(address: string): string {
  for (const card of contactsStore.all()) {
    if (Object.values(card.emails ?? {}).some(e => e.address === address)) {
      const did = Object.values(card.cryptoKeys ?? {})[0]?.uri
      if (did) return stableIdKey(did)
    }
  }
  return stableIdKey(address)
}

/** The reverse direction PLANWEBVH.md §3.1 makes mandatory: a stable key
 * cannot address anything on the wire, so anything holding one needs a way
 * back to the CURRENT full DID string. Returns the DID a locally-known Card
 * records for `key`, or undefined when no Card knows it. */
export function currentDidForKey(key: string): string | undefined {
  for (const card of contactsStore.all()) {
    for (const k of Object.values(card.cryptoKeys ?? {})) {
      if (stableIdKey(k.uri) === key) return k.uri
    }
  }
  return undefined
}

// The inverse of contactIdentityKey: every address grouped under `key` (all
// addresses on the Card whose DID matches, if `key` is one) — used to widen
// message filtering so a merged inbox row surfaces messages from every
// address the contact has used, not just the literal one a given row was
// keyed on.
function addressesForContactKey(key: string): string[] {
  if (isDidIdentityKey(key)) {
    for (const card of contactsStore.all()) {
      // Matched on the NORMALIZED uri: after a correspondent's domain move the
      // Card carries their new DID string while `key` is the move-invariant
      // one, so a raw `===` would stop finding the Card it just updated.
      if (Object.values(card.cryptoKeys ?? {}).some(k => stableIdKey(k.uri) === key)) {
        const addrs = Object.values(card.emails ?? {}).map(e => e.address)
        // `key` itself stays in the list, ALWAYS — a Card keeps the DID in
        // `cryptoKeys`, never in `emails` (buildCardForDid), so returning
        // only the Card's addresses silently DROPPED the DID. A DIDComm
        // message is addressed to the raw DID, so app.ts's getInboxEmails
        // (`contactAddrs.includes(emailContact)`, the only caller) then
        // filtered out every DIDComm message in the conversation — while
        // loadInboxSummaries, which doesn't go through here, still showed
        // the inbox row. Symptom: the row is listed with its preview, but
        // opening it shows an empty thread (2026-07-28, user-reported).
        // Only bites once discovery has actually resolved an address for
        // the peer's DID — before that this fell through to `[key]` and
        // happened to work, which is why didcomm-channel.test.ts (no Card)
        // stayed green throughout.
        if (addrs.length) return [key, ...addrs]
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
  const key = stableIdKey(did)
  for (const card of contactsStore.all()) {
    if (Object.values(card.cryptoKeys ?? {}).some(k => stableIdKey(k.uri) === key)) {
      return Object.values(card.emails ?? {})[0]?.address
    }
  }
  return undefined
}

// A DID is unreadable as a label — the compact form shown when a contact is
// DID-mediated but hasn't set a display name keeps the did:method: prefix
// plus just the first/last 3 chars of the identifier (did:dht:6oi…b7x): a
// stable, still-recognisable fingerprint, much more legible than truncating
// blind.
export function shortDid(did: string): string {
  const m = did.match(/^(did:[^:]+:)(.+)$/)
  if (!m) return did
  const id = m[2]!
  return id.length <= 6 ? did : `${m[1]}${id.slice(0, 3)}…${id.slice(-3)}`
}

// The one "how do I show this DID to a human" rule, for every caller that
// has a DID and no self-asserted name for it: a did:webvh identifier bakes
// the username in (identifier.ts's bisetWebvhUsername), so `alice` beats
// `did:webvh:QmZ…enn` and needs no resolve, no Card and nothing published —
// it reads the same identifier the peer is already addressed by. Everything
// else (did:dht/did:peer, whose identifiers are pure key material) falls
// back to the shortened form. Deliberately NOT folded into shortDid itself:
// that one is the "compact but still recognisably a DID" fingerprint the DID
// pill/tooltip want, which a username is not.
export function labelForDid(did: string): string {
  return bisetWebvhUsername(did) ?? shortDid(did)
}

// The full display-label fallback chain for a contact: (1) their
// self-asserted name if known, (2) labelForDid — a did:webvh username, else a
// shortened DID — if one is known but no name is, (3) the literal address —
// never the raw DID in full.
export function displayLabelFor(address: string): string {
  const name = nameForContact(address)
  if (name) return name
  const key = contactIdentityKey(address)
  if (!isDidIdentityKey(key)) return address
  // Labelled from the CURRENT full DID, never from the internal key: a
  // `webvh:{SCID}` stable key is not a DID string and shortDid would mangle
  // it into something that looks like a different method entirely. This is
  // the reverse lookup PLANWEBVH.md §3.1 requires — internal key in, real
  // identifier out, with `address` itself as the fallback when it already IS
  // the DID (the DIDComm case, before any Card exists).
  const did = currentDidForKey(key) ?? (address.startsWith('did:') ? address : undefined)
  return did ? labelForDid(did) : address
}

// Rebinds a locally-known contact Card from its old DID to a new one — the
// receiving side of DIDComm's from_prior rotation (didcomm/rotation.ts):
// verified proof that `oldDid` rotated to `newDid` (PLANWEBVH.md §5.2), so
// any Card still pointing at the old identifier should follow. biset's own
// identities were rotation-less until did:webvh's domain-move added a real
// EMIT path (webvh/publish.ts's moveDidToNewDomain) — this is what makes
// verifying the claim (already done in didcomm/channel.ts) actually mean
// something instead of being logged and discarded. Returns the updated Card,
// or null if no locally-known contact had the old DID — the caller persists
// it (this module has no vault dependency of its own, matching the rest of
// this file's pattern).
export function rebindContactDid(oldDid: string, newDid: string): Card | null {
  const oldKey = stableIdKey(oldDid)
  const newKey = stableIdKey(newDid)
  for (const card of contactsStore.all()) {
    const entries = Object.entries(card.cryptoKeys ?? {})
    // Matched on the normalized key so this still finds the Card when the
    // rebind is a REPEAT of one already applied (a peer re-sends from_prior
    // for the whole 30-day window, PLANWEBVH.md §5.1 — the Card's uri is the
    // new string by then, but its key is unchanged, so the second call is a
    // correct no-op rather than a miss).
    if (!entries.some(([, v]) => stableIdKey(v.uri) === oldKey)) continue
    const updated: Card = {
      ...card,
      // A did:webvh domain move keeps the SCID, so uid (derived from the
      // stable key, buildCardForDid) is unchanged and this is an in-place
      // update. It only shifts for a rotation that genuinely changes the
      // self-certifying part — a different identity by §3.1's definition,
      // which must not be left addressable under the old uid as well.
      uid: newKey === oldKey ? card.uid : `urn:uuid:${uuidv5(newKey)}`,
      cryptoKeys: Object.fromEntries(entries.map(([k, v]) => [k, stableIdKey(v.uri) === oldKey ? { uri: newDid } : v])),
    }
    if (newKey !== oldKey) contactsStore.remove(card.uid)
    contactsStore.put(updated)
    return updated
  }
  return null
}

// The contact's self-asserted display name (see document.ts's `name` field),
// if a locally-known Card for their DID has one. Purely a UX label — same
// trust level as any social profile's display name, never verified.
export function nameForContact(address: string): string | undefined {
  const key = contactIdentityKey(address)
  if (!isDidIdentityKey(key)) return undefined
  for (const card of contactsStore.all()) {
    if (Object.values(card.cryptoKeys ?? {}).some(k => stableIdKey(k.uri) === key)) return card.name?.full
  }
  return undefined
}
