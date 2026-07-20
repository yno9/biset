// DID resolution + publication over Pkarr-relay-format gateways (DID.md: "the
// only method-abstraction — every caller goes through resolve()"). Browsers
// can't speak the DHT directly, so all reads/writes go through an HTTP gateway
// (biset uses its own account's relays as gateways — see DID.md Roles). The
// gateway can withhold or serve a stale record, never forge one: the payload
// signature is verified against the identity key the DID itself names.
import { zbase32Decode } from './zbase32.ts'
import { parseSignedPayload, buildSignedPayload, nowSeq, type ParsedPayload } from './packet.ts'
import { suffixOf, type DidDocument } from './document.ts'
import { splitIntoChain, mergeChain, MAX_CHAIN } from './chain.ts'
import { noteSeq, seenSeq, requireSeqStore } from './freshness.ts'

export type { DidDocument, DidService } from './document.ts'

const ED25519_PUBKEY_LEN = 32

// Public Pkarr relays as a last-resort fallback when an identity's own relays
// are unreachable (DID.md: hardcoded fallback only, never the primary path —
// resolving through a stranger's relay leaks who-looks-up-whom). Callers append
// these after the account's own relay gateways.
export const PUBLIC_PKARR_FALLBACKS = [
  'https://relay.pkarr.org',
  'https://pkarr.pubky.org',
]

// The identity public key is the DID suffix itself (z-base-32 of the pubkey), so
// it needs no network to recover — and it's exactly what the payload signature
// must verify against.
export function identityKeyFromDid(did: string): Uint8Array {
  return zbase32Decode(suffixOf(did), ED25519_PUBKEY_LEN)
}

function trim(u: string): string { return u.replace(/\/$/, '') }

// Resolve a DID across all gateways and keep the highest-seq signature-valid
// payload — a lagging gateway must not win over a fresher one. Signature is
// verified against the key the DID itself names, so a gateway cannot forge; the
// worst it can do is withhold or serve stale, which max-seq + freshness defeat.
//
// Queried in PARALLEL, not one gateway at a time: a caller's list now
// routinely carries 3-4 entries (own relay + own mediator's token-gated
// pkarr + 2 public fallbacks — see channel.ts/discovery.ts's ownGateways),
// and one of those (a real DHT gateway, not a cache) can legitimately take
// several seconds. Querying sequentially meant every SLOW gateway's full
// latency stacked onto every resolve, however many faster ones would have
// answered first — the resolve got proportionally slower every time another
// gateway was added to the list, not just occasionally slow when one happened
// to lag.
export async function resolveVia(did: string, gatewayUrls: string[]): Promise<ParsedPayload | null> {
  const pubkey = identityKeyFromDid(did)
  const suffix = suffixOf(did)
  const results = await Promise.allSettled(gatewayUrls.map(async gw => {
    const resp = await fetch(`${trim(gw)}/${suffix}`, { headers: { Accept: 'application/octet-stream' } })
    if (!resp.ok) throw new Error(`gateway returned ${resp.status}`)
    const payload = new Uint8Array(await resp.arrayBuffer())
    return parseSignedPayload(pubkey, payload) // throws on bad signature → this gateway's result is dropped
  }))
  let best: ParsedPayload | null = null
  for (const r of results) {
    if (r.status !== 'fulfilled') continue
    if (!best || r.value.seq > best.seq) best = r.value
  }
  return best
}

// Every gateway in a caller's list is either this browser's own relay (fast,
// local network) or a real DHT gateway/fallback — the latter routinely takes
// several seconds per COLD lookup (resolveVia's own note). A send resolves
// its recipient fresh every time, and a poll cycle re-resolves every
// delivered message's sender fresh every time — the same identity, over and
// over, within a single chat session. Short-TTL so a real change (a relay
// added, a display name edited) still shows up within a session rather than
// needing a reload; only successful resolves are cached, so a withheld/failed
// lookup always retries immediately rather than being stuck for the TTL.
const resolveCache = new Map<string, { doc: DidDocument; at: number }>()
const RESOLVE_CACHE_TTL_MS = 60_000

// Resolve with rollback protection: rejects a record whose seq is lower than the
// highest previously trusted for this DID (DID.md monotonicity check).
//
// Follows continuation records (chain.ts) transparently, so callers always
// get one logical document however many BEP44 records it actually spans.
// Each link is verified against the key its own DID names, exactly like the
// root — a gateway can withhold a link, never forge one. A missing/corrupt
// link degrades to the services resolved so far rather than failing the
// whole resolve: a partial relay list still beats an unresolvable identity.
export async function resolve(did: string, gatewayUrls: string[]): Promise<DidDocument | null> {
  const cached = resolveCache.get(did)
  if (cached && Date.now() - cached.at < RESOLVE_CACHE_TTL_MS) return cached.doc

  requireSeqStore() // up front: a lookup that finds nothing must still surface a missing store
  const r = await resolveVia(did, gatewayUrls)
  if (!r) return null
  if (!noteSeq(did, r.seq)) return null // rollback attempt — refuse the stale record

  let doc: DidDocument
  if (!r.document.ext) {
    doc = r.document
  } else {
    const continuations: DidDocument[] = []
    const seen = new Set<string>([suffixOf(did)])
    let next: string | undefined = r.document.ext
    while (next && continuations.length < MAX_CHAIN) {
      if (seen.has(next)) break // a chain that points back at itself — stop rather than loop
      seen.add(next)
      const link: ParsedPayload | null = await resolveVia(`did:dht:${next}`, gatewayUrls)
      if (!link) break // withheld or expired link — keep what we have
      continuations.push(link.document)
      next = link.document.ext
    }
    doc = mergeChain(r.document, continuations)
  }
  resolveCache.set(did, { doc, at: Date.now() })
  return doc
}

// Publish a signed document to a gateway (PUT /{suffix} with the raw payload).
// Returns true on 2xx. Callers publish to every gateway (their relays) so the
// record is redundantly kept alive — see DID.md republish rules.
export async function publishTo(gatewayUrl: string, did: string, payload: Uint8Array): Promise<boolean> {
  const url = `${trim(gatewayUrl)}/${suffixOf(did)}`
  // Uint8Array is a valid fetch body in both the DOM and the anchor's DOM-free
  // lib; the two disagree only on the type name (BodyInit), so erase it.
  const put = (ifUnmodifiedSince?: string) => fetch(url, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/octet-stream', ...(ifUnmodifiedSince ? { 'If-Unmodified-Since': ifUnmodifiedSince } : {}) },
    body: payload as any,
  })
  try {
    let resp = await put()
    if (resp.status === 428) {
      // pubky-style relays (relay.pkarr.org) refuse to REPLACE an existing
      // record without a conditional write — a lost-update guard. The first
      // publish of a key succeeds; every update 428s until it carries the
      // record's current Last-Modified back as If-Unmodified-Since. Read it and
      // retry once. (biset's own relay /pkarr proxies straight to a DHT node and
      // never does this, so only the relay-less public-gateway path hits it.)
      const current = await fetch(url, { headers: { Accept: 'application/octet-stream' } })
      const lastModified = current.headers.get('Last-Modified')
      if (lastModified) resp = await put(lastModified)
    }
    return resp.ok
  } catch { return false }
}

// Convenience: build + sign a document and publish it to every gateway. Fired
// in parallel — a DHT PUT takes several seconds per gateway (mainline DHT
// traversal latency, not something we control), so publishing to N gateways
// sequentially took N times as long for no benefit (each PUT is independent).
//
// Splits into continuation records (chain.ts) when the document outgrows
// BEP44's 1000-byte cap; a document that fits publishes exactly as before,
// as a single record. Returns how many gateways accepted the ROOT record —
// the root is what makes the identity resolvable at all, so a link that
// failed everywhere is reported by throwing rather than by a lower count
// (silently publishing a root whose chain is broken would advertise relays
// nobody can reach).
// nowSeq() alone is only 1-second resolution — several publishes of the same
// DID within one second (e.g. deleting several device keys back to back,
// left-pane.ts's device list) would otherwise reuse the same seq. BEP44
// requires each write to strictly exceed what a node already has, so the
// second write is silently rejected everywhere the first one already landed
// — and since a caller here never learns that (only a fully-failed root
// publish is surfaced, see below), it looks like it worked while the
// document never actually changed. seenSeq(did) is this browser's own
// floor — bumped by every resolve AND now by every accepted publish — so
// consecutive writes strictly increase even inside the same wall-clock
// second, without needing every gateway to agree on the current value.
function nextSafeSeq(did: string): number {
  return Math.max(seenSeq(did) + 1, nowSeq())
}

export async function publishDocument(rootPrivateKey: Uint8Array, doc: DidDocument, gatewayUrls: string[]): Promise<number> {
  const links = splitIntoChain(rootPrivateKey, doc)

  // Continuations first: the root's `ext=` pointer must never be live before
  // the record it points at is.
  for (const link of links.slice(1).reverse()) {
    const seq = nextSafeSeq(link.did)
    const payload = buildSignedPayload(link.privateKey, link.doc, seq)
    const accepted = await Promise.all(gatewayUrls.map(gw => publishTo(gw, link.did, payload)))
    if (!accepted.some(Boolean)) throw new Error(`publishDocument: no gateway accepted continuation record ${link.did}`)
    noteSeq(link.did, seq)
  }

  const root = links[0]!
  const seq = nextSafeSeq(root.did)
  const payload = buildSignedPayload(root.privateKey, root.doc, seq)
  const results = await Promise.all(gatewayUrls.map(gw => publishTo(gw, root.did, payload)))
  const accepted = results.filter(Boolean).length
  if (accepted > 0) noteSeq(root.did, seq)
  return accepted
}
