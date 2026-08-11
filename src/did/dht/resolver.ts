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
import { recentlyMissed, noteMiss, clearMissesFor, dhtDocumentMissKey } from '../negcache.ts'

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
// Per-gateway outcome, kept internal to this module — 'found'/'absent' are
// both a REAL answer (the gateway was reached and definitively knows this DID
// has/hasn't got a record); 'unknown' covers everything else a caller must
// not read as a real answer: a network/CORS failure, a timeout, or ANY
// non-404 error status (429 rate-limited, 5xx, etc). A 429 in particular
// looks superficially like "the gateway answered" but it explicitly refused
// to check — collapsing it into the same bucket as a real 404 is exactly the
// bug resolveConfirmedAbsent below exists to avoid.
type GatewayOutcome =
  | { status: 'found'; payload: ParsedPayload }
  | { status: 'absent' }
  | { status: 'unknown' }

// A hard ceiling on ONE gateway's answer. Not a latency target — the racing
// resolve below already stops waiting for a slow gateway the moment a faster
// one answers — but a stop on a request that will never come back at all.
// Nothing here had a timeout of any kind: a hung gateway held a resolve (and,
// through it, a send or a poll cycle) for the browser's own default, which is
// minutes. Generous on purpose, because a cold Kademlia lookup legitimately
// takes seconds and cutting a real answer short would be worse than waiting.
const GATEWAY_TIMEOUT_MS = 8_000

/** One gateway's answer. Never throws: every failure mode collapses into
 * 'unknown', which is what the callers must treat as "we couldn't ask". */
async function fetchGateway(gw: string, suffix: string, pubkey: Uint8Array): Promise<GatewayOutcome> {
  try {
    const resp = await fetch(`${trim(gw)}/${suffix}`, {
      headers: { Accept: 'application/octet-stream' },
      signal: AbortSignal.timeout(GATEWAY_TIMEOUT_MS),
    })
    if (resp.status === 404) return { status: 'absent' }
    if (!resp.ok) return { status: 'unknown' }
    const payload = new Uint8Array(await resp.arrayBuffer())
    try { return { status: 'found', payload: parseSignedPayload(pubkey, payload) } }
    catch { return { status: 'unknown' } } // bad signature / corrupt payload — not trustworthy either way
  } catch {
    return { status: 'unknown' } // network, CORS, or the timeout above
  }
}

async function resolveViaDetailed(did: string, gatewayUrls: string[]): Promise<{ payload: ParsedPayload | null; outcomes: GatewayOutcome[] }> {
  const pubkey = identityKeyFromDid(did)
  const suffix = suffixOf(did)
  const outcomes = await Promise.all(gatewayUrls.map(gw => fetchGateway(gw, suffix, pubkey)))
  let best: ParsedPayload | null = null
  for (const o of outcomes) {
    if (o.status !== 'found') continue
    if (!best || o.payload.seq > best.seq) best = o.payload
  }
  return { payload: best, outcomes }
}

/** Resolve across every gateway in parallel and return THE FIRST REAL ANSWER,
 * without waiting for the rest.
 *
 * The all-gateways-then-pick-max version this replaces was parallel but
 * `await`ed every gateway, so a resolve cost the SLOWEST one however fast the
 * others were — and measured against production, a Pkarr gateway takes 3-6.5s
 * whenever the record isn't in its own read cache. One lagging gateway
 * therefore set the latency of every send and every poll cycle, which is
 * precisely the "sometimes instant, sometimes a long wait" the timings showed:
 * a hit inside the caches is tens of milliseconds, a miss on any one gateway
 * is seconds, and the max was always what got paid.
 *
 * Max-seq is not abandoned, just moved off the critical path: the losing
 * gateways keep running, and if one of them turns out to hold a STRICTLY
 * NEWER record than the one already returned, `onLater` is called with it so
 * the caller can refresh its cache. The next resolve then gets the newer
 * document. Freshness converges one lookup later instead of costing every
 * lookup the slowest gateway.
 *
 * A record whose seq is below this DID's known floor is not a real answer at
 * all — it is the rollback the freshness rule exists to reject (DID.md) — so
 * it never wins the race, and the remaining gateways are still awaited. That
 * keeps a stale-serving fast gateway from turning "someone else has the fresh
 * record" into "no record".
 */
function resolveViaFastest(
  did: string, gatewayUrls: string[], onLater?: (payload: ParsedPayload) => void,
): Promise<ParsedPayload | null> {
  const pubkey = identityKeyFromDid(did)
  const suffix = suffixOf(did)
  const floor = seenSeq(did)
  return new Promise<ParsedPayload | null>(resolve => {
    if (gatewayUrls.length === 0) { resolve(null); return }
    let settled = false
    let best: ParsedPayload | null = null
    let pending = gatewayUrls.length
    const finish = (p: ParsedPayload | null) => { if (!settled) { settled = true; resolve(p) } }
    for (const gw of gatewayUrls) {
      void fetchGateway(gw, suffix, pubkey).then(o => {
        if (o.status === 'found' && o.payload.seq >= floor) {
          const newer = !best || o.payload.seq > best.seq
          if (newer) best = o.payload
          // Strictly newer than what the caller already got — tell it, so the
          // cache catches up without anyone having waited for this gateway.
          if (newer && settled) onLater?.(o.payload)
          finish(o.payload)
        }
      }).finally(() => {
        pending--
        // Nobody had a usable record: only now is "nothing" the real answer.
        if (pending === 0) finish(best)
      })
    }
  })
}

export async function resolveVia(did: string, gatewayUrls: string[]): Promise<ParsedPayload | null> {
  return resolveViaFastest(did, gatewayUrls)
}

// True only when every gateway that gave a real answer said 404, AND at
// least one gateway actually did (an empty/all-unreachable gateway list must
// never read as "confirmed absent" — that's just "we don't know"). Exists
// for exactly one caller: syncDevicePosition's brand-new-device slot
// assignment, which must never treat "couldn't check" (rate-limited, CORS-
// blocked, network down — all 'unknown') as equivalent to "genuinely nothing
// published yet" (all 'absent') — found live: a registration during a
// relay.pkarr.org 429/CORS spell defaulted a new device straight to slot #k1
// as if the identity had never published anything, silently colliding with
// (and displacing) another device's already-live #k1.
export async function resolveConfirmedAbsent(did: string, gatewayUrls: string[]): Promise<boolean> {
  const { outcomes } = await resolveViaDetailed(did, gatewayUrls)
  const definitive = outcomes.filter(o => o.status !== 'unknown')
  return definitive.length > 0 && definitive.every(o => o.status === 'absent')
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

// Coalesces concurrent resolves of the same DID over the same gateways into
// ONE lookup. They are routine, not exotic: pressing send fires the recipient
// resolve, the sibling-device fan-out resolves our own DID, the poll tick
// behind it resolves the sender of whatever just arrived, and a reply also
// kicks off a background contact refresh — all within the same second, all
// through here, and (before this) all paying for their own multi-second
// gateway round trip and adding their own load to the gateways that were
// already the bottleneck. The gateway list is part of the key because the
// own-first escalation below deliberately asks a WIDER set on its second
// round; those two are different questions and must not share an answer.
const inflight = new Map<string, Promise<DidDocument | null>>()

// Resolve with rollback protection: rejects a record whose seq is lower than the
// highest previously trusted for this DID (DID.md monotonicity check).
//
// Follows continuation records (chain.ts) transparently, so callers always
// get one logical document however many BEP44 records it actually spans.
// Each link is verified against the key its own DID names, exactly like the
// root — a gateway can withhold a link, never forge one. A missing/corrupt
// link degrades to the services resolved so far rather than failing the
// whole resolve: a partial relay list still beats an unresolvable identity.
export function resolve(did: string, gatewayUrls: string[], opts?: { skipCache?: boolean }): Promise<DidDocument | null> {
  const cached = resolveCache.get(did)
  if (!opts?.skipCache && cached && Date.now() - cached.at < RESOLVE_CACHE_TTL_MS) return Promise.resolve(cached.doc)

  const key = `${opts?.skipCache ? 'fresh' : 'cached'}|${did}|${gatewayUrls.join(',')}`
  const running = inflight.get(key)
  if (running) return running

  const p = resolveUncoalesced(did, gatewayUrls).finally(() => { inflight.delete(key) })
  inflight.set(key, p)
  return p
}

async function resolveUncoalesced(did: string, gatewayUrls: string[]): Promise<DidDocument | null> {
  requireSeqStore() // up front: a lookup that finds nothing must still surface a missing store
  const r = await resolveViaFastest(did, gatewayUrls, later => {
    // A slower gateway held a newer record than the one this call returned.
    // Finish the same assembly for it in the background and leave the result
    // in the cache, so the next resolve gets the fresher document without any
    // call ever having waited for that gateway.
    void buildDocument(did, later, gatewayUrls)
      .then(doc => { if (doc) resolveCache.set(did, { doc, at: Date.now() }) })
      .catch(() => {})
  })
  if (!r) return null
  const doc = await buildDocument(did, r, gatewayUrls)
  if (!doc) return null
  resolveCache.set(did, { doc, at: Date.now() })
  return doc
}

/** Turns one verified root payload into the logical document: records the new
 * freshness floor, then follows continuation records (chain.ts) so callers
 * always get one document however many BEP44 records it spans. Null when the
 * payload is a rollback the freshness rule refuses. */
async function buildDocument(did: string, r: ParsedPayload, gatewayUrls: string[]): Promise<DidDocument | null> {
  if (!noteSeq(did, r.seq)) return null // rollback attempt — refuse the stale record
  if (!r.document.ext) return r.document
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
  return mergeChain(r.document, continuations)
}

// Own-gateway-first resolve: query only `ownGatewayUrls` (this deployment's
// own relays/anchor) first, and only escalate to PUBLIC_PKARR_FALLBACKS when
// that comes back empty. Every caller used to flat-merge own+public and
// query both in parallel on EVERY resolve — fine for a rare call, but
// resolve() is the highest-volume gateway consumer in the app (every message
// send, every poll tick, every contact refresh), and constantly hitting
// relay.pkarr.org/pkarr.pubky.org at that rate is what tripped their rate
// limit this session, not just the rarer registration/publish paths. Own
// gateways answer the ordinary case; public fallbacks become a genuine last
// resort instead of continuous background load on someone else's free
// infrastructure — worth doing before this deployment has 100s-1000s of
// users generating that traffic instead of one browser's test session.
export async function resolveOwnFirst(
  did: string, ownGatewayUrls: string[],
  opts?: { skipCache?: boolean; fallbackGatewayUrls?: string[] },
): Promise<DidDocument | null> {
  // Both rounds missing is the single most expensive outcome in the whole
  // resolve path — every gateway in both lists runs to completion, ~13s
  // measured — and it is also the one nothing remembered. negcache.ts caps
  // how often that price is paid for the same DID in the same breath; see its
  // own note on why the TTL is only seconds.
  const negKey = dhtDocumentMissKey(did)
  if (!opts?.skipCache && recentlyMissed(negKey)) return null
  const doc = await resolve(did, ownGatewayUrls, opts)
  if (doc) return doc
  const full = await resolve(did, [...ownGatewayUrls, ...(opts?.fallbackGatewayUrls ?? PUBLIC_PKARR_FALLBACKS)], opts)
  if (!full) noteMiss(negKey)
  return full
}

// Publish a signed document to a gateway (PUT /{suffix} with the raw payload).
/** A gateway's answer to one PUT. `reason` carries the gateway's OWN words on
 * failure — biset's anchor answers 400 with the actual cause in the body
 * ("pkarr: put timed out", "pkarr: DNS packet exceeds 1000 bytes",
 * "pkarr: invalid signature"), which are three completely different problems
 * with three different fixes. Collapsing them into a bare false is what left
 * a user staring at "no gateway accepted continuation record <did>" with no
 * way to tell a flaky DHT put from a document that will never fit. */
export interface PublishAttempt { ok: boolean; reason?: string }

// Returns ok on 2xx. Callers publish to every gateway (their relays) so the
// record is redundantly kept alive — see DID.md republish rules.
export async function publishTo(gatewayUrl: string, did: string, payload: Uint8Array): Promise<PublishAttempt> {
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
    if (resp.ok) return { ok: true }
    const body = await resp.text().catch(() => '')
    return { ok: false, reason: `${host(gatewayUrl)}: HTTP ${resp.status}${body ? ` ${body.slice(0, 120)}` : ''}` }
  } catch (e) {
    return { ok: false, reason: `${host(gatewayUrl)}: ${e instanceof Error ? e.message : String(e)}` }
  }
}

/** Gateway hostname for an error line — the full URL repeated per gateway
 * turns one readable sentence into an unreadable wall. */
function host(gatewayUrl: string): string {
  try { return new URL(gatewayUrl).host } catch { return gatewayUrl }
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

/** How many times a link's publish is attempted before giving up, and how long
 * to wait between tries.
 *
 * A DHT put is not a database write: the gateway forwards it into mainline and
 * waits for enough nodes to acknowledge, so it fails for reasons that are gone
 * a few seconds later (pkarr.ts's own PUT_TIMEOUT_MS, a node that stopped
 * answering mid-traversal). One attempt was the whole policy, and on the
 * continuation link that failure is fatal to the entire publish — user-caught
 * 2026-08-05: removing a dead device key kept dying on
 * "no gateway accepted continuation record", while the same anchor was
 * accepting PUTs for that very key seconds before and after. The retry costs
 * nothing when the first attempt works, which is the normal case. */
const PUBLISH_ATTEMPTS = 3
const PUBLISH_RETRY_MS = 1_500

/** One link, published to every gateway, retried as a whole. Each attempt
 * re-signs with a FRESH seq (nextSafeSeq) rather than reusing the first one:
 * a gateway that did accept the earlier attempt now holds that seq, and BEP44
 * requires a strictly greater one, so a verbatim resend would be refused by
 * exactly the gateways that were working. */
async function publishLink(
  did: string, privateKey: Uint8Array, doc: DidDocument, gatewayUrls: string[],
): Promise<{ accepted: number; reasons: string[] }> {
  let reasons: string[] = []
  for (let attempt = 1; attempt <= PUBLISH_ATTEMPTS; attempt++) {
    const seq = nextSafeSeq(did)
    const payload = buildSignedPayload(privateKey, doc, seq)
    const results = await Promise.all(gatewayUrls.map(gw => publishTo(gw, did, payload)))
    const accepted = results.filter(r => r.ok).length
    if (accepted > 0) {
      noteSeq(did, seq)
      return { accepted, reasons: [] }
    }
    reasons = results.map(r => r.reason ?? 'unknown').filter((r, i, a) => a.indexOf(r) === i)
    if (attempt >= PUBLISH_ATTEMPTS) break
    // Re-read what's actually out there before trying again, and raise this
    // browser's floor to it. The dominant cause of a whole-round rejection is
    // a seq that isn't strictly greater than what the network already holds
    // (BEP44's compare-and-set — mainline answers it fast, which is why these
    // failures come back in a fraction of a second rather than timing out),
    // and one identity commonly has several publishers: two of the user's own
    // browsers plus the relay's own republisher, all deriving a seq from a
    // one-second clock. Without this, a retry recomputes the SAME number from
    // the same clock and loses to the same holder; with it, the next attempt
    // is `whatever is live + 1` and converges.
    // Every gateway, not the fastest one: this is asking "what is the HIGHEST
    // seq anyone out there already holds", and a fast gateway serving an older
    // record would answer with a floor that loses to the same holder again.
    // The one place where waiting for the slow gateway is the point.
    const current = await resolveViaDetailed(did, gatewayUrls).then(r => r.payload).catch(() => null)
    if (current) noteSeq(did, current.seq)
    await new Promise(r => setTimeout(r, PUBLISH_RETRY_MS))
  }
  return { accepted: 0, reasons }
}

export async function publishDocument(rootPrivateKey: Uint8Array, doc: DidDocument, gatewayUrls: string[]): Promise<number> {
  const links = splitIntoChain(rootPrivateKey, doc)
  // Whatever this browser knows about this DID is now definitively out of
  // date, including any "not published" it may have just recorded — in every
  // namespace, since the same identity is also looked up through the
  // DIDComm-shaped resolver (see negcache.ts's clearMissesFor).
  resolveCache.delete(doc.id)
  clearMissesFor(doc.id)

  // Continuations first: the root's `ext=` pointer must never be live before
  // the record it points at is.
  for (const link of links.slice(1).reverse()) {
    const { accepted, reasons } = await publishLink(link.did, link.privateKey, link.doc, gatewayUrls)
    // The gateways' own words, not just the count — this is the error a person
    // actually reads when a device removal or a republish refuses to go
    // through, and "no gateway accepted" alone told them nothing about which
    // gateway said what, or whether waiting would help.
    if (accepted === 0) throw new Error(`publishDocument: no gateway accepted continuation record ${link.did} — ${reasons.join('; ')}`)
  }

  const root = links[0]!
  const { accepted, reasons } = await publishLink(root.did, root.privateKey, root.doc, gatewayUrls)
  // Returning 0 stays the contract for the root (a routine best-effort
  // republish must not throw), but the reasons must not evaporate with it —
  // every caller that DOES treat 0 as fatal (a device removal, the Republish
  // button) can only report the count, so without this the cause exists
  // nowhere at all.
  if (accepted === 0) console.warn(`[did/publish] no gateway accepted ${root.did} — ${reasons.join('; ')}`)
  return accepted
}
