// A short-lived memory of "this lookup came back with nothing".
//
// Every DID resolve that finds no record costs a FULL gateway round trip —
// measured against production: 3-6.5s per gateway for a miss, because a Pkarr
// gateway can only answer "no" by finishing an iterative Kademlia lookup that
// never converges on a record. Nothing caches that: dht/resolver.ts's
// resolveCache stores successes only (deliberately — a withheld record must
// retry immediately rather than being stuck for a TTL), and the anchor's own
// read cache stores payloads, of which a miss has none.
//
// So an identity that genuinely isn't published — a contact who never
// registered a device, a DID typed with a typo, a record that hasn't
// propagated yet — was re-looked-up at full price on every send, every poll
// tick and every contact refresh, forever. The own-then-public escalation
// doubles it (dht/resolver.ts's resolveOwnFirst, didcomm/channel.ts's
// resolveDocOwnFirst): both rounds miss, so one logical resolve costs ~13s.
//
// The TTL is deliberately tiny. This is not "remember that this DID doesn't
// exist" — it is "don't ask again in the same breath", which is the actual
// pattern (a send, its sibling fan-out and the poll tick behind it all
// resolving the same DID within a second or two of each other). Anything
// longer would delay a brand-new registration becoming visible, which is
// exactly the case a chat app must not get wrong.
const NEG_TTL_MS = 5_000

// Bounds the map without a sweep timer: entries are evicted oldest-first (a
// Map iterates in insertion order) once the cap is passed.
const NEG_MAX = 500

const misses = new Map<string, number>()

/** True when this exact lookup missed within the TTL — the caller should
 * report "nothing" straight away instead of paying for the round trip again. */
export function recentlyMissed(key: string): boolean {
  const at = misses.get(key)
  if (at === undefined) return false
  if (Date.now() - at >= NEG_TTL_MS) { misses.delete(key); return false }
  return true
}

/** Records that this lookup found nothing. Only for a COMPLETED lookup that
 * genuinely came back empty — never for one that failed in a way the caller
 * couldn't distinguish from "we couldn't ask", which must always retry. */
export function noteMiss(key: string): void {
  misses.delete(key)
  misses.set(key, Date.now())
  if (misses.size > NEG_MAX) {
    const oldest = misses.keys().next().value
    if (oldest !== undefined) misses.delete(oldest)
  }
}

// Every namespace that records misses, declared here rather than as string
// literals at each call site: one DID is looked up through two different
// shapes (dht/resolver.ts's raw document, didcomm/channel.ts's DIDComm-shaped
// one), and "publishing invalidates what we knew about this DID" has to reach
// both of them. Spelling the prefixes at the call sites is how it would end up
// reaching only one.
const missKeys = {
  dhtDocument: (did: string) => `dht|${did}`,
  didcommDocument: (did: string) => `didcommdoc|${did}`,
}

export const dhtDocumentMissKey = missKeys.dhtDocument
export const didcommDocumentMissKey = missKeys.didcommDocument

/** Forgets every recorded miss for a DID — for when something happened that
 * could plausibly have created the record, which in practice means this device
 * just published it. A brand-new identity publishing its very first document
 * is exactly the case that must not then be told "nothing there" by a cache of
 * its own making. */
export function clearMissesFor(did: string): void {
  for (const key of Object.values(missKeys)) misses.delete(key(did))
}
