// Single owner of "what are this mediator's entrances" (PLAN-tor.md Phase 0/
// D-4/D-5/D-6) -- the canonical (clearnet) URI that is embedded in every
// derived did:peer (D-1/D-2) never changes, but a mediator may additionally
// publish a Tor v3 Hidden Service entrance for the SAME queue. Every place
// that needs to reason about "is this the same mediator" (sameMediatorUrl's
// aliases) or "which entrance do I dial" reads it from here, so the
// clearnet/onion pairing lives in exactly one place instead of being
// re-derived ad hoc at each call site.
import { isOnionUrl } from '../../protocol/didcomm/service-endpoint.ts'

/** One mediator's entrances. `canonicalUrl` is the clearnet URI baked into
 * the mediator's own did:peer and into every relationship peer derived
 * against it (PLAN-tor.md D-1/D-2) -- it never varies by transport.
 * `onionUrl`, if present, is an additional entrance into the SAME queue;
 * its absence is the pre-Tor, clearnet-only shape (I-5). */
export interface MediatorEndpoints {
  canonicalUrl: string
  onionUrl?: string
}

/** All URIs naming this one mediator, canonical first. Feeds
 * `sameMediatorUrl`'s `aliases` parameter (below) -- a message
 * that names any of these is the same mediator as one that names another. */
export function mediatorAliases(endpoints: MediatorEndpoints): string[] {
  return endpoints.onionUrl ? [endpoints.canonicalUrl, endpoints.onionUrl] : [endpoints.canonicalUrl]
}

export { isOnionUrl }

/**
 * Picks which entrance a sender should dial (D-5): a non-Tor environment
 * always gets the canonical URI -- `.onion` is never even attempted, so a
 * plain browser never issues a DNS lookup that can only fail (I-3). A Tor
 * environment prefers the onion entrance when this mediator publishes one,
 * and otherwise falls back to canonical (D-4 requires every mediator to
 * keep publishing clearnet, so this fallback always resolves).
 *
 * `torReachable` is never fingerprinting-derived (I-6): callers set it from
 * the one fact this plan trusts -- whether a `.onion` registration attempt
 * with this mediator already succeeded in this session (D-6, 3-2).
 */
export function preferredMediatorUrl(endpoints: MediatorEndpoints, torReachable: boolean): string {
  if (torReachable && endpoints.onionUrl) return endpoints.onionUrl
  return endpoints.canonicalUrl
}

/**
 * True when this page itself is being served from a Tor v3 Hidden Service
 * (D-6, 3-2) -- the ONLY signal this plan trusts to decide "am I in a Tor
 * environment", so a plain browser on the ordinary clearnet origin never
 * even attempts a `.onion` fetch (I-3) and no Tor Browser fingerprinting
 * (User-Agent, screen size, timezone, ...) is ever consulted (I-6).
 *
 * Until biset's own app is additionally served over an onion address, this
 * is always false and every session behaves exactly as before (I-5) --
 * accepting Tor Browser *visitors of the mediator* without them dialing in
 * from an onion biset front end is a later increment, not this plan's v1.
 */
export function isTorEnvironment(hostname: string = safeLocationHostname()): boolean {
  return isOnionUrl(`http://${hostname}`)
}

function safeLocationHostname(): string {
  try {
    return location.hostname
  } catch {
    return ''
  }
}

/**
 * True when two spellings name the same mediator endpoint.
 *
 * A delivery handler has to check that the mediator a relationship message
 * names in its own did:peer service (relationship.ts's
 * relationshipMediatorService) really is the mediator the message arrived
 * from -- but the two strings reach that check from different places: one
 * was minted into a did:peer document by the peer, the other comes from
 * this device's own `mediatorUrls` config. A raw `!==` therefore rejects a
 * perfectly matching pair over nothing but a trailing slash or a default
 * port, so compare the parsed URLs instead. An unparseable spelling is not
 * a match (never throws -- the caller's own "does not match" branch is the
 * right answer for a URL that is not a URL).
 */
export function sameMediatorUrl(a: string, b: string, aliases: readonly string[] = []): boolean {
  try {
    const first = new URL(a).toString()
    const second = new URL(b).toString()
    if (first === second) return true
    // One trusted mediator's entrances, never a flattened list of unrelated
    // mediators or URLs taken from the incoming relationship message.
    const normalized = aliases.map(alias => new URL(alias).toString())
    return normalized.includes(first) && normalized.includes(second)
  } catch {
    return false
  }
}
