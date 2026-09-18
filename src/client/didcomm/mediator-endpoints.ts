// Single owner of "what are this mediator's entrances" (PLAN-tor.md Phase 0/
// D-4/D-5/D-6) -- the canonical (clearnet) URI that is embedded in every
// derived did:peer (D-1/D-2) never changes, but a mediator may additionally
// publish a Tor v3 Hidden Service entrance for the SAME queue. Every place
// that needs to reason about "is this the same mediator" (sameMediatorUrl's
// aliases) or "which entrance do I dial" reads it from here, so the
// clearnet/onion pairing lives in exactly one place instead of being
// re-derived ad hoc at each call site.

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
 * `sameMediatorUrl`'s `aliases` parameter (mediator-watch.ts) -- a message
 * that names any of these is the same mediator as one that names another. */
export function mediatorAliases(endpoints: MediatorEndpoints): string[] {
  return endpoints.onionUrl ? [endpoints.canonicalUrl, endpoints.onionUrl] : [endpoints.canonicalUrl]
}

/** True when `url`'s host is a Tor v3 Hidden Service address. This is the
 * ONLY signal this plan uses to decide "is this entrance Tor" (D-6) --
 * never Tor Browser fingerprinting (I-6). Unparseable input is not an
 * onion URL (never throws). */
export function isOnionUrl(url: string): boolean {
  try {
    return new URL(url).hostname.endsWith('.onion')
  } catch {
    return false
  }
}

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
