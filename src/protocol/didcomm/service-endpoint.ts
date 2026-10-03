// Single owner of "which entry of a DID Document's DIDCommMessaging
// `serviceEndpoint` do I dial" (PLAN-tor.md D-4/D-5). A mediator with a Tor
// entrance publishes `serviceEndpoint` as a set (clearnet + onion) instead of
// one map; every sender -- the browser client, the mail bridge, the mail
// relay -- resolves it through here so they cannot diverge on which entry a
// recipient is reached at.

/** True when `url`'s host is a Tor v3 Hidden Service address (D-6). Never
 * throws; unparseable input is not an onion URL. */
export function isOnionUrl(url: string): boolean {
  try {
    return new URL(url).hostname.endsWith('.onion')
  } catch {
    return false
  }
}

type EndpointEntry = Record<string, unknown> & { uri: string }

function isEntry(value: unknown): value is EndpointEntry {
  return !!value && typeof value === 'object' && !Array.isArray(value) && typeof (value as { uri?: unknown }).uri === 'string'
}

/**
 * Picks the one `{uri, accept, routingKeys}` entry to dial.
 *
 * - a single map (the pre-Tor shape, I-5) is returned unchanged;
 * - a set returns the canonical (clearnet) entry, or the onion entry when
 *   `preferOnion` and one is published for the SAME mediator (identical
 *   `routingKeys`; an onion entry naming different routing keys is a
 *   different mediator and is never used);
 * - a set without a clearnet entry is rejected (D-4: onion-only is never
 *   published), as is any malformed element.
 */
export function selectDidCommEndpoint(serviceEndpoint: unknown, preferOnion = false): EndpointEntry | undefined {
  if (!Array.isArray(serviceEndpoint)) return isEntry(serviceEndpoint) ? serviceEndpoint : undefined
  if (!serviceEndpoint.length || !serviceEndpoint.every(isEntry)) return undefined
  const canonical = serviceEndpoint.find(entry => !isOnionUrl(entry.uri))
  if (!canonical) return undefined
  if (!preferOnion) return canonical
  const onion = serviceEndpoint.find(entry => isOnionUrl(entry.uri))
  return onion && JSON.stringify(onion.routingKeys ?? null) === JSON.stringify(canonical.routingKeys ?? null) ? onion : canonical
}
