// did:vh identifier: `did:vh:<SCID>` and nothing else (didvh-spec: Method-Specific Identifier). No host, no path:
// where the log is published is not part of the DID, so a DID string never changes when the log moves.
const SCID_RE = /^[1-9A-HJ-NP-Za-km-z]{46}$/ // a SHA-256 multihash in base58btc: 34 bytes, 46 characters

export const VH_METHOD = 'did:vh:1.0'

export function isScid(value: unknown): value is string {
  return typeof value === 'string' && SCID_RE.test(value)
}

/** True for a bare `did:vh:<SCID>` (a DID URL with a path, query or fragment is not a DID). */
export function isVhDid(did: string): boolean {
  return /^did:vh:[^:/?#]+$/.test(did) && isScid(did.slice('did:vh:'.length))
}

export function parseVhDid(did: string): { scid: string } {
  if (!isVhDid(did)) throw new Error('parseVhDid: not a did:vh identifier')
  return { scid: did.slice('did:vh:'.length) }
}

/** The SCID of a did:vh, from the DID or from a DID URL (the part before `#`, `?` or `/`); `undefined` for anything else. */
export function vhScidOf(did: string): string | undefined {
  if (!did.startsWith('did:vh:')) return undefined
  const scid = did.slice('did:vh:'.length).split(/[#?/]/)[0]
  return scid && isScid(scid) ? scid : undefined
}

/** What every local store is keyed by for `did`: `did:vh:<SCID>` for a did:vh or a DID URL of one (a did:vh names no host, so
 * nothing in it moves), any other string (a bare mail address, a did:web, a did:peer) as it is. */
export function identityKey(did: string): string {
  const scid = vhScidOf(did)
  return scid ? `did:vh:${scid}` : did
}

/** True when both name the same identity: the same string, or the same did:vh whatever fragment each carries. */
export function sameIdentity(a: string, b: string): boolean {
  return a === b || identityKey(a) === identityKey(b)
}

/**
 * Whether `host` may be asked for a log or a document: a domain name (didvh-spec, Web Locations: "the host MUST be a domain name,
 * not an IP address"). At least two labels, each of letters, digits and hyphens, and a last label that starts with a letter, so an
 * IPv4 literal (`127.0.0.1`) and its disguises (`0x7f.1`, `2130706433`) are not domain names. IDNs arrive in their A-label form.
 */
export function isDomainHost(host: unknown): host is string {
  if (typeof host !== 'string' || host.length > 253 || host !== host.toLowerCase()) return false
  const labels = host.split('.')
  return labels.length >= 2
    && labels.every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))
    && /^[a-z]/.test(labels[labels.length - 1]!)
}
