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
