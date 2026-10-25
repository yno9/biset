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
