// did:webvh identifier parsing/building and the DID-to-HTTPS transform
// (DIDWEBVHFEAT.md §1-§2, did:webvh v1.0 spec).
const SCID_RE = /^[1-9A-HJ-NP-Za-km-z]{46}$/ // base58-btc alphabet, 46 chars (DIDWEBVHFEAT.md §1)

export interface WebvhDidParts {
  scid: string
  domain: string
  port?: number
  pathSegments: string[]
}

export function parseWebvhDid(did: string): WebvhDidParts {
  if (!did.startsWith('did:webvh:')) throw new Error('parseWebvhDid: not a did:webvh identifier')
  const segments = did.slice('did:webvh:'.length).split(':')
  const scid = segments[0]
  if (!scid || !SCID_RE.test(scid)) throw new Error('parseWebvhDid: invalid SCID segment')
  const domainAndPort = segments[1]
  if (!domainAndPort) throw new Error('parseWebvhDid: missing domain segment')

  let domain = domainAndPort
  let port: number | undefined
  const portMatch = /^(.+)%3A(\d{1,5})$/i.exec(domainAndPort)
  if (portMatch) {
    domain = portMatch[1]!
    port = Number(portMatch[2])
  }
  return { scid, domain, port, pathSegments: segments.slice(2) }
}

export function buildWebvhDid(parts: { scid: string; domain: string; port?: number; pathSegments?: string[] }): string {
  const domainPart = parts.port ? `${parts.domain}%3A${parts.port}` : parts.domain
  const path = parts.pathSegments?.length ? ':' + parts.pathSegments.join(':') : ''
  return `did:webvh:${parts.scid}:${domainPart}${path}`
}

/** biset-specific: the path-segment form that avoids the apex-sharing problem
 * (PLANWEBVH.md §2.3) — every biset user gets their own path segment under
 * the shared domain, e.g. did:webvh:{scid}:biset.md:dids:alice, so that
 * biset.md's and t.biset.md's users don't collide on the same
 * .well-known/did.jsonl file. */
export function buildBisetWebvhDid(scid: string, domain: string, username: string): string {
  return buildWebvhDid({ scid, domain, pathSegments: ['dids', username] })
}

/** The reverse of buildBisetWebvhDid's username: the identifier itself
 * carries it, so a did:webvh contact always has a human-readable label
 * available with no resolve, no Card and no self-asserted name published
 * anywhere (contacts.ts's labelForDid — did:dht has no equivalent, its
 * identifier is pure key material).
 *
 * Undefined for anything that isn't biset's `:dids:{username}` path shape —
 * a webvh DID at an apex (`.well-known`) or under someone else's path
 * convention has no username to read, and inventing one from an arbitrary
 * segment would label a stranger with a name they never chose. */
export function bisetWebvhUsername(did: string): string | undefined {
  if (!did.startsWith('did:webvh:')) return undefined
  try {
    const { pathSegments } = parseWebvhDid(did)
    if (pathSegments.length !== 2 || pathSegments[0] !== 'dids') return undefined
    const username = decodeURIComponent(pathSegments[1]!)
    return username || undefined
  } catch {
    return undefined
  }
}

function percentEncodeUpper(s: string): string {
  // RFC3986 percent-encoding, uppercase hex — encodeURIComponent already does
  // the former but emits lowercase hex digits, so re-case just the escapes.
  return encodeURIComponent(s).replace(/%[0-9a-f]{2}/g, m => m.toUpperCase())
}

function validatePathSegment(seg: string): string {
  const decoded = decodeURIComponent(seg)
  if (decoded === '') throw new Error('didToHttpsUrl: empty path segment')
  if (decoded === '.' || decoded === '..') throw new Error('didToHttpsUrl: "." / ".." path segment not allowed')
  if (/[/\\\0]/.test(decoded)) throw new Error('didToHttpsUrl: path segment contains "/", "\\" or NUL')
  if (decoded !== decoded.trim()) throw new Error('didToHttpsUrl: path segment has leading/trailing whitespace')
  return percentEncodeUpper(decoded)
}

/** The DID-to-HTTPS transform (DIDWEBVHFEAT.md §2): where a did:webvh
 * identifier's log actually lives. Domain normalization (IDNA/Punycode,
 * RFC9233) is delegated to the platform's URL parser rather than
 * reimplemented. */
export function didToHttpsUrl(did: string): string {
  const { domain, port, pathSegments } = parseWebvhDid(did)
  const hostname = new URL(`https://${domain}`).hostname
  const hostPart = port ? `${hostname}:${port}` : hostname

  if (pathSegments.length === 0) return `https://${hostPart}/.well-known/did.jsonl`
  return `https://${hostPart}/${pathSegments.map(validatePathSegment).join('/')}/did.jsonl`
}
