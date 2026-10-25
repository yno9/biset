// did:webvh identifier parsing and the DID-to-HTTPS transform
// (DIDWEBVHFEAT.md §1-§2, did:webvh v1.0 spec). Read-only: this resolver
// never builds a did:webvh string, only parses and dereferences one.
import { SCID_PLACEHOLDER } from './scid.ts'

const SCID_RE = /^[1-9A-HJ-NP-Za-km-z]{46}$/ // base58-btc alphabet, 46 chars (DIDWEBVHFEAT.md §1)

export interface WebvhDidParts {
  scid: string
  domain: string
  port?: number
  pathSegments: string[]
}

export function buildWebvhDid(parts: { scid: string; domain: string; port?: number; pathSegments?: string[] }): string {
  const domainPart = parts.port ? `${parts.domain}%3A${parts.port}` : parts.domain
  const path = parts.pathSegments?.length ? ':' + parts.pathSegments.join(':') : ''
  return `did:webvh:${parts.scid}:${domainPart}${path}`
}

export function parseWebvhDid(did: string): WebvhDidParts {
  if (!did.startsWith('did:webvh:')) throw new Error('parseWebvhDid: not a did:webvh identifier')
  const segments = did.slice('did:webvh:'.length).split(':')
  const scid = segments[0]
  if (!scid || !(SCID_RE.test(scid) || scid === SCID_PLACEHOLDER)) throw new Error('parseWebvhDid: invalid SCID segment')
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

function didJsonlUrlFor(hostPart: string, pathSegments: string[]): string {
  if (pathSegments.length === 0) return `https://${hostPart}/.well-known/did.jsonl`
  return `https://${hostPart}/${pathSegments.map(validatePathSegment).join('/')}/did.jsonl`
}

/** The DID-to-HTTPS transform (DIDWEBVHFEAT.md §2). Domain normalization
 * (IDNA/Punycode, RFC9233) is delegated to the platform's URL parser rather
 * than reimplemented. */
export function didToHttpsUrl(did: string): string {
  const { domain, port, pathSegments } = parseWebvhDid(did)
  const hostname = new URL(`https://${domain}`).hostname
  const hostPart = port ? `${hostname}:${port}` : hostname
  return didJsonlUrlFor(hostPart, pathSegments)
}

/** Same transform as `didToHttpsUrl`, but from a bare domain — no SCID
 * needed, since a subdomain-per-identity did:webvh (no `pathSegments`,
 * `create-genesis.ts`'s own convention) has a fixed, SCID-independent
 * `did.jsonl` location. This is what a recovery-phrase login uses: it knows
 * only the identity's own subdomain, not its DID string, until AFTER
 * fetching this URL and reading `state.id` out of the genesis entry
 * (`resolver.ts`'s `resolveByDomain`). */
export function domainDidJsonlUrl(domain: string, port?: number): string {
  const hostname = new URL(`https://${domain}`).hostname
  const hostPart = port ? `${hostname}:${port}` : hostname
  return didJsonlUrlFor(hostPart, [])
}

/** The SCID of a did:webvh, the part of the identity that survives a move to another host (an alias
 * change); `undefined` for any other DID. */
export function scidOf(did: string): string | undefined {
  if (!did.startsWith('did:webvh:')) return undefined
  const scid = did.slice('did:webvh:'.length).split(':')[0]
  return scid && SCID_RE.test(scid) ? scid : undefined
}

/** The SCID of a did:vh (a DID, or a DID URL: the part before `#`, `?` or `/`); `undefined` for any other DID. A did:vh names no
 * host, so unlike a did:webvh its whole string is already the identity. */
export function vhScidOf(did: string): string | undefined {
  if (!did.startsWith('did:vh:')) return undefined
  const scid = did.slice('did:vh:'.length).split(/[#?/]/)[0]
  return scid && SCID_RE.test(scid) ? scid : undefined
}

/** True when both are the same identity: the same method and SCID, whatever host each names (a did:webvh) or whatever
 * fragment each carries (a did:vh). A did:vh and a did:webvh never share a SCID, so they are never the same identity here;
 * they are linked by alsoKnownAs in both directions, which a contact records, not this function. */
export function sameIdentity(a: string, b: string): boolean {
  return a === b || identityKey(a) === identityKey(b)
}

/** What every local store is keyed by for `did`: the SCID form `did:webvh:<SCID>` of a did:webvh
 * (stable across an alias change), `did:vh:<SCID>` of a did:vh, any other DID as it is. */
export function identityKey(did: string): string {
  const scid = scidOf(did)
  if (scid) return `did:webvh:${scid}`
  const vh = vhScidOf(did)
  return vh ? `did:vh:${vh}` : did
}
