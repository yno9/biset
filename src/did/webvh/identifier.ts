// did:webvh identifier parsing/building and the DID-to-HTTPS transform
// (DIDWEBVHFEAT.md §1-§2, did:webvh v1.0 spec).
import { SCID_PLACEHOLDER } from './scid.ts'

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
  // The placeholder is accepted here too, not just SCID_RE's real alphabet:
  // createGenesis (publish.ts) builds a preliminary document — including,
  // now, buildBisetWebvhState's routing.json pointer serviceEndpoint, which
  // calls didToResourceUrl below — against a DID that still carries `{SCID}`
  // literally, before the real SCID is known and substituted in wholesale.
  // Rejecting the placeholder here would make that preliminary pass
  // impossible rather than just producing a URL that gets string-substituted
  // like every other placeholder-bearing field already does.
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

export function buildWebvhDid(parts: { scid: string; domain: string; port?: number; pathSegments?: string[] }): string {
  const domainPart = parts.port ? `${parts.domain}%3A${parts.port}` : parts.domain
  const path = parts.pathSegments?.length ? ':' + parts.pathSegments.join(':') : ''
  return `did:webvh:${parts.scid}:${domainPart}${path}`
}

/** biset-specific: the path-segment form that avoids the apex-sharing problem
 * (PLANWEBVH.md §2.3) — every biset user gets their own path segment under
 * the shared domain, e.g. did:webvh:{scid}:biset.md:alice, so that biset.md's
 * and t.biset.md's users don't collide on the same .well-known/did.jsonl
 * file.
 *
 * No `dids/` prefix segment (2026-08-11, user-requested — shorter DIDs; was
 * `pathSegments: ['dids', username]`). The anchor enforces the corresponding
 * safety property this prefix used to give away for free: a username can
 * never equal RESERVED_USERNAME (server.ts), so `/<username>/did.jsonl` can
 * never collide with one of the anchor's own routes (which all live under
 * `/_anchor/*` for exactly this reason). */
export function buildBisetWebvhDid(scid: string, domain: string, username: string): string {
  return buildWebvhDid({ scid, domain, pathSegments: [username] })
}

/** The reverse of buildBisetWebvhDid's username: the identifier itself
 * carries it, so a did:webvh contact always has a human-readable label
 * available with no resolve, no Card and no self-asserted name published
 * anywhere (contacts.ts's labelForDid — did:dht has no equivalent, its
 * identifier is pure key material).
 *
 * Undefined for anything that isn't biset's single-segment `:{username}`
 * path shape — a webvh DID at an apex (`.well-known`) or under someone
 * else's path convention has no username to read, and inventing one from an
 * arbitrary segment would label a stranger with a name they never chose. */
export function bisetWebvhUsername(did: string): string | undefined {
  if (!did.startsWith('did:webvh:')) return undefined
  try {
    const { pathSegments } = parseWebvhDid(did)
    if (pathSegments.length !== 1) return undefined
    const username = decodeURIComponent(pathSegments[0]!)
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

/** The DID-to-HTTPS transform (DIDWEBVHFEAT.md §2), generalized to any
 * filename logically beside `did.jsonl` at the DID's own location — the same
 * pattern the spec itself uses for `did-witness.json` and `/whois.vp`.
 * webvh/routing.ts's routing.json (volatile connectivity data kept out of
 * the signed log) is the other consumer. Domain normalization
 * (IDNA/Punycode, RFC9233) is delegated to the platform's URL parser rather
 * than reimplemented. */
export function didToResourceUrl(did: string, filename: string): string {
  const { domain, port, pathSegments } = parseWebvhDid(did)
  const hostname = new URL(`https://${domain}`).hostname
  const hostPart = port ? `${hostname}:${port}` : hostname

  if (pathSegments.length === 0) return `https://${hostPart}/.well-known/${filename}`
  return `https://${hostPart}/${pathSegments.map(validatePathSegment).join('/')}/${filename}`
}

export function didToHttpsUrl(did: string): string {
  return didToResourceUrl(did, 'did.jsonl')
}
