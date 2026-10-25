// Where a did:vh log is fetched from: the `src` of didvh-spec ("Web Locations"). A web location is the base URL under which `did.jsonl`
// is published: `https://alice.did.md` at `/.well-known/did.jsonl`, `https://example.com/dids/issuer` at `/dids/issuer/did.jsonl`.
// The rules are the specification's, and the same as dito's packages/vh/src/src.ts (ported from it; checked against the same cases): a
// domain name, never an IP address; https; no credentials, query or fragment; path segments checked after percent-decoding.
//
// This is also the guard for anything fetched on someone else's say-so: a `src` in a DID URL someone typed or sent is only a place to
// look, and what is found there is verified in full by SCID, hash chain and signatures.
import { VhResolutionError } from './errors.ts'

const LABEL = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?'
const DOMAIN = new RegExp(`^(?=.{1,253}$)(?:${LABEL}\\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
const LOOPBACK = /^(?:localhost|127(?:\.\d{1,3}){3}|\[::1\])$/
const IPV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/

export interface SrcOptions {
  /** Allow `http` to a loopback host: for a resolver that runs next to its client (development, tests). Never from a DID URL. */
  allowLoopback?: boolean
}

const refuse = (message: string) => new VhResolutionError('invalidOptions', message)

/** A validated web location: its origin and its path segments in the form they were written. */
export interface WebLocation { origin: string; host: string; port?: number; segments: string[] }

export function parseWebLocation(src: unknown, options: SrcOptions = {}): WebLocation {
  if (typeof src !== 'string') throw refuse('src must be a string.')
  const match = /^(https?):\/\/([^/?#@\\]+)((?:\/[^?#\\]*)?)$/i.exec(src)
  if (!match) throw refuse('src must be an absolute https URL without credentials, query or fragment.')
  const scheme = match[1]!.toLowerCase()
  // The authority is checked in its written form: the URL parser would normalise a dotted-decimal or hex host.
  const hostPort = /^(\[[0-9a-f:.]+\]|[^:]+)(?::(\d{1,5}))?$/i.exec(match[2]!)
  if (!hostPort) throw refuse('src has an invalid host.')
  const host = hostPort[1]!.toLowerCase()
  const port = hostPort[2] === undefined ? undefined : Number(hostPort[2])
  if (port !== undefined && (port < 1 || port > 65535)) throw refuse('src has an invalid port.')

  if (scheme === 'http') {
    if (!options.allowLoopback || !LOOPBACK.test(host)) throw refuse('src must use https (http is for a loopback host in a local resolver only).')
    return location(scheme, host, port, match[3]!)
  }
  if (IPV4.test(host) || host.startsWith('[')) throw refuse('src must name a domain, not an IP address.')
  let ascii: string
  try { ascii = new URL(`https://${host}`).hostname } catch { throw refuse('src has an invalid host.') }
  if (!DOMAIN.test(ascii)) throw refuse('src must name a fully qualified domain.')
  return location(scheme, ascii, port, match[3]!)
}

function location(scheme: string, host: string, port: number | undefined, path: string): WebLocation {
  const trimmed = path.replace(/\/+$/, '')
  const segments = trimmed ? trimmed.slice(1).split('/') : []
  for (const segment of segments) {
    let decoded: string
    try { decoded = decodeURIComponent(segment) } catch { throw refuse('src has an invalid path.') }
    // Checked after decoding: %2E%2E, %2F, %5C and %00 would otherwise pass unnoticed.
    if (!decoded || decoded === '.' || decoded === '..' || /[\\/\0]/.test(decoded) || decoded.trim() !== decoded) throw refuse('src has an invalid path segment.')
  }
  return { origin: `${scheme}://${host}${port === undefined ? '' : `:${port}`}`, host, port, segments }
}

/** The URL of `did.jsonl` for a web location (no path: `/.well-known/did.jsonl`). */
export function logUrlOf(src: string, options: SrcOptions = {}): string {
  const where = parseWebLocation(src, options)
  return where.segments.length ? `${where.origin}/${where.segments.join('/')}/did.jsonl` : `${where.origin}/.well-known/did.jsonl`
}

/** A place a log is looked for, as it is kept: a `src` (`https://alice.did.md`, `https://example.com/dids/issuer`), or a bare host
 * (`alice.did.md`, from an address), which is the web location `https://<host>`. Normalised (lower-case host, no trailing slash);
 * undefined when it is not a valid web location. */
export function normalizeLocation(place: string): string | undefined {
  try {
    const where = parseWebLocation(place.includes('://') ? place : `https://${place}`)
    return `${where.origin}${where.segments.length ? `/${where.segments.join('/')}` : ''}`
  } catch { return undefined }
}
