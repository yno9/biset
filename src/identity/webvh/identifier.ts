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

/** `{username}@mail.{apexDomain}` from an identity's own subdomain-per-
 * identity DID -- moved here (from identity/bootstrap.ts) so both the
 * Client (buildMailSubmitter) and Anchor (mail address credential
 * issuance, src/anchor/oid4vp.ts) can derive the same address from the
 * same DID without a Client -> Anchor import (bootstrap.ts pulls in DOM
 * APIs the Anchor's DOM-less tsconfig rejects). */
export function mailFromForIdentity(identityId: string, apexDomain: string): string {
  const { domain } = parseWebvhDid(identityId)
  const suffix = `.${apexDomain}`
  if (!domain.endsWith(suffix)) throw new Error(`mailFromForIdentity: identity domain ${domain} is not a subdomain of ${apexDomain}`)
  const username = domain.slice(0, domain.length - suffix.length)
  if (!username) throw new Error('mailFromForIdentity: identity domain has no username segment')
  return `${username}@mail.${apexDomain}`
}

/** The inverse of `mailFromForIdentity`: `{username}@mail.{apexDomain}` ->
 * the identity's own subdomain (`{username}.{apexDomain}`) -- no SCID, no
 * signed-log resolve, just the same deterministic naming convention run
 * backward. What the mail plugin bridge (mediator/mail-plugin/bridge.ts)
 * uses to turn an inbound SMTP recipient address into a domain it can fetch
 * routing.json from directly (didcomm/webvh-routing.ts's
 * `fetchRoutingByDomain`) -- the did:webvh<->mail mapping this derives is
 * already public, so there is nothing this lookup needs to keep hidden. */
export function identityDomainForMailAddress(address: string, apexDomain: string): string {
  const at = address.indexOf('@')
  if (at <= 0) throw new Error(`identityDomainForMailAddress: ${address} is not a valid mail address`)
  const username = address.slice(0, at)
  const host = address.slice(at + 1)
  if (host !== `mail.${apexDomain}`) throw new Error(`identityDomainForMailAddress: ${address} is not a mail.${apexDomain} address`)
  return `${username}.${apexDomain}`
}
