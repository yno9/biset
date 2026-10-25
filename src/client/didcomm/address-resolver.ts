// Mail address -> DID, by WebFinger (RFC 7033; didmail PROTOCOL.md §9).
// Biset never sends mail: an address is only another name for a DID, and
// whoever answers for the address says which. Asked in order:
//
//   1. the address's own domain -- a domain that gives its users DIDs answers
//      with theirs, and the message goes to them directly;
//   2. each configured mail gateway -- a mail bridge, which answers any
//      address with the DID it bridges that address at.
//
// The answer is a pointer, not a credential: the DID it names is resolved
// and its document, not the WebFinger reply, is what a message is encrypted
// to.

import { DidRefused, rememberVhLocation, resolveTrustedDid } from '../../protocol/did-resolve.ts'
import { fetchVhResolution } from '../../protocol/vh/fetch.ts'
import { parseVhDidUrl } from '../../protocol/vh/identifier.ts'

// A circuit through Tor takes seconds longer than a direct connection: a page served at an onion address waits for it.
const onionPage = (): boolean => typeof location !== 'undefined' && location.hostname.endsWith('.onion')
const timeoutMs = (): number => onionPage() ? 30_000 : 5000

/** A mail address: `local@domain`, with a dotted domain. */
export function isMailAddress(value: string): boolean {
  const at = value.lastIndexOf('@')
  return at > 0 && !value.startsWith('did:') && /^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/i.test(value.slice(at + 1))
}

/** The first DID among a JRD's `aliases`, or undefined. */
function didOfJrd(value: unknown): string | undefined {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return undefined
  const aliases = (value as { aliases?: unknown }).aliases
  if (!Array.isArray(aliases)) return undefined
  return aliases.find((alias): alias is string => typeof alias === 'string' && (alias.startsWith('did:web:') || alias.startsWith('did:vh:')))
}

async function webFinger(host: string, address: string, fetchImpl: typeof fetch): Promise<string | undefined> {
  const url = `https://${host}/.well-known/webfinger?resource=${encodeURIComponent(`acct:${address}`)}`
  try {
    const response = await fetchImpl(url, { headers: { accept: 'application/jrd+json, application/json' }, signal: AbortSignal.timeout(timeoutMs()) })
    if (!response.ok) return undefined
    return didOfJrd(await response.json())
  } catch {
    // No WebFinger there, no CORS, or no answer in time: not this host.
    return undefined
  }
}

/** The web host a name-style address is published at: `alice@did.md` is `alice.did.md` (didmail's form, the inverse of labelForDid). */
export function hostOfAddress(address: string): string {
  const at = address.lastIndexOf('@')
  return `${address.slice(0, at)}.${address.slice(at + 1)}`.toLowerCase()
}

/** What the address's own domain answered. A domain is the authority over its own addresses (it is the one that says who `alice@did.md`
 * is), but what it answers is only a pointer: the DID is read and confirmed before anything is sent to it.
 *  - a did:web (what a domain that gives each user a host of their own answers): the first rung of the ladder, followed to the
 *    did:vh its document points to and confirmed in both directions (`resolveTrustedDid`); one that points to no did:vh is a plain
 *    did:web contact; one that points to a did:vh that does not confirm it is refused;
 *  - a did:vh, with the place of its log as `?src=` when the domain knows it: the log must be found and verify. */
async function settle(address: string, answer: string, fetchImpl: typeof fetch): Promise<string> {
  if (answer.startsWith('did:web:')) {
    const did = answer
    try {
      const trusted = await resolveTrustedDid(did, { fetch: fetchImpl })
      return trusted?.did ?? did
    } catch (error) {
      if (error instanceof DidRefused) throw new Error(`${address}: ${error.message}`)
      return did // not reachable now: it is resolved again when the message is sent
    }
  }
  let parsed: { did: string; src?: string }
  try { parsed = parseVhDidUrl(answer) } catch { throw new Error(`${address} is answered with ${answer}, which is not a DID`) }
  return await foundDid(parsed, fetchImpl, `${address} is answered with ${parsed.did}`)
}

/** A did:vh given with the place of its log (`did:vh:<SCID>?src=…`): the place is remembered, the log must be found and verify. */
async function foundDid(parsed: { did: string; src?: string }, fetchImpl: typeof fetch, who: string): Promise<string> {
  if (parsed.src) rememberVhLocation(parsed.did, parsed.src)
  const found = await fetchVhResolution(parsed.did, { locations: parsed.src ? [parsed.src] : [], fetch: fetchImpl })
  if (!found?.resolution.doc) throw new Error(`${who}, but its log was not found`)
  return parsed.did
}

/**
 * The DID a compose recipient is: a mail address is looked up (`resolveMailAddressDid`); a did:vh may be written with the place of its
 * log (`did:vh:<SCID>?src=https://example.com/dids/issuer`, didvh-spec: Reading did:vh DID URLs), which is for a recipient who has no
 * did:web to start from. The `src` is only where to look: it is remembered, validated as a web location (src.ts), and dropped, so the
 * recipient is always the bare `did:vh:<SCID>`; the log found there must verify against that SCID. Anything else is the DID as written.
 */
export async function resolveRecipient(value: string, gateways: readonly string[], fetchImpl: typeof fetch = fetch): Promise<string> {
  const text = value.trim()
  if (isMailAddress(text)) return resolveMailAddressDid(text, gateways, fetchImpl)
  if (!text.startsWith('did:vh:') || !text.includes('?')) return text
  let parsed: { did: string; src?: string }
  try { parsed = parseVhDidUrl(text) } catch (error) { throw new Error(`${text}: ${(error as Error).message}`) }
  return foundDid(parsed, fetchImpl, parsed.did)
}

/** The DID `address` is reached at: the address's own domain answers (WebFinger), else the first gateway (a mail bridge, which
 * answers any address with its bridge DID). Throws when nobody answers. */
export async function resolveMailAddressDid(address: string, gateways: readonly string[], fetchImpl: typeof fetch = fetch): Promise<string> {
  if (!isMailAddress(address)) throw new TypeError(`${address} is not a mail address`)
  const domain = address.slice(address.lastIndexOf('@') + 1).toLowerCase()
  for (const host of [domain, ...gateways.filter(gateway => gateway.toLowerCase() !== domain)]) {
    const answer = await webFinger(host, address, fetchImpl)
    if (answer) return host === domain ? await settle(address, answer, fetchImpl) : answer
  }
  throw new Error(gateways.length
    ? `No DID answers for ${address}: neither ${domain} nor the mail gateway knows it`
    : `No DID answers for ${address}, and no mail gateway is configured`)
}
