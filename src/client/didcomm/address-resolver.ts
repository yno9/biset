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

import { rememberVhLocation } from '../../protocol/did-resolve.ts'
import { fetchVhResolution, resolveVhByHost } from '../../protocol/vh/fetch.ts'
import { didWebDocumentUrl, verifiedAddress } from '../../protocol/vh/didweb.ts'

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

/** A did:vh names no host, so an answer naming one is only a claim until its own log agrees: the log (found at the host the
 * address is published at) must list `did:web:<host>` in `alsoKnownAs`, and the shadow there must be what the log derives. An
 * answer that fails is refused: whoever answered cannot make a DID speak for an address it does not name. */
async function confirmVhAnswer(address: string, did: string, fetchImpl: typeof fetch): Promise<void> {
  const host = hostOfAddress(address)
  rememberVhLocation(did, host)
  const found = await fetchVhResolution(did, { locations: [host], fetch: fetchImpl })
  const doc = found?.resolution.doc
  if (!doc) throw new Error(`${address} is answered with ${did}, but its log was not found at ${host}`)
  if (verifiedAddress(doc as unknown as Record<string, unknown>, `did:web:${host}`, await shadowOf(host, fetchImpl)) !== address.toLowerCase()) {
    throw new Error(`${address} is answered with ${did}, but that DID does not name ${address} (alsoKnownAs and its did:web document must agree)`)
  }
}

async function shadowOf(host: string, fetchImpl: typeof fetch): Promise<unknown> {
  try {
    const response = await fetchImpl(didWebDocumentUrl(`did:web:${host}`))
    return response.ok ? await response.json() : undefined
  } catch {
    return undefined
  }
}

/** The identity published at the host of an address under a domain that gives each user a host of their own (`alice@did.md` at
 * `alice.did.md`): its log is the host's `/.well-known/did.jsonl`, it must name `did:web:<host>`, and the did:web document served
 * there must be the shadow the log derives. Nobody else is asked, so this works with every bridge down. undefined: no such identity
 * (or the host could not be reached: the caller then asks the usual way). */
async function identityAtHost(address: string, fetchImpl: typeof fetch): Promise<string | undefined> {
  const host = hostOfAddress(address)
  let found: Awaited<ReturnType<typeof resolveVhByHost>>
  try { found = await resolveVhByHost(host, { fetch: fetchImpl }) } catch { return undefined }
  if (!found) return undefined
  if (verifiedAddress(found.document as unknown as Record<string, unknown>, `did:web:${host}`, await shadowOf(host, fetchImpl)) !== address.toLowerCase()) {
    throw new Error(`${host} publishes ${found.did}, but that DID does not name ${address} (alsoKnownAs and its did:web document must agree)`)
  }
  rememberVhLocation(found.did, host)
  return found.did
}

/** The DID `address` is reached at: a domain that gives each user a host of their own is read directly (`identityDomains`), else
 * the address's own domain answers, else the first gateway. Throws when nobody answers. */
export async function resolveMailAddressDid(address: string, gateways: readonly string[], fetchImpl: typeof fetch = fetch, identityDomains: readonly string[] = []): Promise<string> {
  if (!isMailAddress(address)) throw new TypeError(`${address} is not a mail address`)
  const domain = address.slice(address.lastIndexOf('@') + 1).toLowerCase()
  if (identityDomains.includes(domain)) {
    const direct = await identityAtHost(address, fetchImpl)
    if (direct) return direct
  }
  for (const host of [domain, ...gateways.filter(gateway => gateway.toLowerCase() !== domain)]) {
    const did = await webFinger(host, address, fetchImpl)
    if (did?.startsWith('did:vh:')) await confirmVhAnswer(address, did, fetchImpl)
    if (did) return did
  }
  throw new Error(gateways.length
    ? `No DID answers for ${address}: neither ${domain} nor the mail gateway knows it`
    : `No DID answers for ${address}, and no mail gateway is configured`)
}
