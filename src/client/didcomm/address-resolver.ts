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

const TIMEOUT_MS = 5000

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
  return aliases.find((alias): alias is string => typeof alias === 'string' && (alias.startsWith('did:webvh:') || alias.startsWith('did:web:')))
}

async function webFinger(host: string, address: string, fetchImpl: typeof fetch): Promise<string | undefined> {
  const url = `https://${host}/.well-known/webfinger?resource=${encodeURIComponent(`acct:${address}`)}`
  try {
    const response = await fetchImpl(url, { headers: { accept: 'application/jrd+json, application/json' }, signal: AbortSignal.timeout(TIMEOUT_MS) })
    if (!response.ok) return undefined
    return didOfJrd(await response.json())
  } catch {
    // No WebFinger there, no CORS, or no answer in time: not this host.
    return undefined
  }
}

/** The DID `address` is reached at: its own domain's answer, else the first
 * gateway's. Throws when nobody answers. */
export async function resolveMailAddressDid(address: string, gateways: readonly string[], fetchImpl: typeof fetch = fetch): Promise<string> {
  if (!isMailAddress(address)) throw new TypeError(`${address} is not a mail address`)
  const domain = address.slice(address.lastIndexOf('@') + 1).toLowerCase()
  for (const host of [domain, ...gateways.filter(gateway => gateway.toLowerCase() !== domain)]) {
    const did = await webFinger(host, address, fetchImpl)
    if (did) return did
  }
  throw new Error(gateways.length
    ? `No DID answers for ${address}: neither ${domain} nor the mail gateway knows it`
    : `No DID answers for ${address}, and no mail gateway is configured`)
}
