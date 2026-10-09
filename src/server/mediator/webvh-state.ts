// did:webvh key state for the mediator: which X25519 keys a DID lists in its
// `keyAgreement` right now.
//
// Two ways to learn it, both ending in the same verified `WebvhState`:
//
//  (a) RESOLVE -- the mediator fetches the DID's log itself
//      (`createNetworkWebvhResolver`), as any DIDComm agent resolves a
//      sender's DID. This is how DIDComm works and what the default is.
//  (b) PUSH -- a client hands the mediator its log (`POST /webvh-log`,
//      server.ts). NOT part of DIDComm: a biset-specific side channel that
//      lets a mediator run without ever dialling out. Kept for a deployment
//      that must not resolve DIDs (no `resolveWebvh` given to
//      `createMediator`); no client sends it any more.
//
// Either way the log is verified in full here (SCID, entry-hash chain, proofs)
// with the same code, so a state means the same thing whichever way it came.
import { signingKeyOfMethod, type SigningKey } from '../../protocol/didcomm/jws.ts'
import { lookup as dnsLookup } from 'node:dns/promises'
import { parseLog, entryVersionNumber } from '../../protocol/webvh/log.ts'
import { resolveEntries } from '../../protocol/webvh/resolver.ts'
import { didToHttpsUrl } from '../../protocol/webvh/identifier.ts'
import { decodeX25519Multikey } from '../../protocol/didcomm/multikey.ts'
import type { WebvhDidDocument } from '../../protocol/webvh/document.ts'

const toHex = (b: Uint8Array): string => [...b].map(x => x.toString(16).padStart(2, '0')).join('')

/** A DID's keyAgreement state at one log version. */
export interface WebvhState {
  did: string
  versionNumber: number
  /** Every keyAgreement kid (absolute DID URL) -> its X25519 public key, hex. */
  keys: Record<string, string>
  /** Every authentication kid (absolute) -> its signing key, for a signed
   * message (jws.ts). Only as resolved: not kept by the store. */
  authentication?: Record<string, SigningKey>
}

/** The keys could not be learned right now (the network, the host) -- as
 * opposed to the DID having no log, or an invalid one. Retry later. */
export class WebvhUnavailable extends Error {}

/** `null`: the DID has no (valid) log. Throws `WebvhUnavailable` when it could not be asked. */
export type WebvhStateResolver = (did: string) => Promise<WebvhState | null>

/** Every keyAgreement kid (absolute) of a resolved document and its X25519
 * key. Entries this mediator can't read are left out -- they can't
 * authenticate anything here anyway. */
function keyAgreementKeys(doc: WebvhDidDocument): Record<string, string> {
  const absolute = (id: string) => id.startsWith('#') ? `${doc.id}${id}` : id
  const keys: Record<string, string> = {}
  for (const ref of doc.keyAgreement ?? []) {
    const kid = absolute(ref)
    const method = doc.verificationMethod.find(vm => absolute(vm.id) === kid)
    if (!method) continue
    try { keys[kid] = toHex(decodeX25519Multikey(method.publicKeyMultibase)) } catch { /* not X25519 */ }
  }
  return keys
}

/** Every authentication kid (absolute) of a resolved document and its
 * signing key; entries that are not a signing key are left out. */
function authenticationKeys(doc: WebvhDidDocument): Record<string, SigningKey> {
  const absolute = (id: string) => id.startsWith('#') ? `${doc.id}${id}` : id
  const keys: Record<string, SigningKey> = {}
  for (const ref of doc.authentication ?? []) {
    const kid = absolute(ref)
    const method = doc.verificationMethod.find(vm => absolute(vm.id) === kid)
    if (!method) continue
    try { keys[kid] = signingKeyOfMethod(method) } catch { /* not a signing key */ }
  }
  return keys
}

/** Verifies a did:webvh log (JSONL) and reads its keyAgreement state. Throws
 * if the log is not valid. The DID is whatever the LATEST entry says: a
 * domain move (an alias renamed to its real hostname, say) rewrites the
 * domain part of every state, and the genesis entry keeps the old one; the
 * SCID, which verification checks against the whole chain, stays. */
export function webvhStateFromLog(jsonl: string): WebvhState {
  const entries = parseLog(jsonl)
  const did = (entries[entries.length - 1]?.state as { id?: unknown } | undefined)?.id
  if (typeof did !== 'string' || !did.startsWith('did:webvh:')) throw new Error('the log does not name a did:webvh')
  const doc = resolveEntries(did, entries)
  if (!doc || doc.id !== did) throw new Error('the log does not resolve to its own DID')
  return { did: doc.id, versionNumber: entryVersionNumber(entries[entries.length - 1]!.versionId), keys: keyAgreementKeys(doc), authentication: authenticationKeys(doc) }
}

/** A host NAME the mediator may dial for a DID's log. The DID -- so the host --
 * comes from a message anyone can send, so the mediator never connects to
 * itself, a private network, or a literal address. This looks at the name
 * only; `isPublicAddress` checks what the name resolves to. */
export function isPublicHostname(hostname: string): boolean {
  // A trailing dot is the same name (`localhost.` is `localhost`).
  const host = hostname.toLowerCase().replace(/\.+$/, '')
  if (!host.includes('.') || host.includes(':') || host.startsWith('[')) return false
  // Anything an address parser would read as IPv4 -- `127.0.0.1`, `127.1`,
  // `2130706433`, `0x7f.1`, `0177.0.0.1`: the last label is a number (the
  // WHATWG URL parser's own test for "this host is an IPv4 address").
  if (/^(0x[0-9a-f]*|\d+)$/.test(host.slice(host.lastIndexOf('.') + 1))) return false
  return !(host === 'localhost' || /\.(localhost|local|internal|lan|home|test|invalid)$/.test(host))
}

function ipv4Bytes(ip: string): number[] | undefined {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip)
  const bytes = m ? m.slice(1).map(Number) : undefined
  return bytes && bytes.every(b => b <= 255) ? bytes : undefined
}

function ipv6Bytes(ip: string): number[] | undefined {
  let text = ip.toLowerCase().replace(/%.*$/, '')
  const tail = /(\d{1,3}(?:\.\d{1,3}){3})$/.exec(text)
  if (tail) {
    const v4 = ipv4Bytes(tail[1]!)
    if (!v4) return undefined
    text = text.slice(0, -tail[1]!.length) + ((v4[0]! << 8) | v4[1]!).toString(16) + ':' + ((v4[2]! << 8) | v4[3]!).toString(16)
  }
  const halves = text.split('::')
  if (halves.length > 2) return undefined
  const head = halves[0] ? halves[0].split(':') : []
  const rest = halves.length === 2 && halves[1] ? halves[1].split(':') : []
  const missing = 8 - head.length - rest.length
  if ((halves.length === 1 && missing !== 0) || missing < 0) return undefined
  const groups = [...head, ...Array(halves.length === 2 ? missing : 0).fill('0'), ...rest]
  if (groups.length !== 8 || groups.some(g => !/^[0-9a-f]{1,4}$/.test(g))) return undefined
  return groups.flatMap(g => [parseInt(g, 16) >> 8, parseInt(g, 16) & 255])
}

/** Whether an IP address is one the mediator may dial: not loopback,
 * private, link-local, CGNAT, multicast or otherwise reserved. An IPv4
 * address inside an IPv6 one (IPv4-mapped, or a NAT64 `64:ff9b::/96`
 * address, which an IPv6-only host sees for any IPv4 site) is judged as the
 * IPv4 address it carries. */
export function isPublicAddress(ip: string): boolean {
  const v4 = ipv4Bytes(ip)
  if (v4) {
    const [a, b, c] = v4 as [number, number, number, number]
    return !(a === 0 || a === 10 || a === 127 || a >= 224
      || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31)
      || (a === 192 && b === 168) || (a === 192 && b === 0 && c === 0) || (a === 198 && (b === 18 || b === 19)))
  }
  const v6 = ipv6Bytes(ip)
  if (!v6) return false
  const embedded = v6.slice(12, 16).join('.')
  if (v6.slice(0, 10).every(x => x === 0) && v6[10] === 255 && v6[11] === 255) return isPublicAddress(embedded) // ::ffff:a.b.c.d
  if (v6.slice(0, 12).join(',') === '0,100,255,155,0,0,0,0,0,0,0,0') return isPublicAddress(embedded) // 64:ff9b::/96
  if (v6.every(x => x === 0) || (v6.slice(0, 15).every(x => x === 0) && v6[15] === 1)) return false // :: and ::1
  return !((v6[0]! & 0xfe) === 0xfc || (v6[0] === 0xfe && (v6[1]! & 0xc0) === 0x80) || v6[0] === 0xff) // fc00::/7, fe80::/10, ff00::/8
}

export interface NetworkResolverOptions {
  fetch?: typeof fetch
  timeoutMs?: number
  maxLogBytes?: number
  /** Overrides `isPublicHostname` -- tests, or a private deployment's own rule. */
  allowHost?: (hostname: string) => boolean
  /** Every address a name resolves to (default: the system resolver). The
   * log is fetched only if ALL of them pass `isPublicAddress`; `null`
   * disables the check (a deployment that cannot reach private networks anyway). */
  lookup?: ((hostname: string) => Promise<string[]>) | null
}

async function systemLookup(hostname: string): Promise<string[]> {
  return (await dnsLookup(hostname, { all: true })).map(entry => entry.address)
}

/** Resolves a did:webvh by fetching its log: https only, a public host (the
 * name AND everything it resolves to), no redirects, a time and size limit
 * (one fetch can still be pointed elsewhere if DNS changes between the check
 * and the connection -- the mediator should have no route to private
 * networks regardless), and a unique query string so the host's CDN cannot answer
 * with a log that predates a key added moments ago (the host serves public
 * reads with `s-maxage=30` and does not purge on write). */
export function createNetworkWebvhResolver(options: NetworkResolverOptions = {}): WebvhStateResolver {
  const fetchImpl = options.fetch ?? fetch
  const timeoutMs = options.timeoutMs ?? 5000
  const maxLogBytes = options.maxLogBytes ?? 1024 * 1024
  const allowHost = options.allowHost ?? isPublicHostname
  const lookup = options.lookup === null ? undefined : options.lookup ?? systemLookup

  return async did => {
    let url: URL
    try { url = new URL(didToHttpsUrl(did)) } catch { return null }
    if (url.protocol !== 'https:' || url.port !== '' || !allowHost(url.hostname)) return null
    if (lookup) {
      let addresses: string[]
      try { addresses = await lookup(url.hostname.replace(/\.+$/, '')) } catch (error) {
        const code = (error as { code?: string }).code
        if (code === 'ENOTFOUND' || code === 'ENODATA') return null
        throw new WebvhUnavailable(`could not look up ${url.hostname}: ${error instanceof Error ? error.message : String(error)}`)
      }
      if (addresses.length === 0 || !addresses.every(isPublicAddress)) return null
    }
    url.searchParams.set('_', `${Date.now()}${Math.random().toString(36).slice(2, 8)}`)

    let response: Response
    try {
      response = await fetchImpl(url, { redirect: 'error', cache: 'no-store', signal: AbortSignal.timeout(timeoutMs), headers: { accept: 'application/jsonl, text/plain, */*' } })
    } catch (error) {
      throw new WebvhUnavailable(`could not fetch the log of ${did}: ${error instanceof Error ? error.message : String(error)}`)
    }
    if (response.status === 404 || response.status === 410) return null
    if (!response.ok) throw new WebvhUnavailable(`the log of ${did} answered HTTP ${response.status}`)
    if (Number(response.headers.get('content-length') ?? 0) > maxLogBytes) return null
    let text: string
    try { text = await response.text() } catch (error) {
      throw new WebvhUnavailable(`could not read the log of ${did}: ${error instanceof Error ? error.message : String(error)}`)
    }
    if (text.length > maxLogBytes) return null
    try {
      const state = webvhStateFromLog(text)
      // Only the DID that was asked about: a log that names another DID says nothing about it.
      return state.did === did ? state : null
    } catch {
      return null
    }
  }
}
