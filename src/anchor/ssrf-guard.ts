// Fetches an anchor-supplied did:webvh URL safely.
//
// `authorized_did_domain` (jmapsmtp's ARC.md §2a) means the anchor eventually
// has to resolve a did-domain it does not host itself — an operator-supplied
// value from config, not a value this codebase controls. That turns
// `didToHttpsUrl`'s output into an attacker-influenced URL fetched from a
// server process, which is the textbook SSRF shape: nothing stops the config
// (or a resolved CNAME) from pointing at `169.254.169.254` (cloud metadata),
// `127.0.0.1:6379` (a local Redis with no auth), or any other host this
// process can reach that the public internet cannot. A browser's `resolve()`
// (webvh/resolver.ts) never needed this — same-origin/CORS is the browser's
// own guard, and it has no localhost services worth reaching anyway.
//
// Four defenses:
//   1. Resolve the hostname and reject any answer in a private/loopback/
//      link-local/multicast/reserved range, BEFORE connecting.
//   2. **Pin the TCP connection to the exact address just checked** via
//      `node:tls`'s `connect({ host: <the checked IP> })` directly — not
//      `fetch()`, and not `node:https`'s `Agent({ lookup })` either.
//      Verified against this actual Bun runtime (1.3.14) that BOTH of those
//      silently ignore a custom resolver and do their own DNS internally: a
//      `lookup` callback that returns a deliberately wrong address was never
//      even invoked, and the request still reached the real server. Only
//      connecting a raw socket to a literal IP closes the gap — there is no
//      hostname left for anything downstream to re-resolve. `servername`
//      still carries the real hostname for SNI and certificate validation,
//      so only the TCP destination is pinned, not the identity being
//      verified.
//   3. A size cap on the response body, enforced while streaming (not just
//      trusting Content-Length, which a malicious server can lie about or
//      omit) — including through chunked transfer-encoding, decoded here
//      because a raw socket gets the wire format, not a parsed body.
//   4. A timeout, so a server that accepts the connection and never responds
//      can't hold a resolve open indefinitely.
import { lookup } from 'node:dns/promises'
import { isIP } from 'node:net'
import { connect as tlsConnect, type TLSSocket } from 'node:tls'
import { connect as netConnect, type Socket } from 'node:net'

export class SsrfBlockedError extends Error {}

/** The URL resolved to a real, safe host and answered — with "this resource
 * does not exist." Distinct from every other failure this module raises: a
 * caller resolving a DID needs to tell "no such identity" (this) apart from
 * "couldn't check" (network/SSRF/size/timeout — a plain `Error`), the same
 * distinction `webvh/resolver.ts`'s own `resolve()` makes for the browser
 * path. */
export class NotFoundError extends Error {}

const MAX_BODY_BYTES = 4 * 1024 * 1024 // matches server.ts's MAX_WEBVH_LOG_BODY headroom
const MAX_HEADER_BYTES = 32 * 1024 // generous; nothing legitimate here is bigger
const TIMEOUT_MS = 10_000

/** RFC 1918 / loopback / link-local / multicast / reserved — every range a
 * public did:webvh domain's A/AAAA record has no legitimate reason to
 * resolve to. Deliberately over-inclusive (e.g. blocking all of 100.64.0.0/10
 * CGNAT) rather than trying to enumerate exactly what's dangerous — a
 * same-network resolve failing closed is a config problem to fix, a
 * same-network resolve succeeding is the vulnerability. */
function isBlockedIPv4(ip: string): boolean {
  const parts = ip.split('.').map(Number)
  if (parts.length !== 4 || parts.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return true
  const [a, b] = parts as [number, number, number, number]
  if (a === 0) return true // "this network"
  if (a === 10) return true // RFC1918
  if (a === 127) return true // loopback
  if (a === 100 && b >= 64 && b <= 127) return true // CGNAT
  if (a === 169 && b === 254) return true // link-local incl. cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return true // RFC1918
  if (a === 192 && b === 0) return true // IETF protocol assignments / 192.0.0.0/24
  if (a === 192 && b === 168) return true // RFC1918
  if (a === 198 && (b === 18 || b === 19)) return true // benchmarking
  if (a >= 224) return true // multicast + reserved (224.0.0.0/4, 240.0.0.0/4) + broadcast
  return false
}

function isBlockedIPv6(ip: string): boolean {
  const lower = ip.toLowerCase()
  if (lower === '::1') return true // loopback
  if (lower === '::') return true // unspecified
  if (lower.startsWith('fe80:') || lower.startsWith('fe8') || lower.startsWith('fe9') || lower.startsWith('fea') || lower.startsWith('feb')) return true // link-local fe80::/10
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true // unique local fc00::/7
  if (lower.startsWith('::ffff:')) return isBlockedIPv4(lower.slice('::ffff:'.length)) // IPv4-mapped
  return false
}

function isBlockedIP(ip: string): boolean {
  return isIP(ip) === 6 ? isBlockedIPv6(ip) : isBlockedIPv4(ip)
}

/** Resolves `hostname` and returns every address a resolver hands back, after
 * confirming NONE of them is a blocked range. `all: true` so an attacker
 * can't hide a blocked address behind a dual-stack record where only the
 * FIRST answer looks public — every address must be public, not just the
 * one that happens to get used. Throws `SsrfBlockedError` if any address is
 * blocked, a plain `Error` if the lookup itself fails. */
async function resolvePublicAddresses(hostname: string): Promise<Array<{ address: string; family: number }>> {
  // URL.hostname brackets a literal IPv6 address (`[::1]`) per the WHATWG
  // spec; node:dns wants the bare address.
  const bareHost = hostname.startsWith('[') && hostname.endsWith(']') ? hostname.slice(1, -1) : hostname

  let addresses: Array<{ address: string; family: number }>
  try {
    addresses = await lookup(bareHost, { all: true })
  } catch (e) {
    throw new Error(`resolvePublicAddresses: DNS lookup failed for ${bareHost}: ${e instanceof Error ? e.message : e}`)
  }
  if (addresses.length === 0) {
    throw new Error(`resolvePublicAddresses: DNS lookup for ${bareHost} returned no addresses`)
  }
  const blocked = addresses.find(a => isBlockedIP(a.address))
  if (blocked) {
    throw new SsrfBlockedError(`resolvePublicAddresses: ${bareHost} resolves to ${blocked.address}, which is not a public address`)
  }
  return addresses
}

/** Fetches `url` (must be `https:`) after confirming its hostname resolves
 * only to public addresses, then connects to the EXACT address just
 * checked — never re-resolving — while still sending the real hostname as
 * SNI/Host, capping the body size and the wait. Throws `SsrfBlockedError`
 * for anything that looks like an attempt to reach internal infrastructure,
 * `NotFoundError` for an HTTP 404, and a plain `Error` for ordinary network/
 * size/timeout failures. */
export async function fetchGuarded(url: string): Promise<string> {
  const parsed = new URL(url)
  if (parsed.protocol !== 'https:') {
    throw new SsrfBlockedError(`fetchGuarded: refusing non-https URL ${url}`)
  }

  const addresses = await resolvePublicAddresses(parsed.hostname)
  // The first address a real client would try. Pinning to exactly this one
  // (not "any of the checked list") is what removes the TOCTOU window: no
  // second lookup happens between the check above and the connect below, so
  // there is nothing for a short-TTL record or a compromised resolver to
  // answer differently in between.
  const pinned = addresses[0]!

  return fetchCapped(url, pinned)
}

interface ParsedHead { status: number; headers: Record<string, string>; leftover: Buffer }

/** Finds the end of the header block (`\r\n\r\n`) in what's been read so far,
 * and parses the status line + headers if found. Returns null if the head
 * isn't complete yet — the caller keeps reading. */
function tryParseHead(buf: Buffer): ParsedHead | null {
  const sep = buf.indexOf('\r\n\r\n')
  if (sep === -1) return null
  const headText = buf.subarray(0, sep).toString('latin1')
  const lines = headText.split('\r\n')
  const statusLine = lines[0] ?? ''
  const statusMatch = /^HTTP\/1\.[01] (\d{3})/.exec(statusLine)
  const status = statusMatch ? Number(statusMatch[1]) : 0
  const headers: Record<string, string> = {}
  for (const line of lines.slice(1)) {
    const idx = line.indexOf(':')
    if (idx === -1) continue
    headers[line.slice(0, idx).trim().toLowerCase()] = line.slice(idx + 1).trim()
  }
  return { status, headers, leftover: buf.subarray(sep + 4) }
}

/** Decodes an HTTP/1.1 chunked-transfer body from a growing buffer,
 * consuming complete chunks as they arrive. Returns the decoded bytes so
 * far and whether the terminating `0\r\n\r\n` chunk has been seen; the
 * caller re-calls this as more data arrives, each time with the FULL
 * remaining unconsumed buffer (chunk boundaries rarely land on TCP packet
 * boundaries, so partial chunks are ordinary, not an error). */
function decodeChunked(buf: Buffer): { decoded: Buffer; rest: Buffer; done: boolean } {
  const decoded: Buffer[] = []
  let rest = buf
  for (;;) {
    const lineEnd = rest.indexOf('\r\n')
    if (lineEnd === -1) break // size line not fully arrived yet
    const sizeLine = rest.subarray(0, lineEnd).toString('latin1').split(';')[0]!.trim()
    const size = parseInt(sizeLine, 16)
    if (!Number.isFinite(size)) throw new Error(`decodeChunked: malformed chunk size ${JSON.stringify(sizeLine)}`)
    if (size === 0) return { decoded: Buffer.concat(decoded), rest: Buffer.alloc(0), done: true }
    const chunkStart = lineEnd + 2
    const chunkEnd = chunkStart + size
    if (rest.length < chunkEnd + 2) break // chunk body not fully arrived yet
    decoded.push(rest.subarray(chunkStart, chunkEnd))
    rest = rest.subarray(chunkEnd + 2) // skip the trailing \r\n after chunk data
  }
  return { decoded: Buffer.concat(decoded), rest, done: false }
}

/** The pinned-connection, size-capped, timed-out, 404-distinguishing fetch —
 * a raw HTTP/1.1 client over `node:tls`/`node:net`, not `fetch()` or
 * `node:https`: both were verified (against this actual Bun runtime) to
 * ignore any attempt to control which address they connect to, which is the
 * one thing this function exists to control. Split out from [`fetchGuarded`]
 * so a test can exercise it directly against a same-process HTTP server
 * (which the address check would otherwise always reject — a test server is
 * loopback by construction), and so a caller that already resolved+checked
 * an address (as `fetchGuarded` does) doesn't pay for a second lookup.
 * `pinnedAddress` is optional: when omitted, this connects however Node's
 * own resolver would (ordinary DNS, no pinning) — the shape a test wants,
 * never what a real SSRF-guarded call site should pass. Exported for that
 * reason alone; every real call site goes through `fetchGuarded`, never
 * this directly with `pinnedAddress` omitted — skipping the address check
 * outside a test is the exact mistake this module exists to prevent. */
export async function fetchCapped(url: string, pinnedAddress?: { address: string; family: number }): Promise<string> {
  const parsed = new URL(url)
  const isHttps = parsed.protocol === 'https:'
  const port = parsed.port ? Number(parsed.port) : (isHttps ? 443 : 80)
  const connectHost = pinnedAddress?.address ?? parsed.hostname
  const path = parsed.pathname + parsed.search

  return new Promise<string>((resolve, reject) => {
    let socket: Socket | TLSSocket
    let settled = false
    const finish = (fn: () => void) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      fn()
    }

    const timer = setTimeout(() => {
      finish(() => { socket.destroy(); reject(new Error(`fetchCapped: timed out after ${TIMEOUT_MS}ms fetching ${url}`)) })
    }, TIMEOUT_MS)

    const onConnect = () => {
      socket.write(`GET ${path} HTTP/1.1\r\nHost: ${parsed.hostname}\r\nConnection: close\r\nAccept: */*\r\n\r\n`)
    }

    socket = isHttps
      ? tlsConnect({ host: connectHost, port, servername: parsed.hostname }, onConnect)
      : netConnect({ host: connectHost, port }, onConnect)

    let buf: Buffer<ArrayBufferLike> = Buffer.alloc(0)
    let head: ParsedHead | null = null
    const bodyChunks: Buffer<ArrayBufferLike>[] = []
    let bodyBytes = 0
    let chunkedRemainder: Buffer<ArrayBufferLike> = Buffer.alloc(0)

    const tooBig = (n: number) => n > MAX_BODY_BYTES

    socket.on('data', (chunk: Buffer) => {
      if (settled) return
      buf = Buffer.concat([buf, chunk])

      if (!head) {
        if (buf.length > MAX_HEADER_BYTES) {
          finish(() => { socket.destroy(); reject(new Error(`fetchCapped: response headers exceed ${MAX_HEADER_BYTES} bytes for ${url}`)) })
          return
        }
        head = tryParseHead(buf)
        if (!head) return // keep buffering until the header block completes
        buf = head.leftover
      }

      const isChunked = (head.headers['transfer-encoding'] ?? '').toLowerCase().includes('chunked')
      if (isChunked) {
        chunkedRemainder = Buffer.concat([chunkedRemainder, buf])
        buf = Buffer.alloc(0)
        const { decoded, rest, done } = decodeChunked(chunkedRemainder)
        chunkedRemainder = rest
        bodyBytes += decoded.length
        if (tooBig(bodyBytes)) {
          finish(() => { socket.destroy(); reject(new Error(`fetchCapped: response body exceeds ${MAX_BODY_BYTES} bytes for ${url}`)) })
          return
        }
        bodyChunks.push(decoded)
        if (done) {
          finish(() => resolveBody())
        }
      } else {
        bodyChunks.push(buf)
        bodyBytes += buf.length
        buf = Buffer.alloc(0)
        if (tooBig(bodyBytes)) {
          finish(() => { socket.destroy(); reject(new Error(`fetchCapped: response body exceeds ${MAX_BODY_BYTES} bytes for ${url}`)) })
          return
        }
        const contentLength = head.headers['content-length'] ? Number(head.headers['content-length']) : null
        if (contentLength !== null && bodyBytes >= contentLength) {
          finish(() => resolveBody())
        }
      }
    })

    function resolveBody(): void {
      if (!head) {
        reject(new Error(`fetchCapped: connection closed before headers arrived for ${url}`))
        return
      }
      if (head.status === 404) {
        reject(new NotFoundError(`fetchCapped: 404 fetching ${url}`))
        return
      }
      if (head.status < 200 || head.status >= 300) {
        reject(new Error(`fetchCapped: HTTP ${head.status} fetching ${url}`))
        return
      }
      resolve(Buffer.concat(bodyChunks).toString('utf-8'))
    }

    socket.on('end', () => {
      // A non-chunked response with no Content-Length ends when the server
      // closes the connection — that's a legitimate finish, not an error,
      // for `Connection: close` (which every request here sends).
      finish(() => resolveBody())
    })
    socket.on('error', (e: Error) => {
      finish(() => reject(new Error(`fetchCapped: ${e.message} fetching ${url}`)))
    })
  })
}
