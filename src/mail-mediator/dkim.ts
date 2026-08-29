// DKIM (RFC 6376) signature verification -- used to gate the "known
// counterpart" allowlist (a spoofed From must not be able to plant an
// entry an attacker later sends mail to themselves through). Deliberately
// narrow: relaxed/relaxed canonicalization only (the overwhelming
// majority of real-world senders use it; anything claiming
// simple canonicalization is treated as unverifiable, not specially
// supported), rsa-sha256 and ed25519-sha256 (RFC 8463) only, no `l=` body
// length limit support (a real-world abuse vector for hiding appended
// content -- rejected outright rather than honored).
//
// Works on the raw message as a Latin-1 string throughout (one code unit
// per octet) rather than decoding as UTF-8: DKIM canonicalization is an
// OCTET-level transform, and round-tripping through UTF-8 would silently
// corrupt any header/body byte above 0x7f. This is the same reasoning
// mail-smtp-protocol.ts's own header comment gives for treating DATA as
// opaque bytes throughout.
import { sha256 } from '@noble/hashes/sha2.js'
import { ed25519 } from '@noble/curves/ed25519.js'

export interface DkimVerifiedSignature {
  domain: string
  selector: string
  algorithm: 'rsa-sha256' | 'ed25519-sha256'
}

export interface DkimVerifyOptions {
  /** Injectable for tests; defaults to real DNS. Returns TXT record value
   * strings for the queried name (each entry is a full record, already
   * joined if it was split across multiple `<character-string>`s), or an
   * empty array if the name has no TXT records / doesn't resolve. */
  resolveTxt?: (name: string) => Promise<string[]>
}

const SUPPORTED_ALGORITHMS = new Set(['rsa-sha256', 'ed25519-sha256'])

/** Verifies every DKIM-Signature header present and returns one entry per
 * signature that verified successfully (an unparseable, unsupported, or
 * cryptographically invalid signature is silently skipped, never thrown
 * -- a message can carry several signatures, and one bad one must not
 * poison the others). Callers that want spoofing resistance for a
 * specific header (e.g. From) must additionally check DKIM ALIGNMENT
 * themselves: that some returned signature's `domain` matches (or is a
 * parent of) the address they care about. Verifying a signature proves
 * only "this exact domain signed this exact message", never anything
 * about which header claims to be from whom. */
export async function verifyDkimSignatures(rawRfc5322: Uint8Array, options: DkimVerifyOptions = {}): Promise<DkimVerifiedSignature[]> {
  const resolveTxt = options.resolveTxt ?? defaultResolveTxt
  const text = bytesToLatin1(rawRfc5322)
  const split = splitHeadersAndBody(text)
  if (!split) return []
  const headers = parseHeaders(split.headerSection)
  const signatureHeaders = headers.filter(h => h.name.toLowerCase() === 'dkim-signature')

  const results: DkimVerifiedSignature[] = []
  for (const signatureHeader of signatureHeaders) {
    try {
      const verified = await verifyOneSignature(signatureHeader, headers, split.body, resolveTxt)
      if (verified) results.push(verified)
    } catch { /* one bad signature must not affect the others */ }
  }
  return results
}

async function verifyOneSignature(
  signatureHeader: RawHeader, allHeaders: RawHeader[], body: string, resolveTxt: (name: string) => Promise<string[]>,
): Promise<DkimVerifiedSignature | null> {
  const tags = parseTags(signatureHeader.value)
  if (tags.get('v') !== '1') return null
  const algorithm = tags.get('a')
  if (!algorithm || !SUPPORTED_ALGORITHMS.has(algorithm)) return null
  // `c=` defaults to "simple/simple" when absent -- explicitly out of
  // scope (header comment), so an absent or non-"relaxed/relaxed" value
  // is treated the same as unsupported.
  if (tags.get('c') !== 'relaxed/relaxed') return null
  if (tags.has('l')) return null // body length limit: rejected outright, see header comment
  const domain = tags.get('d')
  const selector = tags.get('s')
  const hTag = tags.get('h')
  const bhTag = tags.get('bh')
  const bTag = tags.get('b')
  if (!domain || !selector || !hTag || !bhTag || !bTag || !isDomainName(domain) || !isSelector(selector)) return null

  const bodyHash = sha256(latin1ToBytes(canonicalizeBodyRelaxed(body)))
  let expectedBodyHash: Uint8Array
  try { expectedBodyHash = base64ToBytes(bhTag) } catch { return null }
  if (!timingSafeEqual(bodyHash, expectedBodyHash)) return null

  const headerNames = hTag.split(':').map(name => name.trim()).filter(Boolean)
  // DKIM-Signature itself must be in `h=` per RFC 6376 §5.4, and is
  // always the LAST line of the signing input, with its own `b=` value
  // emptied and with no trailing CRLF after it.
  const signedLines = selectSignedHeaders(allHeaders, headerNames).filter((h): h is RawHeader => !!h).map(canonicalizeHeaderRelaxed)
  signedLines.push(canonicalizeHeaderRelaxed({ name: signatureHeader.name, value: emptyBTag(signatureHeader.value) }))
  const signingInput = latin1ToBytes(signedLines.join('\r\n'))

  let signature: Uint8Array
  try { signature = base64ToBytes(bTag) } catch { return null }

  const keyRecord = await lookupPublicKey(selector, domain, resolveTxt)
  if (!keyRecord) return null
  if (keyRecord.keyType === 'rsa' && algorithm !== 'rsa-sha256') return null
  if (keyRecord.keyType === 'ed25519' && algorithm !== 'ed25519-sha256') return null

  const valid = keyRecord.keyType === 'rsa'
    ? await verifyRsaSha256(keyRecord.publicKey, signingInput, signature)
    : verifyEd25519(keyRecord.publicKey, signingInput, signature)
  if (!valid) return null

  return { domain, selector, algorithm: algorithm as 'rsa-sha256' | 'ed25519-sha256' }
}

// ---- key lookup ----

interface DkimPublicKeyRecord { keyType: 'rsa' | 'ed25519'; publicKey: Uint8Array }

async function lookupPublicKey(selector: string, domain: string, resolveTxt: (name: string) => Promise<string[]>): Promise<DkimPublicKeyRecord | null> {
  const name = `${selector}._domainkey.${domain}`
  let records: string[]
  try { records = await resolveTxt(name) } catch { return null }
  for (const record of records) {
    const tags = parseTags(record)
    if (tags.get('v') && tags.get('v') !== 'DKIM1') continue
    const p = tags.get('p')
    if (p === undefined) continue
    if (p === '') return null // explicitly revoked key (RFC 6376 §3.6.1)
    const keyType = tags.get('k') ?? 'rsa'
    if (keyType !== 'rsa' && keyType !== 'ed25519') continue
    try {
      const publicKey = base64ToBytes(p)
      if (keyType === 'ed25519' && publicKey.length !== 32) continue
      return { keyType, publicKey }
    } catch { continue }
  }
  return null
}

async function defaultResolveTxt(name: string): Promise<string[]> {
  const { resolveTxt } = await import('node:dns/promises')
  const records = await resolveTxt(name)
  return records.map(chunks => chunks.join(''))
}

// ---- signature verification primitives ----

async function verifyRsaSha256(publicKeySpki: Uint8Array, message: Uint8Array, signature: Uint8Array): Promise<boolean> {
  let key: CryptoKey
  try {
    key = await crypto.subtle.importKey('spki', owned(publicKeySpki), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify'])
  } catch { return false }
  try {
    return await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, owned(signature), owned(message))
  } catch { return false }
}

function owned(value: Uint8Array): ArrayBuffer { return value.slice().buffer }

function verifyEd25519(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  try { return ed25519.verify(signature, message, publicKey) } catch { return false }
}

// ---- canonicalization (relaxed only, RFC 6376 §3.4.2/§3.4.3) ----

export interface RawHeader { name: string; value: string }

/** Splits the CRLF-separated header block into (name, raw value) pairs,
 * folding continuation lines into the PREVIOUS header's value verbatim
 * (with their own leading whitespace preserved) -- relaxed
 * canonicalization is what collapses the folding later, not this parse
 * step, matching RFC 6376's own two-stage unfold-then-canonicalize
 * description. */
export function parseHeaders(headerSection: string): RawHeader[] {
  const headers: RawHeader[] = []
  for (const line of headerSection.split('\r\n')) {
    if (/^[ \t]/.test(line) && headers.length > 0) {
      headers[headers.length - 1]!.value += `\r\n${line}`
      continue
    }
    const colon = line.indexOf(':')
    if (colon < 0) continue
    headers.push({ name: line.slice(0, colon), value: line.slice(colon + 1) })
  }
  return headers
}

/** One canonicalized "name:value" line, no trailing CRLF (the caller
 * joins lines with '\r\n' itself). */
export function canonicalizeHeaderRelaxed(header: RawHeader): string {
  const name = header.name.toLowerCase().trim()
  const unfolded = header.value.replace(/\r\n/g, '')
  const collapsed = unfolded.replace(/[ \t]+/g, ' ').trim()
  return `${name}:${collapsed}`
}

export function canonicalizeBodyRelaxed(body: string): string {
  const lines = body.split('\r\n')
  const processed = lines.map(line => line.replace(/[ \t]+/g, ' ').replace(/[ \t]+$/, ''))
  let end = processed.length
  while (end > 0 && processed[end - 1] === '') end--
  if (end === 0) return ''
  return `${processed.slice(0, end).join('\r\n')}\r\n`
}

/** RFC 6376 §5.4.2: `h=` may name a header field more than once, and a
 * repeated name consumes occurrences from the BOTTOM of the header block
 * upward, one per repetition -- not the same occurrence twice. A name
 * absent from the message contributes nothing (skipped, not an empty
 * line). */
function selectSignedHeaders(headers: RawHeader[], headerNames: string[]): Array<RawHeader | undefined> {
  const byName = new Map<string, RawHeader[]>()
  for (const header of headers) {
    const key = header.name.toLowerCase()
    const list = byName.get(key) ?? []
    list.push(header)
    byName.set(key, list)
  }
  const consumed = new Map<string, number>()
  return headerNames.map(name => {
    const key = name.toLowerCase()
    const list = byName.get(key) ?? []
    const count = consumed.get(key) ?? 0
    consumed.set(key, count + 1)
    const index = list.length - 1 - count
    return index >= 0 ? list[index] : undefined
  })
}

/** Empties the `b=` tag's value (up to the next `;` or end of string) --
 * used to canonicalize the DKIM-Signature header itself as part of the
 * signing input, per RFC 6376 §3.7 step 4. `[^;]` matches CRLF too, so a
 * folded (multi-line) base64 value empties correctly in one pass. */
function emptyBTag(value: string): string {
  return value.replace(/(;|^)(\s*b\s*=)[^;]*/, '$1$2')
}

// ---- tag-value list parsing (RFC 6376 §3.2) ----

function parseTags(value: string): Map<string, string> {
  const tags = new Map<string, string>()
  for (const part of value.split(';')) {
    const trimmed = part.trim()
    if (!trimmed) continue
    const eq = trimmed.indexOf('=')
    if (eq < 0) continue
    const key = trimmed.slice(0, eq).trim()
    const raw = trimmed.slice(eq + 1).trim()
    // b=/bh= carry base64 that may be folded across continuation lines --
    // whitespace (including the embedded CRLF this parser's own
    // parseHeaders left in place) is not significant in a tag's value
    // per RFC 6376 §3.2, so it is stripped uniformly for every tag.
    tags.set(key, raw.replace(/\s+/g, ''))
  }
  return tags
}

// ---- small helpers ----

function bytesToLatin1(bytes: Uint8Array): string {
  let out = ''
  for (let i = 0; i < bytes.length; i++) out += String.fromCharCode(bytes[i]!)
  return out
}

function latin1ToBytes(text: string): Uint8Array {
  const out = new Uint8Array(text.length)
  for (let i = 0; i < text.length; i++) out[i] = text.charCodeAt(i) & 0xff
  return out
}

function base64ToBytes(value: string): Uint8Array {
  return Uint8Array.from(atob(value), c => c.charCodeAt(0))
}

function splitHeadersAndBody(text: string): { headerSection: string; body: string } | undefined {
  const index = text.indexOf('\r\n\r\n')
  if (index < 0) return undefined
  return { headerSection: text.slice(0, index), body: text.slice(index + 4) }
}

function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!
  return diff === 0
}

function isDomainName(value: string): boolean {
  return value.length > 0 && value.length <= 253 && /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/.test(value)
}

function isSelector(value: string): boolean {
  return value.length > 0 && value.length <= 253 && /^[a-zA-Z0-9._-]+$/.test(value)
}
