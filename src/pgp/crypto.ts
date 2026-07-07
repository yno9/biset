import * as openpgp from 'openpgp'
import { getKeyRecord } from './keys.ts'
import { buildProtectedHeaders, type GroupOpts } from '../deltachat/protocol.ts'

openpgp.config.aeadProtect = false

const _privKeyCache = new Map<string, openpgp.PrivateKey>()

async function getPrivateKey(email: string): Promise<openpgp.PrivateKey | null> {
  if (_privKeyCache.has(email)) return _privKeyCache.get(email)!
  const record = await getKeyRecord(email)
  if (!record) return null
  const key = await openpgp.readPrivateKey({ armoredKey: record.privateKey })
  _privKeyCache.set(email, key)
  return key
}

// ── Server key helpers ────────────────────────────────────────────────────────

const b64enc = (u: Uint8Array) => btoa(String.fromCharCode(...u))
const b64dec = (s: string) => Uint8Array.from(atob(s), c => c.charCodeAt(0))
const trim = (url: string) => url.replace(/\/$/, '')

export async function fetchEncryptedPrivKey(serverUrl: string, email: string, password: string): Promise<string | null> {
  try {
    const resp = await fetch(`${trim(serverUrl)}/pgp/privkey`, {
      headers: { 'Authorization': 'Basic ' + btoa(email + ':' + password) },
    })
    return resp.ok ? resp.text() : null
  } catch { return null }
}

export async function uploadEncryptedPrivKey(serverUrl: string, email: string, password: string, blob: string): Promise<boolean> {
  try {
    const resp = await fetch(`${trim(serverUrl)}/pgp/privkey`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Basic ' + btoa(email + ':' + password) },
      body: blob,
    })
    return resp.ok
  } catch { return false }
}

export async function uploadPublicKey(serverUrl: string, email: string, password: string, armoredKey: string): Promise<boolean> {
  try {
    const resp = await fetch(`${trim(serverUrl)}/pgp/pubkey`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/pgp-keys', 'Authorization': 'Basic ' + btoa(email + ':' + password) },
      body: armoredKey,
    })
    return resp.ok
  } catch { return false }
}

// ── KEK envelope for private key ──────────────────────────────────────────────

async function importKEK(kek: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', kek as BufferSource, 'AES-GCM', false, ['encrypt', 'decrypt'])
}

export async function encryptPrivKey(armoredKey: string, kek: Uint8Array, email: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const aesKey = await importKEK(kek)
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(email) },
    aesKey, new TextEncoder().encode(armoredKey),
  )
  return JSON.stringify({ iv: b64enc(iv), ct: b64enc(new Uint8Array(ct)) })
}

export async function decryptPrivKey(blob: string, kek: Uint8Array, email: string): Promise<string | null> {
  try {
    const { iv: iv64, ct: ct64 } = JSON.parse(blob)
    const aesKey = await importKEK(kek)
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64dec(iv64), additionalData: new TextEncoder().encode(email) },
      aesKey, b64dec(ct64),
    )
    return new TextDecoder().decode(plain)
  } catch { return null }
}

// ── Recipient key (WKD / server cache) ───────────────────────────────────────

async function wkdHash(localpart: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(localpart.toLowerCase()))
  const alpha = 'ybndrfg8ejkmcpqxot1uwisza345h769'
  const bytes = new Uint8Array(buf)
  let result = '', cur = 0, bits = 0
  for (const b of bytes) {
    cur = (cur << 8) | b; bits += 8
    while (bits >= 5) { bits -= 5; result += alpha[(cur >> bits) & 0x1f] }
  }
  if (bits > 0) result += alpha[(cur << (5 - bits)) & 0x1f]
  return result
}

// Stores a peer's public key (raw binary transferable key) in the server's peer
// key store so encryptText can later fetch it. Used to learn keys from Autocrypt
// headers found inside decrypted messages (chatmail/DeltaChat hide Autocrypt in
// the encrypted part, so the server never sees it on the wire).
export async function uploadPeerKey(recipientEmail: string, keyBinary: Uint8Array, senderEmail: string, serverUrl: string, authToken: string): Promise<void> {
  try {
    await openpgp.readKeys({ binaryKeys: keyBinary })  // validate
    await fetch(`${trim(serverUrl)}/pgp/peerkey?addr=${encodeURIComponent(recipientEmail)}`, {
      method: 'PUT',
      headers: { 'Authorization': 'Basic ' + btoa(senderEmail + ':' + authToken), 'Content-Type': 'application/octet-stream' },
      body: keyBinary as BufferSource,
    })
  } catch {}
}

export async function prefetchRecipientKey(recipientEmail: string, senderEmail: string, serverUrl: string, authToken: string): Promise<void> {
  try {
    const [localpart, domain] = recipientEmail.split('@')
    if (!localpart || !domain) return
    const hash = await wkdHash(localpart)
    const resp = await fetch(`https://${domain}/.well-known/openpgpkey/hu/${hash}?l=${encodeURIComponent(localpart)}`)
    if (!resp.ok) return
    const binary = new Uint8Array(await resp.arrayBuffer())
    if (!binary.length) return
    await openpgp.readKeys({ binaryKeys: binary })
    await fetch(`${trim(serverUrl)}/pgp/peerkey?addr=${encodeURIComponent(recipientEmail)}`, {
      method: 'PUT',
      headers: { 'Authorization': 'Basic ' + btoa(senderEmail + ':' + authToken), 'Content-Type': 'application/octet-stream' },
      body: binary,
    })
  } catch {}
}

async function fetchRecipientPublicKey(recipientEmail: string, serverUrl: string, senderEmail: string, authToken: string): Promise<openpgp.PublicKey | null> {
  try {
    const resp = await fetch(`${trim(serverUrl)}/pgp/peerkey?addr=${encodeURIComponent(recipientEmail)}`, {
      headers: { 'Authorization': 'Basic ' + btoa(senderEmail + ':' + authToken) },
    })
    if (!resp.ok) return null
    const binary = new Uint8Array(await resp.arrayBuffer())
    if (!binary.length) return null
    const keys = await openpgp.readKeys({ binaryKeys: binary })
    return keys[0] ?? null
  } catch { return null }
}

// ── Encrypt / Decrypt ─────────────────────────────────────────────────────────

export async function encryptText(
  text: string, recipientEmails: string | string[], senderEmail: string,
  serverUrl: string, authToken: string, inReplyTo = '',
  groupOpts?: GroupOpts,
  bccEmails: string[] = [],
): Promise<string | null> {
  try {
    const recipients = Array.isArray(recipientEmails) ? recipientEmails : [recipientEmails]
    const record = await getKeyRecord(senderEmail)
    if (!record) return null
    const recipientKeys = await Promise.all(
      recipients.map(e => fetchRecipientPublicKey(e, serverUrl, senderEmail, authToken))
    )
    if (recipientKeys.some(k => k == null)) return null
    // Bcc recipients must be able to decrypt too, so their keys go into
    // encryptionKeys — but they are deliberately kept OUT of `recipients`, so
    // buildProtectedHeaders never gossips their address to the visible ones
    // (that would defeat Bcc). If any Bcc key is missing we bail to plaintext,
    // same as for To/Cc.
    const bccKeys = await Promise.all(
      bccEmails.map(e => fetchRecipientPublicKey(e, serverUrl, senderEmail, authToken))
    )
    if (bccKeys.some(k => k == null)) return null
    const senderPrivKey = await openpgp.readPrivateKey({ armoredKey: record.privateKey })
    const senderPubKey = await openpgp.readKey({ armoredKey: record.publicKey })
    // DeltaChat protocol headers (Chat-Version, group id/name, Autocrypt-Gossip)
    // are built by the deltachat/ layer and embedded INSIDE the encrypted MIME.
    const protectedHeaders = buildProtectedHeaders(recipients, recipientKeys, groupOpts, senderEmail)
    const headers =
      'Content-Type: text/plain; charset=utf-8\r\n' +
      'Content-Transfer-Encoding: 8bit\r\n' +
      protectedHeaders +
      (inReplyTo ? `In-Reply-To: <${inReplyTo}>\r\n` : '') +
      '\r\n'
    const mimeWrapped = headers + text
    const encrypted = await openpgp.encrypt({
      message: await openpgp.createMessage({ text: mimeWrapped }),
      encryptionKeys: [...recipientKeys as any[], ...bccKeys as any[], senderPubKey],
      signingKeys: senderPrivKey,
    })
    return encrypted as string
  } catch { return null }
}

// ── Securejoin (DeltaChat v3) symmetric + generic E2E helpers ──────────────────
// vc-request-pubkey / vc-pubkey are password-encrypted (SEIPDv2 / AEAD-OCB /
// AES128) with `securejoin/<alice_fp>/<auth>` as the shared secret. DeltaChat's
// symm_encrypt_message uses exactly this cipher suite, so we must emit AEAD-OCB
// (biset's global aeadProtect is off for normal E2E, hence per-call config).
const SYMM_CONFIG: openpgp.Config = {
  ...openpgp.config,
  aeadProtect: true,
  preferredAEADAlgorithm: openpgp.enums.aead.ocb,
  preferredSymmetricAlgorithm: openpgp.enums.symmetric.aes128,
}

// OpenPGP CRC-24 (RFC 9580 §6.1) over the raw packet bytes.
function crc24(bytes: Uint8Array): number {
  let crc = 0xb704ce
  for (const b of bytes) {
    crc ^= b << 16
    for (let i = 0; i < 8; i++) {
      crc <<= 1
      if (crc & 0x1000000) crc ^= 0x1864cfb
    }
  }
  return crc & 0xffffff
}

// openpgp.js omits the ASCII-armor CRC-24 checksum for AEAD (SEIPD v2) messages.
// chatmail's filtermail assumes the checksum line is always present and strips
// everything after the last '=' — with no checksum it eats the base64 padding,
// the payload fails to decode, and the message is rejected as "unencrypted"
// (523). DeltaChat's rPGP emits the checksum, so we add it back to match.
export function ensureArmorChecksum(armored: string): string {
  const lines = armored.replace(/\r\n/g, '\n').split('\n')
  const begin = lines.findIndex(l => l.startsWith('-----BEGIN PGP MESSAGE-----'))
  const end = lines.findIndex(l => l.startsWith('-----END PGP MESSAGE-----'))
  if (begin < 0 || end < 0) return armored
  // Already has a checksum line (`=XXXX`) right before END?
  if (/^=[A-Za-z0-9+/]{4}$/.test(lines[end - 1] ?? '')) return armored
  // Body base64 = lines after the blank line that separates armor headers.
  let blank = begin + 1
  while (blank < end && lines[blank].trim() !== '') blank++
  const b64 = lines.slice(blank + 1, end).join('').replace(/\s/g, '')
  if (!b64) return armored
  let bytes: Uint8Array
  try { bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0)) } catch { return armored }
  const crc = crc24(bytes)
  const crcLine = '=' + btoa(String.fromCharCode((crc >> 16) & 0xff, (crc >> 8) & 0xff, crc & 0xff))
  const nl = armored.includes('\r\n') ? '\r\n' : '\n'
  const outLines = [...lines.slice(0, end), crcLine, ...lines.slice(end)]
  return outLines.join(nl)
}

function extractArmored(text: string): string {
  const start = text.indexOf('-----BEGIN PGP MESSAGE-----')
  const end = text.indexOf('-----END PGP MESSAGE-----')
  return (start >= 0 && end >= 0) ? text.slice(start, end + 25) : text
}

// Tries each candidate password to decrypt a symmetric securejoin message.
export async function symmDecryptMime(ciphertext: string, passwords: string[]): Promise<DecryptedMime | null> {
  const armored = extractArmored(ciphertext)
  for (const pw of passwords) {
    try {
      const message = await openpgp.readMessage({ armoredMessage: armored })
      const { data } = await openpgp.decrypt({ message, passwords: [pw], config: SYMM_CONFIG })
      return parseMIME(data as string)
    } catch { /* wrong password / not symmetric */ }
  }
  return null
}

// Salted S2K (RFC 9580 §3.7.1.2): key = H(salt || passphrase), truncated to the
// cipher key length. AES-128 (16 bytes) < SHA-256 (32 bytes), so one hash pass.
async function saltedS2K(salt: Uint8Array, password: string): Promise<Uint8Array> {
  const pw = new TextEncoder().encode(password)
  const buf = new Uint8Array(salt.length + pw.length)
  buf.set(salt); buf.set(pw, salt.length)
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', buf as BufferSource))
  return hash.slice(0, 16)
}

// Skips the first OpenPGP packet (a new-format packet) and returns the rest.
function stripFirstPacket(bytes: Uint8Array): Uint8Array {
  const b1 = bytes[1]
  let off = 1, len = 0
  if (b1 < 192) { len = b1; off += 1 }
  else if (b1 < 224) { len = ((b1 - 192) << 8) + bytes[2] + 192; off += 2 }
  else if (b1 === 255) { len = (bytes[2] << 24) | (bytes[3] << 16) | (bytes[4] << 8) | bytes[5]; off += 4 }
  return bytes.slice(off + len)
}

// Password-encrypts + signs a pre-built inner MIME (securejoin vc-pubkey step).
//
// DeltaChat's `check_symmetric_encryption` (decrypt.rs) only accepts a SKESK with
// a *Salted* S2K, but openpgp.js exclusively emits *Iterated* S2K for password
// encryption and rejects `s2kType: salted` outright. So we build the message by
// hand: derive the session key K = saltedS2K(salt, password), have openpgp.js
// produce a SEIPDv1 with exactly that session key, discard its Iterated SKESK,
// and prepend our own v4 SKESK (Salted S2K, AES-128, no encrypted session key —
// so rPGP derives the same K from the password). Matches DeltaChat's wire format
// closely enough that rPGP decrypts and verifies it.
export async function symmEncryptSignMime(innerMime: string, password: string, signEmail: string): Promise<string | null> {
  try {
    const record = await getKeyRecord(signEmail)
    if (!record) return null
    const signKey = await openpgp.readPrivateKey({ armoredKey: record.privateKey })
    const salt = crypto.getRandomValues(new Uint8Array(8))
    const sessionKey = await saltedS2K(salt, password)
    const enc = await openpgp.encrypt({
      message: await openpgp.createMessage({ text: innerMime }),
      sessionKey: { data: sessionKey, algorithm: 'aes128' },
      passwords: ['x'], // discarded; forces openpgp.js to emit a (stripped) SKESK
      signingKeys: signKey,
      config: { ...openpgp.config, aeadProtect: false },
      format: 'binary',
    }) as Uint8Array
    const seipd = stripFirstPacket(new Uint8Array(enc))
    // v4 SKESK: version 4, AES-128 (7), Salted S2K (type 1) w/ SHA-256 (8) + salt.
    const skeskBody = new Uint8Array([0x04, 0x07, 0x01, 0x08, ...salt])
    const skesk = new Uint8Array([0xc3, skeskBody.length, ...skeskBody])
    const full = new Uint8Array([...skesk, ...seipd])
    const armored = openpgp.armor(openpgp.enums.armor.message, full)
    return ensureArmorChecksum(armored)
  } catch (e) { console.log('[pgp] symmEncryptSignMime failed', e); return null }
}

// E2E-encrypts + signs a pre-built inner MIME to explicit recipient keys.
// Unlike encryptText this adds no protected headers of its own, so the caller
// controls the exact inner MIME (securejoin needs custom Secure-Join + gossip).
export async function encryptMimeE2E(innerMime: string, recipientKeys: openpgp.PublicKey[], signEmail: string): Promise<string | null> {
  try {
    const record = await getKeyRecord(signEmail)
    if (!record) return null
    const signKey = await openpgp.readPrivateKey({ armoredKey: record.privateKey })
    const selfPub = await openpgp.readKey({ armoredKey: record.publicKey })
    return await openpgp.encrypt({
      message: await openpgp.createMessage({ text: innerMime }),
      encryptionKeys: [...recipientKeys, selfPub],
      signingKeys: signKey,
    }) as string
  } catch { return null }
}

// Fetches a recipient's public key from the server peer-key store.
export async function getRecipientKey(recipientEmail: string, serverUrl: string, senderEmail: string, authToken: string): Promise<openpgp.PublicKey | null> {
  return fetchRecipientPublicKey(recipientEmail, serverUrl, senderEmail, authToken)
}

export interface MimeAttachment { contentType: string; filename?: string; bytes: Uint8Array }
export interface DecryptedMime { body: string; inReplyTo?: string; references?: string[]; messageId?: string; headers?: Record<string, string>; gossip?: string[]; attachments?: MimeAttachment[] }

export async function decryptAndParse(ciphertext: string, email: string): Promise<DecryptedMime | null> {
  try {
    const privateKey = await getPrivateKey(email)
    if (!privateKey) { console.log('[pgp] no privkey for', email); return null }
    // biset-old pgp.go:250 と同じく BEGIN/END 範囲を抜き出してから decode (前後のゴミで失敗するのを防ぐ)。
    const start = ciphertext.indexOf('-----BEGIN PGP MESSAGE-----')
    const endMarker = '-----END PGP MESSAGE-----'
    const endIdx = ciphertext.indexOf(endMarker)
    const armored = (start >= 0 && endIdx >= 0)
      ? ciphertext.slice(start, endIdx + endMarker.length)
      : ciphertext
    const message = await openpgp.readMessage({ armoredMessage: armored })
    const { data } = await openpgp.decrypt({ message, decryptionKeys: privateKey })
    return parseMIME(data as string)
  } catch (e) { console.log('[pgp] decrypt failed', email, e); return null }
}

export async function decryptText(ciphertext: string, email: string): Promise<string | null> {
  const res = await decryptAndParse(ciphertext, email)
  return res ? res.body : null
}

function parseMIME(text: string): DecryptedMime {
  const firstLine = text.split(/\r?\n/, 1)[0]
  if (!firstLine || !/^[A-Za-z][\w-]*:\s/.test(firstLine)) return { body: text }
  const sep = text.match(/\r?\n\r?\n/)
  if (!sep || sep.index === undefined) return { body: text }
  const out: DecryptedMime = { body: '', headers: {} }
  parseEntity(out, text, true)
  return out
}

// Unfolds a MIME header block (RFC 5322 continuation lines) into logical lines.
function unfoldHeaders(headerBlock: string): string[] {
  const lines: string[] = []
  for (const line of headerBlock.split(/\r?\n/)) {
    if (line && /^[ \t]/.test(line) && lines.length) lines[lines.length - 1] += ' ' + line.trim()
    else lines.push(line)
  }
  return lines
}

// Splits a multipart body on its boundary into raw part texts (preamble and the
// closing `--boundary--` epilogue dropped).
function splitMultipart(body: string, boundary: string): string[] {
  const parts: string[] = []
  const chunks = body.split('--' + boundary)
  for (let i = 1; i < chunks.length; i++) {
    const c = chunks[i]
    if (c.startsWith('--')) break // closing delimiter
    parts.push(c.replace(/^\r?\n/, '').replace(/\r?\n$/, ''))
  }
  return parts
}

function base64ToBytes(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64.replace(/[\r\n\s]/g, '')), c => c.charCodeAt(0))
}

// Recursively parses one MIME entity into `out`. Top-level protected headers
// (Chat-*, Autocrypt(-Gossip), In-Reply-To, ...) are captured only at the root
// (topLevel). multipart entities recurse into their parts; the first text/* leaf
// becomes the body, other leaves are collected as attachments (used by DeltaChat
// avatar extraction — see deltachat/avatar.ts).
function parseEntity(out: DecryptedMime, text: string, topLevel: boolean): void {
  const sep = text.match(/\r?\n\r?\n/)
  const headerBlock = sep && sep.index !== undefined ? text.slice(0, sep.index) : ''
  const body = sep && sep.index !== undefined ? text.slice(sep.index + sep[0].length) : text

  let cte = '', charset = 'utf-8', ct = '', disposition = '', filename = ''
  for (const line of unfoldHeaders(headerBlock)) {
    const m = line.match(/^([A-Za-z][\w-]*):\s*(.*)$/)
    if (!m) continue
    const name = m[1].toLowerCase(), value = m[2].trim()
    if (topLevel && name === 'autocrypt-gossip') { (out.gossip ??= []).push(value); continue }
    if (topLevel) {
      out.headers![name] = value
      if (name === 'in-reply-to') out.inReplyTo = value.replace(/^<|>$/g, '')
      else if (name === 'references') out.references = value.split(/\s+/).map(r => r.replace(/^<|>$/g, '')).filter(Boolean)
      else if (name === 'message-id') out.messageId = value.replace(/^<|>$/g, '')
    }
    if (name === 'content-transfer-encoding') cte = value.toLowerCase()
    else if (name === 'content-type') {
      ct = value
      const cs = value.match(/charset=["']?([^"';\s]+)/i); if (cs) charset = cs[1].toLowerCase()
      const fn = value.match(/name="?([^"';]+)"?/i); if (fn) filename = fn[1].trim()
    } else if (name === 'content-disposition') {
      disposition = value.toLowerCase()
      const fn = value.match(/filename="?([^"';]+)"?/i); if (fn) filename = fn[1].trim()
    }
  }

  const boundary = ct.match(/boundary="?([^";]+)"?/i)?.[1]
  if (/^multipart\//i.test(ct) && boundary) {
    for (const part of splitMultipart(body, boundary)) parseEntity(out, part, false)
    return
  }

  const isText = ct === '' || /^text\//i.test(ct)
  if (isText && !disposition.includes('attachment')) {
    if (!out.body) {
      out.body = cte === 'base64' ? decodeBase64Body(body, charset)
        : cte === 'quoted-printable' ? decodeQuotedPrintable(body, charset)
        : body
    }
  } else {
    const bytes = cte === 'base64' ? base64ToBytes(body) : new TextEncoder().encode(body)
    ;(out.attachments ??= []).push({ contentType: ct.split(';')[0].trim(), filename: filename || undefined, bytes })
  }
}

function decodeBase64Body(b64: string, charset: string): string {
  try {
    const bytes = Uint8Array.from(atob(b64.replace(/[\r\n\s]/g, '')), c => c.charCodeAt(0))
    return new TextDecoder(charset).decode(bytes)
  } catch { return b64 }
}

function decodeQuotedPrintable(qp: string, charset: string): string {
  try {
    const collapsed = qp.replace(/=\r?\n/g, '')
    const bytes: number[] = []
    for (let i = 0; i < collapsed.length; i++) {
      const c = collapsed[i]!
      if (c === '=' && i + 2 < collapsed.length) {
        const hex = collapsed.slice(i + 1, i + 3)
        if (/^[0-9A-Fa-f]{2}$/.test(hex)) { bytes.push(parseInt(hex, 16)); i += 2; continue }
      }
      bytes.push(c.charCodeAt(0))
    }
    return new TextDecoder(charset).decode(new Uint8Array(bytes))
  } catch { return qp }
}
