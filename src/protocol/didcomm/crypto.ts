// DIDComm v2 JWE construction, pure TypeScript — no wasm, matches biset's
// single-file/`file://` architecture (ARC.md).
//
// Ported from src.bak/did/didcomm/crypto.ts (that file's own header: every
// construction below — ConcatKDF byte layout, ECDH-1PU's Ze||Zs and
// cc_tag-in-pub_info step, JWE field names — was verified against
// hyperledger/aries-askar's askar-crypto source and against didcomm-rust's
// own jwe/*.ts, not reconstructed from memory. See that file's test vectors
// (draft-madden-jose-ecdh-1pu-04 appendices) for a byte-exact KDF check).
//
// Three algorithms:
//   - authcrypt: ECDH-1PU+A256KW / A256CBC-HS512 — the actual
//     sender-to-recipient message, one sender, every recipient key of the
//     recipient DID (multiplexed encryption).
//   - anoncrypt: ECDH-ES+A256KW / A256CBC-HS512 (we produce) or XC20P (we
//     must also consume — didcomm-rust, the reference implementation and
//     hence most third-party agents, defaults anoncrypt's `enc` to XC20P) —
//     used for Routing Protocol 2.0 Forward wrapping, so a mediator
//     forwarding a message never learns who sent it (ARC.md's DIDComm
//     mediator redesign, 2026-08-27). Re-added here after an earlier version
//     of this rewrite dropped it outright on the grounds that the DIDComm
//     adapter was "first-party infrastructure, not a blind third-party
//     mediator" — since revisited: a genuinely decentralized mediator has to
//     be blind, which needs Forward wrapping to exist.
import { sha256, sha512 } from '@noble/hashes/sha2.js'
import { hmac } from '@noble/hashes/hmac.js'
import { cbc, aeskw, gcm } from '@noble/ciphers/aes.js'
import { generateKeyAgreementKeyPair, jwkOfKeyAgreementKey, keyAgreementKeyFromJwk, keyAgreementSharedSecret, type KeyAgreementCurve } from './key-agreement.ts'
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'

// ── byte helpers ─────────────────────────────────────────────────────────────
function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const len = parts.reduce((n, p) => n + p.length, 0)
  const out = new Uint8Array(len)
  let off = 0
  for (const p of parts) { out.set(p, off); off += p.length }
  return out
}

function u32be(n: number): Uint8Array {
  const b = new Uint8Array(4)
  new DataView(b.buffer).setUint32(0, n, false)
  return b
}

function u64beBits(byteLen: number): Uint8Array {
  const bits = BigInt(byteLen) * 8n
  const b = new Uint8Array(8)
  new DataView(b.buffer).setBigUint64(0, bits, false)
  return b
}

function utf8(s: string): Uint8Array { return new TextEncoder().encode(s) }

export function b64url(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function b64urlToBytes(s: string): Uint8Array {
  const pad = (4 - (s.length % 4)) % 4
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat(pad)
  const bin = atob(b64)
  return Uint8Array.from(bin, c => c.charCodeAt(0))
}

// ── ConcatKDF (NIST SP 800-56A), single-pass SHA-256 ────────────────────────
// Matches askar-crypto's ConcatKDFHash exactly: counter(1) || Z || len(alg)||alg
// || len(apu)||apu || len(apv)||apv || pub_info || prv_info, single SHA-256
// call (our output is always ≤32 bytes, so only one pass is ever needed).
function concatKDF(z: Uint8Array, alg: Uint8Array, apu: Uint8Array, apv: Uint8Array, pubInfo: Uint8Array, outputLen: number): Uint8Array {
  if (outputLen > 32) throw new Error('concatKDF: single-pass output limited to 32 bytes')
  const counter = u32be(1)
  const message = concatBytes(
    counter, z,
    u32be(alg.length), alg,
    u32be(apu.length), apu,
    u32be(apv.length), apv,
    pubInfo,
  )
  return sha256(message).slice(0, outputLen)
}

function ecdh(curve: KeyAgreementCurve, privKey: Uint8Array, pubKey: Uint8Array): Uint8Array {
  return keyAgreementSharedSecret(curve, privKey, pubKey)
}

/** ECDH-1PU key derivation (authcrypt). Ze = ECDH(ephemeral, recipient),
 * Zs = ECDH(sender, recipient) — order matters, Ze is hashed first. Callers
 * on the decrypt side compute the identical Ze/Zs via ECDH's commutativity
 * (ECDH(myPriv, theirPub) === ECDH(theirPriv, myPub)), so this function is
 * shared by both encrypt and decrypt. */
function deriveEcdh1PU(ze: Uint8Array, zs: Uint8Array, alg: string, apu: Uint8Array, apv: Uint8Array, ccTag: Uint8Array, outputLenBits: number): Uint8Array {
  const z = concatBytes(ze, zs)
  let pubInfo = u32be(outputLenBits)
  if (ccTag.length > 0) pubInfo = concatBytes(pubInfo, u32be(ccTag.length), ccTag)
  return concatKDF(z, utf8(alg), apu, apv, pubInfo, outputLenBits / 8)
}

/** ECDH-ES key derivation (anoncrypt). `z` = ECDH(ephemeral, recipient) --
 * no sender term at all, unlike ECDH-1PU: that is the whole point of
 * anoncrypt, the recipient learns nothing about who encrypted this. */
function deriveEcdhEs(z: Uint8Array, alg: string, apu: Uint8Array, apv: Uint8Array, outputLenBits: number): Uint8Array {
  const pubInfo = u32be(outputLenBits)
  return concatKDF(z, utf8(alg), apu, apv, pubInfo, outputLenBits / 8)
}

// ── AES-KW (RFC 3394) ────────────────────────────────────────────────────────
function wrapKey(kek: Uint8Array, cek: Uint8Array): Uint8Array { return aeskw(kek).encrypt(cek) }
function unwrapKey(kek: Uint8Array, wrapped: Uint8Array): Uint8Array { return aeskw(kek).decrypt(wrapped) }

// ── A256CBC-HS512 (RFC 7518 §5.2.3, AES_256_CBC_HMAC_SHA_512) ──────────────
// cek = MAC_KEY(32) || ENC_KEY(32). tag = first 32 bytes of
// HMAC-SHA-512(MAC_KEY, AAD || IV || Ciphertext || AL), AL = 8-byte
// big-endian bit-length of AAD.
function aesCbcHs512Encrypt(cek: Uint8Array, iv: Uint8Array, aad: Uint8Array, plaintext: Uint8Array): { ciphertext: Uint8Array; tag: Uint8Array } {
  const macKey = cek.slice(0, 32)
  const encKey = cek.slice(32, 64)
  const ciphertext = cbc(encKey, iv).encrypt(plaintext)
  const mac = hmac(sha512, macKey, concatBytes(aad, iv, ciphertext, u64beBits(aad.length)))
  return { ciphertext, tag: mac.slice(0, 32) }
}

function aesCbcHs512Decrypt(cek: Uint8Array, iv: Uint8Array, aad: Uint8Array, ciphertext: Uint8Array, tag: Uint8Array): Uint8Array {
  const macKey = cek.slice(0, 32)
  const encKey = cek.slice(32, 64)
  const mac = hmac(sha512, macKey, concatBytes(aad, iv, ciphertext, u64beBits(aad.length)))
  if (!constantTimeEqual(mac.slice(0, 32), tag)) throw new Error('A256CBC-HS512: authentication tag mismatch')
  return cbc(encKey, iv).decrypt(ciphertext)
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!
  return diff === 0
}

// ── XC20P (XChaCha20-Poly1305) ─────────────────────────────────────────────
// Decrypt only: didcomm-rust's default `enc` for anoncrypt, so it arrives
// from third parties, but we never choose it ourselves (we only ever
// produce A256CBC-HS512, matching authcrypt). 32-byte CEK, 24-byte nonce,
// and the 16-byte Poly1305 tag lives in the JWE's own `tag` field rather
// than appended to the ciphertext, so it is concatenated back on here --
// the layout @noble/ciphers (and every AEAD API) expects.
const XC20P_KEY_BYTES = 32

function xc20pDecrypt(cek: Uint8Array, iv: Uint8Array, aad: Uint8Array, ciphertext: Uint8Array, tag: Uint8Array): Uint8Array {
  if (cek.length !== XC20P_KEY_BYTES) throw new Error(`XC20P: expected a ${XC20P_KEY_BYTES}-byte key, got ${cek.length}`)
  if (iv.length !== 24) throw new Error(`XC20P: expected a 24-byte nonce, got ${iv.length}`)
  return xchacha20poly1305(cek, iv, aad).decrypt(concatBytes(ciphertext, tag))
}

// ── A256GCM (RFC 7518 §5.3) ────────────────────────────────────────────────
// Decrypt only, like XC20P: DIDComm v2.1 recommends it for anoncrypt; we
// produce A256CBC-HS512. 32-byte CEK, 12-byte IV, 16-byte tag.
function a256gcmDecrypt(cek: Uint8Array, iv: Uint8Array, aad: Uint8Array, ciphertext: Uint8Array, tag: Uint8Array): Uint8Array {
  if (iv.length !== 12) throw new Error(`A256GCM: expected a 12-byte IV, got ${iv.length}`)
  return gcm(cek, iv, aad).decrypt(concatBytes(ciphertext, tag))
}

/** The content-encryption half of unpacking anoncrypt, where -- unlike
 * authcrypt -- the sender's choice of `enc` is genuinely open (we send
 * A256CBC-HS512, didcomm-rust sends XC20P). Unknown values are named and
 * refused rather than left to fail as an opaque tag mismatch. */
function decryptContent(enc: string, cek: Uint8Array, jwe: DidCommJWE): Uint8Array {
  const iv = b64urlToBytes(jwe.iv)
  const aad = utf8(jwe.protected)
  const ciphertext = b64urlToBytes(jwe.ciphertext)
  const tag = b64urlToBytes(jwe.tag)
  if (enc === 'A256CBC-HS512') return aesCbcHs512Decrypt(cek, iv, aad, ciphertext, tag)
  if (enc === 'XC20P') return xc20pDecrypt(cek, iv, aad, ciphertext, tag)
  if (enc === 'A256GCM') return a256gcmDecrypt(cek, iv, aad, ciphertext, tag)
  throw new Error(`unpackAnoncrypt: unsupported enc ${JSON.stringify(enc)} -- anoncrypt reads A256CBC-HS512, A256GCM and XC20P`)
}

/** How many bytes of CEK an `enc` needs -- the KDF has to produce the right
 * length before the content algorithm is ever reached, so a mismatch is
 * reported plainly instead of surfacing as a downstream AEAD failure. */
function cekBytesFor(enc: string): number {
  if (enc === 'A256CBC-HS512') return 64
  if (enc === 'XC20P') return XC20P_KEY_BYTES
  if (enc === 'A256GCM') return 32
  throw new Error(`unpackAnoncrypt: unsupported enc ${JSON.stringify(enc)} -- anoncrypt reads A256CBC-HS512, A256GCM and XC20P`)
}

// ── JWE (general JSON serialization, DIDComm's single-recipient subset) ────
export interface DidCommJWE {
  protected: string
  recipients: Array<{ header: { kid: string }; encrypted_key: string }>
  iv: string
  ciphertext: string
  tag: string
}

/** A JWE this implementation is willing to attempt, or `null`.
 *
 * Structure only. Whether the ciphertext decrypts, the tag matches, or the
 * sender is who they claim is decided further in — this is the gate that
 * makes reaching those checks safe against a malformed/adversarial body
 * (an ingress payload before any decrypt has been attempted). */
export function parseJwe(value: unknown): DidCommJWE | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null
  const j = value as Record<string, unknown>
  const str = (v: unknown): v is string => typeof v === 'string' && v.length > 0
  if (!str(j.protected) || !str(j.iv) || !str(j.ciphertext) || !str(j.tag)) return null
  if (!Array.isArray(j.recipients) || j.recipients.length === 0) return null
  for (const r of j.recipients) {
    if (typeof r !== 'object' || r === null) return null
    const rec = r as Record<string, unknown>
    if (!str(rec.encrypted_key)) return null
    const h = rec.header
    if (typeof h !== 'object' || h === null) return null
    if (!str((h as Record<string, unknown>).kid)) return null
  }
  return value as DidCommJWE
}

/** The decoded `protected` header, or `null` if it is not base64url of a
 * JSON object. */
export function protectedHeaderOf(jwe: DidCommJWE): Record<string, unknown> | null {
  try {
    const header = JSON.parse(new TextDecoder().decode(b64urlToBytes(jwe.protected)))
    if (typeof header !== 'object' || header === null || Array.isArray(header)) return null
    return header as Record<string, unknown>
  } catch {
    return null
  }
}

/** A key-agreement key a message is encrypted to (or from). `curve` defaults
 * to X25519; a NIST key's public half is a SEC1 point (key-agreement.ts).
 * Every recipient of one JWE is on the same curve -- the JWE has one
 * ephemeral key -- and an authcrypt sender is on that curve too. */
export interface X25519Recipient { kid: string; publicKey: Uint8Array; curve?: KeyAgreementCurve }
export interface X25519Sender { kid: string; privateKey: Uint8Array; curve?: KeyAgreementCurve }

const curveOf = (key: { curve?: KeyAgreementCurve }): KeyAgreementCurve => key.curve ?? 'X25519'

/** The recipients an authcrypt from `sender` can reach: those on its curve
 * (ECDH-1PU needs the sender's and the recipients' keys on one curve). */
export function recipientsForSender<T extends { curve?: KeyAgreementCurve }>(recipients: readonly T[], sender: X25519Sender): T[] {
  const reachable = recipients.filter(recipient => curveOf(recipient) === curveOf(sender))
  if (reachable.length === 0 && recipients.length > 0) {
    throw new Error(`the recipient has no key-agreement key on this sender's curve (${curveOf(sender)}); its keys are ${[...new Set(recipients.map(curveOf))].join(', ')}`)
  }
  return reachable
}

/** The recipients of one curve among `recipients` -- `prefer`'s, if it has
 * any, else the first curve listed -- since one JWE carries one curve. */
export function sameCurveRecipients<T extends { curve?: KeyAgreementCurve }>(recipients: readonly T[], prefer: KeyAgreementCurve = 'X25519'): T[] {
  const curve = recipients.some(recipient => curveOf(recipient) === prefer) ? prefer : recipients[0] ? curveOf(recipients[0]) : prefer
  return recipients.filter(recipient => curveOf(recipient) === curve)
}

/** DIDComm v2.1 §"ECDH-1PU key wrapping and common protected headers":
 * `apv` is the SHA-256 of every recipient `kid`, sorted, joined by `.` —
 * the same value whether the JWE has one recipient or many. */
function apvFor(recipientKids: readonly string[]): Uint8Array {
  return sha256(utf8([...recipientKids].sort().join('.')))
}

function assertRecipients(fn: string, recipients: readonly { kid: string; curve?: KeyAgreementCurve }[]): KeyAgreementCurve {
  if (recipients.length === 0) throw new Error(`${fn}: no recipients`)
  if (new Set(recipients.map(r => r.kid)).size !== recipients.length) throw new Error(`${fn}: duplicate recipient kid`)
  const curve = curveOf(recipients[0]!)
  if (recipients.some(recipient => curveOf(recipient) !== curve)) throw new Error(`${fn}: recipients are on different curves (one JWE has one ephemeral key)`)
  return curve
}

/** Refuses a JWE whose `apv` is not the spec digest of its own `recipients`
 * kids — the key-wrapping KDF already binds `apv`, so this only catches a
 * sender (or a mangling hop) that disagrees with the spec about which
 * recipients the message was for. */
function assertApvMatchesRecipients(fn: string, jwe: DidCommJWE, header: Record<string, unknown>): Uint8Array {
  if (typeof header.apv !== 'string') throw new Error(`${fn}: missing apv`)
  const apv = b64urlToBytes(header.apv)
  const want = apvFor(jwe.recipients.map(r => r.header.kid))
  if (apv.length !== want.length || apv.some((b, i) => b !== want[i])) throw new Error(`${fn}: apv does not match the recipient kids`)
  return apv
}

/** The media type of an encrypted DIDComm message -- its JWE `typ`, and the
 * HTTP Content-Type every transport MUST carry it under (DIDComm v2.1). */
export const DIDCOMM_ENCRYPTED_MEDIA_TYPE = 'application/didcomm-encrypted+json'

/** The HTTP request that delivers one encrypted DIDComm message. */
export function didCommPost(jwe: DidCommJWE, signal?: AbortSignal): RequestInit {
  return { method: 'POST', headers: { 'content-type': DIDCOMM_ENCRYPTED_MEDIA_TYPE }, body: JSON.stringify(jwe), ...(signal ? { signal } : {}) }
}

/** Whether an HTTP delivery of a DIDComm message was accepted: any 2xx
 * (DIDComm v2.1 transports: success MUST be a 2xx code; 202 is only the
 * recommended one, so a 200 or 204 is acceptance too). */
export function didCommAccepted(status: number): boolean {
  return status >= 200 && status < 300
}

/** Whether a request declares the encrypted DIDComm media type (any
 * parameters after `;` ignored). */
export function isDidCommEncryptedRequest(request: Request): boolean {
  return request.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase() === DIDCOMM_ENCRYPTED_MEDIA_TYPE
}

function buildProtectedHeader(
  alg: string, sender: X25519Sender | null, apvRaw: Uint8Array, epk: Record<string, string>,
): { headerStr: string; apu: Uint8Array } {
  const apu = sender ? utf8(sender.kid) : new Uint8Array(0)
  const header: Record<string, unknown> = {
    typ: DIDCOMM_ENCRYPTED_MEDIA_TYPE,
    alg,
    enc: 'A256CBC-HS512',
    ...(sender ? { skid: sender.kid, apu: b64url(apu) } : {}),
    apv: b64url(apvRaw),
    epk,
  }
  return { headerStr: JSON.stringify(header), apu }
}

/** anoncrypt: ECDH-ES+A256KW / A256CBC-HS512, no sender at all, one
 * content encryption shared by every recipient (each gets its own wrap of
 * the CEK under the one ephemeral key — DIDComm v2.1 multiplexed
 * encryption). Used for Routing Protocol 2.0 Forward wrapping -- the
 * mediator must not learn who queued a message, only which registered
 * routing kid it's addressed to (a recipient `kid` here names a ROUTING kid,
 * not a message recipient's real keyAgreement kid -- the caller decides what
 * to wrap). */
export function packAnoncrypt(plaintext: Uint8Array, recipients: readonly X25519Recipient[]): DidCommJWE {
  const curve = assertRecipients('packAnoncrypt', recipients)
  const alg = 'ECDH-ES+A256KW'
  const { privateKey: ephemPriv, publicKey: ephemPub } = generateKeyAgreementKeyPair(curve)
  const apv = apvFor(recipients.map(r => r.kid))
  const { headerStr, apu } = buildProtectedHeader(alg, null, apv, jwkOfKeyAgreementKey({ curve, publicKey: ephemPub }))
  const protectedB64 = b64url(utf8(headerStr))

  const cek = crypto.getRandomValues(new Uint8Array(64))
  const iv = crypto.getRandomValues(new Uint8Array(16))
  const { ciphertext, tag } = aesCbcHs512Encrypt(cek, iv, utf8(protectedB64), plaintext)

  return {
    protected: protectedB64,
    recipients: recipients.map(recipient => {
      const z = ecdh(curve, ephemPriv, recipient.publicKey)
      const kek = deriveEcdhEs(z, alg, apu, apv, 256)
      return { header: { kid: recipient.kid }, encrypted_key: b64url(wrapKey(kek, cek)) }
    }),
    iv: b64url(iv),
    ciphertext: b64url(ciphertext),
    tag: b64url(tag),
  }
}

/** authcrypt: ECDH-1PU+A256KW / A256CBC-HS512, one sender, one content
 * encryption wrapped for every recipient. DIDComm v2.1 says a sender SHOULD
 * list every `keyAgreement` key of the recipient DID here, so each of the
 * recipient's devices can open the same message. */
export function packAuthcrypt(plaintext: Uint8Array, sender: X25519Sender, recipients: readonly X25519Recipient[]): DidCommJWE {
  const curve = assertRecipients('packAuthcrypt', recipients)
  if (curveOf(sender) !== curve) throw new Error(`packAuthcrypt: the sender's key is ${curveOf(sender)}, the recipients' ${curve} (ECDH-1PU needs one curve)`)
  const alg = 'ECDH-1PU+A256KW'
  const { privateKey: ephemPriv, publicKey: ephemPub } = generateKeyAgreementKeyPair(curve)
  const apv = apvFor(recipients.map(r => r.kid))
  const { headerStr, apu } = buildProtectedHeader(alg, sender, apv, jwkOfKeyAgreementKey({ curve, publicKey: ephemPub }))
  const protectedB64 = b64url(utf8(headerStr))

  const cek = crypto.getRandomValues(new Uint8Array(64))
  const iv = crypto.getRandomValues(new Uint8Array(16))
  const { ciphertext, tag } = aesCbcHs512Encrypt(cek, iv, utf8(protectedB64), plaintext)

  return {
    protected: protectedB64,
    recipients: recipients.map(recipient => {
      const ze = ecdh(curve, ephemPriv, recipient.publicKey)
      const zs = ecdh(curve, sender.privateKey, recipient.publicKey)
      const kek = deriveEcdh1PU(ze, zs, alg, apu, apv, tag, 256)
      return { header: { kid: recipient.kid }, encrypted_key: b64url(wrapKey(kek, cek)) }
    }),
    iv: b64url(iv),
    ciphertext: b64url(ciphertext),
    tag: b64url(tag),
  }
}

export interface UnpackedAuthcrypt { plaintext: Uint8Array; senderKid: string }

/** Resolves the sender's X25519 public key for the kid named in the JWE's
 * `apu`/`skid` header — the caller already knows how to resolve a DID
 * (biset's own resolver, or a did:peer self-decode).
 *
 * `senderKid` is UNVERIFIED input at the point this is called: it is read
 * straight from the sender-supplied `apu` header of a message that has not
 * decrypted yet, so a real implementation of this (e.g.
 * `didcomm/webvh-resolve.ts`'s `resolveDidCommSenderKey`) makes a LIVE
 * outbound HTTP fetch to whatever domain the CLAIMED sender's DID names —
 * an attacker-steerable request. unpackAuthcrypt below calls this only
 * after every cheap, no-network structural check on the message has already
 * passed (alg, enc, apv) specifically so a message
 * that's going to be rejected anyway never gets a chance to make this
 * device dial an arbitrary attacker-chosen host first (found live,
 * 2026-08-26 — see ARC.md's DIDComm section).
 *
 * `fresh` asks for a genuinely re-resolved key rather than a cached one, for
 * a caller retrying after an unpack failed with a possibly-stale cached key. */
export type ResolveSenderKey = (senderKid: string, opts?: { fresh?: boolean }) => Uint8Array | Promise<Uint8Array>

/** The JWE's ephemeral public key, which must be on the recipient key's curve
 * (a NIST point is checked to be on the curve). */
function ephemeralKeyOf(fn: string, header: Record<string, unknown>, recipient: X25519Sender): { curve: KeyAgreementCurve; publicKey: Uint8Array } {
  const epk = header.epk
  if (epk === null || typeof epk !== 'object' || Array.isArray(epk)) throw new Error(`${fn}: missing epk`)
  const key = keyAgreementKeyFromJwk(epk as Record<string, unknown>)
  if (key.curve !== curveOf(recipient)) throw new Error(`${fn}: the epk is ${key.curve}, the recipient key ${curveOf(recipient)}`)
  return key
}

function parseProtectedHeader(jwe: DidCommJWE): Record<string, unknown> {
  return JSON.parse(new TextDecoder().decode(b64urlToBytes(jwe.protected)))
}

export async function unpackAuthcrypt(jwe: DidCommJWE, recipient: X25519Sender, resolveSenderKey: ResolveSenderKey): Promise<UnpackedAuthcrypt> {
  const header = parseProtectedHeader(jwe)
  if (header.alg !== 'ECDH-1PU+A256KW') throw new Error(`unpackAuthcrypt: unexpected alg ${header.alg}`)
  // didcomm-rust's authcrypt offers no `enc` but this one, so an authcrypt
  // arriving as anything else isn't an interop case to support — refuse by
  // name rather than fail cryptically on a tag mismatch. Checked here, before
  // any network resolution below: a message this cheap to reject must never
  // first trigger a live DID resolve to a sender-claimed (and therefore
  // attacker-steerable) domain — see resolveSenderKey's own note.
  if (header.enc !== 'A256CBC-HS512') {
    throw new Error(`unpackAuthcrypt: unsupported enc ${JSON.stringify(header.enc)} — authcrypt is A256CBC-HS512 only`)
  }
  const apu = b64urlToBytes(header.apu as string)
  const senderKid = new TextDecoder().decode(apu)
  if (header.skid && header.skid !== senderKid) throw new Error('unpackAuthcrypt: skid does not match apu')

  const rec = jwe.recipients.find(r => r.header.kid === recipient.kid)
  if (!rec) throw new Error('unpackAuthcrypt: recipient kid not present in JWE')

  const epk = ephemeralKeyOf('unpackAuthcrypt', header, recipient)
  const apv = assertApvMatchesRecipients('unpackAuthcrypt', jwe, header)
  const senderPub = await resolveSenderKey(senderKid)
  const tag = b64urlToBytes(jwe.tag)

  const ze = ecdh(epk.curve, recipient.privateKey, epk.publicKey)
  const zs = ecdh(epk.curve, recipient.privateKey, senderPub)
  const kek = deriveEcdh1PU(ze, zs, header.alg, apu, apv, tag, 256)
  const cek = unwrapKey(kek, b64urlToBytes(rec.encrypted_key))

  const plaintext = aesCbcHs512Decrypt(cek, b64urlToBytes(jwe.iv), utf8(jwe.protected), b64urlToBytes(jwe.ciphertext), tag)
  return { plaintext, senderKid }
}

/** Unwraps a Forward envelope's anoncrypt layer -- a mediator's own job
 * (it holds `recipient.privateKey` for the routing kid a Forward was
 * addressed to, never a message's real recipient key) or, symmetrically, a
 * device peeling off ITS mediator's outer wrap before authcrypt-unpacking
 * the inner message. No sender to authenticate here by construction --
 * that is anoncrypt's entire point -- so this returns plaintext bytes only,
 * not a claimed sender kid the way unpackAuthcrypt does. */
export async function unpackAnoncrypt(jwe: DidCommJWE, recipient: X25519Sender): Promise<Uint8Array> {
  const header = parseProtectedHeader(jwe)
  if (header.alg !== 'ECDH-ES+A256KW') throw new Error(`unpackAnoncrypt: unexpected alg ${header.alg}`)

  const rec = jwe.recipients.find(r => r.header.kid === recipient.kid)
  if (!rec) throw new Error('unpackAnoncrypt: recipient kid not present in JWE')

  const epk = ephemeralKeyOf('unpackAnoncrypt', header, recipient)
  const apu = header.apu ? b64urlToBytes(header.apu as string) : new Uint8Array(0)
  const apv = assertApvMatchesRecipients('unpackAnoncrypt', jwe, header)

  const z = ecdh(epk.curve, recipient.privateKey, epk.publicKey)
  const kek = deriveEcdhEs(z, header.alg as string, apu, apv, 256)
  const cek = unwrapKey(kek, b64urlToBytes(rec.encrypted_key))

  // The sender picked `enc`, and for anoncrypt that is genuinely open (see
  // this file's own header). Checking the unwrapped CEK is the length that
  // `enc` implies here, before ever reaching the AEAD, means a sender/
  // receiver key-schedule mismatch is reported plainly instead of as an
  // opaque tag failure.
  const want = cekBytesFor(header.enc as string)
  if (cek.length !== want) {
    throw new Error(`unpackAnoncrypt: ${header.enc} wants a ${want}-byte CEK, unwrapped ${cek.length}`)
  }
  return decryptContent(header.enc as string, cek, jwe)
}

// ── exported for test-vector checks ─────────────────────────────────────────
export const __internal = { concatKDF, deriveEcdh1PU, deriveEcdhEs, ecdh, u32be, utf8, b64url }
