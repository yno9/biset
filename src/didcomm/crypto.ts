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
//   - authcrypt: ECDH-1PU+A256KW / A256CBC-HS512 (plain and the
//     biset-specific X25519+ML-KEM-768 hybrid variant) — the actual
//     sender-to-recipient message, both directions, single sender/recipient.
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
import { x25519 } from '@noble/curves/ed25519.js'
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js'
import { sha256, sha512 } from '@noble/hashes/sha2.js'
import { hmac } from '@noble/hashes/hmac.js'
import { cbc, aeskw } from '@noble/ciphers/aes.js'
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

function ecdh(privKey: Uint8Array, pubKey: Uint8Array): Uint8Array {
  return x25519.getSharedSecret(privKey, pubKey)
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

/** ECDH-1PU key derivation, PQ-hybrid variant (PLAN.md "did:webvh
 * PQハイブリッド化", Phase 2): identical to deriveEcdh1PU except `z` also
 * concatenates `zpq` — the ML-KEM-768 shared secret — after Ze/Zs. Ze/Zs
 * alone still carry sender authentication (ECDH-1PU's whole point; ML-KEM is
 * a KEM, not a DH, so it cannot contribute to that half); zpq's only job is
 * making the derived key safe against a future CRQC recovering it from
 * today's ciphertext (HNDL) even if X25519 alone is eventually broken. Order
 * (Ze, Zs, then Zpq) is arbitrary but fixed, matching how deriveEcdh1PU
 * orders Ze before Zs. */
function deriveEcdh1PUHybrid(ze: Uint8Array, zs: Uint8Array, zpq: Uint8Array, alg: string, apu: Uint8Array, apv: Uint8Array, ccTag: Uint8Array, outputLenBits: number): Uint8Array {
  const z = concatBytes(ze, zs, zpq)
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
  throw new Error(`unpackAnoncrypt: unsupported enc ${JSON.stringify(enc)} -- anoncrypt reads A256CBC-HS512 and XC20P`)
}

/** How many bytes of CEK an `enc` needs -- the KDF has to produce the right
 * length before the content algorithm is ever reached, so a mismatch is
 * reported plainly instead of surfacing as a downstream AEAD failure. */
function cekBytesFor(enc: string): number {
  if (enc === 'A256CBC-HS512') return 64
  if (enc === 'XC20P') return XC20P_KEY_BYTES
  throw new Error(`unpackAnoncrypt: unsupported enc ${JSON.stringify(enc)} -- anoncrypt reads A256CBC-HS512 and XC20P`)
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

export interface X25519Recipient { kid: string; publicKey: Uint8Array }
export interface X25519Sender { kid: string; privateKey: Uint8Array }

function apvFor(recipientKid: string): Uint8Array { return sha256(utf8(recipientKid)) }

function buildProtectedHeader(
  alg: string, sender: X25519Sender | null, apvRaw: Uint8Array, epkPub: Uint8Array,
  pqKemCiphertext?: Uint8Array,
): { headerStr: string; apu: Uint8Array } {
  const apu = sender ? utf8(sender.kid) : new Uint8Array(0)
  const header: Record<string, unknown> = {
    typ: 'application/didcomm-encrypted+json',
    alg,
    enc: 'A256CBC-HS512',
    ...(sender ? { skid: sender.kid, apu: b64url(apu) } : {}),
    apv: b64url(apvRaw),
    epk: { kty: 'OKP', crv: 'X25519', x: b64url(epkPub) },
    // biset-specific field, not part of DIDComm v2 — carries the ML-KEM-768
    // encapsulation this JWE also derives its CEK-wrapping key from. Only
    // ever produced/consumed between two biset devices that both published a
    // keyAgreement ML-KEM entry — a non-hybrid recipient never sees this
    // field, since the sender only reaches for the hybrid `pack*` function
    // when it already resolved one.
    ...(pqKemCiphertext ? { pqKem: { alg: 'ML-KEM-768', ct: b64url(pqKemCiphertext) } } : {}),
  }
  return { headerStr: JSON.stringify(header), apu }
}

/** anoncrypt: ECDH-ES+A256KW / A256CBC-HS512, single recipient, no sender at
 * all. Used for Routing Protocol 2.0 Forward wrapping -- the mediator must
 * not learn who queued a message, only which registered routing kid it's
 * addressed to (`recipient.kid` here names the ROUTING kid, not a message
 * recipient's real keyAgreement kid -- the caller decides what to wrap). */
export function packAnoncrypt(plaintext: Uint8Array, recipient: X25519Recipient): DidCommJWE {
  const alg = 'ECDH-ES+A256KW'
  const ephemPriv = x25519.utils.randomSecretKey()
  const ephemPub = x25519.getPublicKey(ephemPriv)
  const apv = apvFor(recipient.kid)
  const { headerStr, apu } = buildProtectedHeader(alg, null, apv, ephemPub)
  const protectedB64 = b64url(utf8(headerStr))

  const cek = crypto.getRandomValues(new Uint8Array(64))
  const iv = crypto.getRandomValues(new Uint8Array(16))
  const { ciphertext, tag } = aesCbcHs512Encrypt(cek, iv, utf8(protectedB64), plaintext)

  const z = ecdh(ephemPriv, recipient.publicKey)
  const kek = deriveEcdhEs(z, alg, apu, apv, 256)
  const encryptedKey = wrapKey(kek, cek)

  return {
    protected: protectedB64,
    recipients: [{ header: { kid: recipient.kid }, encrypted_key: b64url(encryptedKey) }],
    iv: b64url(iv),
    ciphertext: b64url(ciphertext),
    tag: b64url(tag),
  }
}

/** authcrypt: ECDH-1PU+A256KW / A256CBC-HS512, single sender + recipient. */
export function packAuthcrypt(plaintext: Uint8Array, sender: X25519Sender, recipient: X25519Recipient): DidCommJWE {
  const alg = 'ECDH-1PU+A256KW'
  const ephemPriv = x25519.utils.randomSecretKey()
  const ephemPub = x25519.getPublicKey(ephemPriv)
  const apv = apvFor(recipient.kid)
  const { headerStr, apu } = buildProtectedHeader(alg, sender, apv, ephemPub)
  const protectedB64 = b64url(utf8(headerStr))

  const cek = crypto.getRandomValues(new Uint8Array(64))
  const iv = crypto.getRandomValues(new Uint8Array(16))
  const { ciphertext, tag } = aesCbcHs512Encrypt(cek, iv, utf8(protectedB64), plaintext)

  const ze = ecdh(ephemPriv, recipient.publicKey)
  const zs = ecdh(sender.privateKey, recipient.publicKey)
  const kek = deriveEcdh1PU(ze, zs, alg, apu, apv, tag, 256)
  const encryptedKey = wrapKey(kek, cek)

  return {
    protected: protectedB64,
    recipients: [{ header: { kid: recipient.kid }, encrypted_key: b64url(encryptedKey) }],
    iv: b64url(iv),
    ciphertext: b64url(ciphertext),
    tag: b64url(tag),
  }
}

const HYBRID_ALG = 'ECDH-1PU-X25519MLKEM768+A256KW'

export interface HybridRecipient { kid: string; x25519PublicKey: Uint8Array; mlkemPublicKey: Uint8Array }
export interface HybridSelf { kid: string; x25519PrivateKey: Uint8Array; mlkemPrivateKey: Uint8Array }

/** Hybrid authcrypt: same ECDH-1PU/A256CBC-HS512 shape as packAuthcrypt,
 * plus an ML-KEM-768 encapsulation folded into the key-wrapping key
 * (deriveEcdh1PUHybrid) and carried in the protected header's `pqKem` field
 * so the recipient can decapsulate. biset-specific `alg` — never sent to a
 * peer that hasn't itself published an ML-KEM-768 keyAgreement entry (the
 * caller's own negotiation, not this function's concern). */
export function packAuthcryptHybrid(plaintext: Uint8Array, sender: X25519Sender, recipient: HybridRecipient): DidCommJWE {
  const ephemPriv = x25519.utils.randomSecretKey()
  const ephemPub = x25519.getPublicKey(ephemPriv)
  const apv = apvFor(recipient.kid)
  const { cipherText: kemCt, sharedSecret: zpq } = ml_kem768.encapsulate(recipient.mlkemPublicKey)
  const { headerStr, apu } = buildProtectedHeader(HYBRID_ALG, sender, apv, ephemPub, kemCt)
  const protectedB64 = b64url(utf8(headerStr))

  const cek = crypto.getRandomValues(new Uint8Array(64))
  const iv = crypto.getRandomValues(new Uint8Array(16))
  const { ciphertext, tag } = aesCbcHs512Encrypt(cek, iv, utf8(protectedB64), plaintext)

  const ze = ecdh(ephemPriv, recipient.x25519PublicKey)
  const zs = ecdh(sender.privateKey, recipient.x25519PublicKey)
  const kek = deriveEcdh1PUHybrid(ze, zs, zpq, HYBRID_ALG, apu, apv, tag, 256)
  const encryptedKey = wrapKey(kek, cek)

  return {
    protected: protectedB64,
    recipients: [{ header: { kid: recipient.kid }, encrypted_key: b64url(encryptedKey) }],
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
 * an attacker-steerable request. The unpack*WithHeader functions above call
 * this only after every cheap, no-network structural check on the message
 * has already passed (alg, enc, pqKem shape) specifically so a message
 * that's going to be rejected anyway never gets a chance to make this
 * device dial an arbitrary attacker-chosen host first (found live,
 * 2026-08-26 — see ARC.md's DIDComm section).
 *
 * `fresh` asks for a genuinely re-resolved key rather than a cached one, for
 * a caller retrying after an unpack failed with a possibly-stale cached key. */
export type ResolveSenderKey = (senderKid: string, opts?: { fresh?: boolean }) => Uint8Array | Promise<Uint8Array>

/** Parses the JWE's `protected` header once — shared by every unpack path
 * below so a message routed through `unpackAuthcryptAuto` (which has to peek
 * at `alg` to dispatch) never pays for a second base64url-decode-plus-parse
 * of the exact same bytes. */
function parseProtectedHeader(jwe: DidCommJWE): Record<string, unknown> {
  return JSON.parse(new TextDecoder().decode(b64urlToBytes(jwe.protected)))
}

async function unpackAuthcryptHybridWithHeader(
  jwe: DidCommJWE, header: Record<string, unknown>, recipient: HybridSelf, resolveSenderKey: ResolveSenderKey,
): Promise<UnpackedAuthcrypt> {
  if (header.alg !== HYBRID_ALG) throw new Error(`unpackAuthcryptHybrid: unexpected alg ${header.alg}`)
  if (!(header.pqKem as { ct?: unknown } | undefined)?.ct) throw new Error('unpackAuthcryptHybrid: missing pqKem.ct')
  // Every structural/format check that does NOT need a network round trip
  // happens before resolveSenderKey below: that call is a live DID resolve
  // to a domain the SENDER-CLAIMED, unverified `apu`/`skid` names, so a
  // message this cheap to reject must never trigger it first — see
  // resolveSenderKey's own note on why this ordering matters.
  if (header.enc !== 'A256CBC-HS512') {
    throw new Error(`unpackAuthcryptHybrid: unsupported enc ${JSON.stringify(header.enc)} — hybrid authcrypt is A256CBC-HS512 only`)
  }
  const apu = b64urlToBytes(header.apu as string)
  const senderKid = new TextDecoder().decode(apu)
  if (header.skid && header.skid !== senderKid) throw new Error('unpackAuthcryptHybrid: skid does not match apu')

  const rec = jwe.recipients.find(r => r.header.kid === recipient.kid)
  if (!rec) throw new Error('unpackAuthcryptHybrid: recipient kid not present in JWE')

  const epkPub = b64urlToBytes((header.epk as { x: string }).x)
  const senderPub = await resolveSenderKey(senderKid)
  const apv = b64urlToBytes(header.apv as string)
  const tag = b64urlToBytes(jwe.tag)

  const ze = ecdh(recipient.x25519PrivateKey, epkPub)
  const zs = ecdh(recipient.x25519PrivateKey, senderPub)
  const zpq = ml_kem768.decapsulate(b64urlToBytes((header.pqKem as { ct: string }).ct), recipient.mlkemPrivateKey)
  const kek = deriveEcdh1PUHybrid(ze, zs, zpq, header.alg, apu, apv, tag, 256)
  const cek = unwrapKey(kek, b64urlToBytes(rec.encrypted_key))

  const plaintext = aesCbcHs512Decrypt(cek, b64urlToBytes(jwe.iv), utf8(jwe.protected), b64urlToBytes(jwe.ciphertext), tag)
  return { plaintext, senderKid }
}

export async function unpackAuthcryptHybrid(jwe: DidCommJWE, recipient: HybridSelf, resolveSenderKey: ResolveSenderKey): Promise<UnpackedAuthcrypt> {
  return unpackAuthcryptHybridWithHeader(jwe, parseProtectedHeader(jwe), recipient, resolveSenderKey)
}

async function unpackAuthcryptWithHeader(
  jwe: DidCommJWE, header: Record<string, unknown>, recipient: X25519Sender, resolveSenderKey: ResolveSenderKey,
): Promise<UnpackedAuthcrypt> {
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

  const epkPub = b64urlToBytes((header.epk as { x: string }).x)
  const senderPub = await resolveSenderKey(senderKid)
  const apv = b64urlToBytes(header.apv as string)
  const tag = b64urlToBytes(jwe.tag)

  const ze = ecdh(recipient.privateKey, epkPub)
  const zs = ecdh(recipient.privateKey, senderPub)
  const kek = deriveEcdh1PU(ze, zs, header.alg, apu, apv, tag, 256)
  const cek = unwrapKey(kek, b64urlToBytes(rec.encrypted_key))

  const plaintext = aesCbcHs512Decrypt(cek, b64urlToBytes(jwe.iv), utf8(jwe.protected), b64urlToBytes(jwe.ciphertext), tag)
  return { plaintext, senderKid }
}

export async function unpackAuthcrypt(jwe: DidCommJWE, recipient: X25519Sender, resolveSenderKey: ResolveSenderKey): Promise<UnpackedAuthcrypt> {
  return unpackAuthcryptWithHeader(jwe, parseProtectedHeader(jwe), recipient, resolveSenderKey)
}

export interface SelfKeys { kid: string; x25519PrivateKey: Uint8Array; mlkemPrivateKey?: Uint8Array }

/** Dispatches to unpackAuthcryptHybrid or plain unpackAuthcrypt by reading
 * the JWE's own `alg` — the receiving side's half of the negotiation the
 * sending side decides (whether it resolved a hybrid keyAgreement entry for
 * this recipient). A device without its own ML-KEM-768 key
 * (`self.mlkemPrivateKey` unset) can never legitimately receive a hybrid JWE
 * addressed to it, so that combination throws rather than silently
 * mishandling it.
 *
 * Parses the header once and passes it to whichever *WithHeader variant
 * handles it, rather than calling the public unpackAuthcrypt(Hybrid)
 * functions (which would parse it again from scratch). */
export async function unpackAuthcryptAuto(jwe: DidCommJWE, self: SelfKeys, resolveSenderKey: ResolveSenderKey): Promise<UnpackedAuthcrypt> {
  const header = parseProtectedHeader(jwe)
  if (header.alg === HYBRID_ALG) {
    if (!self.mlkemPrivateKey) throw new Error('unpackAuthcryptAuto: received a hybrid-encrypted message but this device has no ML-KEM-768 key')
    return unpackAuthcryptHybridWithHeader(jwe, header, { kid: self.kid, x25519PrivateKey: self.x25519PrivateKey, mlkemPrivateKey: self.mlkemPrivateKey }, resolveSenderKey)
  }
  return unpackAuthcryptWithHeader(jwe, header, { kid: self.kid, privateKey: self.x25519PrivateKey }, resolveSenderKey)
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

  const epkPub = b64urlToBytes((header.epk as { x: string }).x)
  const apu = header.apu ? b64urlToBytes(header.apu as string) : new Uint8Array(0)
  const apv = b64urlToBytes(header.apv as string)

  const z = ecdh(recipient.privateKey, epkPub)
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
export const __internal = { concatKDF, deriveEcdh1PU, deriveEcdh1PUHybrid, deriveEcdhEs, ecdh, u32be, utf8, b64url }
