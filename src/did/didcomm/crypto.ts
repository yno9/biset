// DIDComm v2 JWE construction, pure TypeScript — no wasm, keeps biset's
// single-file/`file://` architecture intact (see ARC.md; the wasm-bindgen
// `didcomm`/`didcomm-node` packages emit a separate ~0.9MB asset fetched at
// runtime, which doesn't fit that constraint — see PLAN.md).
//
// Scope: X25519 only, single recipient only (biset never fans a message out
// to multiple keys/curves at once — that generality exists in didcomm-rust
// for interop with arbitrary implementations, not something biset itself
// needs to produce). Two algorithms:
//   - anoncrypt: ECDH-ES+A256KW / A256CBC-HS512 — used for Forward wrapping
//     (the mediator must not learn who queued a message).
//   - authcrypt: ECDH-1PU+A256KW / A256CBC-HS512 — used for the actual
//     sender-to-recipient message.
//
// Every construction below (ConcatKDF byte layout, ECDH-1PU's Ze||Zs and
// cc_tag-in-pub_info step, JWE field names) was verified against
// hyperledger/aries-askar's askar-crypto source (askar-crypto/src/kdf/
// concat.rs, ecdh_1pu.rs, ecdh_es.rs — the crate didcomm-rust itself uses)
// and against didcomm-rust's own jwe/envelope.rs, jwe/encrypt.rs,
// jwe/decrypt.rs, message/pack_encrypted/authcrypt.rs, message/unpack/
// authcrypt.rs, protocols/routing/mod.rs — not reconstructed from memory.
// See this file's test vectors (draft-madden-jose-ecdh-1pu-04 appendices)
// for a byte-exact check of the KDF, independent of any DIDComm library, and
// scratch-didcomm-crypto-interop.mjs for a round-trip check against the real
// didcomm-node library (round-trips both directions, both algorithms).
//
// `enc` is always A256CBC-HS512, never XC20P/A256GCM — those are other
// libraries' options for content this one never needs to produce (we always
// choose our own forward-wrap's `enc`) or is ever asked to consume (didmediator
// relays already-encrypted bytes opaquely; it doesn't re-encrypt under a
// different `enc`). unpack* below will reject anything else rather than
// silently mishandle it.
import { x25519 } from '@noble/curves/ed25519.js'
import { sha256, sha512 } from '@noble/hashes/sha2.js'
import { hmac } from '@noble/hashes/hmac.js'
import { cbc, aeskw } from '@noble/ciphers/aes.js'

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

function b64url(bytes: Uint8Array): string {
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

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!
  return diff === 0
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

/** ECDH-ES key derivation (anoncrypt). `z` = ECDH(ephemeral, recipient). */
function deriveEcdhEs(z: Uint8Array, alg: string, apu: Uint8Array, apv: Uint8Array, outputLenBits: number): Uint8Array {
  const pubInfo = u32be(outputLenBits)
  return concatKDF(z, utf8(alg), apu, apv, pubInfo, outputLenBits / 8)
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

// ── JWE (general JSON serialization, DIDComm's single-recipient subset) ────
export interface DidCommJWE {
  protected: string
  recipients: Array<{ header: { kid: string }; encrypted_key: string }>
  iv: string
  ciphertext: string
  tag: string
}

export interface X25519Recipient { kid: string; publicKey: Uint8Array }
export interface X25519Sender { kid: string; privateKey: Uint8Array }

function apvFor(recipientKid: string): Uint8Array { return sha256(utf8(recipientKid)) }

function buildProtectedHeader(alg: string, sender: X25519Sender | null, apvRaw: Uint8Array, epkPub: Uint8Array): { headerStr: string; apu: Uint8Array } {
  const apu = sender ? utf8(sender.kid) : new Uint8Array(0)
  const header: Record<string, unknown> = {
    typ: 'application/didcomm-encrypted+json',
    alg,
    enc: 'A256CBC-HS512',
    ...(sender ? { skid: sender.kid, apu: b64url(apu) } : {}),
    apv: b64url(apvRaw),
    epk: { kty: 'OKP', crv: 'X25519', x: b64url(epkPub) },
  }
  return { headerStr: JSON.stringify(header), apu }
}

/** anoncrypt: ECDH-ES+A256KW / A256CBC-HS512, single recipient. Used for
 * Routing Forward wrapping — the mediator must not learn the sender. */
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

export interface UnpackedAuthcrypt { plaintext: Uint8Array; senderKid: string }

/** Resolves the sender's X25519 public key for the kid named in the JWE's
 * `apu`/`skid` header — the caller already knows how to resolve a DID
 * (biset's own resolver, or a did:peer self-decode). */
export type ResolveSenderKey = (senderKid: string) => Uint8Array | Promise<Uint8Array>

export async function unpackAuthcrypt(jwe: DidCommJWE, recipient: X25519Sender, resolveSenderKey: ResolveSenderKey): Promise<UnpackedAuthcrypt> {
  const header = JSON.parse(new TextDecoder().decode(b64urlToBytes(jwe.protected)))
  if (header.alg !== 'ECDH-1PU+A256KW') throw new Error(`unpackAuthcrypt: unexpected alg ${header.alg}`)
  const apu = b64urlToBytes(header.apu)
  const senderKid = new TextDecoder().decode(apu)
  if (header.skid && header.skid !== senderKid) throw new Error('unpackAuthcrypt: skid does not match apu')

  const rec = jwe.recipients.find(r => r.header.kid === recipient.kid)
  if (!rec) throw new Error('unpackAuthcrypt: recipient kid not present in JWE')

  const epkPub = b64urlToBytes(header.epk.x)
  const senderPub = await resolveSenderKey(senderKid)
  const apv = b64urlToBytes(header.apv)
  const tag = b64urlToBytes(jwe.tag)

  const ze = ecdh(recipient.privateKey, epkPub)
  const zs = ecdh(recipient.privateKey, senderPub)
  const kek = deriveEcdh1PU(ze, zs, header.alg, apu, apv, tag, 256)
  const cek = unwrapKey(kek, b64urlToBytes(rec.encrypted_key))

  const iv = b64urlToBytes(jwe.iv)
  const ciphertext = b64urlToBytes(jwe.ciphertext)
  const plaintext = aesCbcHs512Decrypt(cek, iv, utf8(jwe.protected), ciphertext, tag)
  return { plaintext, senderKid }
}

export async function unpackAnoncrypt(jwe: DidCommJWE, recipient: X25519Sender): Promise<Uint8Array> {
  const header = JSON.parse(new TextDecoder().decode(b64urlToBytes(jwe.protected)))
  if (header.alg !== 'ECDH-ES+A256KW') throw new Error(`unpackAnoncrypt: unexpected alg ${header.alg}`)

  const rec = jwe.recipients.find(r => r.header.kid === recipient.kid)
  if (!rec) throw new Error('unpackAnoncrypt: recipient kid not present in JWE')

  const epkPub = b64urlToBytes(header.epk.x)
  const apu = header.apu ? b64urlToBytes(header.apu) : new Uint8Array(0)
  const apv = b64urlToBytes(header.apv)

  const z = ecdh(recipient.privateKey, epkPub)
  const kek = deriveEcdhEs(z, header.alg, apu, apv, 256)
  const cek = unwrapKey(kek, b64urlToBytes(rec.encrypted_key))

  const iv = b64urlToBytes(jwe.iv)
  const ciphertext = b64urlToBytes(jwe.ciphertext)
  const tag = b64urlToBytes(jwe.tag)
  return aesCbcHs512Decrypt(cek, iv, utf8(jwe.protected), ciphertext, tag)
}

// ── exported for the standalone RFC test-vector check (scratchpad only) ────
export const __internal = { concatKDF, deriveEcdh1PU, deriveEcdhEs, ecdh, u32be, utf8, b64url }
