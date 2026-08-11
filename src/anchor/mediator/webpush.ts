// Web Push sender — RFC 8291 (Message Encryption, aes128gcm) + RFC 8292 (VAPID).
//
// Written out rather than pulled in as a dependency for the same reason the
// mediator speaks biset's own DIDComm instead of didcomm-node (see server.ts's
// header): the anchor ships as ONE `bun build --compile` binary with no runtime
// files beside it, and the usual npm push libraries are Node-shaped (native
// crypto bindings, `require` of files at runtime). Everything needed is already
// a dependency here — @noble/curves for P-256, @noble/hashes for HKDF/HMAC,
// @noble/ciphers for AES-GCM — and the two RFCs are small and fully specified.
//
// The relays do the same job with webpush-go (go-jmapserver/push.go). Both must
// stay interchangeable from the browser's point of view: **a Service Worker
// registration can hold only ONE PushSubscription, and that subscription is
// bound to the single applicationServerKey it was created with.** So the anchor
// cannot mint its own VAPID keypair — it has to be configured with the very
// same one the relays use, or a client would need a second subscription it is
// not allowed to have.
import { p256 } from '@noble/curves/nist.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { gcm } from '@noble/ciphers/aes.js'
import { base64urlnopad } from '@scure/base'

export interface PushSubscriptionKeys { p256dh: string; auth: string }
export interface WebPushSubscription { endpoint: string; keys: PushSubscriptionKeys }

export interface VapidKeys {
  /** base64url, uncompressed P-256 point (65 bytes) — the applicationServerKey
   * every client subscribes with. */
  publicKey: string
  /** base64url, 32-byte P-256 scalar. */
  privateKey: string
  /** RFC 8292 `sub` claim: a bare email address or an https: URL identifying
   * the sender. Apple's push service rejects a send outright when it's missing
   * or malformed, so this is required, not decorative. */
  subscriber: string
}

const b64u = {
  encode: (b: Uint8Array) => base64urlnopad.encode(b),
  decode: (s: string) => base64urlnopad.decode(s.replace(/=+$/, '')),
}

const utf8 = (s: string) => new TextEncoder().encode(s)

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let off = 0
  for (const p of parts) { out.set(p, off); off += p.length }
  return out
}

// RFC 8291 §3.3's info strings are length-prefixed labels; both use a 2-byte
// big-endian length for the key material they name.
function lengthPrefixed(b: Uint8Array): Uint8Array {
  return concat(new Uint8Array([b.length >> 8, b.length & 0xff]), b)
}

/** RFC 8291 §3: derives the content-encryption key and nonce from the
 * subscription's public key + auth secret and an ephemeral keypair, then
 * returns the full `aes128gcm` body (RFC 8188 header block ‖ ciphertext). */
function encryptPayload(payload: Uint8Array, sub: WebPushSubscription): Uint8Array {
  const uaPublic = b64u.decode(sub.keys.p256dh)
  const authSecret = b64u.decode(sub.keys.auth)

  const asPrivate = p256.utils.randomSecretKey()
  const asPublic = p256.getPublicKey(asPrivate, false) // uncompressed, 65 bytes
  const sharedSecret = p256.getSharedSecret(asPrivate, uaPublic, true).slice(1) // drop the 0x04/0x02 prefix → 32-byte X

  // ikm = HKDF(auth_secret, ecdh_secret, "WebPush: info" ‖ ua_public ‖ as_public)
  const keyInfo = concat(utf8('WebPush: info\0'), uaPublic, asPublic)
  const ikm = hkdf(sha256, sharedSecret, authSecret, keyInfo, 32)

  const salt = crypto.getRandomValues(new Uint8Array(16))
  const cek = hkdf(sha256, ikm, salt, utf8('Content-Encoding: aes128gcm\0'), 16)
  const nonce = hkdf(sha256, ikm, salt, utf8('Content-Encoding: nonce\0'), 12)

  // RFC 8188 §2: a single record, so the padding delimiter is 0x02 ("last").
  const plaintext = concat(payload, new Uint8Array([0x02]))
  const ciphertext = gcm(cek, nonce).encrypt(plaintext)

  // RFC 8188 header: salt(16) ‖ rs(4, big-endian) ‖ idlen(1) ‖ keyid(as_public)
  const rs = 4096
  const header = concat(
    salt,
    new Uint8Array([(rs >>> 24) & 0xff, (rs >>> 16) & 0xff, (rs >>> 8) & 0xff, rs & 0xff]),
    new Uint8Array([asPublic.length]),
    asPublic,
  )
  return concat(header, ciphertext)
}

/** RFC 8292 §2: an ES256 JWT over {aud, exp, sub}, signed with the VAPID
 * private key. `aud` is the push service's origin, NOT the full endpoint. */
function vapidAuthorization(endpoint: string, vapid: VapidKeys): string {
  const aud = new URL(endpoint).origin
  // A bare "mailto:" prefix supplied by the caller would double up; strip it
  // (go-jmapserver's SetVAPIDKeys carries the same defensive note — that exact
  // doubling is a 403 from Apple).
  const sub = vapid.subscriber.replace(/^mailto:/i, '')
  const header = b64u.encode(utf8(JSON.stringify({ typ: 'JWT', alg: 'ES256' })))
  const claims = b64u.encode(utf8(JSON.stringify({
    aud,
    exp: Math.floor(Date.now() / 1000) + 12 * 60 * 60,
    sub: sub.includes('://') ? sub : `mailto:${sub}`,
  })))
  const signingInput = utf8(`${header}.${claims}`)
  // ES256 wants raw r‖s (64 bytes), not DER — which is exactly what
  // @noble/curves v2's sign() returns for an already-hashed message.
  const sig = p256.sign(sha256(signingInput), b64u.decode(vapid.privateKey), { prehash: false })
  return `vapid t=${header}.${claims}.${b64u.encode(sig)}, k=${vapid.publicKey}`
}

export interface PushResult {
  ok: boolean
  status: number
  /** The push service says this subscription is gone (404/410) — the caller
   * should forget it rather than keep sending. */
  expired: boolean
}

/** Sends one push. Never throws: a push is best-effort by nature, and the
 * caller (a Forward being queued) must not fail because a third-party push
 * service is unreachable. */
export async function sendWebPush(
  sub: WebPushSubscription,
  vapid: VapidKeys,
  payload: Uint8Array,
  ttlSeconds = 86400,
): Promise<PushResult> {
  try {
    const body = encryptPayload(payload, sub)
    const res = await fetch(sub.endpoint, {
      method: 'POST',
      headers: {
        'Content-Encoding': 'aes128gcm',
        'Content-Type': 'application/octet-stream',
        // A phone asleep or out of coverage is unreachable for far longer than
        // a minute, and the push service DISCARDS anything whose TTL ran out
        // rather than delivering it late (go-jmapserver/push.go carries the
        // same reasoning after the same bug).
        TTL: String(ttlSeconds),
        Urgency: 'high',
        Authorization: vapidAuthorization(sub.endpoint, vapid),
      },
      // The anchor's tsconfig has no DOM lib (it isn't a browser build), so
      // there is no BodyInit type to name here — a Uint8Array is a valid fetch
      // body at runtime either way.
      body: body as any,
    })
    return { ok: res.ok, status: res.status, expired: res.status === 404 || res.status === 410 }
  } catch {
    return { ok: false, status: 0, expired: false }
  }
}
