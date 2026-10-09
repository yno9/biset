// Key-agreement keys of every curve DIDComm Messaging v2.1 requires (X25519,
// P-384 and P-256 MUST be supported; P-521 is optional and not supported
// here): reading one from a DID document (Multikey or JWK), and the one
// place that knows how each curve's public key is laid out.
//
// A public key is kept as the curve's own encoding: 32 raw bytes for X25519,
// a SEC1 point (compressed or uncompressed) for the NIST curves -- what
// @noble/curves takes for ECDH, which also refuses a point that is not on
// the curve (DIDComm v2.1: a received NIST public key MUST be checked).
import { base58 } from '@scure/base'
import { p256, p384 } from '@noble/curves/nist.js'
import { x25519 } from '@noble/curves/ed25519.js'
import { base64urlToBytes as b64urlToBytes, bytesToBase64url as b64url } from '../canonical.ts'

export type KeyAgreementCurve = 'X25519' | 'P-256' | 'P-384'

export interface KeyAgreementKey { curve: KeyAgreementCurve; publicKey: Uint8Array }

/** Multicodec prefixes (varint) of the key types a keyAgreement entry may carry. */
const MULTICODECS: ReadonlyArray<{ curve: KeyAgreementCurve; prefix: readonly [number, number] }> = [
  { curve: 'X25519', prefix: [0xec, 0x01] }, // x25519-pub
  { curve: 'P-256', prefix: [0x80, 0x24] }, // p256-pub (0x1200)
  { curve: 'P-384', prefix: [0x81, 0x24] }, // p384-pub (0x1201)
]

const NIST = { 'P-256': { curve: p256, size: 32 }, 'P-384': { curve: p384, size: 48 } } as const

function checked(curve: KeyAgreementCurve, publicKey: Uint8Array): KeyAgreementKey {
  if (curve === 'X25519') {
    if (publicKey.length !== 32) throw new Error('an X25519 public key is 32 bytes')
  } else {
    NIST[curve].curve.Point.fromBytes(publicKey) // throws unless a point on the curve
  }
  return { curve, publicKey }
}

/** A multibase (base58btc) Multikey of a key-agreement curve, or throws. */
export function decodeKeyAgreementMultikey(multibase: string): KeyAgreementKey {
  if (!multibase.startsWith('z')) throw new Error('Multikey: expected multibase base58btc ("z"-prefixed)')
  const bytes = base58.decode(multibase.slice(1))
  const codec = MULTICODECS.find(({ prefix }) => bytes[0] === prefix[0] && bytes[1] === prefix[1])
  if (!codec) throw new Error('Multikey: not a key-agreement key type (X25519, P-256 or P-384)')
  return checked(codec.curve, bytes.slice(2))
}

/** The multibase Multikey of `key` (a NIST key compressed, as Multikey writes it). */
export function encodeKeyAgreementMultikey(key: KeyAgreementKey): string {
  const codec = MULTICODECS.find(value => value.curve === key.curve)!
  const body = key.curve === 'X25519' ? key.publicKey : NIST[key.curve].curve.Point.fromBytes(key.publicKey).toBytes(true)
  return 'z' + base58.encode(new Uint8Array([...codec.prefix, ...body]))
}

/** A JWK (`OKP`/X25519 or `EC`/P-256, P-384) as a key-agreement key, or throws. */
export function keyAgreementKeyFromJwk(jwk: { kty?: unknown; crv?: unknown; x?: unknown; y?: unknown }): KeyAgreementKey {
  if (jwk.kty === 'OKP' && jwk.crv === 'X25519' && typeof jwk.x === 'string') return checked('X25519', b64urlToBytes(jwk.x))
  if (jwk.kty === 'EC' && (jwk.crv === 'P-256' || jwk.crv === 'P-384') && typeof jwk.x === 'string' && typeof jwk.y === 'string') {
    const x = b64urlToBytes(jwk.x)
    const y = b64urlToBytes(jwk.y)
    if (x.length !== NIST[jwk.crv].size || y.length !== NIST[jwk.crv].size) throw new Error(`JWK: ${jwk.crv} coordinates have the wrong length`)
    return checked(jwk.crv, new Uint8Array([0x04, ...x, ...y]))
  }
  throw new Error('JWK: not a key-agreement key (OKP X25519, EC P-256 or P-384)')
}

/** `key` as a JWK. */
export function jwkOfKeyAgreementKey(key: KeyAgreementKey): { kty: string; crv: string; x: string; y?: string } {
  if (key.curve === 'X25519') return { kty: 'OKP', crv: 'X25519', x: b64url(key.publicKey) }
  const { size } = NIST[key.curve]
  const point = NIST[key.curve].curve.Point.fromBytes(key.publicKey).toBytes(false)
  return { kty: 'EC', crv: key.curve, x: b64url(point.slice(1, 1 + size)), y: b64url(point.slice(1 + size)) }
}

/** The multicodec key type of a did:peer / Multikey prefix, X25519/P-256/P-384, or undefined. */
export function keyAgreementCurveOfPrefix(b0: number | undefined, b1: number | undefined): KeyAgreementCurve | undefined {
  return MULTICODECS.find(({ prefix }) => prefix[0] === b0 && prefix[1] === b1)?.curve
}

/** A fresh key pair on `curve` (an ephemeral key; a test's key). A NIST
 * public key is the uncompressed SEC1 point. */
export function generateKeyAgreementKeyPair(curve: KeyAgreementCurve): { privateKey: Uint8Array; publicKey: Uint8Array } {
  if (curve === 'X25519') { const privateKey = x25519.utils.randomSecretKey(); return { privateKey, publicKey: x25519.getPublicKey(privateKey) } }
  const privateKey = NIST[curve].curve.utils.randomSecretKey()
  return { privateKey, publicKey: NIST[curve].curve.getPublicKey(privateKey, false) }
}

/** ECDH on `curve`. For the NIST curves `Z` is the x-coordinate of the shared
 * point (JWA §4.6); the peer's point is checked to be on the curve. */
export function keyAgreementSharedSecret(curve: KeyAgreementCurve, privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  if (curve === 'X25519') return x25519.getSharedSecret(privateKey, publicKey)
  return NIST[curve].curve.getSharedSecret(privateKey, publicKey, true).slice(1)
}
