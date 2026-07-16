// did:peer method 2 — encode/decode + fresh-identity generation.
//
// Scope (PLAN.md "Multi-method resolution" / "Mediator接続用の一時did:peer生成"):
// biset's own identifier is `did:dht` only, always — this module is NOT an
// alternate identity for biset users. It exists purely as an interop
// fallback: when a third-party mediator/resolver can't resolve `did:dht`
// (verified against RootsID/adorsys — see PLAN.md's 実地検証ログ), biset
// mints one did:peer per external-mediator relationship to talk to it.
//
// did:peer:2 doesn't standardize kid naming or the service segment's
// internal shape — we follow the adorsys/didcomm-mediator-rs convention
// (kid = positional "#key-N", service payload = {id, t, s: {uri, a, r}}),
// verified to interoperate against our own ~/didmediator (which decodes the
// same way) and against adorsys's own mediator.
import { x25519, ed25519 } from '@noble/curves/ed25519.js'

export function b64url(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function b64urlDecodeToBytes(s: string): Uint8Array {
  const pad = (4 - (s.length % 4)) % 4
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat(pad)
  const bin = atob(b64)
  return Uint8Array.from(bin, c => c.charCodeAt(0))
}

function b64urlDecodeToString(s: string): string {
  const pad = (4 - (s.length % 4)) % 4
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat(pad)
  return atob(b64)
}

const B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

function base58Encode(bytes: Uint8Array): string {
  let num = 0n
  for (const b of bytes) num = num * 256n + BigInt(b)
  let out = ''
  while (num > 0n) {
    out = B58_ALPHABET.charAt(Number(num % 58n)) + out
    num = num / 58n
  }
  let leadingZeros = 0
  for (const b of bytes) {
    if (b === 0) leadingZeros++
    else break
  }
  return B58_ALPHABET.charAt(0).repeat(leadingZeros) + out
}

function base58Decode(str: string): Uint8Array {
  let num = 0n
  for (const ch of str) {
    const idx = B58_ALPHABET.indexOf(ch)
    if (idx < 0) throw new Error(`invalid base58 char ${ch}`)
    num = num * 58n + BigInt(idx)
  }
  let hex = num.toString(16)
  if (hex.length % 2) hex = '0' + hex
  const bytes = Uint8Array.from(hex.match(/.{2}/g)?.map(b => parseInt(b, 16)) ?? [])
  let leadingZeros = 0
  for (const ch of str) {
    if (ch === '1') leadingZeros++
    else break
  }
  return new Uint8Array([...new Array(leadingZeros).fill(0), ...bytes])
}

export interface PeerService {
  uri: string
  accept?: string[]
  routingKeys?: string[]
}

export interface PeerDidDoc {
  id: string
  keyAgreement: string[]
  authentication: string[]
  verificationMethod: Array<{
    id: string
    type: string
    controller: string
    publicKeyJwk: { kty: string; crv: string; x: string }
  }>
  service: Array<{
    id: string
    type: string
    serviceEndpoint: { uri: string; accept: string[]; routing_keys: string[] }
  }>
}

export interface PeerSecret {
  id: string
  type: string
  privateKeyJwk: { kty: string; crv: string; x: string; d: string }
}

export interface PeerIdentity {
  did: string
  xKid: string // keyAgreement (X25519) kid
  edKid: string // authentication (Ed25519) kid
  xPub: Uint8Array
  edPub: Uint8Array
  xPriv: Uint8Array
  edPriv: Uint8Array
  doc: PeerDidDoc
  secrets: Record<string, PeerSecret>
}

function encodeServiceSegment(service: PeerService): string {
  const sVal = {
    id: '#didcomm',
    t: 'dm',
    s: { uri: service.uri, a: service.accept ?? ['didcomm/v2'], r: service.routingKeys ?? [] },
  }
  return 'S' + btoa(JSON.stringify(sVal)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** Build a did:peer:2 string from raw public keys, with an optional service. */
export function encodePeerDid2(xPub: Uint8Array, edPub: Uint8Array, service?: PeerService): string {
  const eSeg = 'E' + 'z' + base58Encode(new Uint8Array([0xec, 0x01, ...xPub]))
  const vSeg = 'V' + 'z' + base58Encode(new Uint8Array([0xed, 0x01, ...edPub]))
  let did = `did:peer:2.${eSeg}.${vSeg}`
  if (service) did += '.' + encodeServiceSegment(service)
  return did
}

/** Decode a did:peer:2 string into a resolvable DID doc (self-certifying, no network). */
export function decodePeerDid2(did: string): PeerDidDoc {
  const rest = did.replace(/^did:peer:2\./, '')
  const segments = rest.split('.')
  const verificationMethod: PeerDidDoc['verificationMethod'] = []
  const keyAgreement: string[] = []
  const authentication: string[] = []
  const service: PeerDidDoc['service'] = []
  let idx = 0
  for (const seg of segments) {
    const purpose = seg[0]
    const body = seg.slice(1)
    if (purpose === 'S') {
      const parsed = JSON.parse(b64urlDecodeToString(body))
      service.push({
        id: `${did}#${parsed.id?.replace(/^#/, '') ?? 'didcomm'}`,
        type: 'DIDCommMessaging',
        serviceEndpoint: { uri: parsed.s.uri, accept: parsed.s.a ?? ['didcomm/v2'], routing_keys: parsed.s.r ?? [] },
      })
      continue
    }
    const decoded = base58Decode(body.slice(1)) // strip leading 'z' (multibase)
    const raw = decoded.slice(2) // strip 2-byte multicodec varint prefix
    idx++
    const kid = `${did}#key-${idx}`
    const isX25519 = decoded[0] === 0xec
    verificationMethod.push({
      id: kid,
      type: 'JsonWebKey2020',
      controller: did,
      publicKeyJwk: isX25519
        ? { kty: 'OKP', crv: 'X25519', x: b64url(raw) }
        : { kty: 'OKP', crv: 'Ed25519', x: b64url(raw) },
    })
    if (purpose === 'E') keyAgreement.push(kid)
    if (purpose === 'V') authentication.push(kid)
  }
  return { id: did, keyAgreement, authentication, verificationMethod, service }
}

/** Builds a full did:peer:2 identity from an existing X25519/Ed25519 keypair
 * — the shared constructor behind both a fresh mint and a UI that persists
 * keys across reloads (a stable identity, unlike the mediator-relationship
 * fallback this module otherwise implies, is occasionally still useful — a
 * debug page shouldn't force re-registering with a mediator on every reload). */
export function identityFromKeys(xPriv: Uint8Array, edPriv: Uint8Array, service?: PeerService): PeerIdentity {
  const xPub = x25519.getPublicKey(xPriv)
  const edPub = ed25519.getPublicKey(edPriv)
  const did = encodePeerDid2(xPub, edPub, service)
  const xKid = `${did}#key-1`
  const edKid = `${did}#key-2`
  const doc: PeerDidDoc = {
    id: did,
    keyAgreement: [xKid],
    authentication: [edKid],
    verificationMethod: [
      { id: xKid, type: 'JsonWebKey2020', controller: did, publicKeyJwk: { kty: 'OKP', crv: 'X25519', x: b64url(xPub) } },
      { id: edKid, type: 'JsonWebKey2020', controller: did, publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: b64url(edPub) } },
    ],
    // Was hardcoded to [] regardless of `service` — silently dropped it from
    // the in-memory doc even though encodePeerDid2 above embeds it in the DID
    // string. Only surfaced via decodePeerDid2(did) re-parsing the string;
    // any caller using .doc directly (not re-decoding) saw no service at all.
    service: service
      ? [{ id: `${did}#didcomm`, type: 'DIDCommMessaging', serviceEndpoint: { uri: service.uri, accept: service.accept ?? ['didcomm/v2'], routing_keys: service.routingKeys ?? [] } }]
      : [],
  }
  const secrets: Record<string, PeerSecret> = {
    [xKid]: { id: xKid, type: 'JsonWebKey2020', privateKeyJwk: { kty: 'OKP', crv: 'X25519', x: b64url(xPub), d: b64url(xPriv) } },
    [edKid]: { id: edKid, type: 'JsonWebKey2020', privateKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: b64url(edPub), d: b64url(edPriv) } },
  }
  return { did, xKid, edKid, xPub, edPub, xPriv, edPriv, doc, secrets }
}

/** Mint a fresh did:peer:2 identity for one external-mediator relationship
 * (E + V segments; V is required by at least one third-party implementation
 * tested against, even though the sender side never authenticates with it). */
export function generatePeerIdentity(service?: PeerService): PeerIdentity {
  return identityFromKeys(x25519.utils.randomSecretKey(), ed25519.utils.randomSecretKey(), service)
}
