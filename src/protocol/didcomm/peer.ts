// did:peer method 2 -- encode/decode + fresh-identity generation.
//
// This is the standalone mediator's OWN identity method (ARC.md's DIDComm
// mediator redesign, 2026-08-27): every client's mediate-request and
// keylist-update targets this DID's keyAgreement kid. did:peer:2 needs no
// network resolution (the keys are IN the DID string), which is what lets a
// mediator authenticate itself with zero external dependencies -- unlike
// biset users' own did:webvh, which the mediator never needs or wants to be.
// Lives under didcomm/, not mediator/, because the CLIENT decodes it too
// (mediator-coordinate.ts/mediator-pickup.ts, Phase 4) -- a browser needs
// this module to talk to a mediator, without pulling in mediator/'s
// node:fs-backed identity/queue/connection persistence.
//
// did:peer:2 doesn't standardize kid naming or the service segment's
// internal shape -- follows the adorsys/didcomm-mediator-rs convention
// (kid = positional "#key-N", service payload = {id, t, s: {uri, a, r}}),
// ported from src.bak/did/peer/peer.ts (verified there to interoperate
// against adorsys's own mediator).
import { x25519, ed25519 } from '@noble/curves/ed25519.js'
import { extract, expand } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'

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

export interface PeerIdentity {
  did: string
  xKid: string // keyAgreement (X25519) kid
  edKid: string // authentication (Ed25519) kid
  xPub: Uint8Array
  edPub: Uint8Array
  xPriv: Uint8Array
  edPriv: Uint8Array
  doc: PeerDidDoc
}

/** The public key for `kid` from an already-decoded doc. */
export function publicKeyOf(doc: PeerDidDoc, kid: string): Uint8Array {
  const vm = doc.verificationMethod.find(v => v.id === kid)
  if (!vm) throw new Error(`publicKeyOf: kid ${kid} not found in DID doc`)
  return b64urlDecodeToBytes(vm.publicKeyJwk.x)
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

/** Builds a full did:peer:2 identity from an existing X25519/Ed25519 keypair. */
export function identityFromKeys(xPriv: Uint8Array, edPriv: Uint8Array, service?: PeerService): PeerIdentity {
  const xPub = x25519.getPublicKey(xPriv)
  const edPub = ed25519.getPublicKey(edPriv)
  const did = encodePeerDid2(xPub, edPub, service)
  const doc = decodePeerDid2(did)
  return { did, xKid: doc.keyAgreement[0]!, edKid: doc.authentication[0]!, xPub, edPub, xPriv, edPriv, doc }
}

/** Mint a fresh did:peer:2 identity. */
export function generatePeerIdentity(service?: PeerService): PeerIdentity {
  return identityFromKeys(x25519.utils.randomSecretKey(), ed25519.utils.randomSecretKey(), service)
}

/**
 * Derives the SAME did:peer:2 identity every time for a given (relationship
 * secret, counterparty DID) pair, instead of minting a fresh random one per
 * relationship attempt.
 *
 * This replaces what used to be an in-memory "pending initiation" map: a
 * random peer identity can only be recovered by remembering it somewhere,
 * so a page reload between sending RELATIONSHIP_INIT and receiving its
 * ACCEPT orphaned that attempt -- the next `ensureContact` call minted yet
 * another random identity, sent another INIT, and (found live, 2026-09-15)
 * mediators accumulated one did:peer connection per attempt while the two
 * sides never converged on a single ContactKeyV1 (`selectUnsuperseded`
 * eventually throwing "ambiguous" once two independently-initiated, non-
 * superseding contacts existed for the same counterparty).
 *
 * `relationshipSecret` MUST be identical across every device of the same
 * Wallet identity (did-md-oauth.ts derives it from the Wallet's permanent
 * Root key via the same OAuth derived-secret grant VCK uses, under its own
 * fixed, non-rotating purpose) -- NOT a per-device front-door key. The first
 * version of this function took the device's own front-door X25519 key,
 * which only made ONE device's own retries idempotent: two DIFFERENT
 * devices of the same identity, each contacting the same external
 * counterparty for the first time before Vault Sync had converged, still
 * derived two different, non-superseding peer identities and hit the exact
 * same "ambiguous, explicit rotation required" dead end this was meant to
 * prevent (found live, 2026-09-15, on a third device). Keying on a secret
 * every device already derives identically removes the race at its root:
 * there is only ever one possible derived identity for a given counterparty,
 * regardless of which device gets there first.
 *
 * A deterministic identity needs no memory: recompute it and you get back
 * the exact same did:peer, so a retry after a reload, a second concurrent
 * send from the same or a different device, or re-registering with the
 * mediator are all naturally idempotent. Unlinkability is unaffected --
 * HKDF is one-way, so nothing this identity's public half reveals lets an
 * observer recover the relationship secret it came from, and salting on
 * `counterpartyDid` keeps every counterparty's derived identity independent
 * of every other's, exactly as a random one would be.
 */
export function deriveRelationshipPeerIdentity(relationshipSecret: Uint8Array, counterpartyDid: string, service?: PeerService): PeerIdentity {
  if (relationshipSecret.length !== 32) throw new TypeError('relationship secret must be 32 bytes')
  if (!counterpartyDid) throw new TypeError('counterparty DID is required to derive a relationship peer identity')
  const prk = extract(sha256, relationshipSecret, new TextEncoder().encode(counterpartyDid))
  const xPriv = expand(sha256, prk, new TextEncoder().encode('biset/relationship-peer/x25519/v1'), 32)
  const edPriv = expand(sha256, prk, new TextEncoder().encode('biset/relationship-peer/ed25519/v1'), 32)
  return identityFromKeys(xPriv, edPriv, service)
}
