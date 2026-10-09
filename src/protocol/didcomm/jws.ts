// Signatures in DIDComm Messaging v2.1: the signing algorithms a recipient
// MUST be able to verify (EdDSA/Ed25519, ES256/P-256, ES256K/secp256k1) and
// the one it signs with (EdDSA); the rule that a signing key MUST be
// referenced from the signer DID's `authentication`; and signed messages
// (`application/didcomm-signed+json`), General and Flattened JWS JSON alike.
//
// Used by the `from_prior` JWT (from-prior.ts) and by every place a received
// message is opened (open.ts).
import { ed25519 } from '@noble/curves/ed25519.js'
import { p256 } from '@noble/curves/nist.js'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { base58 } from '@scure/base'
import { base64urlToBytes, bytesToBase64url } from '../canonical.ts'
import { decodePeerDid2 } from './peer.ts'
import { resolveDidWeb } from './did-web.ts'
import { resolve as resolveWebvh } from '../webvh/resolver.ts'

export const DIDCOMM_SIGNED_MEDIA_TYPE = 'application/didcomm-signed+json'

export type JwsAlgorithm = 'EdDSA' | 'ES256' | 'ES256K'
type SigningKeyType = 'Ed25519' | 'P-256' | 'secp256k1'
export interface SigningKey { type: SigningKeyType; publicKey: Uint8Array }

const ALGORITHM_OF: Record<SigningKeyType, JwsAlgorithm> = { Ed25519: 'EdDSA', 'P-256': 'ES256', secp256k1: 'ES256K' }
export const JWS_ALGORITHMS: readonly JwsAlgorithm[] = ['EdDSA', 'ES256', 'ES256K']

/** A signature that does not hold, or a key that may not make it. Never a
 * network failure: retrying gives the same answer. */
export class SignatureError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'SignatureError'
  }
}

// ---- keys ----

/** Multicodec prefixes (varint) of the signing key types. */
const SIGNING_MULTICODECS: ReadonlyArray<{ type: SigningKeyType; prefix: readonly [number, number]; size: number }> = [
  { type: 'Ed25519', prefix: [0xed, 0x01], size: 32 },
  { type: 'P-256', prefix: [0x80, 0x24], size: 33 },
  { type: 'secp256k1', prefix: [0xe7, 0x01], size: 33 },
]

interface VerificationMethodLike { id: string; publicKeyMultibase?: string; publicKeyJwk?: { kty?: unknown; crv?: unknown; x?: unknown; y?: unknown } }

/** The signing key a verification method carries (Multikey or JWK), or throws. */
export function signingKeyOfMethod(method: VerificationMethodLike): SigningKey {
  if (typeof method.publicKeyMultibase === 'string' && method.publicKeyMultibase.startsWith('z')) {
    const bytes = base58.decode(method.publicKeyMultibase.slice(1))
    const codec = SIGNING_MULTICODECS.find(({ prefix }) => bytes[0] === prefix[0] && bytes[1] === prefix[1])
    if (!codec || bytes.length !== 2 + codec.size) throw new SignatureError(`${method.id} is not an Ed25519, P-256 or secp256k1 key`)
    return { type: codec.type, publicKey: bytes.slice(2) }
  }
  const jwk = method.publicKeyJwk
  if (jwk?.kty === 'OKP' && jwk.crv === 'Ed25519' && typeof jwk.x === 'string') return { type: 'Ed25519', publicKey: base64urlToBytes(jwk.x) }
  if (jwk?.kty === 'EC' && (jwk.crv === 'P-256' || jwk.crv === 'secp256k1') && typeof jwk.x === 'string' && typeof jwk.y === 'string') {
    return { type: jwk.crv, publicKey: new Uint8Array([0x04, ...base64urlToBytes(jwk.x), ...base64urlToBytes(jwk.y)]) }
  }
  throw new SignatureError(`${method.id} is not an Ed25519, P-256 or secp256k1 key`)
}

/** Whether `signature` over `signingInput` holds for `key` under `alg`
 * (the algorithm has to be the key type's). JOSE does not require low-S
 * ECDSA signatures, so neither does this. */
export function verifyJwsSignature(alg: unknown, key: SigningKey, signingInput: Uint8Array, signature: Uint8Array): boolean {
  if (alg !== ALGORITHM_OF[key.type]) return false
  try {
    if (key.type === 'Ed25519') return ed25519.verify(signature, signingInput, key.publicKey)
    if (key.type === 'P-256') return p256.verify(signature, signingInput, key.publicKey, { lowS: false })
    return secp256k1.verify(signature, signingInput, key.publicKey, { lowS: false })
  } catch {
    return false
  }
}

function fragmentOf(id: string): string {
  const hash = id.indexOf('#')
  return hash < 0 ? id : id.slice(hash)
}

interface DocumentMethods { id: string; verificationMethod?: readonly VerificationMethodLike[]; authentication?: readonly unknown[] }

/** The method `kid` names, when the document references it from
 * `authentication` (compared by fragment: a domain move rewrites a
 * did:webvh's DID part, never a key's fragment). */
export function authenticationMethodOf(document: DocumentMethods, kid: string): VerificationMethodLike | undefined {
  const wanted = fragmentOf(kid)
  if (!(document.authentication ?? []).some(reference => typeof reference === 'string' && fragmentOf(reference) === wanted)) return undefined
  return (document.verificationMethod ?? []).find(value => fragmentOf(value.id) === wanted)
}

/** The signing key `kid` names in `document` -- which DIDComm v2.1 allows
 * only when `authentication` references it -- or SignatureError. */
export function authenticationSigningKey(document: DocumentMethods, kid: string): SigningKey {
  const method = authenticationMethodOf(document, kid)
  if (!method) throw new SignatureError(`${kid} is not an authentication key of ${document.id}`)
  return signingKeyOfMethod(method)
}

/** Resolves a signer kid to the key its DID document authorizes, or throws
 * (SignatureError when the document answers no). */
export type SigningKeyResolver = (kid: string) => Promise<SigningKey>

/** did:peer:2 from the DID itself, did:web and did:webvh by resolution.
 * `fetchImpl` should bypass a host's CDN. */
export function signingKeyResolver(fetchImpl: typeof fetch = fetch): SigningKeyResolver {
  return async kid => {
    const did = kid.split('#', 1)[0]!
    if (!kid.includes('#')) throw new SignatureError(`${kid} is not a DID URL`)
    if (did.startsWith('did:peer:2.')) return authenticationSigningKey(decodePeerDid2(did) as unknown as DocumentMethods, kid)
    if (did.startsWith('did:web:')) {
      const document = await resolveDidWeb(did, fetchImpl)
      if (!document) throw new SignatureError(`${did} does not resolve`)
      return authenticationSigningKey(document as DocumentMethods, kid)
    }
    if (did.startsWith('did:webvh:')) {
      const document = await resolveWebvh(did, undefined, fetchImpl)
      if (!document) throw new SignatureError(`${did} does not resolve`)
      return authenticationSigningKey(document as unknown as DocumentMethods, kid)
    }
    throw new SignatureError(`unsupported DID method for signer ${kid}`)
  }
}

// ---- signed messages ----

/** A JWS in General JSON serialization (a Flattened one is read into this). */
export interface DidCommJws {
  payload: string
  signatures: Array<{ protected: string; signature: string; header?: { kid?: string } }>
}

/** A signed message (General or Flattened JWS JSON), normalized to General,
 * or null when `value` is not one. */
export function parseDidCommJws(value: unknown): DidCommJws | null {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null
  const jws = value as Record<string, unknown>
  if (typeof jws.payload !== 'string') return null
  const one = (item: unknown) => {
    if (item === null || typeof item !== 'object' || Array.isArray(item)) return null
    const value = item as Record<string, unknown>
    if (typeof value.protected !== 'string' || typeof value.signature !== 'string') return null
    const header = value.header && typeof value.header === 'object' && !Array.isArray(value.header) ? value.header as { kid?: string } : undefined
    return { protected: value.protected, signature: value.signature, ...(header ? { header } : {}) }
  }
  if (Array.isArray(jws.signatures)) {
    const signatures = jws.signatures.map(one)
    if (signatures.length === 0 || signatures.some(signature => !signature)) return null
    return { payload: jws.payload, signatures: signatures as DidCommJws['signatures'] }
  }
  const flattened = one(jws)
  return flattened ? { payload: jws.payload, signatures: [flattened] } : null
}

/** Verifies every signature of `jws` against the key its `kid` names (one
 * that the signer DID's `authentication` references) and returns the signed
 * payload with the (first) signer's kid. Several signers must all be of the
 * same DID. */
export async function verifyDidCommJws(jws: DidCommJws, resolveKey: SigningKeyResolver): Promise<{ payload: Uint8Array; signerKid: string }> {
  let signerKid: string | undefined
  for (const entry of jws.signatures) {
    let header: Record<string, unknown>
    try { header = JSON.parse(new TextDecoder().decode(base64urlToBytes(entry.protected))) } catch { throw new SignatureError('a JWS protected header is not JSON') }
    const kid = typeof header.kid === 'string' ? header.kid : entry.header?.kid
    if (typeof kid !== 'string' || !kid.includes('#')) throw new SignatureError('a JWS signature names no signer kid')
    if (!JWS_ALGORITHMS.includes(header.alg as JwsAlgorithm)) throw new SignatureError(`unsupported JWS alg ${JSON.stringify(header.alg)}`)
    if (signerKid && kid.split('#', 1)[0] !== signerKid.split('#', 1)[0]) throw new SignatureError('a signed message has signers of different DIDs')
    const key = await resolveKey(kid)
    const signingInput = new TextEncoder().encode(`${entry.protected}.${jws.payload}`)
    if (!verifyJwsSignature(header.alg, key, signingInput, base64urlToBytes(entry.signature))) throw new SignatureError(`the signature of ${kid} does not verify`)
    signerKid ??= kid
  }
  return { payload: base64urlToBytes(jws.payload), signerKid: signerKid! }
}

/** Signs a plaintext message with an Ed25519 key `kid` (EdDSA), as a General
 * JWS JSON: the one algorithm biset signs with. `kid` must be referenced from
 * the signer DID's `authentication` for a recipient to accept it. */
export function signDidCommMessage(plaintext: object, kid: string, privateKey: Uint8Array): DidCommJws {
  const protectedHeader = bytesToBase64url(new TextEncoder().encode(JSON.stringify({ typ: DIDCOMM_SIGNED_MEDIA_TYPE, alg: 'EdDSA', kid })))
  const payload = bytesToBase64url(new TextEncoder().encode(JSON.stringify(plaintext)))
  const signature = ed25519.sign(new TextEncoder().encode(`${protectedHeader}.${payload}`), privateKey)
  return { payload, signatures: [{ protected: protectedHeader, signature: bytesToBase64url(signature), header: { kid } }] }
}
