// DIDComm signed messages (signature.md): a JWS over the plaintext JWM, used
// for non-repudiation (sign-then-encrypt) or tamper-resistance on an
// unencrypted message (e.g. an Out-of-Band invitation). EdDSA / Ed25519 only —
// the one algorithm the spec says implementations MUST be able to sign with,
// and the key type biset's identities already hold (the DID's #k0 identity /
// authentication key). ES256/ES256K are spec-listed for verify but no peer
// reachable from here signs with them, mirroring crypto.ts's enc scoping.
//
// Serialization: the spec allows General or Flattened JSON JWS and requires
// recipients to process BOTH. We EMIT flattened (a DIDComm signed message has
// exactly one meaningful signature — the sender's) and ACCEPT either.
import { ed25519 } from '@noble/curves/ed25519.js'
import { b64url, b64urlToBytes } from './crypto.ts'

const utf8 = (s: string) => new TextEncoder().encode(s)
const fromUtf8 = (b: Uint8Array) => new TextDecoder().decode(b)

export interface SignedJWS {
  payload: string // base64url(plaintext JWM bytes)
  // Flattened form: protected+signature at top level. General form: signatures[].
  protected?: string
  signature?: string
  signatures?: Array<{ protected: string; signature: string }>
}

export interface JwsSigner {
  /** A DID URL from the signer's `authentication` section (signature.md: the
   * kid MUST refer to an authentication key). */
  kid: string
  /** Ed25519 private key (32 bytes / seed). */
  edPrivateKey: Uint8Array
}

/** Resolves the Ed25519 public key for a signer kid — the caller knows how to
 * resolve a DID and MUST confirm the kid is in that DID's `authentication`
 * section before returning (signature.md Verification). */
export type ResolveSignerKey = (signerKid: string, opts?: { fresh?: boolean }) => Uint8Array | Promise<Uint8Array>

/** Structural check: is this parsed JSON a DIDComm signed message (JWS JSON
 * serialization) rather than a bare plaintext? */
export function isSignedMessage(v: unknown): v is SignedJWS {
  if (typeof v !== 'object' || v === null) return false
  const o = v as Record<string, unknown>
  if (typeof o.payload !== 'string') return false
  const flattened = typeof o.protected === 'string' && typeof o.signature === 'string'
  const general = Array.isArray(o.signatures) && o.signatures.length > 0
  return flattened || general
}

/** Signs plaintext JWM bytes, producing a flattened JWS. */
export function packSigned(plaintext: Uint8Array, signer: JwsSigner): SignedJWS {
  const protectedHeader = { typ: 'application/didcomm-signed+json', alg: 'EdDSA', kid: signer.kid }
  const protectedB64 = b64url(utf8(JSON.stringify(protectedHeader)))
  const payloadB64 = b64url(plaintext)
  const signingInput = utf8(`${protectedB64}.${payloadB64}`)
  const signature = ed25519.sign(signingInput, signer.edPrivateKey)
  return { payload: payloadB64, protected: protectedB64, signature: b64url(signature) }
}

export interface UnpackedSigned { plaintext: Uint8Array; signerKid: string }

/** Verifies a JWS (either serialization) and returns the inner plaintext bytes
 * plus the signer's kid. Throws on a missing/invalid signature or when the
 * resolver rejects the key. */
export async function unpackSigned(jws: SignedJWS, resolveSignerKey: ResolveSignerKey): Promise<UnpackedSigned> {
  const sig = jws.signatures?.[0] ?? (jws.protected && jws.signature ? { protected: jws.protected, signature: jws.signature } : null)
  if (!sig) throw new Error('unpackSigned: no signature present')

  const header = JSON.parse(fromUtf8(b64urlToBytes(sig.protected))) as { alg?: string; kid?: string }
  if (header.alg !== 'EdDSA') throw new Error(`unpackSigned: unsupported alg ${header.alg} — EdDSA only`)
  if (!header.kid) throw new Error('unpackSigned: signature header has no kid')

  const signerPub = await resolveSignerKey(header.kid)
  const signingInput = utf8(`${sig.protected}.${jws.payload}`)
  const okSig = ed25519.verify(b64urlToBytes(sig.signature), signingInput, signerPub)
  if (!okSig) throw new Error('unpackSigned: signature does not verify')

  return { plaintext: b64urlToBytes(jws.payload), signerKid: header.kid }
}

/** Receive-side convenience: given decrypted inner bytes, transparently peel a
 * signature layer if present (verifying it), else return the bytes unchanged.
 * Returns the (possibly verified) plaintext bytes and, when signed, the signer.
 * This is what lets the unpack path treat signed and unsigned inner messages
 * uniformly. */
export async function unwrapMaybeSigned(bytes: Uint8Array, resolveSignerKey: ResolveSignerKey): Promise<{ plaintext: Uint8Array; signerKid: string | null }> {
  let parsed: unknown
  try {
    parsed = JSON.parse(fromUtf8(bytes))
  } catch {
    return { plaintext: bytes, signerKid: null }
  }
  if (!isSignedMessage(parsed)) return { plaintext: bytes, signerKid: null }
  const { plaintext, signerKid } = await unpackSigned(parsed, resolveSignerKey)
  return { plaintext, signerKid }
}
