// DID Rotation (signature.md "DID Rotation"): the `from_prior` header, a
// compact JWT signed by a key of the PRIOR DID, asserting that the prior DID
// (iss) has rotated to the new DID (sub) now carried in `from`. It lets a
// correspondent re-bind an existing relationship to a fresh DID without a
// separate protocol.
//
// biset's own identities are rotation-LESS by design ([[project_biset_did]]:
// rotation-less + successor reservation), so biset never EMITS a from_prior in
// normal operation — but a conforming agent must still be able to build and,
// above all, VERIFY one from a peer that does rotate. Both directions live here.
//
// The JWT is EdDSA/Ed25519 compact form (header.payload.signature), matching
// the signing key type biset and most did:key/did:peer peers use.
import { ed25519 } from '@noble/curves/ed25519.js'
import { b64url, b64urlToBytes } from './crypto.ts'

const utf8 = (s: string) => new TextEncoder().encode(s)
const fromUtf8 = (b: Uint8Array) => new TextDecoder().decode(b)

interface FromPriorClaims {
  iss: string           // prior DID
  sub?: string          // new DID — omitted when ENDING a relationship (rotate to nothing)
  iat: number           // datetime of the rotation (epoch seconds), NOT of the message
}

export interface FromPriorSigner {
  /** A key id authorized in the PRIOR DID's document. */
  kid: string
  edPrivateKey: Uint8Array
}

/** Builds the compact JWT for a `from_prior` header. `iat` defaults to now but
 * SHOULD be the datetime of the rotation for repeated sends (signature.md). */
export function buildFromPrior(priorDid: string, newDid: string | undefined, signer: FromPriorSigner, iat = Math.floor(Date.now() / 1000)): string {
  const header = { typ: 'JWT', alg: 'EdDSA', crv: 'Ed25519', kid: signer.kid }
  const payload: FromPriorClaims = { iss: priorDid, iat }
  if (newDid !== undefined) payload.sub = newDid
  const headerB64 = b64url(utf8(JSON.stringify(header)))
  const payloadB64 = b64url(utf8(JSON.stringify(payload)))
  const signingInput = utf8(`${headerB64}.${payloadB64}`)
  const sig = ed25519.sign(signingInput, signer.edPrivateKey)
  return `${headerB64}.${payloadB64}.${b64url(sig)}`
}

/** Resolves the Ed25519 public key for the `from_prior` JWT's `kid`, and MUST
 * confirm that key is authorized in the PRIOR DID (`iss`)'s document
 * (signature.md: "The indicated key MUST be authorized in the DID Document of
 * the prior DID"). Throw to reject an unauthorized kid. */
export type ResolveRotationKey = (kid: string, priorDid: string) => Uint8Array | Promise<Uint8Array>

export interface VerifiedRotation {
  priorDid: string      // iss
  newDid: string | null // sub, or null when the relationship is being ended
  iat: number
}

/** Verifies a `from_prior` JWT and returns the rotation it asserts. `newDidFromMessage`
 * is the message's own `from` (or undefined when ending a relationship) — it
 * MUST equal the JWT's `sub`, else the rotation claim doesn't match who
 * actually sent the message and is rejected. */
export async function verifyFromPrior(jwt: string, resolveKey: ResolveRotationKey, newDidFromMessage: string | undefined): Promise<VerifiedRotation> {
  const parts = jwt.split('.')
  if (parts.length !== 3) throw new Error('verifyFromPrior: malformed JWT (expected 3 parts)')
  const [headerB64, payloadB64, sigB64] = parts as [string, string, string]

  const header = JSON.parse(fromUtf8(b64urlToBytes(headerB64))) as { alg?: string; kid?: string }
  if (header.alg !== 'EdDSA') throw new Error(`verifyFromPrior: unsupported alg ${header.alg} — EdDSA only`)
  if (!header.kid) throw new Error('verifyFromPrior: JWT header has no kid')

  const claims = JSON.parse(fromUtf8(b64urlToBytes(payloadB64))) as FromPriorClaims
  if (!claims.iss) throw new Error('verifyFromPrior: JWT has no iss (prior DID)')
  // sub is present on a normal rotation and absent when ending a relationship;
  // when present it MUST match the DID the message now claims to be from.
  if (claims.sub !== undefined && newDidFromMessage !== undefined && claims.sub !== newDidFromMessage) {
    throw new Error('verifyFromPrior: JWT sub does not match the message `from` (new DID)')
  }

  const key = await resolveKey(header.kid, claims.iss)
  const ok = ed25519.verify(b64urlToBytes(sigB64), utf8(`${headerB64}.${payloadB64}`), key)
  if (!ok) throw new Error('verifyFromPrior: signature does not verify against the prior DID key')

  return { priorDid: claims.iss, newDid: claims.sub ?? null, iat: claims.iat }
}
