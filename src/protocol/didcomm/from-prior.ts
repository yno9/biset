// DIDComm v2.1 DID Rotation (didcomm-messaging-spec-v2.1.md "DID Rotation"):
// a message sent from a NEW DID carries `from_prior`, a JWT with `iss` = the
// prior DID, `sub` = the new one, `iat` = when the rotation happened, signed
// by a key the prior DID authorizes. A recipient that does not know the new
// DID checks it and moves the relationship over.
//
// biset rotates only pairwise did:peer:2 relationship DIDs this way (their
// documents cannot be updated in place). Signed with the prior DID's Ed25519
// authentication key, so verification needs nothing but the prior DID
// string itself.
import { ed25519 } from '@noble/curves/ed25519.js'
import { b64url, b64urlToBytes } from './crypto.ts'
import { decodePeerDid2, publicKeyOf } from './peer.ts'

export interface FromPriorClaims { iss: string; sub: string; iat: number }

const utf8 = (value: string) => new TextEncoder().encode(value)
const json = (value: unknown) => b64url(utf8(JSON.stringify(value)))

/** `prior.edKid` must be an authentication key of `prior.did`. */
export function signFromPrior(prior: { did: string; edKid: string; edPrivateKey: Uint8Array }, newDid: string, iat = Math.floor(Date.now() / 1000)): string {
  if (!prior.edKid.startsWith(`${prior.did}#`)) throw new TypeError('from_prior signing key must belong to the prior DID')
  if (newDid === prior.did) throw new TypeError('from_prior must name a different DID')
  const signingInput = `${json({ typ: 'JWT', alg: 'EdDSA', crv: 'Ed25519', kid: prior.edKid })}.${json({ iss: prior.did, sub: newDid, iat })}`
  return `${signingInput}.${b64url(ed25519.sign(utf8(signingInput), prior.edPrivateKey))}`
}

/** Checks a `from_prior` JWT against the prior did:peer:2 it names and the
 * `from` of the message carrying it. Throws on anything else. */
export function verifyFromPrior(jwt: string, messageFrom: string): FromPriorClaims {
  const parts = jwt.split('.')
  if (parts.length !== 3) throw new TypeError('from_prior is not a compact JWT')
  let header: Record<string, unknown>
  let claims: Record<string, unknown>
  try {
    header = JSON.parse(new TextDecoder().decode(b64urlToBytes(parts[0]!)))
    claims = JSON.parse(new TextDecoder().decode(b64urlToBytes(parts[1]!)))
  } catch { throw new TypeError('from_prior is not readable') }
  if (header.alg !== 'EdDSA' || typeof header.kid !== 'string') throw new TypeError('from_prior must be an EdDSA JWT naming its key')
  const { iss, sub, iat } = claims
  if (typeof iss !== 'string' || typeof sub !== 'string' || typeof iat !== 'number') throw new TypeError('from_prior needs iss, sub and iat')
  if (sub !== messageFrom) throw new TypeError('from_prior names a different DID than the message sender')
  if (iss === sub) throw new TypeError('from_prior must name a different prior DID')
  if (!iss.startsWith('did:peer:2.') || !header.kid.startsWith(`${iss}#`)) throw new TypeError('from_prior must be signed by a key of its prior did:peer')
  const prior = decodePeerDid2(iss)
  if (!prior.authentication.includes(header.kid)) throw new TypeError('from_prior key is not an authentication key of the prior DID')
  if (!ed25519.verify(b64urlToBytes(parts[2]!), utf8(`${parts[0]}.${parts[1]}`), publicKeyOf(prior, header.kid))) throw new TypeError('from_prior signature is invalid')
  return { iss, sub, iat }
}
