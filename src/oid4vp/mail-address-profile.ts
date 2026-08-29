// A second, narrower VC profile alongside profile.ts's
// BisetAnchorLoginCredential: proves "the holder of THIS did:peer:2
// relationship identity owns this mail address" without ever naming the
// identity's own DID (PLAN_biset-mail-mediator.md section 4, revised --
// replaces the front-door-kid authentication design with this credential).
//
// Two deliberate departures from profile.ts's BisetAnchorLoginCredential:
//
// 1. `cnf` is `{ relationshipDid }`, not a JWK. A did:peer:2 relationship
//    identity carries BOTH an X25519 keyAgreement key (what a route-bind
//    message is actually authcrypt'd with) and an Ed25519 authentication
//    key (what signs this credential's holder-binding, and the only kind
//    of key a JWT/JWS can verify against at all) -- a bare JWK names only
//    one of the two and can't reconstruct the other, so the DID string
//    itself is what mediator/server.ts checks a route-bind's sender
//    against (didOfKid(senderKid) === cnf.relationshipDid), not a
//    recomputed key match.
//
// 2. There is no VerifiablePresentation layer (createBisetLoginPresentation's
//    counterpart). Proof of holding the relationship's private key is
//    already what authcrypt IS -- the route-bind message that carries this
//    credential can only have been produced by whoever holds the
//    relationship's X25519 private key. A second, JWT-wrapped
//    proof-of-possession on top would be redundant with what the DIDComm
//    layer already proves.
import { ed25519 } from '@noble/curves/ed25519.js'
import { base64urlToBytes, bytesToBase64url, canonicalBytes, type CanonicalValue } from '../protocol/canonical.ts'

export const BISET_MAIL_ADDRESS_CREDENTIAL_TYPE = 'BisetMailAddressOwnershipCredential'
const VC_CONTEXT = 'https://www.w3.org/ns/credentials/v2'

export interface BisetMailAddressCredentialClaims {
  '@context': [typeof VC_CONTEXT]
  id: string
  type: ['VerifiableCredential', typeof BISET_MAIL_ADDRESS_CREDENTIAL_TYPE]
  issuer: string
  validFrom: string
  validUntil: string
  credentialSubject: { address: string }
  cnf: { relationshipDid: string }
}

export interface IssueMailAddressCredentialOptions {
  issuer: string
  signingKeyId: string
  signingPrivateKey: Uint8Array
  address: string
  relationshipDid: string
  validFrom: Date
  validUntil: Date
  credentialId?: string
}

export function issueBisetMailAddressCredential(options: IssueMailAddressCredentialOptions): string {
  const issuer = httpsOrigin(options.issuer, 'credential issuer')
  if (!options.signingKeyId.startsWith(`${issuer}/`) || options.signingPrivateKey.length !== 32) throw new TypeError('credential signing key is invalid')
  if (!isMailAddress(options.address)) throw new TypeError('mail address is invalid')
  if (!options.relationshipDid.startsWith('did:peer:2.')) throw new TypeError('relationship DID is invalid')
  if (!(options.validFrom instanceof Date) || !(options.validUntil instanceof Date) || !Number.isFinite(options.validFrom.getTime()) || options.validUntil.getTime() <= options.validFrom.getTime()) throw new TypeError('credential validity is invalid')
  const credentialId = options.credentialId ?? `urn:uuid:${crypto.randomUUID()}`
  if (!/^urn:uuid:[0-9a-f-]{36}$/i.test(credentialId)) throw new TypeError('credential ID is invalid')
  const claims: BisetMailAddressCredentialClaims = {
    '@context': [VC_CONTEXT],
    id: credentialId,
    type: ['VerifiableCredential', BISET_MAIL_ADDRESS_CREDENTIAL_TYPE],
    issuer,
    validFrom: options.validFrom.toISOString(),
    validUntil: options.validUntil.toISOString(),
    credentialSubject: { address: options.address },
    cnf: { relationshipDid: options.relationshipDid },
  }
  return signJwt({ alg: 'EdDSA', kid: options.signingKeyId, typ: 'vc+jwt', cty: 'vc' }, claims as unknown as CanonicalValue, options.signingPrivateKey)
}

export function verifyBisetMailAddressCredential(token: string, options: {
  issuer: string
  signingKeyId: string
  signingPublicKey: Uint8Array
  now: Date
}): BisetMailAddressCredentialClaims {
  const parsed = verifyJwt(token, options.signingPublicKey)
  exactHeader(parsed.header, { alg: 'EdDSA', kid: options.signingKeyId, typ: 'vc+jwt', cty: 'vc' })
  const claims = assertCredentialClaims(parsed.payload)
  if (claims.issuer !== httpsOrigin(options.issuer, 'credential issuer')) throw new TypeError('credential issuer is invalid')
  const now = options.now.getTime()
  if (!Number.isFinite(now) || Date.parse(claims.validFrom) > now || Date.parse(claims.validUntil) <= now) throw new TypeError('credential is outside its validity period')
  return claims
}

function isMailAddress(value: string): boolean {
  return /^[^\s@:]+@[^\s@:]+$/.test(value)
}

function signJwt(header: CanonicalValue, payload: CanonicalValue, privateKey: Uint8Array): string {
  const protectedHeader = bytesToBase64url(canonicalBytes(header))
  const body = bytesToBase64url(canonicalBytes(payload))
  const input = new TextEncoder().encode(`${protectedHeader}.${body}`)
  return `${protectedHeader}.${body}.${bytesToBase64url(ed25519.sign(input, privateKey))}`
}

function verifyJwt(token: string, publicKey: Uint8Array): { header: Record<string, unknown>; payload: Record<string, unknown> } {
  const parsed = decodeJwt(token)
  const parts = token.split('.')
  const input = new TextEncoder().encode(`${parts[0]}.${parts[1]}`)
  if (!ed25519.verify(base64urlToBytes(parts[2]!), input, publicKey)) throw new TypeError('JWT signature is invalid')
  return parsed
}

function decodeJwt(token: string): { header: Record<string, unknown>; payload: Record<string, unknown> } {
  const parts = token.split('.')
  if (parts.length !== 3 || parts.some(part => part.length === 0)) throw new TypeError('compact JWT is invalid')
  try {
    const header = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(base64urlToBytes(parts[0]!)))
    const payload = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(base64urlToBytes(parts[1]!)))
    return { header: object(header, 'JWT header'), payload: object(payload, 'JWT payload') }
  } catch (error) {
    if (error instanceof TypeError) throw error
    throw new TypeError('compact JWT JSON is invalid')
  }
}

function assertCredentialClaims(value: Record<string, unknown>): BisetMailAddressCredentialClaims {
  const allowed = ['@context', 'cnf', 'credentialSubject', 'id', 'issuer', 'type', 'validFrom', 'validUntil']
  if (!exactKeys(value, allowed) || !Array.isArray(value['@context']) || value['@context'].length !== 1 || value['@context'][0] !== VC_CONTEXT || !Array.isArray(value.type) || value.type.length !== 2 || value.type[0] !== 'VerifiableCredential' || value.type[1] !== BISET_MAIL_ADDRESS_CREDENTIAL_TYPE || typeof value.id !== 'string' || typeof value.issuer !== 'string' || typeof value.validFrom !== 'string' || typeof value.validUntil !== 'string') throw new TypeError('mail address credential shape is invalid')
  const subject = object(value.credentialSubject, 'credential subject')
  const cnf = object(value.cnf, 'credential confirmation')
  if (!exactKeys(subject, ['address']) || typeof subject.address !== 'string' || !isMailAddress(subject.address)) throw new TypeError('mail address credential subject is invalid')
  if (!exactKeys(cnf, ['relationshipDid']) || typeof cnf.relationshipDid !== 'string' || !cnf.relationshipDid.startsWith('did:peer:2.')) throw new TypeError('mail address credential confirmation is invalid')
  const result = { ...value, credentialSubject: { address: subject.address }, cnf: { relationshipDid: cnf.relationshipDid } } as unknown as BisetMailAddressCredentialClaims
  if (!/^urn:uuid:[0-9a-f-]{36}$/i.test(result.id) || Number.isNaN(Date.parse(result.validFrom)) || Number.isNaN(Date.parse(result.validUntil))) throw new TypeError('mail address credential values are invalid')
  return result
}

function exactHeader(value: Record<string, unknown>, expected: Record<string, string>): void {
  if (!exactKeys(value, Object.keys(expected)) || Object.entries(expected).some(([key, expectedValue]) => value[key] !== expectedValue)) throw new TypeError('JWT protected header is invalid')
}
function exactKeys(value: Record<string, unknown>, keys: string[]): boolean { return Object.keys(value).sort().join('\0') === [...keys].sort().join('\0') }
function object(value: unknown, name: string): Record<string, unknown> { if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError(`${name} is invalid`); return value as Record<string, unknown> }
function httpsOrigin(value: string, name: string): string { const url = new URL(value); if (url.protocol !== 'https:' || url.pathname !== '/' || url.search || url.hash || url.username || url.password) throw new TypeError(`${name} must be an HTTPS origin`); return url.origin }
