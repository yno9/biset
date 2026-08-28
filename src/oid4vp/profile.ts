import { p256 } from '@noble/curves/nist.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { base64urlToBytes, bytesToBase64url, canonicalBytes, type CanonicalValue } from '../protocol/canonical.ts'

export const BISET_LOGIN_CREDENTIAL_TYPE = 'BisetAnchorLoginCredential'
export const BISET_LOGIN_CREDENTIAL_FORMAT = 'jwt_vc_json'
const VC_CONTEXT = 'https://www.w3.org/ns/credentials/v2'

export interface P256PublicJwk {
  kty: 'EC'
  crv: 'P-256'
  x: string
  y: string
}

export interface BisetAnchorLoginCredentialClaims {
  '@context': [typeof VC_CONTEXT]
  id: string
  type: ['VerifiableCredential', typeof BISET_LOGIN_CREDENTIAL_TYPE]
  issuer: string
  validFrom: string
  validUntil: string
  credentialSubject: {
    id: string
    type: 'BisetAnchorAccount'
  }
  cnf: { jwk: P256PublicJwk }
}

export interface IssueBisetLoginCredentialOptions {
  issuer: string
  signingKeyId: string
  signingPrivateKey: Uint8Array
  accountRef: string
  holderPublicKey: P256PublicJwk
  validFrom: Date
  validUntil: Date
  credentialId?: string
}

export interface BisetLoginPresentationOptions {
  credential: string
  holderPrivateKey: Uint8Array
  verifierId: string
  nonce: string
  now: Date
  ttlSeconds?: number
}

export interface VerifiedBisetLoginPresentation {
  credential: BisetAnchorLoginCredentialClaims
  credentialToken: string
  holderKeyId: string
}

export function p256PublicJwk(privateKey: Uint8Array): P256PublicJwk {
  if (privateKey.length !== 32) throw new TypeError('P-256 private key must be 32 bytes')
  const publicKey = p256.getPublicKey(privateKey, false)
  return {
    kty: 'EC', crv: 'P-256',
    x: bytesToBase64url(publicKey.slice(1, 33)),
    y: bytesToBase64url(publicKey.slice(33, 65)),
  }
}

export function p256JwkThumbprint(jwk: P256PublicJwk): string {
  assertP256Jwk(jwk)
  const digest = sha256(canonicalBytes({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }))
  return `urn:ietf:params:oauth:jwk-thumbprint:sha-256:${bytesToBase64url(digest)}`
}

export function issueBisetAnchorLoginCredential(options: IssueBisetLoginCredentialOptions): string {
  const issuer = httpsOrigin(options.issuer, 'credential issuer')
  if (!options.signingKeyId.startsWith(`${issuer}/`) || options.signingPrivateKey.length !== 32) throw new TypeError('credential signing key is invalid')
  if (!/^[A-Za-z0-9_-]{32,128}$/.test(options.accountRef)) throw new TypeError('opaque Anchor account reference is invalid')
  assertP256Jwk(options.holderPublicKey)
  if (!(options.validFrom instanceof Date) || !(options.validUntil instanceof Date) || !Number.isFinite(options.validFrom.getTime()) || options.validUntil.getTime() <= options.validFrom.getTime()) throw new TypeError('credential validity is invalid')
  const credentialId = options.credentialId ?? `urn:uuid:${crypto.randomUUID()}`
  if (!/^urn:uuid:[0-9a-f-]{36}$/i.test(credentialId)) throw new TypeError('credential ID is invalid')
  const claims: BisetAnchorLoginCredentialClaims = {
    '@context': [VC_CONTEXT],
    id: credentialId,
    type: ['VerifiableCredential', BISET_LOGIN_CREDENTIAL_TYPE],
    issuer,
    validFrom: options.validFrom.toISOString(),
    validUntil: options.validUntil.toISOString(),
    credentialSubject: { id: `urn:biset:anchor-account:${options.accountRef}`, type: 'BisetAnchorAccount' },
    cnf: { jwk: copyJwk(options.holderPublicKey) },
  }
  return signJwt({ alg: 'ES256', kid: options.signingKeyId, typ: 'vc+jwt', cty: 'vc' }, claims as unknown as CanonicalValue, options.signingPrivateKey)
}

export function verifyBisetAnchorLoginCredential(token: string, options: {
  issuer: string
  signingKeyId: string
  signingPublicKey: P256PublicJwk
  now: Date
}): BisetAnchorLoginCredentialClaims {
  const parsed = verifyJwt(token, options.signingPublicKey)
  exactHeader(parsed.header, { alg: 'ES256', kid: options.signingKeyId, typ: 'vc+jwt', cty: 'vc' })
  const claims = assertCredentialClaims(parsed.payload)
  if (claims.issuer !== httpsOrigin(options.issuer, 'credential issuer')) throw new TypeError('credential issuer is invalid')
  const now = options.now.getTime()
  if (!Number.isFinite(now) || Date.parse(claims.validFrom) > now || Date.parse(claims.validUntil) <= now) throw new TypeError('credential is outside its validity period')
  return claims
}

export function createBisetLoginPresentation(options: BisetLoginPresentationOptions): string {
  const holderJwk = p256PublicJwk(options.holderPrivateKey)
  const ttl = options.ttlSeconds ?? 120
  if (!Number.isSafeInteger(ttl) || ttl < 30 || ttl > 300 || !opaque(options.nonce)) throw new TypeError('presentation lifetime or nonce is invalid')
  const verifierId = httpsUrl(options.verifierId, 'OID4VP verifier ID')
  const now = Math.floor(options.now.getTime() / 1000)
  if (!Number.isSafeInteger(now)) throw new TypeError('presentation time is invalid')
  const payload = {
    '@context': [VC_CONTEXT],
    type: ['VerifiablePresentation'],
    verifiableCredential: [options.credential],
    iss: p256JwkThumbprint(holderJwk),
    aud: verifierId,
    nonce: options.nonce,
    iat: now,
    exp: now + ttl,
  }
  return signJwt({ alg: 'ES256', kid: p256JwkThumbprint(holderJwk), typ: 'vp+jwt', cty: 'vp' }, payload, options.holderPrivateKey)
}

export function verifyBisetLoginPresentation(token: string, options: {
  verifierId: string
  nonce: string
  issuer: string
  credentialSigningKeyId: string
  credentialSigningPublicKey: P256PublicJwk
  now: Date
}): VerifiedBisetLoginPresentation {
  const unverified = decodeJwt(token)
  const payload = object(unverified.payload, 'presentation payload')
  const credentials = payload.verifiableCredential
  if (!Array.isArray(credentials) || credentials.length !== 1 || typeof credentials[0] !== 'string') throw new TypeError('presentation must contain exactly one credential')
  const credential = verifyBisetAnchorLoginCredential(credentials[0], {
    issuer: options.issuer,
    signingKeyId: options.credentialSigningKeyId,
    signingPublicKey: options.credentialSigningPublicKey,
    now: options.now,
  })
  const holder = credential.cnf.jwk
  const verified = verifyJwt(token, holder)
  const holderKeyId = p256JwkThumbprint(holder)
  exactHeader(verified.header, { alg: 'ES256', kid: holderKeyId, typ: 'vp+jwt', cty: 'vp' })
  const value = object(verified.payload, 'presentation payload')
  if (!Array.isArray(value['@context']) || value['@context'].length !== 1 || value['@context'][0] !== VC_CONTEXT || !Array.isArray(value.type) || value.type.length !== 1 || value.type[0] !== 'VerifiablePresentation') throw new TypeError('presentation data model is invalid')
  if (value.iss !== holderKeyId || value.aud !== httpsUrl(options.verifierId, 'OID4VP verifier ID') || value.nonce !== options.nonce) throw new TypeError('presentation session binding is invalid')
  const now = Math.floor(options.now.getTime() / 1000)
  const issuedAt = value.iat
  const expiresAt = value.exp
  if (typeof issuedAt !== 'number' || typeof expiresAt !== 'number' || !Number.isSafeInteger(issuedAt) || !Number.isSafeInteger(expiresAt) || issuedAt > now + 30 || issuedAt < now - 300 || expiresAt <= now || expiresAt > issuedAt + 300) throw new TypeError('presentation lifetime is invalid')
  return { credential, credentialToken: credentials[0], holderKeyId }
}

export function accountRefFromCredential(claims: BisetAnchorLoginCredentialClaims): string {
  const prefix = 'urn:biset:anchor-account:'
  if (!claims.credentialSubject.id.startsWith(prefix)) throw new TypeError('credential account reference is invalid')
  const value = claims.credentialSubject.id.slice(prefix.length)
  if (!/^[A-Za-z0-9_-]{32,128}$/.test(value)) throw new TypeError('credential account reference is invalid')
  return value
}

function signJwt(header: CanonicalValue, payload: CanonicalValue, privateKey: Uint8Array): string {
  const protectedHeader = bytesToBase64url(canonicalBytes(header))
  const body = bytesToBase64url(canonicalBytes(payload))
  const input = new TextEncoder().encode(`${protectedHeader}.${body}`)
  return `${protectedHeader}.${body}.${bytesToBase64url(p256.sign(input, privateKey, { format: 'compact', lowS: true }))}`
}

function verifyJwt(token: string, jwk: P256PublicJwk): { header: Record<string, unknown>; payload: Record<string, unknown> } {
  const parsed = decodeJwt(token)
  const parts = token.split('.')
  const input = new TextEncoder().encode(`${parts[0]}.${parts[1]}`)
  if (!p256.verify(base64urlToBytes(parts[2]!), input, publicKeyBytes(jwk), { format: 'compact', lowS: true })) throw new TypeError('JWT signature is invalid')
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

function assertCredentialClaims(value: Record<string, unknown>): BisetAnchorLoginCredentialClaims {
  const allowed = ['@context', 'cnf', 'credentialSubject', 'id', 'issuer', 'type', 'validFrom', 'validUntil']
  if (!exactKeys(value, allowed) || !Array.isArray(value['@context']) || value['@context'].length !== 1 || value['@context'][0] !== VC_CONTEXT || !Array.isArray(value.type) || value.type.length !== 2 || value.type[0] !== 'VerifiableCredential' || value.type[1] !== BISET_LOGIN_CREDENTIAL_TYPE || typeof value.id !== 'string' || typeof value.issuer !== 'string' || typeof value.validFrom !== 'string' || typeof value.validUntil !== 'string') throw new TypeError('login credential shape is invalid')
  const subject = object(value.credentialSubject, 'credential subject')
  const cnf = object(value.cnf, 'credential confirmation')
  if (!exactKeys(subject, ['id', 'type']) || typeof subject.id !== 'string' || subject.type !== 'BisetAnchorAccount' || !exactKeys(cnf, ['jwk'])) throw new TypeError('login credential subject is invalid')
  const jwk = assertP256Jwk(cnf.jwk)
  const result = { ...value, credentialSubject: { id: subject.id, type: 'BisetAnchorAccount' as const }, cnf: { jwk } } as unknown as BisetAnchorLoginCredentialClaims
  accountRefFromCredential(result)
  if (!/^urn:uuid:[0-9a-f-]{36}$/i.test(result.id) || Number.isNaN(Date.parse(result.validFrom)) || Number.isNaN(Date.parse(result.validUntil))) throw new TypeError('login credential values are invalid')
  return result
}

function assertP256Jwk(value: unknown): P256PublicJwk {
  const jwk = object(value, 'P-256 JWK')
  if (!exactKeys(jwk, ['crv', 'kty', 'x', 'y']) || jwk.kty !== 'EC' || jwk.crv !== 'P-256' || typeof jwk.x !== 'string' || typeof jwk.y !== 'string') throw new TypeError('P-256 JWK is invalid')
  const result: P256PublicJwk = { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }
  publicKeyBytes(result)
  return result
}

function publicKeyBytes(jwk: P256PublicJwk): Uint8Array {
  const x = base64urlToBytes(jwk.x)
  const y = base64urlToBytes(jwk.y)
  if (x.length !== 32 || y.length !== 32) throw new TypeError('P-256 JWK coordinates are invalid')
  const bytes = new Uint8Array(65)
  bytes[0] = 4
  bytes.set(x, 1)
  bytes.set(y, 33)
  try { p256.Point.fromBytes(bytes) } catch { throw new TypeError('P-256 JWK point is invalid') }
  return bytes
}

function exactHeader(value: Record<string, unknown>, expected: Record<string, string>): void {
  if (!exactKeys(value, Object.keys(expected)) || Object.entries(expected).some(([key, expectedValue]) => value[key] !== expectedValue)) throw new TypeError('JWT protected header is invalid')
}
function exactKeys(value: Record<string, unknown>, keys: string[]): boolean { return Object.keys(value).sort().join('\0') === [...keys].sort().join('\0') }
function object(value: unknown, name: string): Record<string, unknown> { if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError(`${name} is invalid`); return value as Record<string, unknown> }
function copyJwk(value: P256PublicJwk): P256PublicJwk { return { kty: value.kty, crv: value.crv, x: value.x, y: value.y } }
function opaque(value: string): boolean { return typeof value === 'string' && /^[A-Za-z0-9._~-]{1,512}$/.test(value) }
function httpsOrigin(value: string, name: string): string { const url = new URL(value); if (url.protocol !== 'https:' || url.pathname !== '/' || url.search || url.hash || url.username || url.password) throw new TypeError(`${name} must be an HTTPS origin`); return url.origin }
function httpsUrl(value: string, name: string): string { const url = new URL(value); if (url.protocol !== 'https:' || url.username || url.password || url.hash) throw new TypeError(`${name} must be an HTTPS URL`); return url.href }
