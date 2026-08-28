import {
  BISET_LOGIN_CREDENTIAL_FORMAT,
  BISET_LOGIN_CREDENTIAL_TYPE,
  createBisetLoginPresentation,
  p256JwkThumbprint,
  p256PublicJwk,
  verifyBisetAnchorLoginCredential,
  type P256PublicJwk,
} from './profile.ts'
import type { BisetLoginWalletCredential, BisetLoginWalletCredentialStore } from './wallet-store.ts'
import { p256 } from '@noble/curves/nist.js'
import { buildProof } from '../identity/webvh/proof.ts'

export interface TrustedAnchorOid4vpIssuer {
  issuer: string
  credentialSigningKeyId: string
  credentialSigningPublicKey: P256PublicJwk
}

export async function discoverTrustedAnchorOid4vpIssuer(issuer: string, fetchImpl: typeof fetch = fetch): Promise<TrustedAnchorOid4vpIssuer> {
  const normalized = origin(issuer)
  const response = await fetchImpl(`${normalized}/oid4vp/jwks`)
  if (!response.ok) throw new Error(`Anchor OID4VP JWKS discovery failed (${response.status})`)
  const body = await response.json() as { keys?: unknown }
  if (!Array.isArray(body.keys) || body.keys.length !== 1) throw new TypeError('Anchor OID4VP JWKS must contain exactly one credential signing key')
  const value = object(body.keys[0])
  if (value.alg !== 'ES256' || value.use !== 'sig' || typeof value.kid !== 'string' || !value.kid.startsWith(`${normalized}/oid4vp/jwks#`)) throw new TypeError('Anchor OID4VP credential signing key metadata is invalid')
  const credentialSigningPublicKey = publicJwk(value)
  return { issuer: normalized, credentialSigningKeyId: value.kid, credentialSigningPublicKey }
}

interface Oid4vpRequestObject {
  client_id: string
  response_uri: string
  response_type: 'vp_token'
  response_mode: 'direct_post'
  nonce: string
  state: string
  dcql_query: unknown
  client_metadata: unknown
}

/** Minimal Biset Wallet adapter for the Anchor-only login credential profile. */
export class BisetOid4vpWallet {
  private readonly issuer: string
  constructor(private readonly options: {
    identityId: string
    trust: TrustedAnchorOid4vpIssuer
    store: BisetLoginWalletCredentialStore
    fetch?: typeof fetch
    now?: () => Date
  }) {
    this.issuer = origin(options.trust.issuer)
    if (!options.identityId || !options.trust.credentialSigningKeyId.startsWith(`${this.issuer}/`)) throw new TypeError('Biset Wallet Anchor trust is invalid')
  }

  async install(credential: string, holderPrivateKey: Uint8Array): Promise<BisetLoginWalletCredential> {
    const now = (this.options.now ?? (() => new Date()))()
    const claims = verifyBisetAnchorLoginCredential(credential, {
      issuer: this.issuer,
      signingKeyId: this.options.trust.credentialSigningKeyId,
      signingPublicKey: this.options.trust.credentialSigningPublicKey,
      now,
    })
    if (p256JwkThumbprint(claims.cnf.jwk) !== p256JwkThumbprint(p256PublicJwk(holderPrivateKey))) throw new TypeError('login credential is bound to another holder key')
    const record: BisetLoginWalletCredential = {
      version: 1, identityId: this.options.identityId, issuer: this.issuer,
      credentialId: claims.id, credential, holderPrivateKey: holderPrivateKey.slice(),
      expiresAt: claims.validUntil, installedAt: now.toISOString(),
    }
    await this.options.store.put(record)
    return { ...record, holderPrivateKey: record.holderPrivateKey.slice() }
  }

  async current(): Promise<BisetLoginWalletCredential | undefined> {
    return this.options.store.current(this.options.identityId, this.issuer, (this.options.now ?? (() => new Date()))())
  }

  async refreshToken(clientId: string): Promise<string | undefined> { return (await this.options.store.oidcRefreshSession(this.options.identityId, this.issuer, clientId))?.refreshToken }
  async saveRefreshToken(clientId: string, refreshToken: string): Promise<void> { await this.options.store.putOidcRefreshSession({ version: 1, identityId: this.options.identityId, issuer: this.issuer, clientId, refreshToken, updatedAt: (this.options.now ?? (() => new Date()))().toISOString() }) }
  async clearRefreshToken(clientId: string): Promise<void> { await this.options.store.removeOidcRefreshSession(this.options.identityId, this.issuer, clientId) }

  async enroll(options: { did: string; authenticationVerificationMethod: string; authenticationPrivateKey: Uint8Array }): Promise<BisetLoginWalletCredential> {
    if (!options.did.startsWith('did:webvh:') || !options.authenticationVerificationMethod.startsWith(`${options.did}#`) || options.authenticationPrivateKey.length !== 32) throw new TypeError('Anchor enrollment authority is invalid')
    const holderPrivateKey = p256.utils.randomSecretKey()
    const fetchImpl = this.options.fetch ?? fetch
    const challengeResponse = await fetchImpl(`${this.issuer}/oid4vp/enrollment/challenge`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ did: options.did, holder_jwk: p256PublicJwk(holderPrivateKey) }),
    })
    if (!challengeResponse.ok) throw new Error(`Anchor enrollment challenge failed (${challengeResponse.status})`)
    const challenge = await challengeResponse.json() as { document?: unknown }
    if (challenge.document === null || typeof challenge.document !== 'object' || Array.isArray(challenge.document)) throw new TypeError('Anchor enrollment document is invalid')
    const proof = buildProof(challenge.document as object, {
      verificationMethod: options.authenticationVerificationMethod,
      proofPurpose: 'authentication',
      privateKey: options.authenticationPrivateKey,
      created: (this.options.now ?? (() => new Date()))().toISOString(),
    })
    const issuedResponse = await fetchImpl(`${this.issuer}/oid4vp/enrollment/complete`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ document: challenge.document, proof }),
    })
    if (issuedResponse.status !== 201) throw new Error(`Anchor enrollment failed (${issuedResponse.status})`)
    const issued = await issuedResponse.json() as { format?: unknown; credential?: unknown }
    if (issued.format !== BISET_LOGIN_CREDENTIAL_FORMAT || typeof issued.credential !== 'string') throw new TypeError('Anchor enrollment response is invalid')
    return this.install(issued.credential, holderPrivateKey)
  }

  async respond(requestUri: string): Promise<string> {
    const uri = new URL(requestUri)
    if (uri.origin !== this.issuer || !uri.pathname.startsWith('/oid4vp/request/') || uri.search || uri.hash) throw new TypeError('OID4VP request URI is not trusted')
    const fetchImpl = this.options.fetch ?? fetch
    const response = await fetchImpl(uri)
    if (!response.ok) throw new Error(`OID4VP request failed (${response.status})`)
    const request = assertRequestObject(await response.json(), this.issuer)
    const now = (this.options.now ?? (() => new Date()))()
    const credential = await this.options.store.current(this.options.identityId, this.issuer, now)
    if (!credential) throw new Error('no current Anchor login credential is available')
    const vpToken = createBisetLoginPresentation({
      credential: credential.credential,
      holderPrivateKey: credential.holderPrivateKey,
      verifierId: request.client_id,
      nonce: request.nonce,
      now,
    })
    const result = await fetchImpl(request.response_uri, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ vp_token: vpToken, state: request.state }),
    })
    if (!result.ok) throw new Error(`OID4VP presentation failed (${result.status})`)
    const body = await result.json() as { redirect_uri?: unknown }
    if (typeof body.redirect_uri !== 'string') throw new TypeError('OID4VP response has no completion URI')
    const completion = new URL(body.redirect_uri)
    if (completion.origin !== this.issuer || completion.pathname !== '/oid4vp/complete' || !completion.searchParams.get('response_code') || completion.hash) throw new TypeError('OID4VP completion URI is not trusted')
    return completion.href
  }
}

function assertRequestObject(input: unknown, issuer: string): Oid4vpRequestObject {
  if (input === null || typeof input !== 'object' || Array.isArray(input)) throw new TypeError('OID4VP request object is invalid')
  const value = input as Record<string, unknown>
  const responseUri = `${issuer}/oid4vp/response`
  if (value.client_id !== responseUri || value.response_uri !== responseUri || value.response_type !== 'vp_token' || value.response_mode !== 'direct_post' || !opaque(value.nonce) || !opaque(value.state)) throw new TypeError('OID4VP request binding is invalid')
  const dcql = object(value.dcql_query)
  const credentials = dcql.credentials
  if (!Array.isArray(credentials) || credentials.length !== 1) throw new TypeError('OID4VP DCQL query is unsupported')
  const query = object(credentials[0])
  const meta = object(query.meta)
  if (query.id !== 'biset_anchor_login' || query.format !== BISET_LOGIN_CREDENTIAL_FORMAT || JSON.stringify(meta.type_values) !== JSON.stringify([[BISET_LOGIN_CREDENTIAL_TYPE]])) throw new TypeError('OID4VP credential request is unsupported')
  const metadata = object(value.client_metadata)
  const formats = object(metadata.vp_formats_supported)
  const format = object(formats[BISET_LOGIN_CREDENTIAL_FORMAT])
  if (!Array.isArray(format.alg_values) || format.alg_values.length !== 1 || format.alg_values[0] !== 'ES256') throw new TypeError('OID4VP presentation algorithm is unsupported')
  return value as unknown as Oid4vpRequestObject
}
function object(value: unknown): Record<string, unknown> { if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('OID4VP object is invalid'); return value as Record<string, unknown> }
function publicJwk(value: Record<string, unknown>): P256PublicJwk { if (value.kty !== 'EC' || value.crv !== 'P-256' || typeof value.x !== 'string' || typeof value.y !== 'string') throw new TypeError('Anchor OID4VP credential signing JWK is invalid'); const result: P256PublicJwk = { kty: 'EC', crv: 'P-256', x: value.x, y: value.y }; p256JwkThumbprint(result); return result }
function opaque(value: unknown): value is string { return typeof value === 'string' && /^[A-Za-z0-9._~-]{1,512}$/.test(value) }
function origin(value: string): string { const url = new URL(value); if (url.protocol !== 'https:' || url.pathname !== '/' || url.search || url.hash || url.username || url.password) throw new TypeError('trusted Anchor issuer must be an HTTPS origin'); return url.origin }
