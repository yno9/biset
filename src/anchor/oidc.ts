import { p256 } from '@noble/curves/nist.js'
import { hmac } from '@noble/hashes/hmac.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToBase64url } from '../protocol/canonical.ts'

export interface AnchorOidcClient {
  clientId: string
  redirectUris: string[]
  /** Origins allowed to host the wallet-bearing public Client. `null` is
   * the browser origin serialized for the supported file:// application. */
  applicationOrigins?: string[]
  sectorIdentifier: string
  audience: string
  allowedScopes: string[]
}

export interface AnchorAuthenticatedSubject {
  /** Anchor-local stable account identifier. It is never emitted directly. */
  subject: string
  /** Opaque WebVH versionId proven by the current Sign key. */
  generation: string
  authenticatedAt?: Date
}

export interface AnchorSubjectAuthenticator {
  authenticate(request: Request, options?: { force: boolean }): Promise<AnchorAuthenticatedSubject | null>
  /** Starts an interactive login when no authenticated session exists. */
  beginAuthentication?(request: Request): Promise<Response>
}

export interface AuthorizationCodeRecord {
  codeHash: string
  clientId: string
  redirectUri: string
  rootSubject: string
  generation: string
  sectorIdentifier: string
  audience: string
  scopes: string[]
  codeChallenge: string
  nonce: string
  authenticatedAt: number
  expiresAt: number
}

export interface AnchorAuthorizationCodeStore {
  put(value: AuthorizationCodeRecord): Promise<void>
  take(codeHash: string): Promise<AuthorizationCodeRecord | undefined>
  putRefresh(value: RefreshTokenRecord): Promise<void>
  takeRefresh(tokenHash: string): Promise<RefreshTokenRecord | undefined>
}

export interface RefreshTokenRecord {
  tokenHash: string
  clientId: string
  rootSubject: string
  generation: string
  sectorIdentifier: string
  audience: string
  scopes: string[]
  expiresAt: number
}

export class MemoryAnchorAuthorizationCodeStore implements AnchorAuthorizationCodeStore {
  private readonly values = new Map<string, AuthorizationCodeRecord>()
  private readonly refresh = new Map<string, RefreshTokenRecord>()
  async put(value: AuthorizationCodeRecord): Promise<void> { this.values.set(value.codeHash, { ...value, scopes: [...value.scopes] }) }
  async take(codeHash: string): Promise<AuthorizationCodeRecord | undefined> {
    const value = this.values.get(codeHash)
    this.values.delete(codeHash)
    return value && { ...value, scopes: [...value.scopes] }
  }
  async putRefresh(value: RefreshTokenRecord): Promise<void> { this.refresh.set(value.tokenHash, { ...value, scopes: [...value.scopes] }) }
  async takeRefresh(tokenHash: string): Promise<RefreshTokenRecord | undefined> { const value = this.refresh.get(tokenHash); this.refresh.delete(tokenHash); return value && { ...value, scopes: [...value.scopes] } }
}

export interface AnchorOidcProviderOptions {
  issuer: string
  clients: AnchorOidcClient[]
  authenticator: AnchorSubjectAuthenticator
  codes: AnchorAuthorizationCodeStore
  signingPrivateKey: Uint8Array
  pairwiseSecret: Uint8Array
  signingKeyId?: string
  codeTtlSeconds?: number
  accessTokenTtlSeconds?: number
  idTokenTtlSeconds?: number
  refreshTokenTtlSeconds?: number
  now?: () => Date
}

/** OIDC Authorization Code + PKCE provider with static public-client registration. */
export class AnchorOidcProvider {
  private readonly issuer: string
  private readonly clients: Map<string, AnchorOidcClient>
  private readonly kid: string
  private readonly now: () => Date
  private readonly codeTtl: number
  private readonly accessTtl: number
  private readonly idTtl: number
  private readonly refreshTtl: number

  constructor(private readonly options: AnchorOidcProviderOptions) {
    this.issuer = normalizeIssuer(options.issuer)
    this.clients = new Map(options.clients.map(client => [client.clientId, validateClient(client)]))
    if (this.clients.size !== options.clients.length) throw new TypeError('OIDC client IDs must be unique')
    if (options.signingPrivateKey.length !== 32 || options.pairwiseSecret.length < 32) throw new TypeError('OIDC signing and pairwise keys are invalid')
    this.kid = options.signingKeyId ?? 'anchor-es256-1'
    this.now = options.now ?? (() => new Date())
    this.codeTtl = positiveTtl(options.codeTtlSeconds ?? 300, 'authorization code')
    this.accessTtl = positiveTtl(options.accessTokenTtlSeconds ?? 300, 'access token')
    this.idTtl = positiveTtl(options.idTokenTtlSeconds ?? 300, 'ID token')
    this.refreshTtl = refreshTtl(options.refreshTokenTtlSeconds ?? 30 * 24 * 60 * 60)
  }

  metadata(): Record<string, unknown> {
    return {
      issuer: this.issuer,
      authorization_endpoint: `${this.issuer}/oauth/authorize`,
      token_endpoint: `${this.issuer}/oauth/token`,
      jwks_uri: `${this.issuer}/oauth/jwks`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      subject_types_supported: ['pairwise'],
      id_token_signing_alg_values_supported: ['ES256'],
      token_endpoint_auth_methods_supported: ['none'],
      code_challenge_methods_supported: ['S256'],
      scopes_supported: [...new Set(['openid', ...this.options.clients.flatMap(client => client.allowedScopes)])],
    }
  }

  jwks(): Record<string, unknown> {
    const publicKey = p256.getPublicKey(this.options.signingPrivateKey, false)
    return { keys: [{ kty: 'EC', crv: 'P-256', alg: 'ES256', use: 'sig', kid: this.kid, x: bytesToBase64url(publicKey.slice(1, 33)), y: bytesToBase64url(publicKey.slice(33, 65)) }] }
  }

  async authorize(request: Request): Promise<Response> {
    const url = new URL(request.url)
    const value = (name: string): string => single(url.searchParams, name)
    const client = this.clients.get(value('client_id'))
    if (!client) return oauthError(400, 'invalid_request', 'unknown client_id')
    const redirectUri = value('redirect_uri')
    if (!client.redirectUris.includes(redirectUri)) return oauthError(400, 'invalid_request', 'redirect_uri is not registered')
    if (value('response_type') !== 'code') return redirectError(redirectUri, value('state'), 'unsupported_response_type')
    const walletOrigin = value('wallet_origin')
    if (!client.applicationOrigins?.includes(walletOrigin)) return redirectError(redirectUri, value('state'), 'invalid_request')
    const state = value('state')
    const nonce = value('nonce')
    const codeChallenge = value('code_challenge')
    if (!opaque(state, 512) || !opaque(nonce, 512) || !/^[A-Za-z0-9_-]{43,128}$/.test(codeChallenge) || value('code_challenge_method') !== 'S256') {
      return redirectError(redirectUri, state, 'invalid_request')
    }
    const scopes = parseScopes(value('scope'))
    if (!scopes.includes('openid') || scopes.some(scope => scope !== 'openid' && !client.allowedScopes.includes(scope))) return redirectError(redirectUri, state, 'invalid_scope')
    const prompt = value('prompt')
    if (prompt && prompt !== 'login') return redirectError(redirectUri, state, 'invalid_request')
    const authenticated = await this.options.authenticator.authenticate(request, { force: prompt === 'login' })
    if (!authenticated) return this.options.authenticator.beginAuthentication
      ? this.options.authenticator.beginAuthentication(request)
      : oauthError(401, 'login_required', 'Anchor login is required')
    if (!opaque(authenticated.subject, 512) || !generationValue(authenticated.generation)) return oauthError(401, 'login_required', 'Anchor login is required')
    const code = randomToken(32)
    const now = this.now()
    await this.options.codes.put({
      codeHash: tokenHash(code), clientId: client.clientId, redirectUri,
      rootSubject: authenticated.subject, generation: authenticated.generation, sectorIdentifier: client.sectorIdentifier,
      audience: client.audience, scopes: scopes.filter(scope => scope !== 'openid'),
      codeChallenge, nonce,
      authenticatedAt: Math.floor((authenticated.authenticatedAt ?? now).getTime() / 1000),
      expiresAt: Math.floor(now.getTime() / 1000) + this.codeTtl,
    })
    const destination = new URL(redirectUri)
    destination.searchParams.set('code', code)
    destination.searchParams.set('state', state)
    return new Response(null, { status: 302, headers: { location: destination.href, 'cache-control': 'no-store' } })
  }

  async token(request: Request): Promise<Response> {
    if (request.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase() !== 'application/x-www-form-urlencoded') return oauthError(415, 'invalid_request', 'form content type is required')
    const form = new URLSearchParams(await request.text())
    if (single(form, 'grant_type') === 'refresh_token') return this.refreshToken(form)
    if (single(form, 'grant_type') !== 'authorization_code') return oauthError(400, 'unsupported_grant_type', 'only authorization_code and refresh_token are supported')
    const clientId = single(form, 'client_id')
    const code = single(form, 'code')
    const verifier = single(form, 'code_verifier')
    const redirectUri = single(form, 'redirect_uri')
    if (!opaque(code, 512) || !/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)) return oauthError(400, 'invalid_grant', 'authorization code or verifier is invalid')
    const grant = await this.options.codes.take(tokenHash(code))
    const now = this.now()
    const nowSeconds = Math.floor(now.getTime() / 1000)
    if (!grant || grant.expiresAt <= nowSeconds || grant.clientId !== clientId || grant.redirectUri !== redirectUri || bytesToBase64url(sha256(new TextEncoder().encode(verifier))) !== grant.codeChallenge) {
      return oauthError(400, 'invalid_grant', 'authorization code is invalid')
    }
    const accessToken = this.accessToken(grant, nowSeconds)
    const refreshToken = await this.rotateRefreshToken(grant, nowSeconds)
    const subject = pairwiseSubject(this.options.pairwiseSecret, grant.sectorIdentifier, grant.rootSubject)
    const idToken = this.jwt('JWT', {
      iss: this.issuer, sub: subject, aud: grant.clientId, nonce: grant.nonce,
      auth_time: grant.authenticatedAt, iat: nowSeconds, exp: nowSeconds + this.idTtl,
    })
    return Response.json({ access_token: accessToken, token_type: 'Bearer', expires_in: this.accessTtl, scope: grant.scopes.join(' '), id_token: idToken, refresh_token: refreshToken }, { headers: noStoreHeaders() })
  }

  private async refreshToken(form: URLSearchParams): Promise<Response> {
    const clientId = single(form, 'client_id')
    const token = single(form, 'refresh_token')
    if (!opaque(token, 512) || !this.clients.has(clientId)) return oauthError(400, 'invalid_grant', 'refresh token is invalid')
    const grant = await this.options.codes.takeRefresh(tokenHash(token))
    const nowSeconds = Math.floor(this.now().getTime() / 1000)
    if (!grant || grant.expiresAt <= nowSeconds || grant.clientId !== clientId) return oauthError(400, 'invalid_grant', 'refresh token is invalid')
    const accessToken = this.accessToken(grant, nowSeconds)
    const refreshToken = await this.rotateRefreshToken(grant, nowSeconds)
    return Response.json({ access_token: accessToken, token_type: 'Bearer', expires_in: this.accessTtl, scope: grant.scopes.join(' '), refresh_token: refreshToken }, { headers: noStoreHeaders() })
  }

  private accessToken(grant: Pick<RefreshTokenRecord, 'rootSubject' | 'generation' | 'sectorIdentifier' | 'audience' | 'clientId' | 'scopes'>, nowSeconds: number): string {
    const subject = pairwiseSubject(this.options.pairwiseSecret, grant.sectorIdentifier, grant.rootSubject)
    return this.jwt('at+jwt', { iss: this.issuer, sub: subject, aud: grant.audience, client_id: grant.clientId, jti: randomToken(16), scope: grant.scopes.join(' '), biset_generation: grant.generation, iat: nowSeconds, exp: nowSeconds + this.accessTtl })
  }

  private async rotateRefreshToken(grant: Pick<RefreshTokenRecord, 'rootSubject' | 'generation' | 'sectorIdentifier' | 'audience' | 'clientId' | 'scopes'>, nowSeconds: number): Promise<string> {
    const token = randomToken(32)
    await this.options.codes.putRefresh({ tokenHash: tokenHash(token), clientId: grant.clientId, rootSubject: grant.rootSubject, generation: grant.generation, sectorIdentifier: grant.sectorIdentifier, audience: grant.audience, scopes: [...grant.scopes], expiresAt: nowSeconds + this.refreshTtl })
    return token
  }

  private jwt(typ: 'at+jwt' | 'JWT', claims: Record<string, unknown>): string {
    const header = encoded({ alg: 'ES256', kid: this.kid, typ })
    const payload = encoded(claims)
    const data = new TextEncoder().encode(`${header}.${payload}`)
    const signature = p256.sign(data, this.options.signingPrivateKey, { format: 'compact', lowS: true })
    return `${header}.${payload}.${bytesToBase64url(signature)}`
  }
}

function validateClient(client: AnchorOidcClient): AnchorOidcClient {
  if (!opaque(client.clientId, 512) || !opaque(client.sectorIdentifier, 512) || client.redirectUris.length === 0 || client.allowedScopes.some(scope => !scopeName(scope))) throw new TypeError('OIDC client registration is invalid')
  normalizeAudience(client.audience)
  for (const value of client.redirectUris) {
    const uri = new URL(value)
    if (uri.protocol !== 'https:' && !(uri.protocol === 'http:' && (uri.hostname === '127.0.0.1' || uri.hostname === 'localhost'))) throw new TypeError('OIDC redirect URI must use HTTPS or loopback HTTP')
  }
  const applicationOrigins = client.applicationOrigins ?? ['null']
  if (applicationOrigins.length === 0 || new Set(applicationOrigins).size !== applicationOrigins.length) throw new TypeError('OIDC application origins are invalid')
  for (const value of applicationOrigins) validateApplicationOrigin(value)
  return { ...client, redirectUris: [...client.redirectUris], applicationOrigins: [...applicationOrigins], allowedScopes: [...client.allowedScopes] }
}

function normalizeIssuer(value: string): string {
  const url = new URL(value)
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || url.pathname !== '/') throw new TypeError('OIDC issuer must be an HTTPS origin')
  return url.origin
}
function normalizeAudience(value: string): void { normalizeIssuer(value) }
function validateApplicationOrigin(value: string): void {
  if (value === 'null') return
  const url = new URL(value)
  if (url.protocol !== 'https:' || url.origin !== value || url.username || url.password) throw new TypeError('OIDC application origin must be null or an HTTPS origin')
}
function positiveTtl(value: number, name: string): number { if (!Number.isSafeInteger(value) || value < 30 || value > 3600) throw new TypeError(`${name} TTL is invalid`); return value }
function refreshTtl(value: number): number { if (!Number.isSafeInteger(value) || value < 3600 || value > 365 * 24 * 60 * 60) throw new TypeError('refresh token TTL is invalid'); return value }
function opaque(value: string, max: number): boolean { return value.length > 0 && value.length <= max && /^[\x21-\x7e]+$/.test(value) }
function scopeName(value: string): boolean { return /^[A-Za-z0-9._:-]{1,128}$/.test(value) }
function generationValue(value: string): boolean { return typeof value === 'string' && /^[1-9][0-9]*-[A-Za-z0-9_-]{20,200}$/.test(value) }
function parseScopes(value: string): string[] { const scopes = value.split(' ').filter(Boolean); return scopes.length > 0 && scopes.every(scopeName) && new Set(scopes).size === scopes.length ? scopes : [] }
function single(values: URLSearchParams, name: string): string { const found = values.getAll(name); return found.length === 1 ? found[0]! : '' }
function randomToken(bytes: number): string { return bytesToBase64url(crypto.getRandomValues(new Uint8Array(bytes))) }
function tokenHash(value: string): string { return bytesToBase64url(sha256(new TextEncoder().encode(value))) }
function pairwiseSubject(secret: Uint8Array, sector: string, root: string): string { return bytesToBase64url(hmac(sha256, secret, new TextEncoder().encode(`biset/oidc/pairwise/v1\0${sector}\0${root}`))) }
function encoded(value: unknown): string { return bytesToBase64url(new TextEncoder().encode(JSON.stringify(value))) }
function noStoreHeaders(): Record<string, string> { return { 'cache-control': 'no-store', pragma: 'no-cache' } }
function oauthError(status: number, error: string, description: string): Response { return Response.json({ error, error_description: description }, { status, headers: noStoreHeaders() }) }
function redirectError(redirectUri: string, state: string, error: string): Response { const url = new URL(redirectUri); url.searchParams.set('error', error); if (state) url.searchParams.set('state', state); return new Response(null, { status: 302, headers: { location: url.href, 'cache-control': 'no-store' } }) }
