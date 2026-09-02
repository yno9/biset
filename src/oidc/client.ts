import { sha256 } from '@noble/hashes/sha2.js'
import { base64urlToBytes, bytesToBase64url } from '../protocol/canonical.ts'
import { handleBisetOid4vpBridgeMessage } from '../oid4vp/file-bridge.ts'
import type { BisetOid4vpWallet } from '../oid4vp/wallet.ts'

interface OidcMetadata {
  issuer: string
  authorization_endpoint: string
  token_endpoint: string
  jwks_uri: string
}

interface CachedAccessToken {
  token: string
  scopes: Set<string>
  expiresAt: number
}

interface OidcJwk extends JsonWebKey {
  kid: string
  alg: 'ES256'
  use: 'sig'
  kty: 'EC'
  crv: 'P-256'
  x: string
  y: string
}

/** A client-registered permission string, opaque to this file -- scoped and
 * validated entirely by whatever OIDC resource server the caller points
 * `audience` at. */
export type AnchorOidcScope = string

export interface AnchorOidcPkceClientOptions {
  issuer: string
  clientId: string
  audience: string
  allowedScopes: AnchorOidcScope[]
  wallet: BisetOid4vpWallet
  fetch?: typeof fetch
  openPopup?: (url: string, target: string, features: string) => Window | null
  eventTarget?: Pick<Window, 'addEventListener' | 'removeEventListener'>
  now?: () => Date
  timeoutMs?: number
}

/** OIDC public client for the file:// UI. Access tokens stay in memory;
 * a rotating refresh token is kept in the device-local Wallet so polling
 * resumes after reload without another interactive login. */
export class AnchorOidcPkceClient {
  private readonly issuer: string
  private readonly audience: string
  private readonly redirectUri: string
  private readonly fetchValue: typeof fetch
  private readonly now: () => Date
  private cached?: CachedAccessToken
  private pending?: Promise<string>
  private refreshing?: Promise<string>

  constructor(private readonly options: AnchorOidcPkceClientOptions) {
    this.issuer = httpsOrigin(options.issuer, 'OIDC issuer')
    this.audience = httpsOrigin(options.audience, 'OIDC audience')
    this.redirectUri = `${this.issuer}/oauth/client-callback`
    this.fetchValue = options.fetch ?? fetch.bind(globalThis)
    this.now = options.now ?? (() => new Date())
    if (!/^[\x21-\x7e]{1,512}$/.test(options.clientId) || options.allowedScopes.length === 0 || new Set(options.allowedScopes).size !== options.allowedScopes.length) throw new TypeError('OIDC public client configuration is invalid')
  }

  async getAccessToken(scope: AnchorOidcScope): Promise<string> {
    if (!this.options.allowedScopes.includes(scope)) throw new TypeError(`OIDC client does not allow ${scope}`)
    if (this.cached && this.cached.expiresAt > seconds(this.now()) + 30 && this.cached.scopes.has(scope)) return this.cached.token
    const token = await this.refreshAccessToken()
    if (!this.cached?.scopes.has(scope)) throw new Error(`refreshed Anchor session does not allow ${scope}`)
    return token
  }

  /** Must normally be called from a user gesture so popup blockers permit it. */
  async authorize(): Promise<string> {
    if (this.cached && this.cached.expiresAt > seconds(this.now()) + 30 && this.options.allowedScopes.every(scope => this.cached!.scopes.has(scope))) return this.cached.token
    if (this.pending) return this.pending
    this.pending = this.runAuthorization().finally(() => { this.pending = undefined })
    return this.pending
  }

  private async runAuthorization(): Promise<string> {
    const popup = (this.options.openPopup ?? ((url, target, features) => window.open(url, target, features)))('about:blank', 'biset-anchor-login', 'popup,width=520,height=720')
    if (!popup) throw new Error('Anchor login popup was blocked')
    try {
      const metadata = await this.metadata()
      const verifier = randomToken(32)
      const state = randomToken(24)
      const nonce = randomToken(24)
      const authorize = new URL(metadata.authorization_endpoint)
      authorize.searchParams.set('client_id', this.options.clientId)
      authorize.searchParams.set('redirect_uri', this.redirectUri)
      authorize.searchParams.set('response_type', 'code')
      // An interactive authorization is identity selection, not merely a
      // check for any Anchor cookie. Resume uses the identity-scoped refresh
      // token and never reaches this path; here we must present the current
      // Biset Wallet credential even if another identity logged in earlier.
      authorize.searchParams.set('prompt', 'login')
      authorize.searchParams.set('wallet_origin', applicationOrigin())
      authorize.searchParams.set('scope', `openid ${this.options.allowedScopes.join(' ')}`)
      authorize.searchParams.set('state', state)
      authorize.searchParams.set('nonce', nonce)
      authorize.searchParams.set('code_challenge', bytesToBase64url(sha256(new TextEncoder().encode(verifier))))
      authorize.searchParams.set('code_challenge_method', 'S256')
      // Install the message listener before navigation. The wallet bridge
      // posts its request once, immediately after its deferred script runs;
      // on a warm cache (especially with a popup reserved during identity
      // restore) registering after replace() can lose that only message and
      // leave the popup stuck on "Biset Walletを開いています…" forever.
      const callbackPending = this.waitForCallback(popup, state)
      popup.location.replace(authorize.href)
      const callback = await callbackPending
      if ('error' in callback) throw new Error(`Anchor login failed: ${callback.error}${callback.errorDescription ? ` (${callback.errorDescription})` : ''}`)
      const tokenResponse = await this.fetchValue(metadata.token_endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code', client_id: this.options.clientId,
          code: callback.code, redirect_uri: this.redirectUri, code_verifier: verifier,
        }),
      })
      if (!tokenResponse.ok) throw new Error(`Anchor token exchange failed (${tokenResponse.status})`)
      const result = exactObject(await tokenResponse.json(), ['access_token', 'token_type', 'expires_in', 'scope', 'id_token', 'refresh_token'], 'OIDC token response')
      if (result.token_type !== 'Bearer' || typeof result.access_token !== 'string' || typeof result.id_token !== 'string' || typeof result.refresh_token !== 'string' || typeof result.scope !== 'string' || typeof result.expires_in !== 'number') throw new TypeError('OIDC token response is invalid')
      const keys = await this.jwks(metadata.jwks_uri)
      await verifyJwt(result.id_token, keys, { typ: 'JWT', issuer: this.issuer, audience: this.options.clientId, nonce, now: this.now() })
      const accessClaims = await verifyJwt(result.access_token, keys, { typ: 'at+jwt', issuer: this.issuer, audience: this.audience, clientId: this.options.clientId, now: this.now() })
      const scopes = new Set(result.scope.split(' ').filter(Boolean))
      if (this.options.allowedScopes.some(scope => !scopes.has(scope)) || accessClaims.scope !== result.scope) throw new TypeError('OIDC access token scopes are invalid')
      const expiresAt = numberClaim(accessClaims.exp, 'exp')
      this.cached = { token: result.access_token, scopes, expiresAt }
      await this.options.wallet.saveRefreshToken(this.options.clientId, result.refresh_token)
      try { popup.close() } catch {}
      return result.access_token
    } catch (error) {
      try { popup.close() } catch {}
      throw error
    }
  }

  async hasRefreshSession(): Promise<boolean> { return !!(await this.options.wallet.refreshToken(this.options.clientId)) }

  private async refreshAccessToken(): Promise<string> {
    if (this.refreshing) return this.refreshing
    this.refreshing = (async () => {
      const refreshToken = await this.options.wallet.refreshToken(this.options.clientId)
      if (!refreshToken) throw new Error('Anchor login interaction is required')
      const metadata = await this.metadata()
      const response = await this.fetchValue(metadata.token_endpoint, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'refresh_token', client_id: this.options.clientId, refresh_token: refreshToken }) })
      if (!response.ok) { await this.options.wallet.clearRefreshToken(this.options.clientId); throw new Error(`Anchor session refresh failed (${response.status})`) }
      const result = exactObject(await response.json(), ['access_token', 'token_type', 'expires_in', 'scope', 'refresh_token'], 'OIDC refresh response')
      if (result.token_type !== 'Bearer' || typeof result.access_token !== 'string' || typeof result.refresh_token !== 'string' || typeof result.scope !== 'string' || typeof result.expires_in !== 'number') throw new TypeError('OIDC refresh response is invalid')
      const keys = await this.jwks(metadata.jwks_uri)
      const claims = await verifyJwt(result.access_token, keys, { typ: 'at+jwt', issuer: this.issuer, audience: this.audience, clientId: this.options.clientId, now: this.now() })
      const scopes = new Set(result.scope.split(' ').filter(Boolean))
      if (this.options.allowedScopes.some(scope => !scopes.has(scope)) || claims.scope !== result.scope) throw new TypeError('OIDC refreshed access token scopes are invalid')
      this.cached = { token: result.access_token, scopes, expiresAt: numberClaim(claims.exp, 'exp') }
      await this.options.wallet.saveRefreshToken(this.options.clientId, result.refresh_token)
      return result.access_token
    })().finally(() => { this.refreshing = undefined })
    return this.refreshing
  }

  async clear(): Promise<void> {
    this.cached = undefined
    await this.options.wallet.clearRefreshToken(this.options.clientId)
  }

  hasFreshAccessToken(): boolean {
    return !!this.cached && this.cached.expiresAt > seconds(this.now()) + 30
  }

  private async metadata(): Promise<OidcMetadata> {
    const response = await this.fetchValue(`${this.issuer}/.well-known/openid-configuration`)
    if (!response.ok) throw new Error(`Anchor OIDC discovery failed (${response.status})`)
    const value = exactObject(await response.json(), ['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri', 'response_types_supported', 'grant_types_supported', 'subject_types_supported', 'id_token_signing_alg_values_supported', 'token_endpoint_auth_methods_supported', 'code_challenge_methods_supported', 'scopes_supported'], 'OIDC metadata')
    const authorizationEndpoint = exactEndpoint(value.authorization_endpoint, this.issuer, '/oauth/authorize')
    const tokenEndpoint = exactEndpoint(value.token_endpoint, this.issuer, '/oauth/token')
    const jwksUri = exactEndpoint(value.jwks_uri, this.issuer, '/oauth/jwks')
    if (value.issuer !== this.issuer || !arrayEquals(value.response_types_supported, ['code']) || !arrayIncludes(value.code_challenge_methods_supported, 'S256')) throw new TypeError('Anchor OIDC metadata is unsupported')
    return { issuer: this.issuer, authorization_endpoint: authorizationEndpoint, token_endpoint: tokenEndpoint, jwks_uri: jwksUri }
  }

  private async jwks(uri: string): Promise<OidcJwk[]> {
    const response = await this.fetchValue(uri)
    if (!response.ok) throw new Error(`Anchor OIDC JWKS failed (${response.status})`)
    const value = exactObject(await response.json(), ['keys'], 'OIDC JWKS')
    if (!Array.isArray(value.keys) || value.keys.length === 0) throw new TypeError('Anchor OIDC JWKS is invalid')
    return value.keys.map(key => {
      const jwk = exactObject(key, ['kty', 'crv', 'alg', 'use', 'kid', 'x', 'y'], 'OIDC JWK')
      if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || jwk.alg !== 'ES256' || jwk.use !== 'sig' || typeof jwk.kid !== 'string' || typeof jwk.x !== 'string' || typeof jwk.y !== 'string') throw new TypeError('OIDC JWK is invalid')
      return jwk as unknown as OidcJwk
    })
  }

  private waitForCallback(popup: Window, state: string): Promise<{ code: string } | { error: string; errorDescription: string }> {
    const eventTarget = this.options.eventTarget ?? window
    const timeoutMs = this.options.timeoutMs ?? 5 * 60 * 1000
    return new Promise((resolve, reject) => {
      const cleanup = () => { clearTimeout(timer); clearInterval(closed); eventTarget.removeEventListener('message', onMessage as EventListener) }
      const onMessage = (event: MessageEvent<unknown>) => {
        if (event.origin !== this.issuer || event.source !== popup) return
        void handleBisetOid4vpBridgeMessage({ event, popup, anchorOrigin: this.issuer, wallet: this.options.wallet }).catch(error => { cleanup(); reject(error) }).then(handled => {
          if (handled) return
          const callback = oidcCallback(event.data)
          if (!callback || callback.state !== state) return
          cleanup()
          if (callback.code) resolve({ code: callback.code })
          else resolve({ error: callback.error!, errorDescription: callback.errorDescription ?? '' })
        })
      }
      const timer = setTimeout(() => { cleanup(); reject(new Error('Anchor login timed out')) }, timeoutMs)
      const closed = setInterval(() => { if (popup.closed) { cleanup(); reject(new Error('Anchor login popup was closed')) } }, 500)
      eventTarget.addEventListener('message', onMessage as EventListener)
    })
  }
}

interface JwtExpectation { typ: 'JWT' | 'at+jwt'; issuer: string; audience: string; nonce?: string; clientId?: string; now: Date }
async function verifyJwt(token: string, keys: OidcJwk[], expected: JwtExpectation): Promise<Record<string, unknown>> {
  const parts = token.split('.')
  if (parts.length !== 3) throw new TypeError('OIDC JWT is invalid')
  const header = jsonPart(parts[0]!)
  const claims = jsonPart(parts[1]!)
  if (header.alg !== 'ES256' || header.typ !== expected.typ || typeof header.kid !== 'string') throw new TypeError('OIDC JWT header is invalid')
  const key = keys.find(candidate => candidate.kid === header.kid && candidate.kty === 'EC' && candidate.crv === 'P-256' && candidate.alg === 'ES256' && candidate.use === 'sig')
  if (!key) throw new TypeError('OIDC JWT signing key is unknown')
  const cryptoKey = await crypto.subtle.importKey('jwk', key, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'])
  const valid = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, cryptoKey, owned(base64urlToBytes(parts[2]!)), owned(new TextEncoder().encode(`${parts[0]}.${parts[1]}`)))
  const now = seconds(expected.now)
  if (!valid || claims.iss !== expected.issuer || !audience(claims.aud, expected.audience) || typeof claims.sub !== 'string' || numberClaim(claims.exp, 'exp') <= now || numberClaim(claims.iat, 'iat') > now + 60) throw new TypeError('OIDC JWT claims are invalid')
  if (expected.nonce !== undefined && claims.nonce !== expected.nonce) throw new TypeError('OIDC ID token nonce is invalid')
  if (expected.clientId !== undefined && claims.client_id !== expected.clientId) throw new TypeError('OIDC access token client is invalid')
  return claims
}

function oidcCallback(value: unknown): { state: string; code?: string; error?: string; errorDescription?: string } | undefined {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return undefined
  const input = value as Record<string, unknown>
  if (input.type !== 'biset.oidc.callback.v1' || typeof input.state !== 'string') return undefined
  if (typeof input.code === 'string' && input.error === undefined) return { state: input.state, code: input.code }
  if (typeof input.error === 'string' && input.code === undefined && (input.errorDescription === undefined || typeof input.errorDescription === 'string')) return { state: input.state, error: input.error, ...(typeof input.errorDescription === 'string' ? { errorDescription: input.errorDescription } : {}) }
  return undefined
}
function exactObject(value: unknown, keys: string[], name: string): Record<string, unknown> { if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError(`${name} is invalid`); const record = value as Record<string, unknown>; const actual = Object.keys(record).sort(); const expected = [...keys].sort(); if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) throw new TypeError(`${name} has unexpected fields`); return record }
function exactEndpoint(value: unknown, issuer: string, path: string): string { if (typeof value !== 'string') throw new TypeError('OIDC endpoint is invalid'); const url = new URL(value); if (url.origin !== issuer || url.pathname !== path || url.search || url.hash) throw new TypeError('OIDC endpoint is not trusted'); return url.href }
function httpsOrigin(value: string, name: string): string { const url = new URL(value); if (url.protocol !== 'https:' || url.pathname !== '/' || url.search || url.hash || url.username || url.password) throw new TypeError(`${name} must be an HTTPS origin`); return url.origin }
function applicationOrigin(): string {
  // Safari may expose a file document's Location.origin as `file://`
  // instead of the serialized opaque origin `null`. OAuth registration and
  // postMessage use the latter, so normalize by protocol first.
  if (globalThis.location?.protocol === 'file:') return 'null'
  const value = globalThis.location?.origin ?? 'null'
  if (value === 'null') return value
  const url = new URL(value)
  if (url.protocol !== 'https:' || url.origin !== value) throw new TypeError('OIDC wallet application must use file:// or HTTPS')
  return value
}
function jsonPart(value: string): Record<string, unknown> { const decoded = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(base64urlToBytes(value))); if (decoded === null || typeof decoded !== 'object' || Array.isArray(decoded)) throw new TypeError('OIDC JWT JSON is invalid'); return decoded as Record<string, unknown> }
function audience(value: unknown, expected: string): boolean { return value === expected || (Array.isArray(value) && value.length === 1 && value[0] === expected) }
function numberClaim(value: unknown, name: string): number { if (typeof value !== 'number' || !Number.isSafeInteger(value)) throw new TypeError(`OIDC ${name} claim is invalid`); return value }
function arrayEquals(value: unknown, expected: string[]): boolean { return Array.isArray(value) && value.length === expected.length && value.every((item, index) => item === expected[index]) }
function arrayIncludes(value: unknown, expected: string): boolean { return Array.isArray(value) && value.includes(expected) }
function randomToken(length: number): string { return bytesToBase64url(crypto.getRandomValues(new Uint8Array(length))) }
function seconds(value: Date): number { return Math.floor(value.getTime() / 1000) }
function owned(value: Uint8Array): ArrayBuffer { return value.slice().buffer }
