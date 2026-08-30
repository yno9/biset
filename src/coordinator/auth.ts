import { base64urlToBytes } from '../protocol/canonical.ts'

export interface VaultAccessPrincipal {
  /** Pairwise subject scoped to the Coordinator audience. Never a DID/SCID. */
  subject: string
  /** Opaque Anchor-attested WebVH versionId; Coordinator sees no DID/SCID. */
  generation: string
  scopes: ReadonlySet<string>
  expiresAt: number
}

export interface VaultAccessTokenVerifier {
  verify(token: string, now?: Date): Promise<VaultAccessPrincipal>
}

export class VaultAuthenticationError extends Error {}
export class VaultAuthenticationUnavailableError extends Error {}
export class VaultAuthorizationError extends Error {}

export async function authorizeBearer(
  request: Request,
  verifier: VaultAccessTokenVerifier,
  requiredScope: string,
): Promise<VaultAccessPrincipal> {
  const authorization = request.headers.get('authorization')
  const match = authorization?.match(/^Bearer ([\x21-\x7e]{1,16384})$/)
  if (!match) throw new VaultAuthenticationError('Bearer access token is required')
  const principal = await verifier.verify(match[1])
  if (!principal.scopes.has(requiredScope)) throw new VaultAuthorizationError(`access token lacks ${requiredScope} scope`)
  return principal
}

export interface OidcJwtAccessTokenVerifierOptions {
  issuer: string
  audience: string
  jwksUri?: string
  fetch?: typeof fetch
  cacheTtlMs?: number
}

interface JwtHeader { alg: 'RS256' | 'ES256'; kid: string; typ: 'at+jwt' }
interface JsonWebKey {
  alg?: string
  crv?: string
  e?: string
  ext?: boolean
  key_ops?: string[]
  kid?: string
  kty?: string
  n?: string
  use?: string
  x?: string
  y?: string
}
interface JsonWebKeySet { keys: JsonWebKey[] }

/**
 * Strict RFC 9068-shaped JWT access-token verifier for the Coordinator. OIDC is
 * used to authenticate the user; this verifier consumes the OAuth access
 * token, never an ID Token. Only asymmetric RS256/ES256 keys are accepted.
 */
export class OidcJwtAccessTokenVerifier implements VaultAccessTokenVerifier {
  private readonly fetchImpl: typeof fetch
  private readonly cacheTtlMs: number
  private cachedKeys?: { expiresAt: number; keys: JsonWebKey[] }
  private discoveredJwksUri?: string

  constructor(private readonly options: OidcJwtAccessTokenVerifierOptions) {
    const issuer = normalizedOrigin(options.issuer, 'OIDC issuer')
    const audience = normalizedOrigin(options.audience, 'OAuth audience')
    this.options = { ...options, issuer, audience }
    this.fetchImpl = options.fetch ?? globalThis.fetch.bind(globalThis)
    this.cacheTtlMs = options.cacheTtlMs ?? 5 * 60 * 1000
    if (!Number.isSafeInteger(this.cacheTtlMs) || this.cacheTtlMs <= 0) throw new TypeError('OIDC JWKS cache TTL must be positive')
  }

  async verify(token: string, now = new Date()): Promise<VaultAccessPrincipal> {
    const parts = token.split('.')
    if (parts.length !== 3 || parts.some(part => part.length === 0)) throw new VaultAuthenticationError('access token is not a compact JWT')
    const header = jsonPart(parts[0]) as Partial<JwtHeader>
    if ((header.alg !== 'RS256' && header.alg !== 'ES256') || typeof header.kid !== 'string' || !header.kid || header.typ !== 'at+jwt') {
      throw new VaultAuthenticationError('access token header is not accepted')
    }
    const claims = jsonPart(parts[1]) as Record<string, unknown>
    const key = (await this.keys(now)).find(candidate => candidate.kid === header.kid && (!candidate.alg || candidate.alg === header.alg) && (!candidate.use || candidate.use === 'sig'))
    if (!key) throw new VaultAuthenticationError('access token signing key is unknown')
    const cryptoKey = await importVerificationKey(key, header.alg)
    const signature = base64urlToBytes(parts[2])
    const data = new TextEncoder().encode(`${parts[0]}.${parts[1]}`)
    const algorithm = header.alg === 'RS256' ? { name: 'RSASSA-PKCS1-v1_5' } : { name: 'ECDSA', hash: 'SHA-256' }
    if (!(await crypto.subtle.verify(algorithm, cryptoKey, ownedBuffer(signature), ownedBuffer(data)))) throw new VaultAuthenticationError('access token signature is invalid')
    return validateClaims(claims, this.options.issuer, this.options.audience, now)
  }

  private async keys(now: Date): Promise<JsonWebKey[]> {
    if (this.cachedKeys && this.cachedKeys.expiresAt > now.getTime()) return this.cachedKeys.keys
    const jwksUri = this.options.jwksUri ?? await this.discoverJwksUri()
    const response = await oidcFetch(this.fetchImpl, jwksUri)
    if (!response.ok) throw new VaultAuthenticationError(`OIDC JWKS request failed (${response.status})`)
    const body = await oidcJson(response) as Partial<JsonWebKeySet>
    if (!Array.isArray(body.keys)) throw new VaultAuthenticationError('OIDC JWKS is invalid')
    this.cachedKeys = { expiresAt: now.getTime() + this.cacheTtlMs, keys: body.keys }
    return body.keys
  }

  private async discoverJwksUri(): Promise<string> {
    if (this.discoveredJwksUri) return this.discoveredJwksUri
    const response = await oidcFetch(this.fetchImpl, `${this.options.issuer}/.well-known/openid-configuration`)
    if (!response.ok) throw new VaultAuthenticationError(`OIDC discovery failed (${response.status})`)
    const metadata = await oidcJson(response) as Record<string, unknown>
    if (metadata.issuer !== this.options.issuer || typeof metadata.jwks_uri !== 'string') throw new VaultAuthenticationError('OIDC discovery metadata is invalid')
    this.discoveredJwksUri = normalizedHttpsUrl(metadata.jwks_uri, 'OIDC jwks_uri')
    return this.discoveredJwksUri
  }
}

function validateClaims(claims: Record<string, unknown>, issuer: string, audience: string, now: Date): VaultAccessPrincipal {
  const nowSeconds = Math.floor(now.getTime() / 1000)
  if (claims.iss !== issuer) throw new VaultAuthenticationError('access token issuer is invalid')
  const audiences = typeof claims.aud === 'string' ? [claims.aud] : Array.isArray(claims.aud) && claims.aud.every(value => typeof value === 'string') ? claims.aud : []
  if (!audiences.includes(audience)) throw new VaultAuthenticationError('access token audience is invalid')
  if (typeof claims.sub !== 'string' || !/^[\x21-\x7e]{1,255}$/.test(claims.sub)) throw new VaultAuthenticationError('access token subject is invalid')
  if (typeof claims.client_id !== 'string' || !/^[\x21-\x7e]{1,512}$/.test(claims.client_id)) throw new VaultAuthenticationError('access token client_id is invalid')
  if (typeof claims.jti !== 'string' || !/^[\x21-\x7e]{1,255}$/.test(claims.jti)) throw new VaultAuthenticationError('access token jti is invalid')
  if (typeof claims.exp !== 'number' || !Number.isSafeInteger(claims.exp) || claims.exp <= nowSeconds) throw new VaultAuthenticationError('access token is expired')
  if (claims.nbf !== undefined && (typeof claims.nbf !== 'number' || !Number.isSafeInteger(claims.nbf) || claims.nbf > nowSeconds)) throw new VaultAuthenticationError('access token is not active')
  if (typeof claims.iat !== 'number' || !Number.isSafeInteger(claims.iat) || claims.iat > nowSeconds + 60) throw new VaultAuthenticationError('access token issued-at time is invalid')
  if (typeof claims.scope !== 'string') throw new VaultAuthenticationError('access token scope is invalid')
  if (typeof claims.biset_generation !== 'string' || !/^[1-9][0-9]*-[A-Za-z0-9_-]{20,200}$/.test(claims.biset_generation)) throw new VaultAuthenticationError('access token generation is invalid')
  const scopes = claims.scope.split(' ').filter(Boolean)
  return { subject: claims.sub, generation: claims.biset_generation, scopes: new Set(scopes), expiresAt: claims.exp }
}

function jsonPart(value: string): unknown {
  try { return JSON.parse(new TextDecoder().decode(base64urlToBytes(value))) } catch { throw new VaultAuthenticationError('access token contains invalid JSON') }
}

async function importVerificationKey(jwk: JsonWebKey, alg: JwtHeader['alg']): Promise<CryptoKey> {
  try {
    if (alg === 'RS256' && jwk.kty === 'RSA') return await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify'])
    if (alg === 'ES256' && jwk.kty === 'EC' && jwk.crv === 'P-256') return await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'])
  } catch {
    throw new VaultAuthenticationError('access token signing key is invalid')
  }
  throw new VaultAuthenticationError('access token signing key does not match its algorithm')
}

function ownedBuffer(value: Uint8Array): ArrayBuffer {
  return Uint8Array.from(value).buffer
}

function normalizedOrigin(value: string, name: string): string {
  const url = new URL(value)
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || url.pathname !== '/') throw new TypeError(`${name} must be an HTTPS origin`)
  return url.origin
}

function normalizedHttpsUrl(value: string, name: string): string {
  const url = new URL(value)
  if (url.protocol !== 'https:' || url.username || url.password || url.hash) throw new VaultAuthenticationError(`${name} must be an HTTPS URL`)
  return url.href
}

async function oidcFetch(fetchImpl: typeof fetch, url: string): Promise<Response> {
  try { return await fetchImpl(url, { headers: { accept: 'application/json' } }) }
  catch { throw new VaultAuthenticationUnavailableError('OIDC metadata is temporarily unavailable') }
}

async function oidcJson(response: Response): Promise<unknown> {
  try { return await response.json() }
  catch { throw new VaultAuthenticationUnavailableError('OIDC metadata response is invalid') }
}
