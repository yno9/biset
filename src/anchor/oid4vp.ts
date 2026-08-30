import { sha256 } from '@noble/hashes/sha2.js'
import { ed25519 } from '@noble/curves/ed25519.js'
import { base64urlToBytes, bytesToBase64url } from '../protocol/canonical.ts'
import {
  BISET_LOGIN_CREDENTIAL_FORMAT,
  BISET_LOGIN_CREDENTIAL_TYPE,
  accountRefFromCredential,
  issueBisetAnchorLoginCredential,
  p256JwkThumbprint,
  p256PublicJwk,
  verifyBisetLoginPresentation,
  type P256PublicJwk,
} from '../oid4vp/profile.ts'
import type { AnchorAuthenticatedSubject, AnchorSubjectAuthenticator } from './oidc.ts'
import { parseLog } from '../identity/webvh/log.ts'
import { parseWebvhDid } from '../identity/webvh/identifier.ts'
import { resolveEntries } from '../identity/webvh/resolver.ts'
import { decodeMultikey } from '../identity/webvh/multikey.ts'
import { verifyProof, type DataIntegrityProof } from '../identity/webvh/proof.ts'
import type { WebvhLogStore } from './webvh/webvh-store.ts'

export interface AnchorLoginCredentialRecord {
  credentialId: string
  credentialHash: string
  accountRef: string
  rootSubject: string
  holderKeyId: string
  issuedAt: number
  expiresAt: number
  revokedAt?: number
}

export interface AnchorOid4vpTransaction {
  transactionId: string
  state: string
  nonce: string
  returnUrl: string
  expiresAt: number
}

export interface AnchorOid4vpCompletion {
  responseCodeHash: string
  rootSubject: string
  authenticatedAt: number
  returnUrl: string
  expiresAt: number
}

export interface AnchorOid4vpSession {
  sessionHash: string
  rootSubject: string
  authenticatedAt: number
  expiresAt: number
}

export interface AnchorOid4vpEnrollmentChallenge {
  challengeHash: string
  did: string
  holderKeyId: string
  expiresAt: number
}

export interface AnchorOid4vpStore {
  accountRef(rootSubject: string): Promise<string>
  putCredential(record: AnchorLoginCredentialRecord): Promise<void>
  credential(credentialId: string): Promise<AnchorLoginCredentialRecord | undefined>
  revokeCredential(credentialId: string, revokedAt: number): Promise<boolean>
  putTransaction(value: AnchorOid4vpTransaction): Promise<void>
  transaction(transactionId: string): Promise<AnchorOid4vpTransaction | undefined>
  takeTransactionByState(state: string): Promise<AnchorOid4vpTransaction | undefined>
  putCompletion(value: AnchorOid4vpCompletion): Promise<void>
  takeCompletion(responseCodeHash: string): Promise<AnchorOid4vpCompletion | undefined>
  putSession(value: AnchorOid4vpSession): Promise<void>
  session(sessionHash: string): Promise<AnchorOid4vpSession | undefined>
  putEnrollmentChallenge(value: AnchorOid4vpEnrollmentChallenge): Promise<void>
  takeEnrollmentChallenge(challengeHash: string): Promise<AnchorOid4vpEnrollmentChallenge | undefined>
}

export class MemoryAnchorOid4vpStore implements AnchorOid4vpStore {
  private readonly accounts = new Map<string, string>()
  private readonly credentials = new Map<string, AnchorLoginCredentialRecord>()
  private readonly transactions = new Map<string, AnchorOid4vpTransaction>()
  private readonly transactionByState = new Map<string, string>()
  private readonly completions = new Map<string, AnchorOid4vpCompletion>()
  private readonly sessions = new Map<string, AnchorOid4vpSession>()
  private readonly enrollments = new Map<string, AnchorOid4vpEnrollmentChallenge>()

  async accountRef(rootSubject: string): Promise<string> {
    const existing = this.accounts.get(rootSubject)
    if (existing) return existing
    const accountRef = randomToken(32)
    this.accounts.set(rootSubject, accountRef)
    return accountRef
  }
  async putCredential(value: AnchorLoginCredentialRecord): Promise<void> { if (this.credentials.has(value.credentialId)) throw new Error('credential ID already exists'); this.credentials.set(value.credentialId, { ...value }) }
  async credential(id: string): Promise<AnchorLoginCredentialRecord | undefined> { const value = this.credentials.get(id); return value && { ...value } }
  async revokeCredential(id: string, revokedAt: number): Promise<boolean> { const value = this.credentials.get(id); if (!value) return false; this.credentials.set(id, { ...value, revokedAt }); return true }
  async putTransaction(value: AnchorOid4vpTransaction): Promise<void> { this.transactions.set(value.transactionId, { ...value }); this.transactionByState.set(value.state, value.transactionId) }
  async transaction(id: string): Promise<AnchorOid4vpTransaction | undefined> { const value = this.transactions.get(id); return value && { ...value } }
  async takeTransactionByState(state: string): Promise<AnchorOid4vpTransaction | undefined> { const id = this.transactionByState.get(state); if (!id) return undefined; this.transactionByState.delete(state); const value = this.transactions.get(id); this.transactions.delete(id); return value && { ...value } }
  async putCompletion(value: AnchorOid4vpCompletion): Promise<void> { this.completions.set(value.responseCodeHash, { ...value }) }
  async takeCompletion(hash: string): Promise<AnchorOid4vpCompletion | undefined> { const value = this.completions.get(hash); this.completions.delete(hash); return value && { ...value } }
  async putSession(value: AnchorOid4vpSession): Promise<void> { this.sessions.set(value.sessionHash, { ...value }) }
  async session(hash: string): Promise<AnchorOid4vpSession | undefined> { const value = this.sessions.get(hash); return value && { ...value } }
  async putEnrollmentChallenge(value: AnchorOid4vpEnrollmentChallenge): Promise<void> { this.enrollments.set(value.challengeHash, { ...value }) }
  async takeEnrollmentChallenge(hash: string): Promise<AnchorOid4vpEnrollmentChallenge | undefined> { const value = this.enrollments.get(hash); this.enrollments.delete(hash); return value && { ...value } }
}

export interface AnchorOid4vpProviderOptions {
  issuer: string
  store: AnchorOid4vpStore
  credentialSigningPrivateKey: Uint8Array
  credentialSigningKeyId?: string
  walletAuthorizationEndpoint?: string
  credentialTtlSeconds?: number
  transactionTtlSeconds?: number
  completionTtlSeconds?: number
  sessionTtlSeconds?: number
  enrollmentTtlSeconds?: number
  now?: () => Date
}

/** Anchor-issued login credentials presented through the OID4VP direct_post flow. */
export class AnchorOid4vpProvider implements AnchorSubjectAuthenticator {
  private readonly issuer: string
  private readonly responseUri: string
  private readonly signingKeyId: string
  private readonly walletEndpoint: string
  private readonly now: () => Date
  private readonly credentialTtl: number
  private readonly transactionTtl: number
  private readonly completionTtl: number
  private readonly sessionTtl: number
  private readonly enrollmentTtl: number

  constructor(private readonly options: AnchorOid4vpProviderOptions) {
    this.issuer = origin(options.issuer)
    this.responseUri = `${this.issuer}/oid4vp/response`
    this.signingKeyId = options.credentialSigningKeyId ?? `${this.issuer}/oid4vp/jwks#login-credential-es256-1`
    if (options.credentialSigningPrivateKey.length !== 32 || !this.signingKeyId.startsWith(`${this.issuer}/`)) throw new TypeError('OID4VP credential signing key is invalid')
    this.walletEndpoint = options.walletAuthorizationEndpoint ?? `${this.issuer}/oid4vp/wallet-bridge`
    new URL(this.walletEndpoint)
    this.now = options.now ?? (() => new Date())
    this.credentialTtl = ttl(options.credentialTtlSeconds ?? 60 * 60 * 24 * 30, 300, 60 * 60 * 24 * 366, 'credential')
    this.transactionTtl = ttl(options.transactionTtlSeconds ?? 300, 30, 600, 'transaction')
    this.completionTtl = ttl(options.completionTtlSeconds ?? 120, 30, 300, 'completion')
    this.sessionTtl = ttl(options.sessionTtlSeconds ?? 60 * 60 * 12, 300, 60 * 60 * 24 * 7, 'session')
    this.enrollmentTtl = ttl(options.enrollmentTtlSeconds ?? 300, 30, 600, 'enrollment')
  }

  jwks(): Record<string, unknown> {
    return { keys: [{ ...p256PublicJwk(this.options.credentialSigningPrivateKey), alg: 'ES256', use: 'sig', kid: this.signingKeyId }] }
  }

  async issueCredential(rootSubject: string, holderPublicKey: P256PublicJwk): Promise<{ credential: string; expiresAt: string }> {
    if (!subjectValue(rootSubject)) throw new TypeError('Anchor root subject is invalid')
    const now = this.now()
    // A freshly issued credential is presented by a different clock (the
    // browser) immediately. Backdate not-before by a small, fixed tolerance
    // so ordinary sub-minute clock skew cannot make it unusable at issuance.
    const validFrom = new Date(now.getTime() - 60_000)
    const expiresAt = new Date(now.getTime() + this.credentialTtl * 1000)
    const accountRef = await this.options.store.accountRef(rootSubject)
    const credential = issueBisetAnchorLoginCredential({
      issuer: this.issuer, signingKeyId: this.signingKeyId,
      signingPrivateKey: this.options.credentialSigningPrivateKey,
      accountRef, holderPublicKey, validFrom, validUntil: expiresAt,
    })
    const id = credentialPayload(credential).id
    await this.options.store.putCredential({
      credentialId: id, credentialHash: hashToken(credential), accountRef, rootSubject,
      holderKeyId: p256JwkThumbprint(holderPublicKey),
      issuedAt: seconds(now), expiresAt: seconds(expiresAt),
    })
    return { credential, expiresAt: expiresAt.toISOString() }
  }

  async revokeCredential(credentialId: string): Promise<boolean> {
    return this.options.store.revokeCredential(credentialId, seconds(this.now()))
  }

  async beginEnrollment(request: Request, webvh: WebvhLogStore): Promise<Response> {
    let input: Record<string, unknown>
    try { input = await jsonObject(request, 16 * 1024) } catch { return problem(400, 'invalid_request') }
    if (typeof input.did !== 'string') return problem(400, 'invalid_request')
    let holderKey: P256PublicJwk
    try {
      holderKey = assertedP256Jwk(input.holder_jwk)
      const parts = parseWebvhDid(input.did)
      if (parts.port || parts.pathSegments.length > 0 || !resolveHostedDid(webvh, input.did, parts.domain)) return problem(404, 'unknown_identity')
    } catch { return problem(400, 'invalid_request') }
    const challenge = randomToken(32)
    // Persistence is integer Unix seconds. Construct the public timestamp
    // from that exact value as well; returning the current millisecond
    // fraction and later comparing it to storedSeconds * 1000 made every
    // otherwise-valid enrollment fail deterministically.
    const expiresAtSeconds = seconds(this.now()) + this.enrollmentTtl
    const expiresAt = new Date(expiresAtSeconds * 1000)
    await this.options.store.putEnrollmentChallenge({ challengeHash: hashToken(challenge), did: input.did, holderKeyId: p256JwkThumbprint(holderKey), expiresAt: expiresAtSeconds })
    return Response.json({
      document: {
        type: 'BisetAnchorLoginCredentialEnrollment',
        did: input.did,
        holder_jwk: holderKey,
        challenge,
        expires_at: expiresAt.toISOString(),
      },
    }, { headers: noStore() })
  }

  async completeEnrollment(request: Request, webvh: WebvhLogStore): Promise<Response> {
    let input: Record<string, unknown>
    try { input = await jsonObject(request, 32 * 1024) } catch { return problem(400, 'invalid_request') }
    const document = enrollmentDocument(input.document)
    const proof = enrollmentProof(input.proof)
    if (!document || !proof) return problem(400, 'invalid_request')
    const stored = await this.options.store.takeEnrollmentChallenge(hashToken(document.challenge))
    const now = this.now()
    if (!stored || stored.expiresAt <= seconds(now) || stored.did !== document.did || stored.holderKeyId !== p256JwkThumbprint(document.holder_jwk) || Date.parse(document.expires_at) !== stored.expiresAt * 1000) return problem(400, 'invalid_enrollment')
    let resolved
    let scid: string
    try {
      const parts = parseWebvhDid(document.did)
      scid = parts.scid
      resolved = resolveHostedDid(webvh, document.did, parts.domain)
    } catch { return problem(400, 'invalid_enrollment') }
    if (!resolved || !resolved.authentication.includes(proof.verificationMethod)) return problem(400, 'invalid_enrollment')
    const method = resolved.verificationMethod.find(value => value.id === proof.verificationMethod)
    if (!method) return problem(400, 'invalid_enrollment')
    let valid = false
    try { valid = verifyProof(document, proof, decodeMultikey(method.publicKeyMultibase)) } catch {}
    if (!valid) return problem(400, 'invalid_enrollment')
    const issued = await this.issueCredential(`webvh:${scid}`, document.holder_jwk)
    return Response.json({ format: BISET_LOGIN_CREDENTIAL_FORMAT, credential: issued.credential, expires_at: issued.expiresAt }, { status: 201, headers: noStore() })
  }

  async authenticate(request: Request, options?: { force: boolean }): Promise<AnchorAuthenticatedSubject | null> {
    // OIDC prompt=login must not reuse the browser-wide Anchor cookie. A
    // Biset client can hold a different local identity in the same browser;
    // accepting the previous identity's cookie would attach that new Root
    // seed to the old identity's Coordinator stream.
    if (options?.force) return null
    const token = cookie(request.headers.get('cookie'), '__Host-biset_anchor_session')
    if (!token) return null
    const value = await this.options.store.session(hashToken(token))
    const now = seconds(this.now())
    if (!value || value.expiresAt <= now || !subjectValue(value.rootSubject)) return null
    return { subject: value.rootSubject, authenticatedAt: new Date(value.authenticatedAt * 1000) }
  }

  async beginAuthentication(request: Request): Promise<Response> {
    // The Anchor normally sits behind a TLS-terminating reverse proxy. Bun's
    // request URL therefore has the private HTTP upstream origin even though
    // the browser reached the configured HTTPS issuer. Rebuild the return URL
    // on that trusted issuer instead of trusting (or rejecting) the upstream
    // transport origin; only the path and already-validated OAuth query are
    // carried across.
    const incoming = new URL(request.url)
    if (incoming.pathname !== '/oauth/authorize') throw new TypeError('OID4VP return URL is invalid')
    const returnUrl = new URL(`${incoming.pathname}${incoming.search}`, this.issuer)
    // prompt=login has now done its job: this transaction will mint a fresh
    // Anchor session for the selected Wallet identity. Keeping the flag on
    // the return URL would reject that brand-new session and start the same
    // OID4VP transaction forever.
    returnUrl.searchParams.delete('prompt')
    const openerOrigin = incoming.searchParams.get('wallet_origin') ?? ''
    if (openerOrigin !== 'null') {
      const parsed = new URL(openerOrigin)
      if (parsed.protocol !== 'https:' || parsed.origin !== openerOrigin) throw new TypeError('OID4VP wallet opener origin is invalid')
    }
    const transaction: AnchorOid4vpTransaction = {
      transactionId: randomToken(24), state: randomToken(24), nonce: randomToken(24),
      returnUrl: returnUrl.href, expiresAt: seconds(this.now()) + this.transactionTtl,
    }
    await this.options.store.putTransaction(transaction)
    const location = new URL(this.walletEndpoint)
    location.searchParams.set('client_id', this.responseUri)
    location.searchParams.set('request_uri', `${this.issuer}/oid4vp/request/${transaction.transactionId}`)
    if (location.origin === this.issuer && location.pathname === '/oid4vp/wallet-bridge') {
      location.searchParams.set('bridge_nonce', randomToken(24))
      location.searchParams.set('opener_origin', openerOrigin)
    }
    return new Response(null, { status: 302, headers: { location: location.href, 'cache-control': 'no-store' } })
  }

  async requestObject(transactionId: string): Promise<Response> {
    const transaction = await this.options.store.transaction(transactionId)
    if (!transaction || transaction.expiresAt <= seconds(this.now())) return problem(404, 'invalid_request_uri')
    return Response.json({
      client_id: this.responseUri,
      response_uri: this.responseUri,
      response_type: 'vp_token',
      response_mode: 'direct_post',
      nonce: transaction.nonce,
      state: transaction.state,
      dcql_query: {
        credentials: [{
          id: 'biset_anchor_login', format: BISET_LOGIN_CREDENTIAL_FORMAT,
          meta: { type_values: [[BISET_LOGIN_CREDENTIAL_TYPE]] },
          claims: [{ path: ['credentialSubject', 'id'] }],
        }],
      },
      client_metadata: { vp_formats_supported: { [BISET_LOGIN_CREDENTIAL_FORMAT]: { alg_values: ['ES256'] } } },
    }, { headers: noStore() })
  }

  async directPost(request: Request): Promise<Response> {
    if (request.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase() !== 'application/x-www-form-urlencoded') return problem(415, 'invalid_request')
    const form = new URLSearchParams(await request.text())
    const state = single(form, 'state')
    const vpToken = single(form, 'vp_token')
    const transaction = await this.options.store.takeTransactionByState(state)
    const now = this.now()
    if (!transaction || transaction.expiresAt <= seconds(now) || !vpToken) return problem(400, 'invalid_request')
    let verified
    try {
      verified = verifyBisetLoginPresentation(vpToken, {
        verifierId: this.responseUri, nonce: transaction.nonce, issuer: this.issuer,
        credentialSigningKeyId: this.signingKeyId,
        credentialSigningPublicKey: p256PublicJwk(this.options.credentialSigningPrivateKey), now,
      })
    } catch { return problem(400, 'invalid_vp_token') }
    const accountRef = accountRefFromCredential(verified.credential)
    const record = await this.options.store.credential(verified.credential.id)
    const nowSeconds = seconds(now)
    if (!record || record.revokedAt !== undefined || record.expiresAt <= nowSeconds || record.accountRef !== accountRef || record.credentialHash !== hashToken(verified.credentialToken) || record.holderKeyId !== verified.holderKeyId) return problem(400, 'invalid_vp_token')
    const responseCode = randomToken(32)
    await this.options.store.putCompletion({
      responseCodeHash: hashToken(responseCode), rootSubject: record.rootSubject,
      authenticatedAt: nowSeconds, returnUrl: transaction.returnUrl,
      expiresAt: nowSeconds + this.completionTtl,
    })
    const redirect = new URL(`${this.issuer}/oid4vp/complete`)
    redirect.searchParams.set('response_code', responseCode)
    return Response.json({ redirect_uri: redirect.href }, { headers: noStore() })
  }

  async complete(request: Request): Promise<Response> {
    const url = new URL(request.url)
    const code = single(url.searchParams, 'response_code')
    const completion = code && await this.options.store.takeCompletion(hashToken(code))
    const now = this.now()
    if (!completion || completion.expiresAt <= seconds(now)) return problem(400, 'invalid_response_code')
    const sessionToken = randomToken(32)
    await this.options.store.putSession({
      sessionHash: hashToken(sessionToken), rootSubject: completion.rootSubject,
      authenticatedAt: completion.authenticatedAt, expiresAt: seconds(now) + this.sessionTtl,
    })
    return new Response(null, {
      status: 302,
      headers: {
        location: completion.returnUrl,
        'set-cookie': `__Host-biset_anchor_session=${sessionToken}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${this.sessionTtl}`,
        'cache-control': 'no-store',
      },
    })
  }

  walletBridge(): Response {
    return new Response(`<!doctype html><meta charset="utf-8"><title>Biset Wallet</title><p id="status">Biset Walletを開いています…</p><script src="/oid4vp/wallet-bridge.js" defer></script>`, {
      headers: {
        'content-type': 'text/html; charset=utf-8',
        'cache-control': 'no-store',
        'content-security-policy': "default-src 'none'; script-src 'self'; style-src 'none'; img-src 'none'; connect-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
        'referrer-policy': 'no-referrer',
        'x-content-type-options': 'nosniff',
      },
    })
  }

  walletBridgeScript(): Response {
    return new Response(BRIDGE_SCRIPT, { headers: { 'content-type': 'text/javascript; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' } })
  }

}

const BRIDGE_SCRIPT = `(() => {
  const status = document.getElementById('status');
  const requestUri = new URL(location.href).searchParams.get('request_uri');
  const bridgeNonce = new URL(location.href).searchParams.get('bridge_nonce');
  const openerOrigin = new URL(location.href).searchParams.get('opener_origin');
  const fail = message => { if (status) status.textContent = message; };
  if (!window.opener || !requestUri || !bridgeNonce || !openerOrigin) { fail('Biset Walletを開けませんでした。'); return; }
  window.addEventListener('message', event => {
    if (event.source !== window.opener || event.origin !== openerOrigin) return;
    const value = event.data;
    if (!value || value.type !== 'biset.oid4vp.complete.v1' || value.bridgeNonce !== bridgeNonce || typeof value.completionUri !== 'string') return;
    const completion = new URL(value.completionUri);
    if (completion.origin !== location.origin || completion.pathname !== '/oid4vp/complete' || !completion.searchParams.get('response_code') || completion.hash) { fail('不正なOID4VP応答を拒否しました。'); return; }
    location.replace(completion.href);
  });
  window.opener.postMessage({ type: 'biset.oid4vp.request.v1', requestUri, bridgeNonce }, openerOrigin === 'null' ? '*' : openerOrigin);
})();`

function credentialPayload(token: string): { id: string } {
  const part = token.split('.')[1]
  if (!part) throw new TypeError('issued credential is invalid')
  const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(base64urlToBytes(part))) as { id?: unknown }
  if (typeof value.id !== 'string') throw new TypeError('issued credential ID is invalid')
  return { id: value.id }
}
function hashToken(value: string): string { return bytesToBase64url(sha256(new TextEncoder().encode(value))) }
function randomToken(length: number): string { return bytesToBase64url(crypto.getRandomValues(new Uint8Array(length))) }
function seconds(value: Date): number { return Math.floor(value.getTime() / 1000) }
function ttl(value: number, min: number, max: number, name: string): number { if (!Number.isSafeInteger(value) || value < min || value > max) throw new TypeError(`OID4VP ${name} TTL is invalid`); return value }
function origin(value: string): string { const url = new URL(value); if (url.protocol !== 'https:' || url.pathname !== '/' || url.search || url.hash || url.username || url.password) throw new TypeError('OID4VP issuer must be an HTTPS origin'); return url.origin }
function subjectValue(value: string): boolean { return typeof value === 'string' && value.length > 0 && value.length <= 512 && /^[\x21-\x7e]+$/.test(value) }
function single(values: URLSearchParams, name: string): string { const found = values.getAll(name); return found.length === 1 ? found[0]! : '' }
function cookie(header: string | null, name: string): string { if (!header) return ''; for (const item of header.split(';')) { const [key, ...rest] = item.trim().split('='); if (key === name) return rest.join('=') } return '' }
function noStore(): Record<string, string> { return { 'cache-control': 'no-store', pragma: 'no-cache' } }
function problem(status: number, error: string): Response { return Response.json({ error }, { status, headers: noStore() }) }

interface EnrollmentDocument {
  type: 'BisetAnchorLoginCredentialEnrollment'
  did: string
  holder_jwk: P256PublicJwk
  challenge: string
  expires_at: string
}
function enrollmentDocument(value: unknown): EnrollmentDocument | undefined {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return undefined
  const input = value as Record<string, unknown>
  if (Object.keys(input).sort().join() !== ['challenge', 'did', 'expires_at', 'holder_jwk', 'type'].sort().join() || input.type !== 'BisetAnchorLoginCredentialEnrollment' || typeof input.did !== 'string' || typeof input.challenge !== 'string' || typeof input.expires_at !== 'string') return undefined
  try { return { type: input.type, did: input.did, holder_jwk: assertedP256Jwk(input.holder_jwk), challenge: input.challenge, expires_at: input.expires_at } } catch { return undefined }
}
function enrollmentProof(value: unknown): DataIntegrityProof | undefined {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return undefined
  const input = value as Record<string, unknown>
  if (input.type !== 'DataIntegrityProof' || input.cryptosuite !== 'eddsa-jcs-2022' || input.proofPurpose !== 'authentication' || typeof input.verificationMethod !== 'string' || typeof input.proofValue !== 'string' || (input.created !== undefined && typeof input.created !== 'string')) return undefined
  return { type: input.type, cryptosuite: input.cryptosuite, proofPurpose: input.proofPurpose, verificationMethod: input.verificationMethod, proofValue: input.proofValue, ...(typeof input.created === 'string' ? { created: input.created } : {}) }
}
function assertedP256Jwk(value: unknown): P256PublicJwk {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('holder JWK is invalid')
  const input = value as Record<string, unknown>
  if (Object.keys(input).sort().join() !== ['crv', 'kty', 'x', 'y'].sort().join() || input.kty !== 'EC' || input.crv !== 'P-256' || typeof input.x !== 'string' || typeof input.y !== 'string') throw new TypeError('holder JWK is invalid')
  const jwk: P256PublicJwk = { kty: 'EC', crv: 'P-256', x: input.x, y: input.y }
  p256JwkThumbprint(jwk)
  return jwk
}
function resolveHostedDid(store: WebvhLogStore, did: string, domain: string) {
  const raw = store.read(domain)
  if (!raw) return null
  return resolveEntries(did, parseLog(raw))
}
async function jsonObject(request: Request, limit: number): Promise<Record<string, unknown>> {
  if (request.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase() !== 'application/json') throw new TypeError('JSON is required')
  const text = await request.text()
  if (new TextEncoder().encode(text).length > limit) throw new TypeError('JSON is too large')
  const value = JSON.parse(text)
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('JSON object is required')
  return value as Record<string, unknown>
}
