import type { MailDkimSigner } from '../mediator/mail-plugin/dkim.ts'
import { deliverMail, type MailDeliveryResult } from '../mediator/mail-plugin/smtp-client.ts'
import { decodeMailSubmissionRequestWire, encodeMailSubmissionResultWire } from '../mediator/mail-plugin/mail-submission-wire.ts'
import type { MailSubmissionResultV1 } from '../../protocol/mail-submission.ts'

const MAX_BODY_BYTES = 25 * 1024 * 1024
const PATH = '/v1/mail/submit'
const REPLAY_MS = 5 * 60_000
const replay = new Map<string, number>()
type P256Jwk = { kty: 'EC'; crv: 'P-256'; x: string; y: string }

export interface MailRelaySubmissionOptions {
  hostname: string
  signDkim?: MailDkimSigner
  authorityUrl: string
  authoritySecret: string
  relayOrigin: string
  allowedOrigins: Set<string>
  deliverMailFn?: typeof deliverMail
  idempotency?: { get(messageId: string, request: { mailFrom: string; rcptTo: string[]; rawRfc5322: Uint8Array }): string | undefined; save(messageId: string, request: { mailFrom: string; rcptTo: string[]; rawRfc5322: Uint8Array }, result: string): void }
}

/** HTTP submission for the did.md relay.  A Wallet capability is verified by
 * did.md itself; this process verifies the accompanying DPoP proof so a
 * captured capability cannot be used from another browser/device. */
export function createMailRelaySubmissionHandler(options: MailRelaySubmissionOptions): (request: Request) => Promise<Response> {
  const deliver = options.deliverMailFn ?? deliverMail
  return async request => {
    const origin = request.headers.get('origin')
    if (request.method === 'OPTIONS') {
      if (!origin || !options.allowedOrigins.has(origin)) return new Response(null, { status: 403 })
      return new Response(null, { status: 204, headers: cors(origin) })
    }
    if (origin && !options.allowedOrigins.has(origin)) return text(403, 'origin not allowed', origin)
    if (new URL(request.url).pathname !== PATH) return text(404, 'Not found', origin)
    if (request.method !== 'POST') return text(405, 'Method not allowed', origin)
    try {
      const parsed = decodeMailSubmissionRequestWire(await requestText(request))
      const messageId = request.headers.get('x-biset-mail-message-id')
      if (!messageId || !/^[A-Za-z0-9_-]{20,128}$/.test(messageId)) return text(400, 'mail message id is required', origin)
      const prior = options.idempotency?.get(messageId, parsed)
      if (prior) return json(200, prior, origin)
      const capability = request.headers.get('x-biset-mail-capability')
      if (!capability) return text(403, 'mail capability is required', origin)
      const grant = await authorize(options, capability, parsed.mailFrom)
      if (grant.did !== parsed.identityId) return text(403, 'mail capability belongs to another DID', origin)
      const jkt = await verifyDpop(request.headers.get('dpop') ?? '', request, `${options.relayOrigin}${PATH}`)
      if (jkt !== grant.deviceJkt) return text(403, 'DPoP key is not authorized for this mail capability', origin)
      const results = await deliver({ hostname: options.hostname, signDkim: options.signDkim }, { mailFrom: parsed.mailFrom, rcptTo: parsed.rcptTo, rawRfc5322: parsed.rawRfc5322 })
      const result = encodeMailSubmissionResultWire(collapse(results))
      options.idempotency?.save(messageId, parsed, result)
      return json(200, result, origin)
    } catch (error) {
      if (error instanceof TypeError || error instanceof RangeError) return text(400, error.message, origin)
      return text(403, error instanceof Error ? error.message : 'mail submission is not authorized', origin)
    }
  }
}

async function authorize(options: MailRelaySubmissionOptions, capability: string, address: string): Promise<{ did: string; deviceJkt: string }> {
  let parsed: unknown
  try { parsed = JSON.parse(Buffer.from(capability, 'base64url').toString('utf8')) } catch { throw new Error('mail capability is malformed') }
  const response = await fetch(`${options.authorityUrl.replace(/\/$/, '')}/v1/internal/mail/authorize`, {
    method: 'POST', headers: { 'content-type': 'application/json', 'x-did-md-mail-relay-secret': options.authoritySecret },
    body: JSON.stringify({ capability: parsed, relayOrigin: options.relayOrigin, operation: 'submit', address }),
  })
  if (!response.ok) throw new Error('mail capability is not authorized')
  const value: unknown = await response.json()
  if (value === null || typeof value !== 'object' || Array.isArray(value) || typeof (value as Record<string, unknown>).did !== 'string' || typeof (value as Record<string, unknown>).deviceJkt !== 'string') throw new Error('did.md returned an invalid mail authorization')
  return value as { did: string; deviceJkt: string }
}

async function verifyDpop(value: string, request: Request, expectedUrl: string): Promise<string> {
  const parts = value.split('.')
  if (parts.length !== 3) throw new Error('DPoP proof is malformed')
  let header: Record<string, unknown>; let payload: Record<string, unknown>; let signature: Uint8Array
  try {
    header = JSON.parse(Buffer.from(parts[0]!, 'base64url').toString('utf8'))
    payload = JSON.parse(Buffer.from(parts[1]!, 'base64url').toString('utf8'))
    signature = new Uint8Array(Buffer.from(parts[2]!, 'base64url'))
  } catch { throw new Error('DPoP proof is malformed') }
  const jwk = header.jwk as P256Jwk | undefined
  if (header.typ !== 'dpop+jwt' || header.alg !== 'ES256' || !jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256' || typeof jwk.x !== 'string' || typeof jwk.y !== 'string'
    || payload.htm !== request.method || payload.htu !== expectedUrl || typeof payload.jti !== 'string' || !/^[A-Za-z0-9_-]{20,128}$/.test(payload.jti) || !Number.isSafeInteger(payload.iat)
    || Math.abs(Date.now() - Number(payload.iat) * 1000) > REPLAY_MS || signature.length !== 64) throw new Error('DPoP proof does not bind this request')
  const canonical = JSON.stringify({ crv: 'P-256', kty: 'EC', x: jwk.x, y: jwk.y })
  const thumbprint = Buffer.from(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical))).toString('base64url')
  for (const [key, until] of replay) if (until <= Date.now()) replay.delete(key)
  const replayId = `${thumbprint}:${payload.jti}`
  if (replay.has(replayId)) throw new Error('DPoP proof was replayed')
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'])
  if (!await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, signature as any, new TextEncoder().encode(`${parts[0]}.${parts[1]}`))) throw new Error('DPoP signature is invalid')
  replay.set(replayId, Date.now() + REPLAY_MS)
  return thumbprint
}

function collapse(results: MailDeliveryResult[]): MailSubmissionResultV1 {
  const occurredAt = new Date().toISOString()
  const failed = results.filter(result => result.outcome === 'error' || result.rejected.length > 0)
  if (!failed.length) return { status: 'accepted', occurredAt }
  return { status: 'temporary-failure', occurredAt, detail: failed.map(result => result.error ?? `${result.domain}: ${result.rejected.map(rejected => rejected.address).join(', ')}`).join('; ').slice(0, 2048) }
}
async function requestText(request: Request): Promise<string> {
  const length = request.headers.get('content-length')
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > MAX_BODY_BYTES)) throw new RangeError('mail submission HTTP body is too large')
  const value = new Uint8Array(await request.arrayBuffer())
  if (value.length > MAX_BODY_BYTES) throw new RangeError('mail submission HTTP body is too large')
  return new TextDecoder().decode(value)
}
function cors(origin: string): Record<string, string> { return { 'access-control-allow-origin': origin, 'access-control-allow-methods': 'POST, OPTIONS', 'access-control-allow-headers': 'Content-Type, DPoP, X-Biset-Mail-Capability, X-Biset-Mail-Message-Id', vary: 'Origin' } }
function json(status: number, body: string, origin: string | null): Response { return new Response(body, { status, headers: { 'content-type': 'application/json', ...(origin ? cors(origin) : {}) } }) }
function text(status: number, body: string, origin: string | null): Response { return new Response(`${body}\n`, { status, headers: { 'content-type': 'text/plain; charset=utf-8', ...(origin ? cors(origin) : {}) } }) }
