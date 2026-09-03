// POST /v1/mail/submit -- authenticated outbound mail submission. The
// counterpart to bridge.ts/listener.ts's inbound direction: a device signs
// a MailSubmissionRequestV1 (identity/bootstrap.ts's buildMailSubmitter)
// with its identity's CURRENT did:webvh update key (the same key a
// routing.json/did.jsonl update itself must sign with -- NOT an MLS device
// credential, since that concept lived entirely inside the now-retired
// biset-core's own trusted-device roster and this plugin has no roster at
// all, matching PLAN_biset-mail-mediator.md's own already-stated principle:
// "Identity/Vault device projectionをMail認証に使わない"). Verification here
// is two checks, both required before deliverMail() ever dials an external
// MX -- an unauthenticated or spoofed submission is exactly what turns an
// outbound relay into an open one:
//   1. `mailFrom` actually IS `identityId`'s own address (mailFromForIdentity)
//      -- otherwise a validly-signed request for identity A could claim to
//      send AS identity B.
//   2. `signature` verifies against `identityId`'s CURRENT did:webvh update
//      keys (resolveCurrentUpdateKeys) -- a public, self-certifying fact
//      anyone can check, no separate credential registration needed.
import { deliverMail, type MailDeliveryResult } from './smtp-client.ts'
import { decodeMailSubmissionRequestWire, encodeMailSubmissionResultWire } from '../../protocol/mail-submission-wire.ts'
import { mailSubmissionSigningBytes } from '../../protocol/signing.ts'
import { mailFromForIdentity } from '../../identity/webvh/identifier.ts'
import { resolveCurrentUpdateKeys } from '../../identity/webvh/resolver.ts'
import { decodeMultikey } from '../../identity/webvh/multikey.ts'
import { ed25519 } from '@noble/curves/ed25519.js'
import type { MailSubmissionRequestV1, MailSubmissionResultV1 } from '../../protocol/mail-submission.ts'

const MAX_BODY_BYTES = 25 * 1024 * 1024
const WELL_KNOWN_PATH = '/v1/mail/submit'

export interface MailSubmissionHttpOptions {
  /** Announced in outbound EHLO. */
  hostname: string
  apexDomain: string
  /** DI for tests -- defaults to the real did:webvh resolver. */
  resolveUpdateKeys?: (identityId: string) => Promise<string[]>
  /** DI for tests -- defaults to the real outbound SMTP client. */
  deliverMailFn?: typeof deliverMail
}

export function createMailSubmissionHttpHandler(opts: MailSubmissionHttpOptions): (request: Request) => Promise<Response> {
  const resolveUpdateKeys = opts.resolveUpdateKeys ?? resolveCurrentUpdateKeys
  const deliverMailFn = opts.deliverMailFn ?? deliverMail
  return async function handleMailSubmission(request: Request): Promise<Response> {
    if (new URL(request.url).pathname !== WELL_KNOWN_PATH) return text(404, 'Not found')
    if (request.method !== 'POST') return text(405, 'Method not allowed')
    try {
      const parsed = decodeMailSubmissionRequestWire(await requestText(request))
      if (!(await isAuthorised(parsed, opts.apexDomain, resolveUpdateKeys))) return text(403, 'mail submission is not authorised')
      const results = await deliverMailFn(
        { hostname: opts.hostname },
        { mailFrom: parsed.mailFrom, rcptTo: parsed.rcptTo, rawRfc5322: parsed.rawRfc5322 },
      )
      return json(200, encodeMailSubmissionResultWire(collapseResults(results)))
    } catch (error) {
      if (error instanceof TypeError || error instanceof RangeError) return text(400, error.message)
      return text(500, 'Internal server error')
    }
  }
}

async function isAuthorised(
  request: MailSubmissionRequestV1,
  apexDomain: string,
  resolveUpdateKeys: (identityId: string) => Promise<string[]>,
): Promise<boolean> {
  let expectedMailFrom: string
  try {
    expectedMailFrom = mailFromForIdentity(request.identityId, apexDomain)
  } catch {
    return false
  }
  if (request.mailFrom !== expectedMailFrom) return false
  const updateKeys = await resolveUpdateKeys(request.identityId)
  if (updateKeys.length === 0) return false
  const signingBytes = mailSubmissionSigningBytes(request)
  return updateKeys.some(key => {
    try {
      return ed25519.verify(request.signature, signingBytes, decodeMultikey(key))
    } catch {
      return false
    }
  })
}

/** Collapsed from the outbound SMTP client's per-domain-group results.
 * `accepted` only when every domain group fully succeeded; anything else is
 * `temporary-failure` with `detail` summarizing what happened. */
function collapseResults(results: MailDeliveryResult[]): MailSubmissionResultV1 {
  const occurredAt = new Date().toISOString()
  const failures = results.filter(result => result.outcome === 'error' || result.rejected.length > 0)
  if (failures.length === 0) return { status: 'accepted', occurredAt }
  const detail = failures.map(result => result.error ?? `${result.domain}: ${result.rejected.map(r => `${r.address} (${r.reply})`).join(', ')}`).join('; ')
  return { status: 'temporary-failure', occurredAt, detail: detail.slice(0, 2048) }
}

async function requestText(request: Request): Promise<string> {
  const length = request.headers.get('content-length')
  if (length !== null && (!/^[0-9]+$/.test(length) || Number(length) > MAX_BODY_BYTES)) throw new RangeError('mail submission HTTP body is too large')
  const bytes = new Uint8Array(await request.arrayBuffer())
  if (bytes.length > MAX_BODY_BYTES) throw new RangeError('mail submission HTTP body is too large')
  return new TextDecoder().decode(bytes)
}

function json(status: number, body: string): Response {
  return new Response(body, { status, headers: { 'content-type': 'application/json' } })
}
function text(status: number, body: string): Response {
  return new Response(body + '\n', { status, headers: { 'content-type': 'text/plain; charset=utf-8' } })
}
