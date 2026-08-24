// POST /v1/didcomm/ingress -- the DIDComm adapter's external ingress
// endpoint (PLAN.md §6.1). A plain HTTP POST of one packed JWE (didcomm/
// crypto.ts's DidCommJWE, JSON body) rather than a raw-socket protocol like
// mail's SMTP listener: DIDComm v2 is transport-agnostic and biset's own
// DIDCommMessaging service descriptor (didcomm/webvh-routing.ts) advertises
// this URL as an HTTPS endpoint.
//
// The JWE's recipient kid is read from its OWN unencrypted outer header
// (`recipients[].header.kid`) to resolve which identity this is for --
// never the decrypted plaintext, which only a trusted device sees after a
// signed ingress pull. Same opaque-payload boundary mail.ts's raw RFC 5322
// keeps.
import { parseJwe, protectedHeaderOf } from '../../didcomm/crypto.ts'
import { createDidCommRecipientResolver } from './didcomm-recipient-resolver.ts'
import type { DidCommIngressAdapter } from './didcomm.ts'
import type { TrustedDeviceRoster } from '../identity/device-roster.ts'

const CORS: Record<string, string> = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
}

const text = (body: string, status: number) =>
  new Response(body + '\n', { status, headers: { ...CORS, 'Content-Type': 'text/plain; charset=utf-8' } })

const MAX_BODY = 256 * 1024 // generous for a JWE with a device keyAgreement wrap + control-sized plaintext
// External ingress, OOB, bootstrap, and short control only (PLAN.md §6.1
// scope) -- perishable by nature, so a much shorter TTL than mail's 30-day
// default (vault-delivery-parity) is appropriate. A device that's offline
// for longer than this simply never had this control message reach it,
// which is the correct behavior for a bootstrap/OOB flow -- unlike mail,
// there's no "keep trying forever" expectation here.
const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000

export interface DidCommHttpOptions {
  roster: TrustedDeviceRoster
  ttlMs?: number
}

export function createDidCommHttpHandler(adapter: DidCommIngressAdapter, opts: DidCommHttpOptions): (request: Request) => Promise<Response> {
  const resolveRecipient = createDidCommRecipientResolver({ roster: opts.roster })
  const ttlMs = opts.ttlMs ?? DEFAULT_TTL_MS

  return async function handleDidComm(request: Request): Promise<Response> {
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS })
    if (request.method !== 'POST') return text('method not allowed', 405)

    const body = await request.text()
    if (body.length > MAX_BODY) return text('payload too large', 400)
    let parsed: unknown
    try {
      parsed = JSON.parse(body)
    } catch {
      return text('invalid JSON', 400)
    }
    const jwe = parseJwe(parsed)
    if (!jwe) return text('not a well-formed DIDComm JWE', 400)

    const kid = jwe.recipients[0]?.header.kid
    if (!kid) return text('JWE has no recipient kid', 400)
    const resolution = await resolveRecipient({ did: kid })
    if (!resolution) return text('unknown recipient', 404)

    const header = protectedHeaderOf(jwe)
    const now = new Date()
    const evidence: Record<string, unknown> = {
      alg: header?.alg,
      senderKid: header?.skid,
      receivedAt: now.toISOString(),
    }
    try {
      await adapter.accept({
        ingressId: `didcomm-${crypto.randomUUID()}`,
        recipientIdentityId: resolution.identityId,
        createdAt: now.toISOString(),
        expiresAt: new Date(now.getTime() + ttlMs).toISOString(),
        packedJwe: new TextEncoder().encode(body),
        sourceEvidence: new TextEncoder().encode(JSON.stringify(evidence)),
      })
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      if (/limit exceeded/.test(message)) return text(message, 429)
      return text(message, 400)
    }
    return new Response(null, { status: 202, headers: CORS })
  }
}
