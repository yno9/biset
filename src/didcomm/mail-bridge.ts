// The wire shape a mediator+mail-plugin instance uses to hand an externally
// received SMTP message to its recipient over ordinary DIDComm delivery
// (2026-08-30 mail-mediator redesign: no spool, no relationship credential,
// no VC -- the plugin just resolves the recipient's routing.json by domain
// (identity/webvh/identifier.ts's `identityDomainForMailAddress`,
// didcomm/webvh-routing.ts's `fetchRoutingByDomain`) and Forward-delivers a
// message of this type, same as any other DIDComm sender would).
//
// On the client this arrives through the SAME mediator-polling loop as any
// other DIDComm message (main.ts's `onMessage`) -- recognized by `type`
// alone and routed to MailIngressProjector instead of DidCommIngressProjector,
// carrying the raw RFC 5322 bytes this core's own SMTP ingress already knows
// how to project (core/adapters/mail.ts's `MailIngressInput`).
import { base64urlToBytes, bytesToBase64url } from '../shared/protocol/canonical.ts'

export const MAIL_BRIDGE_INBOUND = 'https://biset.md/mail-bridge/1.0/inbound'

export interface MailBridgeInboundBody {
  /** The exact bytes the plugin's SMTP listener accepted for `DATA` --
   * opaque RFC 5322/MIME, same treatment as core/adapters/mail.ts's own
   * header ("OpenPGP, Autocrypt, DeltaChat headers, and MIME interpretation
   * happen only on an endpoint after a signed ingress pull"). */
  rawRfc5322: Uint8Array
  /** The SMTP envelope (MAIL FROM / RCPT TO) this arrived under -- kept
   * alongside the message body rather than folded into it, same shape
   * MailIngressAdapter already expects. */
  smtpEnvelope: string
}

export interface MailBridgeInboundWireBody {
  rawRfc5322: string
  smtpEnvelope: string
}

export function mailBridgeInboundBodyToWire(body: MailBridgeInboundBody): MailBridgeInboundWireBody {
  if (body.rawRfc5322.length === 0) throw new TypeError('mail bridge inbound body: rawRfc5322 must not be empty')
  if (!body.smtpEnvelope) throw new TypeError('mail bridge inbound body: smtpEnvelope is required')
  return { rawRfc5322: bytesToBase64url(body.rawRfc5322), smtpEnvelope: body.smtpEnvelope }
}

export function mailBridgeInboundBodyOf(msg: { body?: unknown }): MailBridgeInboundBody | null {
  const body = msg.body
  if (body === null || typeof body !== 'object' || Array.isArray(body)) return null
  const rawRfc5322 = (body as Record<string, unknown>).rawRfc5322
  const smtpEnvelope = (body as Record<string, unknown>).smtpEnvelope
  if (typeof rawRfc5322 !== 'string' || typeof smtpEnvelope !== 'string' || !smtpEnvelope) return null
  try {
    const bytes = base64urlToBytes(rawRfc5322)
    if (bytes.length === 0) return null
    return { rawRfc5322: bytes, smtpEnvelope }
  } catch {
    return null
  }
}
