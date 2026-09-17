// The wire shape a mediator+mail-plugin instance uses to hand an externally
// received SMTP message to its recipient over ordinary DIDComm delivery
// (2026-08-30 mail-mediator redesign: no spool, no relationship credential,
// no VC -- the plugin just resolves the recipient's did:webvh log by domain
// (identity/webvh/identifier.ts's `identityDomainForMailAddress`,
// didcomm/webvh-routing.ts's `fetchRoutingByDomain`) and Forward-delivers a
// message of this type, same as any other DIDComm sender would).
//
// On the client this arrives through the SAME mediator-polling loop as any
// other DIDComm message (main.ts's `onMessage`) -- recognized by `type`
// alone and routed to MailIngressProjector instead of DidCommIngressProjector,
// carrying the raw RFC 5322 bytes this core's own SMTP ingress already knows
// how to project (core/adapters/mail.ts's `MailIngressInput`).
import { base64urlToBytes, bytesToBase64url } from '../../../protocol/canonical.ts'

export const MAIL_BRIDGE_INBOUND = 'https://didcomm.org/mail-bridge/1.0/inbound'
export const MAIL_BRIDGE_SEND = 'https://didcomm.org/mail-bridge/1.0/send'
export const MAIL_BRIDGE_SEND_RESULT = 'https://didcomm.org/mail-bridge/1.0/send-result'
export const MAIL_RFC5322_ATTACHMENT_ID = 'rfc5322'

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
  smtpEnvelope: string
}

export interface MailBridgeSendBody {
  mailFrom: string
  rcptTo: string[]
}

export function mailBridgeInboundBodyToWire(body: MailBridgeInboundBody): MailBridgeInboundWireBody {
  if (body.rawRfc5322.length === 0) throw new TypeError('mail bridge inbound body: rawRfc5322 must not be empty')
  if (!body.smtpEnvelope) throw new TypeError('mail bridge inbound body: smtpEnvelope is required')
  return { smtpEnvelope: body.smtpEnvelope }
}

export function mailBridgeRfc5322Attachment(rawRfc5322: Uint8Array) {
  if (rawRfc5322.length === 0) throw new TypeError('mail bridge RFC5322 attachment must not be empty')
  return { id: MAIL_RFC5322_ATTACHMENT_ID, media_type: 'message/rfc822', data: { base64: bytesToBase64url(rawRfc5322) } }
}

function rfc5322AttachmentOf(msg: { attachments?: Array<{ id: string; media_type?: string; data?: { base64?: unknown } }> }): Uint8Array | null {
  const attachment = msg.attachments?.find(value => value.id === MAIL_RFC5322_ATTACHMENT_ID && value.media_type === 'message/rfc822')
  if (!attachment || typeof attachment.data?.base64 !== 'string') return null
  try {
    const bytes = base64urlToBytes(attachment.data.base64)
    return bytes.length ? bytes : null
  } catch { return null }
}

export function mailBridgeInboundBodyOf(msg: { body?: unknown; attachments?: Array<{ id: string; media_type?: string; data?: { base64?: unknown } }> }): MailBridgeInboundBody | null {
  const body = msg.body
  if (body === null || typeof body !== 'object' || Array.isArray(body)) return null
  const smtpEnvelope = (body as Record<string, unknown>).smtpEnvelope
  const rawRfc5322 = rfc5322AttachmentOf(msg)
  if (!rawRfc5322 || typeof smtpEnvelope !== 'string' || !smtpEnvelope) return null
  return { rawRfc5322, smtpEnvelope }
}

export function mailBridgeSendBodyOf(msg: { body?: unknown; attachments?: Array<{ id: string; media_type?: string; data?: { base64?: unknown } }> }): (MailBridgeSendBody & { rawRfc5322: Uint8Array }) | null {
  const body = msg.body
  if (body === null || typeof body !== 'object' || Array.isArray(body)) return null
  const mailFrom = (body as Record<string, unknown>).mailFrom
  const rcptTo = (body as Record<string, unknown>).rcptTo
  const rawRfc5322 = rfc5322AttachmentOf(msg)
  if (typeof mailFrom !== 'string' || !Array.isArray(rcptTo) || rcptTo.some(value => typeof value !== 'string') || !rawRfc5322) return null
  return { mailFrom, rcptTo: [...rcptTo] as string[], rawRfc5322 }
}
