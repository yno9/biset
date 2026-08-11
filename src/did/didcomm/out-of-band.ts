// Out-of-Band Messages 2.0 (out_of_band.md): an `invitation` plaintext passed
// UNENCRYPTED via a URL (or QR code) — `https://<domain>/<path>?_oob=<b64url
// plaintext>` — so two parties with no prior channel can bootstrap one. The
// invitation carries the sender's DID and an optional goal/goal_code plus
// attached protocol messages the receiver can act on.
//
// Privacy (out_of_band.md): nothing private goes in an OOB message — it is in
// the clear. The invitation `id` becomes the `pthid` of whatever response the
// receiver sends, so one invitation can seed several independent threads.
import { buildPlaintext, type DidCommPlaintext } from './message.ts'
import { b64url, b64urlToBytes } from './crypto.ts'

export const INVITATION = 'https://didcomm.org/out-of-band/2.0/invitation'

export interface OobAttachment {
  id: string
  media_type?: string
  data: { json?: unknown; base64?: string }
}

export interface InvitationBody {
  goal_code?: string
  goal?: string
  accept?: string[]
}

export function isInvitation(msg: { type?: string }): boolean { return msg.type === INVITATION }

/** Builds an out-of-band `invitation`. `from` is REQUIRED (the DID the receiver
 * will use for future interactions); there is no `to`. */
export function buildInvitation(from: string, body: InvitationBody = {}, attachments?: OobAttachment[]): DidCommPlaintext {
  const msg = buildPlaintext(INVITATION, body, from)
  // OOB attachments carry media_type/base64 that the routing-shaped
  // DidCommPlaintext.attachments doesn't model — assign through unknown rather
  // than widen the core envelope type for this one protocol's richer shape.
  if (attachments && attachments.length) (msg as unknown as { attachments: OobAttachment[] }).attachments = attachments
  return msg
}

/** The plaintext, whitespace-free, base64url-encoded — the `_oob` value. */
export function encodeInvitation(invitation: DidCommPlaintext): string {
  return b64url(new TextEncoder().encode(JSON.stringify(invitation)))
}

/** A full invitation URL: `<baseUrl>?_oob=<encoded>`. Preserves any existing
 * query on baseUrl. */
export function encodeInvitationURL(baseUrl: string, invitation: DidCommPlaintext): string {
  const sep = baseUrl.includes('?') ? '&' : '?'
  return `${baseUrl}${sep}_oob=${encodeInvitation(invitation)}`
}

/** Decodes a bare `_oob` value back to the invitation plaintext. */
export function decodeInvitation(oob: string): DidCommPlaintext {
  const msg = JSON.parse(new TextDecoder().decode(b64urlToBytes(oob))) as DidCommPlaintext
  if (!isInvitation(msg)) throw new Error(`decodeInvitation: not an out-of-band invitation (type ${msg.type})`)
  return msg
}

/** Extracts and decodes the invitation from a full `?_oob=` URL. Rejects the
 * short `_oobid` form, which requires a separate HTTP GET to resolve (out of
 * scope here) rather than carrying the message inline. */
export function decodeInvitationURL(url: string): DidCommPlaintext {
  const q = url.indexOf('?')
  const params = new URLSearchParams(q === -1 ? '' : url.slice(q + 1))
  const oob = params.get('_oob')
  if (!oob) {
    if (params.get('_oobid')) throw new Error('decodeInvitationURL: short `_oobid` form must be fetched over HTTP first')
    throw new Error('decodeInvitationURL: no _oob parameter in URL')
  }
  return decodeInvitation(oob)
}

/** The `pthid` a receiver MUST set on its response to correlate it with this
 * invitation (out_of_band.md "Message Correlation"). */
export function responsePthidFor(invitation: DidCommPlaintext): string {
  return invitation.id
}
