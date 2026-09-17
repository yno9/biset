import { resolveDidWeb } from '../../protocol/didcomm/did-web.ts'
import { sendFrontDoorMessage } from '../didcomm/front-door-send.ts'
import { MAIL_BRIDGE_SEND, mailBridgeRfc5322Attachment } from '../../server/mediator/mail-plugin/mail-bridge.ts'

const APEX_DID = 'did:web:did.md'

/** Discover the apex's MailBridge service, then submit a durable outbox item
 * as authcrypt to the bridge's own public DID. */
export async function submitDidCommMail(input: {
  fromKid: string; x25519PrivateKey: Uint8Array; messageId: string; mailFrom: string; rcptTo: string[]; rawRfc5322: Uint8Array
}): Promise<void> {
  const apex = await resolveDidWeb(APEX_DID)
  if (!apex) throw new Error('did.md MailBridge discovery DID does not resolve')
  const service = apex.service?.find(value => value.type === 'MailBridge')
  const endpoint = service?.serviceEndpoint
  if (endpoint === null || typeof endpoint !== 'object' || Array.isArray(endpoint) || typeof (endpoint as { uri?: unknown }).uri !== 'string') throw new Error('did.md MailBridge service is invalid')
  const host = new URL((endpoint as { uri: string }).uri).hostname
  const bridgeDid = `did:web:${host}`
  const sent = await sendFrontDoorMessage(bridgeDid, MAIL_BRIDGE_SEND, { mailFrom: input.mailFrom, rcptTo: input.rcptTo }, {
    fromKid: input.fromKid, x25519PrivateKey: input.x25519PrivateKey, id: input.messageId, thid: input.messageId,
    attachments: [mailBridgeRfc5322Attachment(input.rawRfc5322)],
  })
  if (!sent.ok) throw new Error(sent.error)
}
