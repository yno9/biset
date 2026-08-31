// Send-side counterpart to conversation-group-ingress.ts -- PLAN-mimi.md
// §7's "送信側: biset-client自身がgroupへ送るメッセージも、MimiContentとして
// CBORエンコードしてからmessage-submitする必要がある". Composes a MimiContent,
// computes its content-addressed MessageId (mimi-content.ts), and submits it
// as an MLS application message via conversation-group.ts's own
// sendConversationApplicationMessage -- this module owns none of the MLS or
// DS I/O itself, only the MimiContent shape.
//
// Deliberately does NOT also commit the sender's own Vault copy: that's
// `mimi-content-projector.ts`'s `projectMimiConversationMessage`, already a
// public, reusable function -- a caller builds its own-copy mutation by
// calling it directly with this function's `content`/`messageId` result,
// same as `conversation-group-ingress.ts` does on the receive side, rather
// than this module wrapping it a second time.
import type { ClientState } from './vendor/index.ts'
import { memberList } from './group.ts'
import { sendConversationApplicationMessage, type ConversationGroupSigner } from './conversation-group.ts'
import type { ConversationMlsDeliveryTransport } from '../mls-ds/client-transport.ts'
import { computeMimiMessageId, encodeMimiContent, mimiRoomUri, DISPOSITION_RENDER, type MessageId, type MimiContent } from './mimi-content.ts'
import { didOfKid } from '../protocol/ids.ts'

export interface SendConversationTextMessageInput {
  state: ClientState
  transport: ConversationMlsDeliveryTransport
  groupId: string
  deviceKid: string
  text: string
  /** Set for a reply -- PLAN-mimi.md §4.2. Omit for an ordinary message. */
  inReplyTo?: MessageId
  sign: ConversationGroupSigner
  now?: () => Date
}

export interface SendConversationMessageResult {
  /** The advanced ratchet state -- the caller persists this, same
   * contract as sendConversationApplicationMessage's own return. */
  state: ClientState
  content: MimiContent
  messageId: MessageId
  /** Every other current member, for building the sender's own Vault copy
   * via projectMimiConversationMessage's `otherMembers` input -- computed
   * from the PRE-send state since sending doesn't change the roster. */
  otherMembers: string[]
}

/** Sends an ordinary (or reply) text message -- PLAN-mimi.md §2's `render`
 * disposition, `text/plain` SinglePart. Edit/delete/reaction composition
 * (the same table's other rows) are not yet wrapped here; a caller can
 * still reach them by constructing a `MimiContent` directly and calling
 * `sendConversationApplicationMessage` itself, same as this function does
 * underneath. */
export async function sendConversationTextMessage(input: SendConversationTextMessageInput): Promise<SendConversationMessageResult> {
  const now = input.now ?? (() => new Date())
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const senderUri = input.deviceKid
  const roomUri = mimiRoomUri(input.groupId)
  const content: MimiContent = {
    salt,
    replaces: null,
    topicId: new Uint8Array(0),
    expires: null,
    inReplyTo: input.inReplyTo ?? null,
    extensions: { senderUri, roomUri },
    nestedPart: { disposition: DISPOSITION_RENDER, language: 'en', part: { kind: 'single', contentType: 'text/plain', content: new TextEncoder().encode(input.text) } },
  }
  const encoded = encodeMimiContent(content)
  const messageId = await computeMimiMessageId(senderUri, roomUri, encoded, salt)
  const senderDid = didOfKid(input.deviceKid)
  const otherMembers = memberList(input.state).map(m => m.did).filter(did => did !== senderDid)
  const state = await sendConversationApplicationMessage(input.state, input.transport, input.groupId, input.deviceKid, encoded, input.sign, now)
  return { state, content, messageId, otherMembers }
}
