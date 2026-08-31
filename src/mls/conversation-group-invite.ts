// Conversation Group invitation: a peer-to-peer (1:1, existing relationship
// or front-door DIDComm) message telling someone "join this group" --
// PLAN_biset-mls-ds.md §11-2's own open item ("bootstrap/招待経路の具体プロト
// コル"), resolved here as narrowly as the rest of this DS's own bootstrap
// story already is: `groupId` alone IS the invitation (mls-ds/store.ts's
// own groupInfoFor note) -- what carries it needs no new cryptography of
// its own, only a channel that is ALREADY end-to-end encrypted and
// authenticated, which biset's existing 1:1 DIDComm chat/relationship
// infrastructure already is (authcrypt, same as every other message this
// front door sends). This message type rides that channel exactly like
// basicmessage.ts's BASIC_MESSAGE does; it invents no new transport.
//
// Confidentiality of the invite therefore comes from WHO gets sent this
// message and over WHICH already-secure channel, not from any property of
// `groupId` itself being unguessable (it is, at 32 random bytes -- but
// that is defense in depth, not the design's actual security boundary).
import { sendFrontDoorMessage, type DidCommSendResult, type SendDidCommMessageOptions } from '../didcomm/front-door-send.ts'

export const CONVERSATION_GROUP_INVITE = 'https://biset.md/mls-ds/1.0/group-invite'

export function isConversationGroupInvite(msg: { type?: string }): boolean { return msg.type === CONVERSATION_GROUP_INVITE }

export interface ConversationGroupInviteBody {
  groupId: string
  /** The DID whose DID document publishes the `MimiDeliveryService` entry
   * (didcomm/webvh-routing.ts's `buildRoutingDoc` `mimiProvider` input)
   * serving this group. The invitee resolves it fresh at join time via
   * `resolveMimiProviderUrl` (didcomm/webvh-resolve.ts) rather than this
   * message carrying a URL directly -- a DS migration then needs no
   * re-invite, only a DID document update the invitee's own resolve
   * already picks up. */
  ds: string
  /** Display-only; the DS itself has no group-name concept (mls-ds-1.0.md
   * carries none, and store.ts's Group row has no name column). */
  groupName?: string
}

export function conversationGroupInviteBodyOf(msg: { body?: unknown }): ConversationGroupInviteBody | null {
  const body = msg.body
  if (typeof body !== 'object' || body === null) return null
  const record = body as Record<string, unknown>
  if (typeof record.groupId !== 'string' || typeof record.ds !== 'string') return null
  return { groupId: record.groupId, ds: record.ds, ...(typeof record.groupName === 'string' ? { groupName: record.groupName } : {}) }
}

export async function sendConversationGroupInvite(toDid: string, body: ConversationGroupInviteBody, opts: SendDidCommMessageOptions): Promise<DidCommSendResult> {
  return sendFrontDoorMessage(toDid, CONVERSATION_GROUP_INVITE, body, opts)
}
