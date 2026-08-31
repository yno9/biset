// Conversation Group bootstrap: three peer-to-peer (1:1, existing
// relationship or front-door DIDComm) messages that get someone from "you
// are invited" to "you are a member", entirely without the DS ever seeing
// any of it -- PLAN_biset-mls-ds.md §11-2's own open item ("bootstrap/招待
// 経路の具体プロトコル"), resolved as part of the identity-blind DS revision
// (conversation-mls-ds.ts's header). None of this invents a new transport:
// every message here rides biset's existing 1:1 DIDComm chat/relationship
// infrastructure (authcrypt, same as basicmessage.ts's BASIC_MESSAGE), the
// same channel this front door sends everything else over.
//
// The flow (see mls/conversation-group.ts for the DS-facing half of each step):
//
//   1. inviter --CONVERSATION_GROUP_INVITE--> invitee
//      "join this group, its DS is here"
//   2. invitee generates its own group-local keypair + MLS KeyPackage,
//      publishes the KeyPackage to the DS under that group-local id
//      (transport.publishKeyPackages), then:
//      invitee --CONVERSATION_GROUP_JOIN_READY--> inviter
//      "take my KeyPackage under this group-local id"
//   3. inviter takes it (transport.takeKeyPackage), calls
//      addMembersToConversationGroup, and on success:
//      inviter --CONVERSATION_GROUP_WELCOME_READY--> invitee
//      "you're in, pull now"
//   4. invitee calls conversation-group-sync.ts, which pulls the Welcome
//      entry and joins.
//
// Since there is no external-join path any more (an existing member must
// always Add you), `groupId` alone is no longer sufficient to become a
// member -- only to know which group a peer-to-peer exchange is about.
// Confidentiality of the whole flow comes from WHO these messages are sent
// to and over WHICH already end-to-end encrypted channel, not from any
// property of `groupId` being unguessable (it is, at 32 random bytes -- but
// that's defense in depth, not the design's actual security boundary).
import { sendFrontDoorMessage, type DidCommSendResult, type SendDidCommMessageOptions } from '../didcomm/front-door-send.ts'
import type { GroupLocalId } from '../protocol/conversation-mls-ds.ts'

export const CONVERSATION_GROUP_INVITE = 'https://biset.md/mls-ds/1.0/group-invite'
export const CONVERSATION_GROUP_JOIN_READY = 'https://biset.md/mls-ds/1.0/group-join-ready'
export const CONVERSATION_GROUP_WELCOME_READY = 'https://biset.md/mls-ds/1.0/group-welcome-ready'

export function isConversationGroupInvite(msg: { type?: string }): boolean { return msg.type === CONVERSATION_GROUP_INVITE }
export function isConversationGroupJoinReady(msg: { type?: string }): boolean { return msg.type === CONVERSATION_GROUP_JOIN_READY }
export function isConversationGroupWelcomeReady(msg: { type?: string }): boolean { return msg.type === CONVERSATION_GROUP_WELCOME_READY }

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

export interface ConversationGroupJoinReadyBody {
  groupId: string
  /** The invitee's freshly-generated group-local id for this group --
   * whichever KeyPackage the inviter takes under this id becomes the
   * invitee's MLS leaf. */
  groupLocalId: GroupLocalId
}

export function conversationGroupJoinReadyBodyOf(msg: { body?: unknown }): ConversationGroupJoinReadyBody | null {
  const body = msg.body
  if (typeof body !== 'object' || body === null) return null
  const record = body as Record<string, unknown>
  if (typeof record.groupId !== 'string' || typeof record.groupLocalId !== 'string') return null
  return { groupId: record.groupId, groupLocalId: record.groupLocalId }
}

export async function sendConversationGroupJoinReady(toDid: string, body: ConversationGroupJoinReadyBody, opts: SendDidCommMessageOptions): Promise<DidCommSendResult> {
  return sendFrontDoorMessage(toDid, CONVERSATION_GROUP_JOIN_READY, body, opts)
}

export interface ConversationGroupWelcomeReadyBody { groupId: string }

export function conversationGroupWelcomeReadyBodyOf(msg: { body?: unknown }): ConversationGroupWelcomeReadyBody | null {
  const body = msg.body
  if (typeof body !== 'object' || body === null) return null
  const record = body as Record<string, unknown>
  if (typeof record.groupId !== 'string') return null
  return { groupId: record.groupId }
}

export async function sendConversationGroupWelcomeReady(toDid: string, body: ConversationGroupWelcomeReadyBody, opts: SendDidCommMessageOptions): Promise<DidCommSendResult> {
  return sendFrontDoorMessage(toDid, CONVERSATION_GROUP_WELCOME_READY, body, opts)
}
