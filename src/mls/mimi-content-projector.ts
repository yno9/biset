// Translates a decrypted MimiContent (mimi-content.ts) into the Vault
// mutations PLAN-mimi.md §4 defines: message.add for an ordinary message or
// reply, message.edit/message.tombstone for `replaces` with a body/NullPart,
// and reaction.set for a disposition=reaction SinglePart/NullPart.
//
// Scope boundary: this module starts AFTER MLS decryption -- it has no
// opinion on how the caller obtained a MimiContent from an MLS
// PrivateMessage (that's `biset-mls-ds`'s message-notify handling, not yet
// implemented -- ARC-MLS.md §11's "Conversation Group is basis-only").
// Everything here is the same "opaque bytes in, Vault mutation out" shape
// as didcomm/ingress-projector.ts's Basic Message 2.0 branch, just for the
// Conversation Group content model instead of 1:1 DIDComm chat.
import { bytesToBase64url } from '../protocol/canonical.ts'
import type { DeviceId, IdentityId, VaultEventId } from '../protocol/ids.ts'
import type { VaultEventV1, VaultObjectV1 } from '../protocol/vault.ts'
import type { LocalJmapEmail } from '../local-jmap/gateway.ts'
import type { ActiveVaultSegment } from '../vault/active-segment.ts'
import { buildMailMessageAdd, buildMailMessageEdit, type MailMessageBuildContext } from '../vault/mail-message.ts'
import { buildVaultMutation } from '../vault/mutations.ts'
import type { VaultEventSigner } from '../vault/events.ts'
import type { VaultEventRecord, VaultObjectRecord } from '../vault/store.ts'
import { DISPOSITION_REACTION, type MessageId, type MimiContent } from './mimi-content.ts'

/** MimiContent's 32-byte content-addressed MessageId, carried as-is into
 * Vault email ids (base64url) -- deliberately NOT re-hashed with biset's
 * own canonicalHash, so a future HTTPS/MIMI-federated peer computing the
 * same MessageId from the same wire bytes lands on the same id
 * (PLAN-mimi.md §4.1: this is itself a small piece of interop). */
export function messageIdToEmailId(id: MessageId): string {
  return bytesToBase64url(id)
}

/** A Conversation Group's `threadId`/reply-recipient address -- the same
 * `mls:<groupId>` convention src.bak used for both its `group_id` field and
 * its "to" recipient shape, adopted here too so `sendReply`'s dispatch, the
 * thread header's "is this a group" check, and this projector's own
 * `threadId` are all driven by one `startsWith('mls:')` test instead of a
 * separate translation table between a raw-hex groupId and an addressable
 * recipient string. */
export function mlsGroupAddress(groupId: string): string {
  return `mls:${groupId}`
}

/** Inverse of `mlsGroupAddress`. Throws on anything not shaped like one --
 * every call site already gated entry on `startsWith('mls:')` first. */
export function parseMlsGroupAddress(address: string): string {
  if (!address.startsWith('mls:')) throw new MimiContentProjectionError(`not a Conversation Group address: ${address}`)
  return address.slice('mls:'.length)
}

export class MimiContentProjectionError extends TypeError {}

export type MimiConversationOperation =
  | { kind: 'add' }
  | { kind: 'edit'; targetId: string }
  | { kind: 'delete'; targetId: string }
  | { kind: 'reaction'; targetId: string; emoji: string | null }

/** PLAN-mimi.md §2's operation table, read off `replaces`/`inReplyTo`/
 * `disposition`/part cardinality rather than any separate "operation type"
 * field -- MimiContent doesn't have one; the operation IS this shape. */
export function classifyMimiContent(content: MimiContent): MimiConversationOperation {
  const isReaction = content.nestedPart.disposition === DISPOSITION_REACTION
  if (content.replaces !== null) {
    const targetId = messageIdToEmailId(content.replaces)
    if (isReaction) {
      if (content.nestedPart.part.kind !== 'null') throw new MimiContentProjectionError('a reaction retraction (replaces + disposition=reaction) must have a NullPart body')
      return { kind: 'reaction', targetId, emoji: null }
    }
    if (content.nestedPart.part.kind === 'null') return { kind: 'delete', targetId }
    return { kind: 'edit', targetId }
  }
  if (isReaction) {
    if (content.inReplyTo === null) throw new MimiContentProjectionError('a reaction (disposition=reaction, no replaces) must set inReplyTo to its target')
    if (content.nestedPart.part.kind !== 'single') throw new MimiContentProjectionError('a new reaction must have a SinglePart body (the emoji)')
    return { kind: 'reaction', targetId: messageIdToEmailId(content.inReplyTo), emoji: new TextDecoder().decode(content.nestedPart.part.content) }
  }
  return { kind: 'add' }
}

export interface MimiConversationMessageInput {
  content: MimiContent
  messageId: MessageId
  groupId: string
  senderDid: string
  /** Other current group members (PLAN-mimi.md §5's roster-as-recipients,
   * not machine-reconstructed from prior messages -- the caller derives
   * this from the MLS group's accepted roster, chatmail spec's own
   * "MUST NOT construct the member list on other group messages" applied
   * one layer up, at the DS/group-control level PLAN-mimi.md §4 leaves to
   * the group-control-notify path rather than this one). */
  otherMembers: string[]
  receivedAt: string
}

export interface MimiConversationMessageContext {
  identityId: IdentityId
  actorDeviceId: DeviceId
  actorSeq: number
  parents: VaultEventId[]
  segmentId: string
  segmentKey: Uint8Array
  createdAt: string
}

export interface MimiConversationMessageRecord {
  objects: VaultObjectRecord[]
  events: VaultEventRecord[]
}

/** The single entry point: decode a MimiContent, classify it, and build
 * whichever Vault mutation(s) it calls for. Mirrors
 * didcomm/ingress-projector.ts's per-type dispatch, one call per received
 * application message rather than one class instance per connection --
 * this module doesn't own decrypt/dedupe/segment state, the caller
 * (biset-mls-ds's future ingress path) does. */
export async function projectMimiConversationMessage(
  input: MimiConversationMessageInput,
  context: MimiConversationMessageContext,
  signer: VaultEventSigner,
): Promise<MimiConversationMessageRecord> {
  const operation = classifyMimiContent(input.content)
  const buildContext: MailMessageBuildContext = context
  if (operation.kind === 'add') {
    const emailId = messageIdToEmailId(input.messageId)
    const part = input.content.nestedPart.part
    if (part.kind !== 'single') throw new MimiContentProjectionError('an ordinary message must have a SinglePart body')
    const email: Omit<LocalJmapEmail, 'blobId'> = {
      id: emailId,
      threadId: mlsGroupAddress(input.groupId),
      mailboxIds: { inbox: true },
      keywords: {},
      receivedAt: input.receivedAt,
      from: [{ email: input.senderDid }],
      to: input.otherMembers.map(member => ({ email: member })),
      ...(input.content.inReplyTo !== null ? { inReplyTo: messageIdToEmailId(input.content.inReplyTo) } : {}),
    }
    const record = await buildMailMessageAdd({ email, rawRfc5322: part.content }, buildContext, signer)
    return {
      objects: [scopedObject(record.metadataObject, context.identityId), scopedObject(record.rawRfc5322Object, context.identityId)],
      events: [scopedEvent(record.event, context.identityId)],
    }
  }
  if (operation.kind === 'edit') {
    const part = input.content.nestedPart.part
    if (part.kind !== 'single') throw new MimiContentProjectionError('an edit must have a SinglePart body')
    const record = await buildMailMessageEdit({ emailId: operation.targetId, rawRfc5322: part.content }, buildContext, signer)
    return {
      objects: [scopedObject(record.metadataObject, context.identityId), scopedObject(record.rawRfc5322Object, context.identityId)],
      events: [scopedEvent(record.event, context.identityId)],
    }
  }
  if (operation.kind === 'delete') {
    const record = await buildVaultMutation({
      kind: 'message.tombstone',
      targetIds: [operation.targetId],
      payload: { emailId: operation.targetId },
    }, buildContext, signer)
    return { objects: [scopedObject(record.object, context.identityId)], events: [scopedEvent(record.event, context.identityId)] }
  }
  // operation.kind === 'reaction'
  const record = await buildVaultMutation({
    kind: 'reaction.set',
    targetIds: [operation.targetId],
    payload: { emailId: operation.targetId, sender: input.senderDid, emoji: operation.emoji },
  }, buildContext, signer)
  return { objects: [scopedObject(record.object, context.identityId)], events: [scopedEvent(record.event, context.identityId)] }
}

function scopedObject(object: VaultObjectV1, identityId: IdentityId): VaultObjectRecord { return { ...object, identityId } }
function scopedEvent(event: VaultEventV1, identityId: IdentityId): VaultEventRecord { return { ...event, identityId } }
