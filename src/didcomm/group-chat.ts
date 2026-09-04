// DIDComm-native group chat: full-mesh pairwise fan-out over the SAME
// relationship infrastructure 1:1 chat already uses (relationship.ts's
// ContactKeyV1, did:peer:2) -- no shared cryptographic group state, no MLS.
// Every member holds a pairwise relationship with every OTHER member; a
// group message is just N individual pairwise-encrypted sends of the same
// content, tagged with a shared groupId so every recipient renders them as
// one thread. Distinct from both 1:1 chat (basicmessage.ts's
// didCommThreadId, a pure sorted-DID-pair hash -- no group concept) and the
// MLS-based Conversation Groups (mimi-content-projector.ts's `mls:`
// address scheme, now retired from active deployment).
//
// v1 scope, deliberately: group creation and ongoing messages only. No
// membership changes after creation, no cross-device roster sync (see
// group-chat-store.ts's own header), no name changes, no leave, no
// edit/delete/reaction -- matching 1:1 DIDComm chat's own current scope
// (ingress-projector.ts's header).
import { bytesToHex } from '../protocol/canonical.ts'
import type { DeviceId, IdentityId, VaultEventId } from '../protocol/ids.ts'
import type { LocalJmapEmail, LocalJmapProjectionV1, LocalJmapSnapshot } from '../local-jmap/gateway.ts'
import { assertActiveVaultSegment, type ActiveVaultSegment } from '../vault/active-segment.ts'
import { buildVaultCommit } from '../vault/commit.ts'
import { decryptVaultObject } from '../vault/objects.ts'
import type { VaultEventSigner } from '../vault/events.ts'
import type { VaultEventRecord, VaultObjectRecord } from '../vault/store.ts'
import { buildMailMessageAdd } from '../vault/mail-message.ts'

export const GROUP_INVITE = 'https://biset.md/didcomm-group/1.0/invite'
export const GROUP_MESSAGE = 'https://biset.md/didcomm-group/1.0/message'

export function isGroupInvite(msg: { type?: string }): boolean { return msg.type === GROUP_INVITE }
export function isGroupMessage(msg: { type?: string }): boolean { return msg.type === GROUP_MESSAGE }

export interface GroupInviteBody {
  groupId: string
  /** Full roster snapshot at invite time, INCLUDING the sender and the
   * recipient themselves -- every invitee sees the complete member list
   * without the receiving handler needing to inject anyone. */
  members: string[]
  name?: string
}

export function groupInviteBodyOf(msg: { body?: unknown }): GroupInviteBody | null {
  const body = msg.body
  if (body === null || typeof body !== 'object' || Array.isArray(body)) return null
  const groupId = (body as Record<string, unknown>).groupId
  const members = (body as Record<string, unknown>).members
  const name = (body as Record<string, unknown>).name
  if (typeof groupId !== 'string' || !groupId) return null
  if (!Array.isArray(members) || members.length === 0 || !members.every(m => typeof m === 'string' && m)) return null
  if (name !== undefined && typeof name !== 'string') return null
  return { groupId, members, ...(typeof name === 'string' ? { name } : {}) }
}

export interface GroupMessageBody {
  groupId: string
  content: string
  sentAt?: string
  subject?: string
}

export function groupMessageBodyOf(msg: { body?: unknown }): GroupMessageBody | null {
  const body = msg.body
  if (body === null || typeof body !== 'object' || Array.isArray(body)) return null
  const groupId = (body as Record<string, unknown>).groupId
  const content = (body as Record<string, unknown>).content
  const sentAt = (body as Record<string, unknown>).sentAt
  const subject = (body as Record<string, unknown>).subject
  if (typeof groupId !== 'string' || !groupId) return null
  if (typeof content !== 'string') return null
  if (sentAt !== undefined && typeof sentAt !== 'string') return null
  if (subject !== undefined && typeof subject !== 'string') return null
  return {
    groupId, content,
    ...(typeof sentAt === 'string' ? { sentAt } : {}),
    ...(typeof subject === 'string' ? { subject } : {}),
  }
}

const GROUP_ADDRESS_PREFIX = 'didcomm-group:'

export function didcommGroupAddress(groupId: string): string {
  return `${GROUP_ADDRESS_PREFIX}${groupId}`
}

/** Inverse of `didcommGroupAddress`. Throws on anything not shaped like
 * one -- every call site already gates entry on `startsWith(...)` first,
 * mirroring mimi-content-projector.ts's `parseMlsGroupAddress`. */
export function parseDidCommGroupAddress(address: string): string {
  if (!address.startsWith(GROUP_ADDRESS_PREFIX)) throw new TypeError(`not a DIDComm group address: ${address}`)
  return address.slice(GROUP_ADDRESS_PREFIX.length)
}

export function randomDidCommGroupId(): string {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(32)))
}

// Message dedup for group content reuses ingress-projector.ts's
// didCommMessageDedupeId directly (imported there, not re-exported here) --
// keyed by the SENDING member's own (per-recipient) relationship kid plus
// their own message id. Safe across a fan-out: each recipient authenticates
// the sender under a DIFFERENT pairwise relationship kid (relationship.ts's
// own per-counterparty peer identity), so the same logical group message
// never collides with itself across recipients, and a redelivery to the
// SAME recipient still collides correctly.

export interface DidCommGroupMessageVaultRecord {
  objects: VaultObjectRecord[]
  events: VaultEventRecord[]
  projection: LocalJmapProjectionV1
  jmapState: { state: string }
  deliveryOutbox: {
    identityId: IdentityId
    entryId: VaultEventId
    payload: Uint8Array
    payloadHash: Uint8Array
    createdAt: string
    attempts: number
  }
}

/** The shared "group chat content -> committable Vault record" step, used
 * by both the receive path (main.ts's handleDidCommGroupContent) and the
 * send path (main.ts's own outbound flow, committing its own echo) --
 * mirrors conversation-group-sync.ts's buildConversationGroupVaultRecord
 * exactly (build context -> buildMailMessageAdd -> decrypt-for-projection
 * -> reduce -> deliveryOutbox), minus MLS's edit/delete/reaction dispatch:
 * v1 group messages are add-only. */
export async function buildDidCommGroupMessageVaultRecord(
  input: {
    content: string
    emailId: string
    groupId: string
    senderDid: string
    /** Every OTHER current group member -- roster-as-recipients, not
     * reconstructed from prior messages (same rule mimi-content-projector.ts's
     * own MimiConversationMessageInput.otherMembers documents). */
    otherMembers: string[]
    receivedAt: string
    sentAt: string
    subject?: string
  },
  options: {
    identityId: IdentityId
    actorDeviceId: DeviceId
    nextActorSeq(): Promise<number>
    initialParents(): Promise<VaultEventId[]>
    activeSegment(): Promise<ActiveVaultSegment>
    currentSnapshot(): Promise<LocalJmapSnapshot>
    signer: VaultEventSigner
  },
): Promise<DidCommGroupMessageVaultRecord> {
  const segment = await options.activeSegment()
  assertActiveVaultSegment(options.identityId, segment, 'DIDComm group chat')
  const createdAt = input.receivedAt
  const context = {
    identityId: options.identityId,
    actorDeviceId: options.actorDeviceId,
    actorSeq: await options.nextActorSeq(),
    parents: await options.initialParents(),
    segmentId: segment.segmentId,
    segmentKey: segment.segmentKey,
    createdAt,
  }
  const email: Omit<LocalJmapEmail, 'blobId'> = {
    id: input.emailId,
    threadId: didcommGroupAddress(input.groupId),
    mailboxIds: { inbox: true },
    keywords: {},
    receivedAt: input.receivedAt,
    sentAt: input.sentAt,
    from: [{ email: input.senderDid }],
    to: input.otherMembers.map(member => ({ email: member })),
    ...(input.subject ? { subject: input.subject } : {}),
  }
  const record = await buildMailMessageAdd({ email, rawRfc5322: new TextEncoder().encode(input.content) }, context, options.signer)

  const event: VaultEventRecord = { ...record.event, identityId: options.identityId }
  return buildVaultCommit({
    identityId: options.identityId,
    objects: [record.metadataObject, record.rawRfc5322Object],
    events: [event],
    keyWraps: segment.keyWraps,
    createdAt,
    snapshot: await options.currentSnapshot(),
    reduce: [{ event, plaintext: await decryptVaultObject(segment.segmentKey, record.metadataObject) }],
  })
}
