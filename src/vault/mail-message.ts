import { canonicalBytes, type CanonicalValue } from '../protocol/canonical.ts'
import type { DeviceId, IdentityId, SegmentId, VaultEventId } from '../protocol/ids.ts'
import type { VaultEventV1, VaultObjectV1 } from '../protocol/vault.ts'
import type { LocalJmapEmail } from '../local-jmap/gateway.ts'
import { createVaultEvent, type VaultEventSigner } from './events.ts'
import { encryptVaultObject } from './objects.ts'
import { encodeVaultMutationObject, mutationObjectAad } from './mutations.ts'

export interface MailMessageBuildContext {
  identityId: IdentityId
  actorDeviceId: DeviceId
  actorSeq: number
  parents: VaultEventId[]
  segmentId: SegmentId
  segmentKey: Uint8Array
  createdAt: string
}

export interface MailMessageRecord {
  /** The first event reference: encrypted, canonical JMAP read-model metadata. */
  metadataObject: VaultObjectV1
  /** The second event reference: unchanged raw RFC 5322 bytes. */
  rawRfc5322Object: VaultObjectV1
  event: VaultEventV1
}

/**
 * Creates the canonical vault representation for an accepted mail item.
 *
 * The signature binds metadata and the original RFC 5322 bytes together.  The
 * raw bytes remain opaque to the core and are later exposed through JMAP
 * download using their object ID as the blob ID.
 */
export async function buildMailMessageAdd(
  input: { email: Omit<LocalJmapEmail, 'blobId'>; rawRfc5322: Uint8Array },
  context: MailMessageBuildContext,
  signer: VaultEventSigner,
): Promise<MailMessageRecord> {
  assertContext(context, signer)
  if (!(input.rawRfc5322 instanceof Uint8Array)) throw new TypeError('raw RFC 5322 message must be bytes')
  const rawRfc5322Object = await encryptVaultObject(context.segmentKey, {
    segmentId: context.segmentId,
    plaintext: input.rawRfc5322,
    aad: rawRfc5322ObjectAad(context.identityId, context.segmentId),
  })
  const email = assertMailMessageEmail({ ...input.email, blobId: rawRfc5322Object.objectId })
  const intent = {
    kind: 'message.add' as const,
    targetIds: [email.id],
    payload: { email: canonicalMailMessageEmail(email) },
  }
  const metadataObject = await encryptVaultObject(context.segmentKey, {
    segmentId: context.segmentId,
    plaintext: encodeVaultMutationObject(intent),
    aad: mutationObjectAad(context.identityId, context.segmentId, intent.kind, intent.targetIds),
  })
  const event = await createVaultEvent({
    identityId: context.identityId,
    actorDeviceId: context.actorDeviceId,
    actorSeq: context.actorSeq,
    kind: 'message.add',
    targetIds: [email.id],
    objectRefs: [metadataObject.objectId, rawRfc5322Object.objectId],
    parents: [...context.parents],
    createdAt: context.createdAt,
  }, signer)
  return { metadataObject, rawRfc5322Object, event }
}

/** Distinct AAD prevents raw mail from being mistaken for a mutation record. */
export function rawRfc5322ObjectAad(identityId: IdentityId, segmentId: SegmentId): Uint8Array {
  if (!identityId || !segmentId) throw new TypeError('raw RFC 5322 AAD requires identity and segment')
  return canonicalBytes({
    label: 'biset/vault/mail/raw-rfc5322/aad/v1',
    identityId,
    segmentId,
  })
}

/** Validates and defensive-copies the JMAP metadata persisted in `message.add`. */
export function assertMailMessageEmail(value: unknown): LocalJmapEmail {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('mail message email must be an object')
  const email = value as Record<string, unknown>
  if (!nonEmptyString(email.id) || !nonEmptyString(email.blobId) || !nonEmptyString(email.threadId) || !isoDate(email.receivedAt)) {
    throw new TypeError('mail message email has invalid required fields')
  }
  const result: LocalJmapEmail = {
    id: email.id,
    blobId: email.blobId,
    threadId: email.threadId,
    mailboxIds: trueMap(email.mailboxIds, 'mailboxIds'),
    keywords: trueMap(email.keywords, 'keywords'),
    receivedAt: email.receivedAt,
  }
  if (email.sentAt !== undefined) {
    if (!isoDate(email.sentAt)) throw new TypeError('mail message sentAt is invalid')
    result.sentAt = email.sentAt
  }
  if (email.from !== undefined) result.from = addresses(email.from, 'from')
  if (email.to !== undefined) result.to = addresses(email.to, 'to')
  for (const field of ['subject', 'preview'] as const) {
    if (email[field] !== undefined) {
      if (typeof email[field] !== 'string') throw new TypeError(`mail message ${field} is invalid`)
      result[field] = email[field]
    }
  }
  const size = email.size
  if (size !== undefined) {
    if (typeof size !== 'number' || !Number.isSafeInteger(size) || size < 0) throw new TypeError('mail message size is invalid')
    result.size = size
  }
  return result
}

function assertContext(context: MailMessageBuildContext, signer: VaultEventSigner): void {
  if (!context.identityId || !context.actorDeviceId || !context.segmentId) throw new TypeError('mail message context has empty required fields')
  if (context.actorDeviceId !== signer.deviceId) throw new TypeError('mail message signer does not match actor device')
  if (!Number.isSafeInteger(context.actorSeq) || context.actorSeq < 0) throw new TypeError('mail message actor sequence is invalid')
  if (context.segmentKey.length !== 32) throw new TypeError('mail message SegmentKey must be 32 bytes')
  if (!isoDate(context.createdAt)) throw new TypeError('mail message createdAt must be an ISO date string')
}

function trueMap(value: unknown, name: string): Record<string, true> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError(`mail message ${name} must be an object`)
  const result: Record<string, true> = {}
  for (const [id, enabled] of Object.entries(value as Record<string, unknown>)) {
    if (!nonEmptyString(id) || enabled !== true) throw new TypeError(`mail message ${name} is invalid`)
    result[id] = true
  }
  return result
}

function addresses(value: unknown, name: string): Array<{ email?: string; name?: string }> {
  if (!Array.isArray(value)) throw new TypeError(`mail message ${name} must be an array`)
  return value.map((address) => {
    if (address === null || typeof address !== 'object' || Array.isArray(address)) throw new TypeError(`mail message ${name} address is invalid`)
    const result: { email?: string; name?: string } = {}
    for (const field of ['email', 'name'] as const) {
      const entry = (address as Record<string, unknown>)[field]
      if (entry !== undefined) {
        if (typeof entry !== 'string') throw new TypeError(`mail message ${name} address is invalid`)
        result[field] = entry
      }
    }
    if (result.email === undefined && result.name === undefined) throw new TypeError(`mail message ${name} address is empty`)
    return result
  })
}

function canonicalMailMessageEmail(email: LocalJmapEmail): CanonicalValue {
  return {
    id: email.id,
    blobId: email.blobId!,
    threadId: email.threadId,
    mailboxIds: { ...email.mailboxIds },
    keywords: { ...email.keywords },
    receivedAt: email.receivedAt,
    ...(email.sentAt === undefined ? {} : { sentAt: email.sentAt }),
    ...(email.from === undefined ? {} : { from: email.from.map(canonicalAddress) }),
    ...(email.to === undefined ? {} : { to: email.to.map(canonicalAddress) }),
    ...(email.subject === undefined ? {} : { subject: email.subject }),
    ...(email.preview === undefined ? {} : { preview: email.preview }),
    ...(email.size === undefined ? {} : { size: email.size }),
  }
}

function canonicalAddress(address: { email?: string; name?: string }): CanonicalValue {
  return {
    ...(address.email === undefined ? {} : { email: address.email }),
    ...(address.name === undefined ? {} : { name: address.name }),
  }
}

function nonEmptyString(value: unknown): value is string { return typeof value === 'string' && value.length > 0 }
function isoDate(value: unknown): value is string { return typeof value === 'string' && !Number.isNaN(Date.parse(value)) }
