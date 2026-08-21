import { canonicalHash, type CanonicalValue } from '../protocol/canonical.ts'
import type { VaultEventV1 } from '../protocol/vault.ts'
import type { VaultMutationIntent } from './mutations.ts'
import type { LocalJmapEmail, LocalJmapMailbox, LocalJmapSnapshot } from './gateway.ts'

export interface DecryptedMutationRecord {
  event: VaultEventV1
  plaintext: Uint8Array
}

/** Parses the encrypted object referenced by an event after cryptographic verification. */
export function decodeVaultMutation(event: VaultEventV1, plaintext: Uint8Array): VaultMutationIntent {
  let value: unknown
  try {
    value = JSON.parse(new TextDecoder().decode(plaintext))
  } catch {
    throw new TypeError('vault mutation object is not valid JSON')
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('vault mutation object must be an object')
  const mutation = value as Record<string, unknown>
  if (mutation.version !== 1 || mutation.kind !== event.kind || !sameTargets(mutation.targetIds, event.targetIds)) {
    throw new TypeError('vault mutation object does not match its event')
  }
  if (mutation.payload === null || typeof mutation.payload !== 'object' || Array.isArray(mutation.payload)) {
    throw new TypeError('vault mutation payload must be an object')
  }
  return { kind: event.kind, targetIds: [...event.targetIds], payload: mutation.payload as VaultMutationIntent['payload'] }
}

/**
 * Rebuilds the mutable JMAP view from immutable state events. LWW ordering is
 * deterministic across devices. A message tombstone is irreversible in this
 * projection, so a concurrent metadata update cannot resurrect it.
 */
export function reduceLocalJmapProjection(
  identityId: string,
  base: Omit<LocalJmapSnapshot, 'state'>,
  records: DecryptedMutationRecord[],
): LocalJmapSnapshot {
  const emails = new Map(base.emails.map(email => [email.id, copyEmail(email)]))
  const tombstones = new Set<string>()
  for (const record of [...records].sort(compareEvents)) {
    const mutation = decodeVaultMutation(record.event, record.plaintext)
    const emailId = mutation.targetIds[0]
    if (mutation.kind === 'message.tombstone') {
      assertPayloadEmailId(mutation.payload, emailId)
      tombstones.add(emailId)
      emails.delete(emailId)
      continue
    }
    if (tombstones.has(emailId) || !emails.has(emailId)) continue
    const email = emails.get(emailId)!
    if (mutation.kind === 'mailbox.set') {
      const payload = assertPayloadEmailId(mutation.payload, emailId)
      email.mailboxIds = truthyMap(payload.mailboxIds, 'mailboxIds')
    } else if (mutation.kind === 'keyword.set') {
      const payload = assertPayloadEmailId(mutation.payload, emailId)
      email.keywords = truthyMap(payload.keywords, 'keywords')
    }
  }
  const mailboxes = base.mailboxes.map(copyMailbox)
  const resultEmails = [...emails.values()].sort((left, right) => left.id.localeCompare(right.id))
  return {
    state: projectionState(identityId, mailboxes, resultEmails),
    mailboxes,
    emails: resultEmails,
  }
}

export function projectionState(identityId: string, mailboxes: LocalJmapMailbox[], emails: LocalJmapEmail[]): string {
  if (!identityId) throw new TypeError('projection identity is required')
  return canonicalHash('biset/local-jmap/projection/v1', {
    version: 1,
    identityId,
    mailboxes: [...mailboxes].sort((left, right) => left.id.localeCompare(right.id)).map(canonicalMailbox),
    emails: [...emails].sort((left, right) => left.id.localeCompare(right.id)).map(canonicalEmail),
  })
}

function canonicalMailbox(value: LocalJmapMailbox): CanonicalValue {
  return {
    id: value.id,
    name: value.name,
    ...(value.role === undefined ? {} : { role: value.role }),
    ...(value.parentId === undefined ? {} : { parentId: value.parentId }),
    totalEmails: value.totalEmails,
    unreadEmails: value.unreadEmails,
  }
}

function canonicalEmail(value: LocalJmapEmail): CanonicalValue {
  return {
    id: value.id,
    ...(value.blobId === undefined ? {} : { blobId: value.blobId }),
    threadId: value.threadId,
    mailboxIds: { ...value.mailboxIds },
    keywords: { ...value.keywords },
    receivedAt: value.receivedAt,
    ...(value.sentAt === undefined ? {} : { sentAt: value.sentAt }),
    ...(value.from === undefined ? {} : { from: value.from.map(canonicalAddress) }),
    ...(value.to === undefined ? {} : { to: value.to.map(canonicalAddress) }),
    ...(value.subject === undefined ? {} : { subject: value.subject }),
    ...(value.preview === undefined ? {} : { preview: value.preview }),
    ...(value.size === undefined ? {} : { size: value.size }),
  }
}

function canonicalAddress(value: { email?: string; name?: string }): CanonicalValue {
  return {
    ...(value.email === undefined ? {} : { email: value.email }),
    ...(value.name === undefined ? {} : { name: value.name }),
  }
}

function compareEvents(left: DecryptedMutationRecord, right: DecryptedMutationRecord): number {
  const a = left.event
  const b = right.event
  return a.createdAt.localeCompare(b.createdAt)
    || a.actorDeviceId.localeCompare(b.actorDeviceId)
    || a.actorSeq - b.actorSeq
    || a.id.localeCompare(b.id)
}

function sameTargets(value: unknown, expected: string[]): boolean {
  return Array.isArray(value) && value.length === expected.length && value.every((target, index) => target === expected[index])
}

function assertPayloadEmailId(payload: VaultMutationIntent['payload'], expected: string): Record<string, unknown> {
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload) || (payload as Record<string, unknown>).emailId !== expected) {
    throw new TypeError('vault mutation payload does not match target email')
  }
  return payload as Record<string, unknown>
}

function truthyMap(value: unknown, name: string): Record<string, true> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError(`vault mutation ${name} must be an object`)
  const result: Record<string, true> = {}
  for (const [id, enabled] of Object.entries(value as Record<string, unknown>)) {
    if (!id || typeof enabled !== 'boolean') throw new TypeError(`vault mutation ${name} is invalid`)
    if (enabled) result[id] = true
  }
  return result
}

function copyMailbox(value: LocalJmapMailbox): LocalJmapMailbox { return { ...value } }
function copyEmail(value: LocalJmapEmail): LocalJmapEmail {
  return {
    ...value,
    mailboxIds: { ...value.mailboxIds },
    keywords: { ...value.keywords },
    from: value.from?.map(value => ({ ...value })),
    to: value.to?.map(value => ({ ...value })),
  }
}
