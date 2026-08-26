import { canonicalHash, type CanonicalValue } from '../protocol/canonical.ts'
import type { VaultEventV1 } from '../protocol/vault.ts'
import type { VaultMutationIntent } from './mutations.ts'
import type { LocalJmapEmail, LocalJmapMailbox, LocalJmapSnapshot } from './gateway.ts'
import { assertMailMessageEmail } from '../vault/mail-message.ts'

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
    if (mutation.kind === 'message.add') {
      const email = assertMessageAdd(record.event, mutation.payload, emailId)
      if (tombstones.has(emailId)) continue
      if (emails.has(emailId)) throw new TypeError('vault message.add conflicts with an existing email')
      emails.set(emailId, email)
      continue
    }
    if (mutation.kind === 'transport.result') {
      // Deliberately a no-op for the read-model: it's an audit record of an
      // outbound delivery attempt (identity/bootstrap.ts's buildMailSubmitter),
      // not a mailbox/keyword change -- the mailbox.set that moves a message
      // out of "outbox" on success is a separate event in the same commit
      // and goes through the ordinary path below.
      continue
    }
    if (mutation.kind === 'didcomm.control') {
      // Deliberately a no-op for the read-model: an audit record of a
      // received DIDComm control-plane message (didcomm/ingress-projector.ts,
      // PLAN.md §6.1's external-ingress/OOB/bootstrap/control scope) --
      // never a mail/mailbox change. Still an ordinary vault event (advances
      // actorSeq/state/checkpoint like any other), just one this read model
      // has nothing to do with.
      continue
    }
    if (mutation.kind === 'didcomm.device-key.set') {
      // Deliberately a no-op for the read-model: a private
      // (MLS device kid -> DIDComm keyAgreement kid) pairing
      // (vault/didcomm-device-key.ts), read only by revokeDevice (main.ts)
      // directly off the vault events, never projected into mail/mailbox
      // state.
      continue
    }
    if (mutation.kind === 'credential.didcomm.set') {
      // Deliberately a no-op for the read-model: the identity-shared DIDComm
      // keyAgreement private key (vault/didcomm-credential.ts), read only by
      // DidCommCredentialReader directly off the vault events -- never a
      // mailbox/keyword change. A sibling device receiving this event via
      // ordinary vault-delivery sync must not have it rejected here just
      // because this reducer has no mail-projection rule for it.
      continue
    }
    if (mutation.kind === 'contact-key.set') {
      // Deliberately a no-op for the read-model: private per-counterparty
      // DIDComm relationship credentials are read directly from encrypted
      // vault events and never become mail or mailbox state.
      continue
    }
    if (mutation.kind === 'credential.openpgp.set') {
      // Deliberately a no-op for the read-model: the identity-shared OpenPGP
      // mail private key (vault/openpgp-credential-sink.ts), read only by
      // OpenPgpCredentialReader directly off the vault events -- never a
      // mailbox/keyword change. A sibling device receiving this event via
      // ordinary vault-delivery sync must not have it rejected here just
      // because this reducer has no mail-projection rule for it.
      continue
    }
    if (mutation.kind !== 'mailbox.set' && mutation.kind !== 'keyword.set') {
      // `VaultEventKind` (protocol/vault.ts) reserves several kinds
      // (message.edit/reaction.set/read.set/thread.set/settings.set/...)
      // no write path produces yet and this reducer has no projection rule
      // for. Silently dropping a kind it doesn't recognize would be data
      // loss a device could never detect (sync "succeeds", the mutation is
      // just gone) -- fail closed instead, the same way message.add's own
      // conflict check does.
      throw new TypeError(`vault mutation kind '${mutation.kind}' has no Local JMAP projection rule`)
    }
    if (tombstones.has(emailId) || !emails.has(emailId)) continue
    const email = emails.get(emailId)!
    if (mutation.kind === 'mailbox.set') {
      const payload = assertPayloadEmailId(mutation.payload, emailId)
      email.mailboxIds = truthyMap(payload.mailboxIds, 'mailboxIds')
    } else {
      const payload = assertPayloadEmailId(mutation.payload, emailId)
      email.keywords = truthyMap(payload.keywords, 'keywords')
    }
  }
  const mailboxes = mailboxCounts(base.mailboxes, emails.values())
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

/** `message.add` binds its read-model object to the accompanying raw-mail blob. */
function assertMessageAdd(event: VaultEventV1, payload: VaultMutationIntent['payload'], expected: string): LocalJmapEmail {
  if (event.objectRefs.length !== 2) throw new TypeError('vault message.add must reference metadata and raw RFC 5322 objects')
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) throw new TypeError('vault message.add payload is invalid')
  const email = assertMailMessageEmail((payload as Record<string, unknown>).email)
  if (email.id !== expected || email.blobId !== event.objectRefs[1]) {
    throw new TypeError('vault message.add does not bind the email to its raw RFC 5322 object')
  }
  return email
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

function mailboxCounts(base: LocalJmapMailbox[], emails: Iterable<LocalJmapEmail>): LocalJmapMailbox[] {
  const values = base.map(copyMailbox)
  const counts = new Map(values.map(mailbox => [mailbox.id, { total: 0, unread: 0 }]))
  for (const email of emails) {
    const unread = email.keywords.$seen !== true
    for (const mailboxId of Object.keys(email.mailboxIds)) {
      const count = counts.get(mailboxId)
      if (!count) continue
      count.total += 1
      if (unread) count.unread += 1
    }
  }
  return values.map((mailbox) => ({ ...mailbox, totalEmails: counts.get(mailbox.id)!.total, unreadEmails: counts.get(mailbox.id)!.unread }))
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
