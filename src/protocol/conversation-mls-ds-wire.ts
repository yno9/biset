// Strict JSON boundary for the Conversation Group DS narrow HTTP API,
// mirroring mls-ds-wire.ts's shape/binary-encoding split minus `identityId`
// throughout (PLAN_biset-mls-ds.md §7) plus `targetId` on KeyPackage take
// and message-submit (conversation-mls-ds.ts's own note: the one operation
// with no Self Group equivalent). No `deviceCredential` field anywhere --
// the group-local id itself IS the verification key (conversation-mls-ds.ts's
// header explains why).
import { base64urlToBytes, bytesToBase64url } from './canonical.ts'
import type {
  ConversationCommitSubmitV1,
  ConversationDeliveriesPullV1,
  ConversationGroupCreateV1,
  ConversationKeyPackageCountPullV1,
  ConversationKeyPackageDropV1,
  ConversationKeyPackagePublishV1,
  ConversationKeyPackageTakeV1,
  ConversationLogEntry,
  ConversationMessageSubmitV1,
  ConversationPendingRemovalsClearV1,
  ConversationSelfRemoveSubmitV1,
} from './conversation-mls-ds.ts'

export class ConversationDsWireError extends TypeError {}

function record(text: string): Record<string, unknown> {
  let value: unknown
  try { value = JSON.parse(text) } catch { throw new ConversationDsWireError('Conversation DS HTTP body is not JSON') }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new ConversationDsWireError('Conversation DS HTTP body must be an object')
  return value as Record<string, unknown>
}

function requireString(value: unknown, name: string): string {
  if (typeof value !== 'string' || value.length === 0) throw new ConversationDsWireError(`${name} must be a non-empty string`)
  return value
}

function requireBinary(value: unknown, name: string): Uint8Array {
  if (typeof value !== 'string') throw new ConversationDsWireError(`${name} must be a base64url string`)
  return base64urlToBytes(value)
}

function optionalBinary(value: unknown, name: string): Uint8Array | undefined {
  return value === undefined ? undefined : requireBinary(value, name)
}

function requireStringArray(value: unknown, name: string): string[] {
  if (!Array.isArray(value) || value.some(entry => typeof entry !== 'string')) throw new ConversationDsWireError(`${name} must be an array of strings`)
  return [...value] as string[]
}

function optionalStringArray(value: unknown, name: string): string[] | undefined {
  return value === undefined ? undefined : requireStringArray(value, name)
}

function requireInteger(value: unknown, name: string): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) throw new ConversationDsWireError(`${name} must be a non-negative integer`)
  return value
}

// -------------------------------------------------------------- server side

export function decodeConversationGroupCreateWire(text: string): ConversationGroupCreateV1 {
  const input = record(text)
  if (input.version !== 1) throw new ConversationDsWireError('ConversationGroupCreateV1.version must be 1')
  return {
    version: 1,
    groupId: requireString(input.groupId, 'groupId'),
    creatorId: requireString(input.creatorId, 'creatorId'),
    createdAt: requireString(input.createdAt, 'createdAt'),
    signature: requireBinary(input.signature, 'signature'),
  }
}

export function decodeConversationCommitSubmitWire(text: string): ConversationCommitSubmitV1 {
  const input = record(text)
  if (input.version !== 1) throw new ConversationDsWireError('ConversationCommitSubmitV1.version must be 1')
  return {
    version: 1,
    groupId: requireString(input.groupId, 'groupId'),
    senderId: requireString(input.senderId, 'senderId'),
    epoch: requireString(input.epoch, 'epoch'),
    commit: requireBinary(input.commit, 'commit'),
    addedIds: optionalStringArray(input.addedIds, 'addedIds'),
    removedIds: optionalStringArray(input.removedIds, 'removedIds'),
    welcome: optionalBinary(input.welcome, 'welcome'),
    submittedAt: requireString(input.submittedAt, 'submittedAt'),
    signature: requireBinary(input.signature, 'signature'),
  }
}

export function decodeConversationKeyPackagePublishWire(text: string): ConversationKeyPackagePublishV1 {
  const input = record(text)
  if (input.version !== 1) throw new ConversationDsWireError('ConversationKeyPackagePublishV1.version must be 1')
  if (!Array.isArray(input.packages)) throw new ConversationDsWireError('packages must be an array')
  return {
    version: 1,
    id: requireString(input.id, 'id'),
    packages: input.packages.map((entry, index) => requireBinary(entry, `packages[${index}]`)),
    publishedAt: requireString(input.publishedAt, 'publishedAt'),
    signature: requireBinary(input.signature, 'signature'),
  }
}

export function decodeConversationKeyPackageTakeWire(text: string): ConversationKeyPackageTakeV1 {
  const input = record(text)
  if (input.version !== 1) throw new ConversationDsWireError('ConversationKeyPackageTakeV1.version must be 1')
  return {
    version: 1,
    requesterId: requireString(input.requesterId, 'requesterId'),
    targetId: requireString(input.targetId, 'targetId'),
    requestedAt: requireString(input.requestedAt, 'requestedAt'),
    signature: requireBinary(input.signature, 'signature'),
  }
}

export function encodeConversationKeyPackageTakenWire(taken: { keyPackage: Uint8Array } | undefined): string {
  return JSON.stringify(taken ? { keyPackage: bytesToBase64url(taken.keyPackage) } : {})
}

export function decodeConversationSelfRemoveSubmitWire(text: string): ConversationSelfRemoveSubmitV1 {
  const input = record(text)
  if (input.version !== 1) throw new ConversationDsWireError('ConversationSelfRemoveSubmitV1.version must be 1')
  return {
    version: 1,
    groupId: requireString(input.groupId, 'groupId'),
    senderId: requireString(input.senderId, 'senderId'),
    epoch: requireString(input.epoch, 'epoch'),
    proposal: requireBinary(input.proposal, 'proposal'),
    removedId: requireString(input.removedId, 'removedId'),
    submittedAt: requireString(input.submittedAt, 'submittedAt'),
    signature: requireBinary(input.signature, 'signature'),
  }
}

export function decodeConversationPendingRemovalsClearWire(text: string): ConversationPendingRemovalsClearV1 {
  const input = record(text)
  if (input.version !== 1) throw new ConversationDsWireError('ConversationPendingRemovalsClearV1.version must be 1')
  return {
    version: 1,
    groupId: requireString(input.groupId, 'groupId'),
    requesterId: requireString(input.requesterId, 'requesterId'),
    clearedIds: requireStringArray(input.clearedIds, 'clearedIds'),
    clearedAt: requireString(input.clearedAt, 'clearedAt'),
    signature: requireBinary(input.signature, 'signature'),
  }
}

export function decodeConversationDeliveriesPullWire(text: string): ConversationDeliveriesPullV1 {
  const input = record(text)
  if (input.version !== 1) throw new ConversationDsWireError('ConversationDeliveriesPullV1.version must be 1')
  return {
    version: 1,
    groupId: requireString(input.groupId, 'groupId'),
    requesterId: requireString(input.requesterId, 'requesterId'),
    afterSeq: requireInteger(input.afterSeq, 'afterSeq'),
    requestedAt: requireString(input.requestedAt, 'requestedAt'),
    signature: requireBinary(input.signature, 'signature'),
  }
}

function decodeLogEntryKind(value: unknown, name: string): ConversationLogEntry['kind'] {
  if (value !== 'commit' && value !== 'welcome' && value !== 'proposal' && value !== 'application') throw new ConversationDsWireError(`${name} is invalid`)
  return value
}

export function encodeConversationDeliveriesWire(entries: ConversationLogEntry[]): string {
  return JSON.stringify({ entries: entries.map(entry => ({ seq: entry.seq, kind: entry.kind, payload: bytesToBase64url(entry.payload), epoch: entry.epoch, at: entry.at })) })
}

export function decodeConversationKeyPackageDropWire(text: string): ConversationKeyPackageDropV1 {
  const input = record(text)
  if (input.version !== 1) throw new ConversationDsWireError('ConversationKeyPackageDropV1.version must be 1')
  return {
    version: 1,
    id: requireString(input.id, 'id'),
    droppedAt: requireString(input.droppedAt, 'droppedAt'),
    signature: requireBinary(input.signature, 'signature'),
  }
}

export function decodeConversationKeyPackageCountPullWire(text: string): ConversationKeyPackageCountPullV1 {
  const input = record(text)
  if (input.version !== 1) throw new ConversationDsWireError('ConversationKeyPackageCountPullV1.version must be 1')
  return {
    version: 1,
    id: requireString(input.id, 'id'),
    requestedAt: requireString(input.requestedAt, 'requestedAt'),
    signature: requireBinary(input.signature, 'signature'),
  }
}

export function decodeConversationMessageSubmitWire(text: string): ConversationMessageSubmitV1 {
  const input = record(text)
  if (input.version !== 1) throw new ConversationDsWireError('ConversationMessageSubmitV1.version must be 1')
  return {
    version: 1,
    groupId: requireString(input.groupId, 'groupId'),
    senderId: requireString(input.senderId, 'senderId'),
    epoch: requireString(input.epoch, 'epoch'),
    privateMessage: requireBinary(input.privateMessage, 'privateMessage'),
    submittedAt: requireString(input.submittedAt, 'submittedAt'),
    signature: requireBinary(input.signature, 'signature'),
  }
}

// ------------------------------------------------------------- client side
//
// Same rationale as mls-ds-wire.ts: both directions of each pair live here
// so a wire format change can never drift between what the server decodes
// and what a client encodes.

export function encodeConversationGroupCreateWire(value: ConversationGroupCreateV1): string {
  return JSON.stringify({ ...value, signature: bytesToBase64url(value.signature) })
}

export interface ConversationGroupRosterResultWire { roster: string[] }
export function decodeConversationGroupRosterResultWire(text: string): ConversationGroupRosterResultWire {
  const input = record(text)
  return { roster: requireStringArray(input.roster, 'roster') }
}

export function encodeConversationCommitSubmitWire(value: ConversationCommitSubmitV1): string {
  return JSON.stringify({
    ...value,
    commit: bytesToBase64url(value.commit),
    ...(value.welcome === undefined ? {} : { welcome: bytesToBase64url(value.welcome) }),
    signature: bytesToBase64url(value.signature),
  })
}

/** A commit endpoint's rejection body -- the DS's non-2xx JSON, decoded so a
 * caller can retry an `epoch-conflict` instead of treating every rejection
 * as an exception. */
export interface ConversationCommitRejectionWire { reason: string; epoch: string }
export function decodeConversationCommitRejectionWire(text: string): ConversationCommitRejectionWire {
  const input = record(text)
  return { reason: requireString(input.reason, 'reason'), epoch: requireString(input.epoch, 'epoch') }
}

export function encodeConversationKeyPackagePublishWire(value: ConversationKeyPackagePublishV1): string {
  return JSON.stringify({ ...value, packages: value.packages.map(bytesToBase64url), signature: bytesToBase64url(value.signature) })
}

export interface ConversationKeyPackageCountResultWire { count: number }
export function decodeConversationKeyPackageCountResultWire(text: string): ConversationKeyPackageCountResultWire {
  const input = record(text)
  return { count: requireInteger(input.count, 'count') }
}

export function encodeConversationKeyPackageTakeWire(value: ConversationKeyPackageTakeV1): string {
  return JSON.stringify({ ...value, signature: bytesToBase64url(value.signature) })
}

export function decodeConversationKeyPackageTakenWire(text: string): { keyPackage: Uint8Array } | undefined {
  const input = record(text)
  if (input.keyPackage === undefined) return undefined
  return { keyPackage: requireBinary(input.keyPackage, 'keyPackage') }
}

export function encodeConversationSelfRemoveSubmitWire(value: ConversationSelfRemoveSubmitV1): string {
  return JSON.stringify({ ...value, proposal: bytesToBase64url(value.proposal), signature: bytesToBase64url(value.signature) })
}

export function encodeConversationPendingRemovalsClearWire(value: ConversationPendingRemovalsClearV1): string {
  return JSON.stringify({ ...value, signature: bytesToBase64url(value.signature) })
}

export function encodeConversationDeliveriesPullWire(value: ConversationDeliveriesPullV1): string {
  return JSON.stringify({ ...value, signature: bytesToBase64url(value.signature) })
}

export function decodeConversationDeliveriesWire(text: string): ConversationLogEntry[] {
  const input = record(text)
  if (!Array.isArray(input.entries)) throw new ConversationDsWireError('entries must be an array')
  return input.entries.map((entry, index) => {
    if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) throw new ConversationDsWireError(`entries[${index}] must be an object`)
    const value = entry as Record<string, unknown>
    return {
      seq: requireInteger(value.seq, `entries[${index}].seq`),
      kind: decodeLogEntryKind(value.kind, `entries[${index}].kind`),
      payload: requireBinary(value.payload, `entries[${index}].payload`),
      epoch: requireString(value.epoch, `entries[${index}].epoch`),
      at: requireString(value.at, `entries[${index}].at`),
    }
  })
}

export function encodeConversationKeyPackageDropWire(value: ConversationKeyPackageDropV1): string {
  return JSON.stringify({ ...value, signature: bytesToBase64url(value.signature) })
}

export function encodeConversationKeyPackageCountPullWire(value: ConversationKeyPackageCountPullV1): string {
  return JSON.stringify({ ...value, signature: bytesToBase64url(value.signature) })
}

export function encodeConversationMessageSubmitWire(value: ConversationMessageSubmitV1): string {
  return JSON.stringify({ ...value, privateMessage: bytesToBase64url(value.privateMessage), signature: bytesToBase64url(value.signature) })
}
