// Strict JSON boundary for the MLS self-group DS narrow HTTP API, following
// the same shape/binary-encoding split as protocol/ingress-wire.ts.
import { base64urlToBytes, bytesToBase64url } from './canonical.ts'
import type {
  MlsCommitSubmissionV1,
  MlsDeliveriesPullV1,
  MlsExternalCommitSubmissionV1,
  MlsGroupCreationV1,
  MlsGroupInfoPullV1,
  MlsGroupsForPullV1,
  MlsKeyPackageCountPullV1,
  MlsKeyPackageDropV1,
  MlsKeyPackagePublishV1,
  MlsKeyPackageTakeV1,
  MlsPendingRemovalsClearV1,
  MlsSelfRemoveSubmissionV1,
} from './mls-ds.ts'
import type { MlsGroupInfoAnswer, MlsLogEntry } from './mls-ds.ts'

export class MlsDsWireError extends TypeError {}

function record(text: string): Record<string, unknown> {
  let value: unknown
  try { value = JSON.parse(text) } catch { throw new MlsDsWireError('MLS DS HTTP body is not JSON') }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new MlsDsWireError('MLS DS HTTP body must be an object')
  return value as Record<string, unknown>
}

function requireString(value: unknown, name: string): string {
  if (typeof value !== 'string' || value.length === 0) throw new MlsDsWireError(`${name} must be a non-empty string`)
  return value
}

function requireBinary(value: unknown, name: string): Uint8Array {
  if (typeof value !== 'string') throw new MlsDsWireError(`${name} must be a base64url string`)
  return base64urlToBytes(value)
}

function optionalBinary(value: unknown, name: string): Uint8Array | undefined {
  return value === undefined ? undefined : requireBinary(value, name)
}

function requireStringArray(value: unknown, name: string): string[] {
  if (!Array.isArray(value) || value.some(entry => typeof entry !== 'string')) throw new MlsDsWireError(`${name} must be an array of strings`)
  return [...value] as string[]
}

function optionalStringArray(value: unknown, name: string): string[] | undefined {
  return value === undefined ? undefined : requireStringArray(value, name)
}

function requireInteger(value: unknown, name: string): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) throw new MlsDsWireError(`${name} must be a non-negative integer`)
  return value
}

export function decodeMlsGroupCreationWire(text: string): MlsGroupCreationV1 {
  const input = record(text)
  if (input.version !== 1) throw new MlsDsWireError('MlsGroupCreationV1.version must be 1')
  return {
    version: 1,
    groupId: requireString(input.groupId, 'groupId'),
    identityId: requireString(input.identityId, 'identityId'),
    creatorKid: requireString(input.creatorKid, 'creatorKid'),
    roster: requireStringArray(input.roster, 'roster'),
    createdAt: requireString(input.createdAt, 'createdAt'),
    signature: requireBinary(input.signature, 'signature'),
  }
}

export function decodeMlsCommitSubmissionWire(text: string): MlsCommitSubmissionV1 {
  const input = record(text)
  if (input.version !== 1) throw new MlsDsWireError('MlsCommitSubmissionV1.version must be 1')
  return {
    version: 1,
    groupId: requireString(input.groupId, 'groupId'),
    identityId: requireString(input.identityId, 'identityId'),
    senderKid: requireString(input.senderKid, 'senderKid'),
    epoch: requireString(input.epoch, 'epoch'),
    commit: requireBinary(input.commit, 'commit'),
    roster: requireStringArray(input.roster, 'roster'),
    welcome: optionalBinary(input.welcome, 'welcome'),
    welcomeTo: optionalStringArray(input.welcomeTo, 'welcomeTo'),
    groupInfo: optionalBinary(input.groupInfo, 'groupInfo'),
    submittedAt: requireString(input.submittedAt, 'submittedAt'),
    signature: requireBinary(input.signature, 'signature'),
  }
}

export function decodeMlsExternalCommitSubmissionWire(text: string): MlsExternalCommitSubmissionV1 {
  const input = record(text)
  if (input.version !== 1) throw new MlsDsWireError('MlsExternalCommitSubmissionV1.version must be 1')
  return {
    version: 1,
    groupId: requireString(input.groupId, 'groupId'),
    identityId: requireString(input.identityId, 'identityId'),
    senderKid: requireString(input.senderKid, 'senderKid'),
    epoch: requireString(input.epoch, 'epoch'),
    commit: requireBinary(input.commit, 'commit'),
    groupInfo: optionalBinary(input.groupInfo, 'groupInfo'),
    submittedAt: requireString(input.submittedAt, 'submittedAt'),
    signature: requireBinary(input.signature, 'signature'),
  }
}

export function decodeMlsGroupInfoPullWire(text: string): MlsGroupInfoPullV1 {
  const input = record(text)
  if (input.version !== 1) throw new MlsDsWireError('MlsGroupInfoPullV1.version must be 1')
  return {
    version: 1,
    groupId: requireString(input.groupId, 'groupId'),
    identityId: requireString(input.identityId, 'identityId'),
    requesterKid: requireString(input.requesterKid, 'requesterKid'),
    requestedAt: requireString(input.requestedAt, 'requestedAt'),
    signature: requireBinary(input.signature, 'signature'),
  }
}

export function encodeMlsGroupInfoAnswerWire(value: MlsGroupInfoAnswer): string {
  return JSON.stringify({ ...(value.groupInfo ? { groupInfo: bytesToBase64url(value.groupInfo) } : {}), pendingRemovals: value.pendingRemovals })
}

export function decodeMlsKeyPackagePublishWire(text: string): MlsKeyPackagePublishV1 {
  const input = record(text)
  if (input.version !== 1) throw new MlsDsWireError('MlsKeyPackagePublishV1.version must be 1')
  if (!Array.isArray(input.packages)) throw new MlsDsWireError('packages must be an array')
  return {
    version: 1,
    identityId: requireString(input.identityId, 'identityId'),
    kid: requireString(input.kid, 'kid'),
    packages: input.packages.map((entry, index) => requireBinary(entry, `packages[${index}]`)),
    publishedAt: requireString(input.publishedAt, 'publishedAt'),
    signature: requireBinary(input.signature, 'signature'),
  }
}

export function decodeMlsKeyPackageTakeWire(text: string): MlsKeyPackageTakeV1 {
  const input = record(text)
  if (input.version !== 1) throw new MlsDsWireError('MlsKeyPackageTakeV1.version must be 1')
  return {
    version: 1,
    identityId: requireString(input.identityId, 'identityId'),
    requesterKid: requireString(input.requesterKid, 'requesterKid'),
    requestedAt: requireString(input.requestedAt, 'requestedAt'),
    signature: requireBinary(input.signature, 'signature'),
  }
}

export function encodeMlsKeyPackagesTakenWire(taken: Array<{ kid: string; keyPackage: Uint8Array }>): string {
  return JSON.stringify({ items: taken.map(entry => ({ kid: entry.kid, keyPackage: bytesToBase64url(entry.keyPackage) })) })
}

export function decodeMlsSelfRemoveSubmissionWire(text: string): MlsSelfRemoveSubmissionV1 {
  const input = record(text)
  if (input.version !== 1) throw new MlsDsWireError('MlsSelfRemoveSubmissionV1.version must be 1')
  return {
    version: 1,
    groupId: requireString(input.groupId, 'groupId'),
    identityId: requireString(input.identityId, 'identityId'),
    senderKid: requireString(input.senderKid, 'senderKid'),
    epoch: requireString(input.epoch, 'epoch'),
    proposal: requireBinary(input.proposal, 'proposal'),
    removedKid: requireString(input.removedKid, 'removedKid'),
    submittedAt: requireString(input.submittedAt, 'submittedAt'),
    signature: requireBinary(input.signature, 'signature'),
  }
}

export function decodeMlsPendingRemovalsClearWire(text: string): MlsPendingRemovalsClearV1 {
  const input = record(text)
  if (input.version !== 1) throw new MlsDsWireError('MlsPendingRemovalsClearV1.version must be 1')
  return {
    version: 1,
    groupId: requireString(input.groupId, 'groupId'),
    identityId: requireString(input.identityId, 'identityId'),
    requesterKid: requireString(input.requesterKid, 'requesterKid'),
    clearedKids: requireStringArray(input.clearedKids, 'clearedKids'),
    clearedAt: requireString(input.clearedAt, 'clearedAt'),
    signature: requireBinary(input.signature, 'signature'),
  }
}

export function decodeMlsDeliveriesPullWire(text: string): MlsDeliveriesPullV1 {
  const input = record(text)
  if (input.version !== 1) throw new MlsDsWireError('MlsDeliveriesPullV1.version must be 1')
  return {
    version: 1,
    groupId: requireString(input.groupId, 'groupId'),
    identityId: requireString(input.identityId, 'identityId'),
    requesterKid: requireString(input.requesterKid, 'requesterKid'),
    afterSeq: requireInteger(input.afterSeq, 'afterSeq'),
    requestedAt: requireString(input.requestedAt, 'requestedAt'),
    signature: requireBinary(input.signature, 'signature'),
  }
}

export function encodeMlsDeliveriesWire(entries: MlsLogEntry[]): string {
  return JSON.stringify({ entries: entries.map(entry => ({ seq: entry.seq, kind: entry.kind, payload: bytesToBase64url(entry.payload), epoch: entry.epoch, at: entry.at })) })
}

export function decodeMlsKeyPackageDropWire(text: string): MlsKeyPackageDropV1 {
  const input = record(text)
  if (input.version !== 1) throw new MlsDsWireError('MlsKeyPackageDropV1.version must be 1')
  return {
    version: 1,
    identityId: requireString(input.identityId, 'identityId'),
    kid: requireString(input.kid, 'kid'),
    droppedAt: requireString(input.droppedAt, 'droppedAt'),
    signature: requireBinary(input.signature, 'signature'),
  }
}

export function decodeMlsKeyPackageCountPullWire(text: string): MlsKeyPackageCountPullV1 {
  const input = record(text)
  if (input.version !== 1) throw new MlsDsWireError('MlsKeyPackageCountPullV1.version must be 1')
  return {
    version: 1,
    identityId: requireString(input.identityId, 'identityId'),
    kid: requireString(input.kid, 'kid'),
    requestedAt: requireString(input.requestedAt, 'requestedAt'),
    signature: requireBinary(input.signature, 'signature'),
  }
}

export function decodeMlsGroupsForPullWire(text: string): MlsGroupsForPullV1 {
  const input = record(text)
  if (input.version !== 1) throw new MlsDsWireError('MlsGroupsForPullV1.version must be 1')
  return {
    version: 1,
    identityId: requireString(input.identityId, 'identityId'),
    requesterKid: requireString(input.requesterKid, 'requesterKid'),
    requestedAt: requireString(input.requestedAt, 'requestedAt'),
    signature: requireBinary(input.signature, 'signature'),
  }
}

export function encodeMlsGroupsForWire(groups: Array<{ groupId: string; epoch: bigint }>): string {
  return JSON.stringify({ groups: groups.map(g => ({ groupId: g.groupId, epoch: g.epoch.toString() })) })
}

// ------------------------------------------------------------- client side
//
// The encode/decode pair for each request is the exact mirror of the
// decode/encode pair above; both directions live here (rather than one in
// core/mediation, one in a client transport) so a wire format change can
// never drift between what core decodes and what a client encodes.

export function encodeMlsGroupCreationWire(value: MlsGroupCreationV1): string {
  return JSON.stringify({ ...value, signature: bytesToBase64url(value.signature) })
}

export interface MlsGroupRosterResultWire { roster: string[] }
export function decodeMlsGroupRosterResultWire(text: string): MlsGroupRosterResultWire {
  const input = record(text)
  return { roster: requireStringArray(input.roster, 'roster') }
}

export function encodeMlsCommitSubmissionWire(value: MlsCommitSubmissionV1): string {
  return JSON.stringify({
    ...value,
    commit: bytesToBase64url(value.commit),
    ...(value.welcome === undefined ? {} : { welcome: bytesToBase64url(value.welcome) }),
    groupInfo: value.groupInfo === undefined ? undefined : bytesToBase64url(value.groupInfo),
    signature: bytesToBase64url(value.signature),
  })
}

export function encodeMlsExternalCommitSubmissionWire(value: MlsExternalCommitSubmissionV1): string {
  return JSON.stringify({
    ...value,
    commit: bytesToBase64url(value.commit),
    groupInfo: value.groupInfo === undefined ? undefined : bytesToBase64url(value.groupInfo),
    signature: bytesToBase64url(value.signature),
  })
}

/** A commit endpoint's rejection body — the DS's non-2xx JSON, decoded so a
 * caller can retry an `epoch-conflict` instead of treating every rejection
 * as an exception. */
export interface MlsCommitRejectionWire { reason: string; epoch: string }
export function decodeMlsCommitRejectionWire(text: string): MlsCommitRejectionWire {
  const input = record(text)
  return { reason: requireString(input.reason, 'reason'), epoch: requireString(input.epoch, 'epoch') }
}

export function encodeMlsGroupInfoPullWire(value: MlsGroupInfoPullV1): string {
  return JSON.stringify({ ...value, signature: bytesToBase64url(value.signature) })
}

export function decodeMlsGroupInfoAnswerWire(text: string): MlsGroupInfoAnswer {
  const input = record(text)
  return { ...(input.groupInfo === undefined ? {} : { groupInfo: requireBinary(input.groupInfo, 'groupInfo') }), pendingRemovals: requireStringArray(input.pendingRemovals, 'pendingRemovals') }
}

export function encodeMlsKeyPackagePublishWire(value: MlsKeyPackagePublishV1): string {
  return JSON.stringify({ ...value, packages: value.packages.map(bytesToBase64url), signature: bytesToBase64url(value.signature) })
}

export interface MlsKeyPackageCountResultWire { count: number }
export function decodeMlsKeyPackageCountResultWire(text: string): MlsKeyPackageCountResultWire {
  const input = record(text)
  return { count: requireInteger(input.count, 'count') }
}

export function encodeMlsKeyPackageTakeWire(value: MlsKeyPackageTakeV1): string {
  return JSON.stringify({ ...value, signature: bytesToBase64url(value.signature) })
}

export function decodeMlsKeyPackagesTakenWire(text: string): Array<{ kid: string; keyPackage: Uint8Array }> {
  const input = record(text)
  if (!Array.isArray(input.items)) throw new MlsDsWireError('items must be an array')
  return input.items.map((entry, index) => {
    if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) throw new MlsDsWireError(`items[${index}] must be an object`)
    const item = entry as Record<string, unknown>
    return { kid: requireString(item.kid, `items[${index}].kid`), keyPackage: requireBinary(item.keyPackage, `items[${index}].keyPackage`) }
  })
}

export function encodeMlsSelfRemoveSubmissionWire(value: MlsSelfRemoveSubmissionV1): string {
  return JSON.stringify({ ...value, proposal: bytesToBase64url(value.proposal), signature: bytesToBase64url(value.signature) })
}

export function encodeMlsPendingRemovalsClearWire(value: MlsPendingRemovalsClearV1): string {
  return JSON.stringify({ ...value, signature: bytesToBase64url(value.signature) })
}

export function encodeMlsDeliveriesPullWire(value: MlsDeliveriesPullV1): string {
  return JSON.stringify({ ...value, signature: bytesToBase64url(value.signature) })
}

export function decodeMlsDeliveriesWire(text: string): MlsLogEntry[] {
  const input = record(text)
  if (!Array.isArray(input.entries)) throw new MlsDsWireError('entries must be an array')
  return input.entries.map((entry, index) => {
    if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) throw new MlsDsWireError(`entries[${index}] must be an object`)
    const value = entry as Record<string, unknown>
    const kind = value.kind
    if (kind !== 'commit' && kind !== 'welcome' && kind !== 'proposal') throw new MlsDsWireError(`entries[${index}].kind is invalid`)
    return { seq: requireInteger(value.seq, `entries[${index}].seq`), kind, payload: requireBinary(value.payload, `entries[${index}].payload`), epoch: requireString(value.epoch, `entries[${index}].epoch`), at: requireString(value.at, `entries[${index}].at`) }
  })
}

export function encodeMlsKeyPackageDropWire(value: MlsKeyPackageDropV1): string {
  return JSON.stringify({ ...value, signature: bytesToBase64url(value.signature) })
}

export function encodeMlsKeyPackageCountPullWire(value: MlsKeyPackageCountPullV1): string {
  return JSON.stringify({ ...value, signature: bytesToBase64url(value.signature) })
}

export function encodeMlsGroupsForPullWire(value: MlsGroupsForPullV1): string {
  return JSON.stringify({ ...value, signature: bytesToBase64url(value.signature) })
}

export interface MlsGroupsForResultWire { groupId: string; epoch: string }
export function decodeMlsGroupsForWire(text: string): MlsGroupsForResultWire[] {
  const input = record(text)
  if (!Array.isArray(input.groups)) throw new MlsDsWireError('groups must be an array')
  return input.groups.map((entry, index) => {
    if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) throw new MlsDsWireError(`groups[${index}] must be an object`)
    const value = entry as Record<string, unknown>
    return { groupId: requireString(value.groupId, `groups[${index}].groupId`), epoch: requireString(value.epoch, `groups[${index}].epoch`) }
  })
}
