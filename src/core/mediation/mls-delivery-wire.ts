// Strict JSON boundary for the MLS self-group DS narrow HTTP API, following
// the same shape/binary-encoding split as protocol/ingress-wire.ts.
import { base64urlToBytes, bytesToBase64url } from '../../protocol/canonical.ts'
import type {
  MlsCommitSubmissionV1,
  MlsExternalCommitSubmissionV1,
  MlsGroupCreationV1,
  MlsGroupInfoPullV1,
  MlsKeyPackagePublishV1,
  MlsKeyPackageTakeV1,
} from '../../protocol/mls-ds.ts'
import type { MlsGroupInfoAnswer } from './mls-delivery-store.ts'

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
