import { canonicalBytes, canonicalHash, base64urlToBytes, bytesToBase64url, type CanonicalValue } from './canonical.ts'
import { assertDeliverySeq, assertMlsEpoch, assertVaultId, assertVaultMemberId, type DeliverySeq, type MlsEpoch, type VaultId, type VaultMemberId } from './ids.ts'

export interface VaultGroupMemberV1 {
  memberId: VaultMemberId
  signaturePublicKey: Uint8Array
  deliveryFloor: DeliverySeq
}

export interface VaultGroupViewV1 {
  version: 1
  vaultId: VaultId
  groupId: Uint8Array
  groupEpoch: MlsEpoch
  confirmedTranscriptHash: Uint8Array
  previousViewHash: string | null
  members: VaultGroupMemberV1[]
  installerMemberId: VaultMemberId
  signature: Uint8Array
}

const VIEW_HASH = /^sha256:[A-Za-z0-9_-]{43}$/

export function decodeVaultGroupView(text: string): VaultGroupViewV1 {
  let value: unknown
  try { value = JSON.parse(text) } catch { throw new TypeError('Vault group view body is not JSON') }
  const input = exactRecord(value, ['version', 'vaultId', 'groupId', 'groupEpoch', 'confirmedTranscriptHash', 'previousViewHash', 'members', 'installerMemberId', 'signature'], 'Vault group view')
  if (input.version !== 1 || !Array.isArray(input.members)) throw new TypeError('invalid Vault group view')
  assertVaultId(input.vaultId)
  assertMlsEpoch(input.groupEpoch)
  if (input.previousViewHash !== null && (typeof input.previousViewHash !== 'string' || !VIEW_HASH.test(input.previousViewHash))) throw new TypeError('previousViewHash is invalid')
  assertVaultMemberId(input.installerMemberId)
  const members = input.members.map((entry): VaultGroupMemberV1 => {
    const member = exactRecord(entry, ['memberId', 'signaturePublicKey', 'deliveryFloor'], 'Vault group member')
    assertVaultMemberId(member.memberId)
    assertDeliverySeq(member.deliveryFloor)
    const signaturePublicKey = binary(member.signaturePublicKey, 'member signaturePublicKey', 32)
    return { memberId: member.memberId, signaturePublicKey, deliveryFloor: member.deliveryFloor }
  })
  if (members.length === 0 || new Set(members.map(member => member.memberId)).size !== members.length) throw new TypeError('Vault group members must be non-empty and unique')
  if (!members.some(member => member.memberId === input.installerMemberId)) throw new TypeError('installer must be a member of the installed view')
  return {
    version: 1,
    vaultId: input.vaultId,
    groupId: binary(input.groupId, 'MLS groupId', 32),
    groupEpoch: input.groupEpoch,
    confirmedTranscriptHash: binary(input.confirmedTranscriptHash, 'confirmedTranscriptHash', 32),
    previousViewHash: input.previousViewHash,
    members,
    installerMemberId: input.installerMemberId,
    signature: binary(input.signature, 'group view signature', 64),
  }
}

export function encodeVaultGroupView(view: VaultGroupViewV1): string {
  assertVaultGroupView(view)
  return JSON.stringify(wireValue(view, true))
}

export function vaultGroupViewSigningBytes(view: Omit<VaultGroupViewV1, 'signature'> | VaultGroupViewV1): Uint8Array {
  assertVaultGroupView({ ...view, signature: 'signature' in view ? view.signature : new Uint8Array(64) })
  return canonicalBytes(wireValue(view, false))
}

export function vaultGroupViewHash(view: VaultGroupViewV1): string {
  assertVaultGroupView(view)
  return canonicalHash('biset/vault-group-view/v1', wireValue(view, true))
}

export function assertVaultGroupView(view: VaultGroupViewV1): void {
  assertVaultId(view.vaultId)
  assertMlsEpoch(view.groupEpoch)
  if (!(view.groupId instanceof Uint8Array) || view.groupId.length !== 32) throw new TypeError('MLS groupId must contain 32 bytes')
  if (!(view.confirmedTranscriptHash instanceof Uint8Array) || view.confirmedTranscriptHash.length !== 32) throw new TypeError('confirmedTranscriptHash must contain 32 bytes')
  if (view.version !== 1 || (view.previousViewHash !== null && !VIEW_HASH.test(view.previousViewHash))) throw new TypeError('invalid Vault group view')
  assertVaultMemberId(view.installerMemberId)
  if (!(view.signature instanceof Uint8Array) || view.signature.length !== 64) throw new TypeError('group view signature must contain 64 bytes')
  if (view.members.length === 0 || new Set(view.members.map(member => member.memberId)).size !== view.members.length) throw new TypeError('Vault group members must be non-empty and unique')
  for (const member of view.members) {
    assertVaultMemberId(member.memberId)
    assertDeliverySeq(member.deliveryFloor)
    if (!(member.signaturePublicKey instanceof Uint8Array) || member.signaturePublicKey.length !== 32) throw new TypeError('member signaturePublicKey must contain 32 bytes')
  }
  if (!view.members.some(member => member.memberId === view.installerMemberId)) throw new TypeError('installer must be a member of the installed view')
}

function wireValue(view: Omit<VaultGroupViewV1, 'signature'> | VaultGroupViewV1, includeSignature: boolean): CanonicalValue {
  const value: Record<string, CanonicalValue> = {
    version: 1,
    vaultId: view.vaultId,
    groupId: bytesToBase64url(view.groupId),
    groupEpoch: view.groupEpoch,
    confirmedTranscriptHash: bytesToBase64url(view.confirmedTranscriptHash),
    previousViewHash: view.previousViewHash,
    members: view.members.map(member => ({ memberId: member.memberId, signaturePublicKey: bytesToBase64url(member.signaturePublicKey), deliveryFloor: member.deliveryFloor })),
    installerMemberId: view.installerMemberId,
  }
  if (includeSignature && 'signature' in view) value.signature = bytesToBase64url(view.signature)
  return value
}

function exactRecord(value: unknown, keys: string[], name: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError(`${name} must be an object`)
  const record = value as Record<string, unknown>
  const actual = Object.keys(record).sort()
  const expected = [...keys].sort()
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) throw new TypeError(`${name} has unexpected fields`)
  return record
}

function binary(value: unknown, name: string, length: number): Uint8Array {
  if (typeof value !== 'string') throw new TypeError(`${name} must be base64url`)
  const result = base64urlToBytes(value)
  if (result.length !== length) throw new TypeError(`${name} must contain ${length} bytes`)
  return result
}
