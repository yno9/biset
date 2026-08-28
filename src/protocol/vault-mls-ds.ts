import { base64urlToBytes, bytesToBase64url, canonicalBytes, sha256Bytes } from './canonical.ts'
import { assertMlsEpoch, assertVaultId, assertVaultMemberId, type MlsEpoch, type VaultId, type VaultMemberId } from './ids.ts'
import { decodeVaultGroupView, encodeVaultGroupView, vaultGroupViewHash, type VaultGroupViewV1 } from './vault-group-view.ts'

export interface VaultMlsKeyPackagePublishV1 {
  version: 1
  vaultId: VaultId
  memberId: VaultMemberId
  signaturePublicKey: Uint8Array
  keyPackage: Uint8Array
  publishedAt: string
  signature: Uint8Array
}

export interface VaultMlsMemberRequestV1 {
  version: 1
  vaultId: VaultId
  memberId: VaultMemberId
  afterEpoch: MlsEpoch
  requestedAt: string
  signature: Uint8Array
}

export interface VaultMlsWelcomeV1 { memberId: VaultMemberId; payload: Uint8Array }

export interface VaultMlsTransitionV1 {
  version: 1
  groupView: VaultGroupViewV1
  commit: Uint8Array
  welcomes: VaultMlsWelcomeV1[]
  submittedAt: string
  signature: Uint8Array
}

export interface VaultMlsTransitionItemV1 {
  groupView: VaultGroupViewV1
  commit: Uint8Array
  createdAt: string
}

export interface VaultMlsWelcomeDeliveryV1 { groupView: VaultGroupViewV1; welcome: Uint8Array; createdAt: string }
export interface VaultMlsInvitationRedeemV1 { version: 1; invitation: string; redeemedAt: string }
export interface VaultMlsInvitationV1 { invitation: string; expiresAt: string }

export function vaultMlsKeyPackageSigningBytes(value: Omit<VaultMlsKeyPackagePublishV1, 'signature'> | VaultMlsKeyPackagePublishV1): Uint8Array {
  return canonicalBytes({ version: 1, vaultId: value.vaultId, memberId: value.memberId, signaturePublicKey: bytesToBase64url(value.signaturePublicKey), keyPackageHash: bytesToBase64url(sha256Bytes(value.keyPackage)), publishedAt: value.publishedAt })
}

export function vaultMlsMemberRequestSigningBytes(value: Omit<VaultMlsMemberRequestV1, 'signature'> | VaultMlsMemberRequestV1): Uint8Array {
  return canonicalBytes({ version: 1, vaultId: value.vaultId, memberId: value.memberId, afterEpoch: value.afterEpoch, requestedAt: value.requestedAt })
}

export function vaultMlsTransitionSigningBytes(value: Omit<VaultMlsTransitionV1, 'signature'> | VaultMlsTransitionV1): Uint8Array {
  return canonicalBytes({
    version: 1,
    groupViewHash: vaultGroupViewHash(value.groupView),
    commitHash: bytesToBase64url(sha256Bytes(value.commit)),
    welcomes: value.welcomes.map(welcome => ({ memberId: welcome.memberId, payloadHash: bytesToBase64url(sha256Bytes(welcome.payload)) })),
    submittedAt: value.submittedAt,
  })
}

export function encodeVaultMlsKeyPackage(value: VaultMlsKeyPackagePublishV1): string {
  return JSON.stringify({ ...value, signaturePublicKey: bytesToBase64url(value.signaturePublicKey), keyPackage: bytesToBase64url(value.keyPackage), signature: bytesToBase64url(value.signature) })
}

export function decodeVaultMlsKeyPackage(text: string): VaultMlsKeyPackagePublishV1 {
  const value = exactJson(text, ['version', 'vaultId', 'memberId', 'signaturePublicKey', 'keyPackage', 'publishedAt', 'signature'])
  if (value.version !== 1) throw new TypeError('invalid Vault MLS KeyPackage version')
  assertVaultId(value.vaultId); assertVaultMemberId(value.memberId); timestamp(value.publishedAt, 'publishedAt')
  return { version: 1, vaultId: value.vaultId, memberId: value.memberId, signaturePublicKey: binary(value.signaturePublicKey, 32, 32, 'signaturePublicKey'), keyPackage: binary(value.keyPackage, 1, 1024 * 1024, 'keyPackage'), publishedAt: value.publishedAt, signature: binary(value.signature, 64, 64, 'signature') }
}

export function encodeVaultMlsKeyPackageList(values: VaultMlsKeyPackagePublishV1[]): string {
  return JSON.stringify({ packages: values.map(value => JSON.parse(encodeVaultMlsKeyPackage(value))) })
}

export function decodeVaultMlsKeyPackageList(text: string): VaultMlsKeyPackagePublishV1[] {
  const value = exactJson(text, ['packages'])
  if (!Array.isArray(value.packages)) throw new TypeError('Vault MLS KeyPackage list is invalid')
  return value.packages.map(item => decodeVaultMlsKeyPackage(JSON.stringify(item)))
}

export function encodeVaultMlsMemberRequest(value: VaultMlsMemberRequestV1): string {
  return JSON.stringify({ ...value, signature: bytesToBase64url(value.signature) })
}

export function decodeVaultMlsMemberRequest(text: string): VaultMlsMemberRequestV1 {
  const value = exactJson(text, ['version', 'vaultId', 'memberId', 'afterEpoch', 'requestedAt', 'signature'])
  if (value.version !== 1) throw new TypeError('invalid Vault MLS member request version')
  assertVaultId(value.vaultId); assertVaultMemberId(value.memberId); assertMlsEpoch(value.afterEpoch); timestamp(value.requestedAt, 'requestedAt')
  return { version: 1, vaultId: value.vaultId, memberId: value.memberId, afterEpoch: value.afterEpoch, requestedAt: value.requestedAt, signature: binary(value.signature, 64, 64, 'signature') }
}

export function encodeVaultMlsTransition(value: VaultMlsTransitionV1): string {
  return JSON.stringify({ version: 1, groupView: JSON.parse(encodeVaultGroupView(value.groupView)), commit: bytesToBase64url(value.commit), welcomes: value.welcomes.map(item => ({ memberId: item.memberId, payload: bytesToBase64url(item.payload) })), submittedAt: value.submittedAt, signature: bytesToBase64url(value.signature) })
}

export function decodeVaultMlsTransition(text: string): VaultMlsTransitionV1 {
  const value = exactJson(text, ['version', 'groupView', 'commit', 'welcomes', 'submittedAt', 'signature'])
  if (value.version !== 1 || !Array.isArray(value.welcomes)) throw new TypeError('invalid Vault MLS transition')
  const groupView = decodeVaultGroupView(JSON.stringify(value.groupView))
  const welcomes = value.welcomes.map(entry => {
    const item = exactRecord(entry, ['memberId', 'payload'], 'Vault MLS Welcome')
    assertVaultMemberId(item.memberId)
    return { memberId: item.memberId, payload: binary(item.payload, 1, 4 * 1024 * 1024, 'Welcome payload') }
  })
  if (new Set(welcomes.map(item => item.memberId)).size !== welcomes.length) throw new TypeError('Vault MLS Welcome recipients must be unique')
  timestamp(value.submittedAt, 'submittedAt')
  return { version: 1, groupView, commit: binary(value.commit, 1, 4 * 1024 * 1024, 'MLS commit'), welcomes, submittedAt: value.submittedAt, signature: binary(value.signature, 64, 64, 'signature') }
}

export function encodeVaultMlsTransitionItems(items: VaultMlsTransitionItemV1[]): string {
  return JSON.stringify({ items: items.map(item => ({ groupView: JSON.parse(encodeVaultGroupView(item.groupView)), commit: bytesToBase64url(item.commit), createdAt: item.createdAt })) })
}

export function decodeVaultMlsTransitionItems(text: string): VaultMlsTransitionItemV1[] {
  const value = exactJson(text, ['items'])
  if (!Array.isArray(value.items)) throw new TypeError('Vault MLS transition response is invalid')
  return value.items.map(entry => {
    const item = exactRecord(entry, ['groupView', 'commit', 'createdAt'], 'Vault MLS transition item')
    timestamp(item.createdAt, 'createdAt')
    return { groupView: decodeVaultGroupView(JSON.stringify(item.groupView)), commit: binary(item.commit, 1, 4 * 1024 * 1024, 'MLS commit'), createdAt: item.createdAt }
  })
}

export function encodeVaultMlsWelcomeDelivery(value: VaultMlsWelcomeDeliveryV1 | null): string {
  return value === null ? JSON.stringify({ welcome: null }) : JSON.stringify({ welcome: { groupView: JSON.parse(encodeVaultGroupView(value.groupView)), payload: bytesToBase64url(value.welcome), createdAt: value.createdAt } })
}

export function decodeVaultMlsWelcomeDelivery(text: string): VaultMlsWelcomeDeliveryV1 | null {
  const value = exactJson(text, ['welcome'])
  if (value.welcome === null) return null
  const item = exactRecord(value.welcome, ['groupView', 'payload', 'createdAt'], 'Vault MLS Welcome delivery')
  timestamp(item.createdAt, 'createdAt')
  return { groupView: decodeVaultGroupView(JSON.stringify(item.groupView)), welcome: binary(item.payload, 1, 4 * 1024 * 1024, 'Welcome payload'), createdAt: item.createdAt }
}

export function encodeVaultMlsInvitationRedeem(value: VaultMlsInvitationRedeemV1): string { assertInvitation(value.invitation); timestamp(value.redeemedAt, 'redeemedAt'); return JSON.stringify(value) }
export function decodeVaultMlsInvitationRedeem(text: string): VaultMlsInvitationRedeemV1 { const value = exactJson(text, ['version', 'invitation', 'redeemedAt']); if (value.version !== 1) throw new TypeError('invalid Vault invitation version'); assertInvitation(value.invitation); timestamp(value.redeemedAt, 'redeemedAt'); return { version: 1, invitation: value.invitation, redeemedAt: value.redeemedAt } }
export function encodeVaultMlsInvitation(value: VaultMlsInvitationV1): string { assertInvitation(value.invitation); timestamp(value.expiresAt, 'expiresAt'); return JSON.stringify(value) }
export function decodeVaultMlsInvitation(text: string): VaultMlsInvitationV1 { const value = exactJson(text, ['invitation', 'expiresAt']); assertInvitation(value.invitation); timestamp(value.expiresAt, 'expiresAt'); return { invitation: value.invitation, expiresAt: value.expiresAt } }
export function encodeVaultMlsInvitationRedemption(value: { vaultId: VaultId }): string { assertVaultId(value.vaultId); return JSON.stringify(value) }
export function decodeVaultMlsInvitationRedemption(text: string): { vaultId: VaultId } { const value = exactJson(text, ['vaultId']); assertVaultId(value.vaultId); return { vaultId: value.vaultId } }

function exactJson(text: string, keys: string[]): Record<string, unknown> { let value: unknown; try { value = JSON.parse(text) } catch { throw new TypeError('Vault MLS body is not JSON') }; return exactRecord(value, keys, 'Vault MLS body') }
function exactRecord(value: unknown, keys: string[], name: string): Record<string, unknown> { if (!value || typeof value !== 'object' || Array.isArray(value)) throw new TypeError(`${name} must be an object`); const record = value as Record<string, unknown>; const actual = Object.keys(record).sort(); const expected = [...keys].sort(); if (actual.length !== expected.length || actual.some((key, i) => key !== expected[i])) throw new TypeError(`${name} has unexpected fields`); return record }
function binary(value: unknown, min: number, max: number, name: string): Uint8Array { if (typeof value !== 'string') throw new TypeError(`${name} must be base64url`); const bytes = base64urlToBytes(value); if (bytes.length < min || bytes.length > max) throw new TypeError(`${name} has invalid length`); return bytes }
function timestamp(value: unknown, name: string): asserts value is string { if (typeof value !== 'string' || !Number.isFinite(Date.parse(value))) throw new TypeError(`${name} is invalid`) }
function assertInvitation(value: unknown): asserts value is string { if (typeof value !== 'string' || !/^vin_[A-Za-z0-9_-]{43}$/.test(value)) throw new TypeError('Vault invitation is invalid') }
