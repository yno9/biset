import { base64urlToBytes, bytesToBase64url, canonicalBytes, equalBytes, type CanonicalValue } from '../protocol/canonical.ts'
import { assertMlsEpoch, type IdentityId } from '../protocol/ids.ts'
import { VAULT_EVENT_KINDS, type SegmentKeyWrapV1, type VaultEventV1 } from '../protocol/vault.ts'
import type { VaultObjectRecord } from './store.ts'

export interface VaultDeliveryPackV1 {
  version: 1
  identityId: IdentityId
  objects: VaultObjectRecord[]
  events: VaultEventV1[]
  keyWraps: SegmentKeyWrapV1[]
}

/** Canonical opaque body for one shared vault-delivery item. */
export function encodeVaultDeliveryPack(pack: VaultDeliveryPackV1): Uint8Array {
  assertPack(pack)
  return canonicalBytes({
    version: 1,
    identityId: pack.identityId,
    objects: pack.objects.map(objectToWire),
    events: pack.events.map(eventToWire),
    keyWraps: pack.keyWraps.map(wrapToWire),
  })
}

/** Rejects semantically equivalent but non-canonical encodings before unpacking. */
export function decodeVaultDeliveryPack(bytes: Uint8Array): VaultDeliveryPackV1 {
  let parsed: unknown
  try { parsed = JSON.parse(new TextDecoder().decode(bytes)) } catch { throw new TypeError('vault delivery pack is not JSON') }
  const pack = wireToPack(parsed)
  if (!equalBytes(bytes, encodeVaultDeliveryPack(pack))) throw new TypeError('vault delivery pack is not canonical')
  return pack
}

function objectToWire(object: VaultObjectRecord): { [key: string]: CanonicalValue } {
  return {
    version: object.version, identityId: object.identityId, objectId: object.objectId, segmentId: object.segmentId,
    nonce: bytesToBase64url(object.nonce), ciphertext: bytesToBase64url(object.ciphertext), ciphertextHash: bytesToBase64url(object.ciphertextHash),
    plaintextLength: object.plaintextLength, aad: bytesToBase64url(object.aad),
  }
}

function eventToWire(event: VaultEventV1): { [key: string]: CanonicalValue } {
  return {
    version: event.version, id: event.id, identityId: event.identityId, actorDeviceId: event.actorDeviceId, actorSeq: event.actorSeq,
    kind: event.kind, targetIds: [...event.targetIds], objectRefs: [...event.objectRefs], parents: [...event.parents], createdAt: event.createdAt,
    signature: bytesToBase64url(event.signature),
  }
}

function wrapToWire(wrap: SegmentKeyWrapV1): { [key: string]: CanonicalValue } {
  return {
    version: wrap.version, identityId: wrap.identityId, selfGroupId: wrap.selfGroupId, segmentId: wrap.segmentId,
    sourceEpoch: wrap.sourceEpoch, recipientEpoch: wrap.recipientEpoch, nonce: bytesToBase64url(wrap.nonce), aad: bytesToBase64url(wrap.aad),
    wrappedSegmentKey: bytesToBase64url(wrap.wrappedSegmentKey), grantorDeviceId: wrap.grantorDeviceId, grantedAt: wrap.grantedAt,
    signature: bytesToBase64url(wrap.signature),
  }
}

function wireToPack(value: unknown): VaultDeliveryPackV1 {
  const record = object(value, 'vault delivery pack')
  if (record.version !== 1 || typeof record.identityId !== 'string' || !record.identityId) throw new TypeError('vault delivery pack header is invalid')
  if (!Array.isArray(record.objects) || !Array.isArray(record.events) || !Array.isArray(record.keyWraps)) throw new TypeError('vault delivery pack lists are invalid')
  const identityId = record.identityId
  return {
    version: 1,
    identityId,
    objects: record.objects.map(value => wireObject(value, identityId)),
    events: record.events.map(value => wireEvent(value, identityId)),
    keyWraps: record.keyWraps.map(value => wireWrap(value, identityId)),
  }
}

function wireObject(value: unknown, identityId: IdentityId): VaultObjectRecord {
  const input = object(value, 'vault delivery object')
  if (input.version !== 1 || input.identityId !== identityId || !nonempty(input.objectId) || !nonempty(input.segmentId) || !Number.isSafeInteger(input.plaintextLength) || (input.plaintextLength as number) < 0) throw new TypeError('vault delivery object is invalid')
  return { version: 1, identityId, objectId: input.objectId, segmentId: input.segmentId, nonce: binary(input.nonce), ciphertext: binary(input.ciphertext), ciphertextHash: binary(input.ciphertextHash), plaintextLength: input.plaintextLength as number, aad: binary(input.aad) }
}

function wireEvent(value: unknown, identityId: IdentityId): VaultEventV1 {
  const input = object(value, 'vault delivery event')
  if (input.version !== 1 || input.identityId !== identityId || !nonempty(input.id) || !nonempty(input.actorDeviceId) || !eventKind(input.kind) || !Number.isSafeInteger(input.actorSeq) || (input.actorSeq as number) < 0 || !isoDate(input.createdAt)) throw new TypeError('vault delivery event is invalid')
  return { version: 1, id: input.id, identityId, actorDeviceId: input.actorDeviceId, actorSeq: input.actorSeq as number, kind: input.kind as VaultEventV1['kind'], targetIds: strings(input.targetIds), objectRefs: strings(input.objectRefs), parents: strings(input.parents), createdAt: input.createdAt, signature: binary(input.signature) }
}

function wireWrap(value: unknown, identityId: IdentityId): SegmentKeyWrapV1 {
  const input = object(value, 'vault delivery key wrap')
  for (const key of ['selfGroupId', 'segmentId', 'sourceEpoch', 'recipientEpoch', 'grantorDeviceId', 'grantedAt']) if (!nonempty(input[key])) throw new TypeError('vault delivery key wrap is invalid')
  if (input.version !== 1 || input.identityId !== identityId) throw new TypeError('vault delivery key wrap is invalid')
  assertMlsEpoch(input.sourceEpoch)
  assertMlsEpoch(input.recipientEpoch)
  if (!isoDate(input.grantedAt)) throw new TypeError('vault delivery key wrap is invalid')
  return { version: 1, identityId, selfGroupId: input.selfGroupId as string, segmentId: input.segmentId as string, sourceEpoch: input.sourceEpoch as string, recipientEpoch: input.recipientEpoch as string, nonce: binary(input.nonce), aad: binary(input.aad), wrappedSegmentKey: binary(input.wrappedSegmentKey), grantorDeviceId: input.grantorDeviceId as string, grantedAt: input.grantedAt as string, signature: binary(input.signature) }
}

function object(value: unknown, name: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError(`${name} must be an object`)
  return value as Record<string, unknown>
}
function binary(value: unknown): Uint8Array { if (typeof value !== 'string') throw new TypeError('vault delivery binary value is invalid'); return base64urlToBytes(value) }
function strings(value: unknown): string[] { if (!Array.isArray(value) || value.some(value => typeof value !== 'string' || !value)) throw new TypeError('vault delivery string list is invalid'); return [...value] }
function nonempty(value: unknown): value is string { return typeof value === 'string' && value.length > 0 }
function isoDate(value: unknown): value is string { return nonempty(value) && !Number.isNaN(Date.parse(value)) }
function eventKind(value: unknown): value is VaultEventV1['kind'] {
  return typeof value === 'string' && (VAULT_EVENT_KINDS as readonly string[]).includes(value)
}

function assertPack(pack: VaultDeliveryPackV1): void {
  if (!pack.identityId) throw new TypeError('vault delivery pack identity is required')
  for (const object of pack.objects) if (object.identityId !== pack.identityId) throw new TypeError('vault delivery object identity does not match pack')
  for (const event of pack.events) if (event.identityId !== pack.identityId) throw new TypeError('vault delivery event identity does not match pack')
  for (const wrap of pack.keyWraps) if (wrap.identityId !== pack.identityId) throw new TypeError('vault delivery key wrap identity does not match pack')
}
