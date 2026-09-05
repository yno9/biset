import { base64urlToBytes, bytesToBase64url, canonicalBytes, equalBytes } from '../../../shared/protocol/canonical.ts'
import type { DeviceId, IdentityId, SegmentId, VaultEventId } from '../../../shared/protocol/ids.ts'
import type { VaultEventV1, VaultObjectV1 } from '../../../shared/protocol/vault.ts'
import { createVaultEvent, type VaultEventSigner } from './events.ts'
import { encryptVaultObject } from './objects.ts'
import type { VaultCredentialKind } from './credential-store.ts'
import type { VaultCredentialEventReader } from './store.ts'

export interface OpenPgpPrivateCredentialV1 {
  version: 1
  kind: 'credential.openpgp.private'
  identityId: IdentityId
  /** v4 (40 hex chars) or v6 (64 hex chars), normalized to uppercase. */
  fingerprint: string
  privateKey: Uint8Array
  createdAt: string
  supersedesFingerprint?: string
}

export interface OpenPgpCredentialBuildContext {
  identityId: IdentityId
  actorDeviceId: DeviceId
  actorSeq: number
  parents: VaultEventId[]
  segmentId: SegmentId
  segmentKey: Uint8Array
}

export interface OpenPgpCredentialRecord {
  credential: OpenPgpPrivateCredentialV1
  object: VaultObjectV1
  event: VaultEventV1
}

/** Encodes a private key only for an already encrypted endpoint vault object. */
function encodeOpenPgpPrivateCredential(value: OpenPgpPrivateCredentialV1): Uint8Array {
  assertCredential(value)
  return canonicalBytes({
    version: value.version,
    kind: value.kind,
    identityId: value.identityId,
    fingerprint: normalizeFingerprint(value.fingerprint),
    privateKey: bytesToBase64url(value.privateKey),
    createdAt: value.createdAt,
    ...(value.supersedesFingerprint === undefined ? {} : { supersedesFingerprint: normalizeFingerprint(value.supersedesFingerprint) }),
  })
}

/** Rejects non-canonical credential bytes before a decoded private key is used. */
export function decodeOpenPgpPrivateCredential(bytes: Uint8Array): OpenPgpPrivateCredentialV1 {
  let input: unknown
  try { input = JSON.parse(new TextDecoder().decode(bytes)) } catch { throw new TypeError('OpenPGP credential is not JSON') }
  if (input === null || typeof input !== 'object' || Array.isArray(input)) throw new TypeError('OpenPGP credential must be an object')
  const value = input as Record<string, unknown>
  if (value.version !== 1 || value.kind !== 'credential.openpgp.private' || typeof value.identityId !== 'string' || typeof value.fingerprint !== 'string' || typeof value.privateKey !== 'string' || typeof value.createdAt !== 'string' || (value.supersedesFingerprint !== undefined && typeof value.supersedesFingerprint !== 'string')) throw new TypeError('OpenPGP credential shape is invalid')
  const credential: OpenPgpPrivateCredentialV1 = { version: 1, kind: 'credential.openpgp.private', identityId: value.identityId, fingerprint: normalizeFingerprint(value.fingerprint), privateKey: base64urlToBytes(value.privateKey), createdAt: value.createdAt, ...(value.supersedesFingerprint === undefined ? {} : { supersedesFingerprint: normalizeFingerprint(value.supersedesFingerprint) }) }
  if (!equalBytes(bytes, encodeOpenPgpPrivateCredential(credential))) throw new TypeError('OpenPGP credential is not canonical')
  return credential
}

/** Builds the encrypted credential object and the signed rotation-capable event. */
export async function buildOpenPgpPrivateCredential(
  credential: OpenPgpPrivateCredentialV1,
  context: OpenPgpCredentialBuildContext,
  signer: VaultEventSigner,
): Promise<OpenPgpCredentialRecord> {
  assertCredential(credential)
  if (context.identityId !== credential.identityId || context.actorDeviceId !== signer.deviceId || !context.segmentId || context.segmentKey.length !== 32) throw new TypeError('OpenPGP credential build context is invalid')
  const fingerprint = normalizeFingerprint(credential.fingerprint)
  const object = await encryptVaultObject(context.segmentKey, {
    segmentId: context.segmentId,
    plaintext: encodeOpenPgpPrivateCredential(credential),
    aad: openPgpCredentialAad(context.identityId, context.segmentId, fingerprint),
  })
  const event = await createVaultEvent({
    identityId: context.identityId,
    actorDeviceId: context.actorDeviceId,
    actorSeq: context.actorSeq,
    kind: 'credential.openpgp.set',
    targetIds: [`openpgp:${fingerprint}`],
    objectRefs: [object.objectId],
    parents: [...context.parents],
    createdAt: credential.createdAt,
  }, signer)
  return { credential: copyCredential(credential), object, event }
}

export function openPgpCredentialAad(identityId: IdentityId, segmentId: SegmentId, fingerprint: string): Uint8Array {
  return canonicalBytes({ label: 'biset/vault/credential/openpgp-private/aad/v1', identityId, segmentId, fingerprint: normalizeFingerprint(fingerprint) })
}

/** Confirms a decrypted credential belongs to its signed vault event/object. */
export function assertOpenPgpCredentialRecord(event: VaultEventV1, object: VaultObjectV1, plaintext: Uint8Array): OpenPgpPrivateCredentialV1 {
  if (event.kind !== 'credential.openpgp.set' || event.objectRefs.length !== 1 || event.objectRefs[0] !== object.objectId) throw new TypeError('OpenPGP credential event does not reference its object')
  const credential = decodeOpenPgpPrivateCredential(plaintext)
  const fingerprint = normalizeFingerprint(credential.fingerprint)
  if (credential.identityId !== event.identityId || credential.createdAt !== event.createdAt || event.targetIds.length !== 1 || event.targetIds[0] !== `openpgp:${fingerprint}` || !equalBytes(object.aad, openPgpCredentialAad(credential.identityId, object.segmentId, fingerprint))) {
    throw new TypeError('OpenPGP credential record metadata does not match')
  }
  return credential
}

function assertCredential(value: OpenPgpPrivateCredentialV1): void {
  if (!value.identityId || value.kind !== 'credential.openpgp.private' || value.privateKey.length === 0 || value.privateKey.length > 5 * 1024 * 1024 || Number.isNaN(Date.parse(value.createdAt))) throw new TypeError('OpenPGP credential is invalid')
  const fingerprint = normalizeFingerprint(value.fingerprint)
  if (value.supersedesFingerprint !== undefined && normalizeFingerprint(value.supersedesFingerprint) === fingerprint) throw new TypeError('OpenPGP credential cannot supersede itself')
}

function normalizeFingerprint(value: string): string {
  const normalized = value.replace(/\s/g, '').toUpperCase()
  if (!/^(?:[0-9A-F]{40}|[0-9A-F]{64})$/.test(normalized)) throw new TypeError('OpenPGP fingerprint is invalid')
  return normalized
}

function copyCredential(value: OpenPgpPrivateCredentialV1): OpenPgpPrivateCredentialV1 {
  return { ...value, fingerprint: normalizeFingerprint(value.fingerprint), privateKey: value.privateKey.slice(), ...(value.supersedesFingerprint === undefined ? {} : { supersedesFingerprint: normalizeFingerprint(value.supersedesFingerprint) }) }
}

/** Descriptor consumed by vault/credential-store.ts's generic reader and sink. */
export const openPgpCredentialKind: VaultCredentialKind<OpenPgpPrivateCredentialV1, VaultCredentialEventReader> = {
  eventKind: 'credential.openpgp.set',
  label: 'OpenPGP credential',
  segmentLabel: 'OpenPGP credential',
  readEvents: (events, identityId) => events.readCredentialEvents(identityId),
  assert: assertOpenPgpCredentialRecord,
  build: buildOpenPgpPrivateCredential,
  createdAtOf: value => value.createdAt,
  copy: copyCredential,
}
