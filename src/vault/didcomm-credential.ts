// Identity-shared DIDComm keyAgreement credential -- same pattern as
// vault/openpgp-credential.ts, for the same reason (openpgp-credential.ts's
// own header): a private key synced identity-wide to every trusted device
// via the ordinary vault delivery pipeline, rather than one per device.
//
// This replaces the earlier per-device didCommKid scheme (identity/
// bootstrap.ts's enableDidComm used to mint a fresh X25519 keypair on EVERY
// device). That scheme meant a sender had to pick exactly one of the
// recipient's several published keyAgreement keys and hope some device
// eventually claimed the shared ingress item addressed to it -- workable
// only because the shared ingress store lets any trusted device attempt the
// claim, not because any specific device was guaranteed to be listening.
// Sharing the actual private key means EVERY device can decrypt the SAME
// ciphertext, which is also the property a future blind mediator (ARC.md's
// DIDComm mediator redesign) needs: one registered kid, one Forward-wrapped
// copy, whichever device is polling picks it up.
import { base64urlToBytes, bytesToBase64url, canonicalBytes, equalBytes } from '../protocol/canonical.ts'
import type { DeviceId, IdentityId, SegmentId, VaultEventId } from '../protocol/ids.ts'
import type { VaultEventV1, VaultObjectV1 } from '../protocol/vault.ts'
import { createVaultEvent, type VaultEventSigner } from './events.ts'
import { encryptVaultObject } from './objects.ts'
import { x25519 } from '@noble/curves/ed25519.js'
import { deviceKidFragment } from '../didcomm/devicekid.ts'
import type { VaultCredentialKind } from './credential-store.ts'
import type { VaultCredentialEventReader } from './store.ts'

export interface DidCommPrivateCredentialV1 {
  version: 1
  kind: 'credential.didcomm.private'
  identityId: IdentityId
  /** The full DID URL this credential's public key resolves to
   * (`${identityId}${deviceKidFragment(publicKey)}`) -- self-verifying
   * against the private key below, same role openpgp-credential.ts's
   * `fingerprint` plays. */
  didCommKid: string
  /** 32-byte X25519 scalar. */
  privateKey: Uint8Array
  createdAt: string
  supersedesKid?: string
}

export interface DidCommCredentialBuildContext {
  identityId: IdentityId
  actorDeviceId: DeviceId
  actorSeq: number
  parents: VaultEventId[]
  segmentId: SegmentId
  segmentKey: Uint8Array
}

export interface DidCommCredentialRecord {
  credential: DidCommPrivateCredentialV1
  object: VaultObjectV1
  event: VaultEventV1
}

function encodeDidCommPrivateCredential(value: DidCommPrivateCredentialV1): Uint8Array {
  assertCredential(value)
  return canonicalBytes({
    version: value.version,
    kind: value.kind,
    identityId: value.identityId,
    didCommKid: value.didCommKid,
    privateKey: bytesToBase64url(value.privateKey),
    createdAt: value.createdAt,
    ...(value.supersedesKid === undefined ? {} : { supersedesKid: value.supersedesKid }),
  })
}

function decodeDidCommPrivateCredential(bytes: Uint8Array): DidCommPrivateCredentialV1 {
  let input: unknown
  try { input = JSON.parse(new TextDecoder().decode(bytes)) } catch { throw new TypeError('DIDComm credential is not JSON') }
  if (input === null || typeof input !== 'object' || Array.isArray(input)) throw new TypeError('DIDComm credential must be an object')
  const value = input as Record<string, unknown>
  if (value.version !== 1 || value.kind !== 'credential.didcomm.private' || typeof value.identityId !== 'string' || typeof value.didCommKid !== 'string' || typeof value.privateKey !== 'string' || typeof value.createdAt !== 'string' || (value.supersedesKid !== undefined && typeof value.supersedesKid !== 'string')) throw new TypeError('DIDComm credential shape is invalid')
  const credential: DidCommPrivateCredentialV1 = { version: 1, kind: 'credential.didcomm.private', identityId: value.identityId, didCommKid: value.didCommKid, privateKey: base64urlToBytes(value.privateKey), createdAt: value.createdAt, ...(value.supersedesKid === undefined ? {} : { supersedesKid: value.supersedesKid }) }
  if (!equalBytes(bytes, encodeDidCommPrivateCredential(credential))) throw new TypeError('DIDComm credential is not canonical')
  return credential
}

export async function buildDidCommPrivateCredential(
  credential: DidCommPrivateCredentialV1,
  context: DidCommCredentialBuildContext,
  signer: VaultEventSigner,
): Promise<DidCommCredentialRecord> {
  assertCredential(credential)
  if (context.identityId !== credential.identityId || context.actorDeviceId !== signer.deviceId || !context.segmentId || context.segmentKey.length !== 32) throw new TypeError('DIDComm credential build context is invalid')
  const object = await encryptVaultObject(context.segmentKey, {
    segmentId: context.segmentId,
    plaintext: encodeDidCommPrivateCredential(credential),
    aad: didCommCredentialAad(context.identityId, context.segmentId, credential.didCommKid),
  })
  const event = await createVaultEvent({
    identityId: context.identityId,
    actorDeviceId: context.actorDeviceId,
    actorSeq: context.actorSeq,
    kind: 'credential.didcomm.set',
    targetIds: [`didcomm:${credential.didCommKid}`],
    objectRefs: [object.objectId],
    parents: [...context.parents],
    createdAt: credential.createdAt,
  }, signer)
  return { credential: copyCredential(credential), object, event }
}

function didCommCredentialAad(identityId: IdentityId, segmentId: SegmentId, didCommKid: string): Uint8Array {
  return canonicalBytes({ label: 'biset/vault/credential/didcomm-private/aad/v1', identityId, segmentId, didCommKid })
}

export function assertDidCommCredentialRecord(event: VaultEventV1, object: VaultObjectV1, plaintext: Uint8Array): DidCommPrivateCredentialV1 {
  if (event.kind !== 'credential.didcomm.set' || event.objectRefs.length !== 1 || event.objectRefs[0] !== object.objectId) throw new TypeError('DIDComm credential event does not reference its object')
  const credential = decodeDidCommPrivateCredential(plaintext)
  if (credential.identityId !== event.identityId || credential.createdAt !== event.createdAt || event.targetIds.length !== 1 || event.targetIds[0] !== `didcomm:${credential.didCommKid}` || !equalBytes(object.aad, didCommCredentialAad(credential.identityId, object.segmentId, credential.didCommKid))) {
    throw new TypeError('DIDComm credential record metadata does not match')
  }
  return credential
}

function assertCredential(value: DidCommPrivateCredentialV1): void {
  if (!value.identityId || value.kind !== 'credential.didcomm.private' || value.privateKey.length !== 32 || Number.isNaN(Date.parse(value.createdAt))) throw new TypeError('DIDComm credential is invalid')
  if (value.supersedesKid !== undefined && value.supersedesKid === value.didCommKid) throw new TypeError('DIDComm credential cannot supersede itself')
  const expectedKid = `${value.identityId}${deviceKidFragment(x25519.getPublicKey(value.privateKey))}`
  if (value.didCommKid !== expectedKid) throw new TypeError('DIDComm credential kid does not match its private key')
}

function copyCredential(value: DidCommPrivateCredentialV1): DidCommPrivateCredentialV1 {
  return { ...value, privateKey: value.privateKey.slice() }
}

/** Descriptor consumed by vault/credential-store.ts's generic reader and sink. */
export const didCommCredentialKind: VaultCredentialKind<DidCommPrivateCredentialV1, VaultCredentialEventReader> = {
  eventKind: 'credential.didcomm.set',
  label: 'DIDComm credential',
  segmentLabel: 'DIDComm credential',
  readEvents: (events, identityId) => events.readCredentialEvents(identityId),
  assert: assertDidCommCredentialRecord,
  build: buildDidCommPrivateCredential,
  createdAtOf: value => value.createdAt,
  copy: copyCredential,
}
