// Records, once per device, the private link between this identity's MLS
// self-group device kid (self-group.ts's own `#device-{hex}`) and the
// DIDComm keyAgreement kid that same device minted
// (identity/bootstrap.ts's enableDidComm, devicekid.ts's deviceKidFragment)
// -- written to the encrypted vault, never to routing.json.
//
// Why not routing.json: that document is resolved by anyone on the
// internet (webvh-routing.ts's didToRoutingUrl fetches it over plain
// HTTPS, no auth). Recording "this DIDComm key belongs to that specific MLS
// device" there would make a correlation publicly provable that today only
// a passive traffic observer could infer (from a DIDComm JWE's own
// unencrypted `kid` header). Keeping it in the vault instead means only
// this identity's own currently-trusted devices (MLS self-group members,
// via the same vault-epoch-key boundary every other vault object uses) can
// ever read the pairing; a revoked device loses access to future pairings
// the same way it loses access to any other new vault content.
//
// The only reader is revokeDevice (main.ts): given a target MLS device kid,
// look up its didCommKid here, then remove that one entry from
// routing.json. Modeled at the shape level on
// vault/openpgp-credential.ts's credential.openpgp.set (same "write once
// per device, read back across devices via the vault" pattern), trimmed of
// its rotation/supersedes machinery -- there is nothing to rotate here,
// only one pairing per device for as long as that device exists.
import { canonicalBytes, equalBytes } from '../protocol/canonical.ts'
import type { DeviceId, IdentityId, SegmentId, VaultEventId } from '../protocol/ids.ts'
import type { VaultEventV1, VaultObjectV1 } from '../protocol/vault.ts'
import { createVaultEvent, type VaultEventSigner } from './events.ts'
import { encryptVaultObject } from './objects.ts'
import type { VaultCredentialKind } from './credential-store.ts'
import type { VaultRecordReader } from './store.ts'

export interface DidCommDeviceKeyV1 {
  version: 1
  kind: 'didcomm.device-key'
  identityId: IdentityId
  /** This identity's MLS self-group device kid, e.g. `did:webvh:...#device-<hex>`. */
  deviceKid: string
  /** The routing.json keyAgreement verification-method id that same device minted, e.g. `did:webvh:...#k_<hash>`. */
  didCommKid: string
  createdAt: string
}

export interface DeviceKeyBuildContext {
  identityId: IdentityId
  actorDeviceId: DeviceId
  actorSeq: number
  parents: VaultEventId[]
  segmentId: SegmentId
  segmentKey: Uint8Array
}

export interface DeviceKeyRecord {
  key: DidCommDeviceKeyV1
  object: VaultObjectV1
  event: VaultEventV1
}

export function encodeDidCommDeviceKey(value: DidCommDeviceKeyV1): Uint8Array {
  assertDeviceKey(value)
  return canonicalBytes({
    version: value.version,
    kind: value.kind,
    identityId: value.identityId,
    deviceKid: value.deviceKid,
    didCommKid: value.didCommKid,
    createdAt: value.createdAt,
  })
}

export function decodeDidCommDeviceKey(bytes: Uint8Array): DidCommDeviceKeyV1 {
  let input: unknown
  try { input = JSON.parse(new TextDecoder().decode(bytes)) } catch { throw new TypeError('DIDComm device-key record is not JSON') }
  if (input === null || typeof input !== 'object' || Array.isArray(input)) throw new TypeError('DIDComm device-key record must be an object')
  const value = input as Record<string, unknown>
  if (
    value.version !== 1 || value.kind !== 'didcomm.device-key' ||
    typeof value.identityId !== 'string' || typeof value.deviceKid !== 'string' ||
    typeof value.didCommKid !== 'string' || typeof value.createdAt !== 'string'
  ) throw new TypeError('DIDComm device-key record shape is invalid')
  const key: DidCommDeviceKeyV1 = {
    version: 1, kind: 'didcomm.device-key', identityId: value.identityId,
    deviceKid: value.deviceKid, didCommKid: value.didCommKid, createdAt: value.createdAt,
  }
  if (!equalBytes(bytes, encodeDidCommDeviceKey(key))) throw new TypeError('DIDComm device-key record is not canonical')
  return key
}

/** Builds the encrypted record object and its signed vault event. */
export async function buildDidCommDeviceKeyRecord(
  key: DidCommDeviceKeyV1,
  context: DeviceKeyBuildContext,
  signer: VaultEventSigner,
): Promise<DeviceKeyRecord> {
  assertDeviceKey(key)
  if (
    context.identityId !== key.identityId || context.actorDeviceId !== signer.deviceId ||
    !context.segmentId || context.segmentKey.length !== 32
  ) throw new TypeError('DIDComm device-key build context is invalid')
  const object = await encryptVaultObject(context.segmentKey, {
    segmentId: context.segmentId,
    plaintext: encodeDidCommDeviceKey(key),
    aad: deviceKeyAad(context.identityId, context.segmentId, key.deviceKid),
  })
  const event = await createVaultEvent({
    identityId: context.identityId,
    actorDeviceId: context.actorDeviceId,
    actorSeq: context.actorSeq,
    kind: 'didcomm.device-key.set',
    targetIds: [key.deviceKid],
    objectRefs: [object.objectId],
    parents: [...context.parents],
    createdAt: key.createdAt,
  }, signer)
  return { key: { ...key }, object, event }
}

export function deviceKeyAad(identityId: IdentityId, segmentId: SegmentId, deviceKid: string): Uint8Array {
  return canonicalBytes({ label: 'biset/vault/didcomm/device-key/aad/v1', identityId, segmentId, deviceKid })
}

/** Confirms a decrypted record belongs to its signed vault event/object. */
export function assertDidCommDeviceKeyRecord(event: VaultEventV1, object: VaultObjectV1, plaintext: Uint8Array): DidCommDeviceKeyV1 {
  if (event.kind !== 'didcomm.device-key.set' || event.objectRefs.length !== 1 || event.objectRefs[0] !== object.objectId) {
    throw new TypeError('DIDComm device-key event does not reference its object')
  }
  const key = decodeDidCommDeviceKey(plaintext)
  if (
    key.identityId !== event.identityId || key.createdAt !== event.createdAt ||
    event.targetIds.length !== 1 || event.targetIds[0] !== key.deviceKid ||
    !equalBytes(object.aad, deviceKeyAad(key.identityId, object.segmentId, key.deviceKid))
  ) {
    throw new TypeError('DIDComm device-key record metadata does not match')
  }
  return key
}

function assertDeviceKey(value: DidCommDeviceKeyV1): void {
  if (!value.identityId || value.kind !== 'didcomm.device-key' || !value.deviceKid || !value.didCommKid || Number.isNaN(Date.parse(value.createdAt))) {
    throw new TypeError('DIDComm device-key record is invalid')
  }
}

/** Descriptor consumed by vault/credential-store.ts's generic reader and sink. */
export const didCommDeviceKeyKind: VaultCredentialKind<DidCommDeviceKeyV1, VaultRecordReader> = {
  eventKind: 'didcomm.device-key.set',
  label: 'DIDComm device-key',
  // `assertActiveVaultSegment`'s purpose string has always spelled this
  // one "device key"; the error-message noun spells it "device-key".
  segmentLabel: 'DIDComm device key',
  readEvents: (events, identityId) => events.readVaultEvents(identityId),
  assert: assertDidCommDeviceKeyRecord,
  build: buildDidCommDeviceKeyRecord,
  createdAtOf: value => value.createdAt,
  copy: value => ({ ...value }),
}
