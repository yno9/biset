// The verify-then-decrypt step shared by every consumer of this identity's
// vault events/objects that ends up feeding `reduceLocalJmapProjection`
// (local-jmap/reducer.ts) -- `VaultDeliveryProjector` (delivery-projector.ts,
// one delivered pack at a time) and `rebuildLocalJmapProjection`
// (projection-rebuild.ts, this identity's entire history at once). Both used
// to carry their own copy of this loop; factored out here so the two never
// drift on what counts as a valid mutation event (feedback: unify common
// logic instead of letting near-identical implementations diverge).
import type { IdentityId, SegmentId } from '../shared/protocol/ids.ts'
import type { VaultEventV1, VaultObjectV1 } from '../shared/protocol/vault.ts'
import { decryptVaultObject, verifyVaultObjectIntegrity } from './objects.ts'
import { assertContactKeyRecord } from './contact-key.ts'
import { assertDidCommCredentialRecord } from './didcomm-credential.ts'
import { assertDidCommDeviceKeyRecord } from './didcomm-device-key.ts'
import { assertOpenPgpCredentialRecord } from './openpgp-credential.ts'
import { verifyVaultEvent, type VaultEventVerifier } from './events.ts'
import type { SegmentKeyResolver } from './segment-key-resolver.ts'
import type { DecryptedMutationRecord } from '../local-jmap/reducer.ts'

/**
 * Checks every object's content-addressed integrity and every event's
 * signature before decrypting anything, resolves each referenced segment's
 * key at most once. Private credential/key records use their dedicated
 * validators and never feed the JMAP projection reducer; ordinary mutation
 * objects are returned for projection. Fails closed (an exception, not a
 * partial result) the instant any object or event does not check out.
 */
export async function decryptVaultMutationRecords(
  identityId: IdentityId,
  events: VaultEventV1[],
  objectList: VaultObjectV1[],
  resolver: SegmentKeyResolver,
  verifier: VaultEventVerifier,
): Promise<DecryptedMutationRecord[]> {
  const objects = objectMap(objectList)
  for (const object of objects.values()) {
    if (!(await verifyVaultObjectIntegrity(object))) throw new TypeError('vault object integrity is invalid')
  }
  const keys = new Map<SegmentId, Uint8Array>()
  try {
    const records: DecryptedMutationRecord[] = []
    for (const event of events) {
      if (!(await verifyVaultEvent(event, verifier))) throw new TypeError('vault event signature is invalid')
      const expectedObjectRefs = event.kind === 'message.add' ? 2 : 1
      if (event.objectRefs.length !== expectedObjectRefs) {
        throw new TypeError(event.kind === 'message.add'
          ? 'vault message.add must reference metadata and raw RFC 5322 objects'
          : 'vault mutation event must reference exactly one object')
      }
      const object = objects.get(event.objectRefs[0]!)
      if (!object) throw new TypeError('vault event references an absent object')
      if (event.kind === 'message.add' && !objects.has(event.objectRefs[1]!)) {
        throw new TypeError('vault message.add references an absent raw RFC 5322 object')
      }
      let key = keys.get(object.segmentId)
      if (!key) {
        key = await resolver.resolveSegmentKey(identityId, object.segmentId)
        keys.set(object.segmentId, key)
      }
      const plaintext = await decryptVaultObject(key, object)
      if (event.kind === 'credential.openpgp.set') {
        assertOpenPgpCredentialRecord(event, object, plaintext)
      } else if (event.kind === 'credential.didcomm.set') {
        assertDidCommCredentialRecord(event, object, plaintext)
      } else if (event.kind === 'didcomm.device-key.set') {
        assertDidCommDeviceKeyRecord(event, object, plaintext)
      } else if (event.kind === 'contact-key.set') {
        assertContactKeyRecord(event, object, plaintext)
      } else {
        records.push({ event, plaintext })
      }
    }
    return records
  } finally {
    for (const key of keys.values()) key.fill(0)
  }
}

function objectMap(objects: VaultObjectV1[]): Map<string, VaultObjectV1> {
  const values = new Map<string, VaultObjectV1>()
  for (const object of objects) {
    if (values.has(object.objectId)) throw new TypeError('vault object list has a duplicate object ID')
    values.set(object.objectId, object)
  }
  return values
}
