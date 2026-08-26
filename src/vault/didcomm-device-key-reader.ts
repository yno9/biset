import type { IdentityId, SegmentId } from '../protocol/ids.ts'
import { decryptVaultObject } from './objects.ts'
import { assertDidCommDeviceKeyRecord, type DidCommDeviceKeyV1 } from './didcomm-device-key.ts'
import type { SegmentKeyResolver } from './segment-key-resolver.ts'
import type { VaultObjectReader, VaultRecordReader } from './store.ts'
import { verifyVaultEvent, type VaultEventVerifier } from './events.ts'

export interface DidCommDeviceKeyReaderOptions {
  identityId: IdentityId
  objects: VaultObjectReader
  events: VaultRecordReader
  segmentKeys: SegmentKeyResolver
  verifier: VaultEventVerifier
}

/**
 * Endpoint-only reader for the (deviceKid, didCommKid) pairings held in the
 * encrypted vault -- see didcomm-device-key.ts's own header. The only
 * caller is revokeDevice (main.ts), looking up the DIDComm key a specific
 * MLS device kid minted so it can be removed from routing.json too.
 */
export class DidCommDeviceKeyReader {
  constructor(private readonly options: DidCommDeviceKeyReaderOptions) {
    if (!options.identityId) throw new TypeError('DIDComm device-key reader identity is required')
  }

  /** Every verified pairing this device currently knows about. */
  async readAll(): Promise<DidCommDeviceKeyV1[]> {
    const events = (await this.options.events.readVaultEvents(this.options.identityId))
      .filter(event => event.kind === 'didcomm.device-key.set')
    const keys = new Map<SegmentId, Uint8Array>()
    try {
      const records: DidCommDeviceKeyV1[] = []
      for (const event of events) {
        if (!(await verifyVaultEvent(event, this.options.verifier))) throw new TypeError('DIDComm device-key event signature is invalid')
        if (event.objectRefs.length !== 1) throw new TypeError('DIDComm device-key event must reference exactly one object')
        const object = await this.options.objects.readObject(this.options.identityId, event.objectRefs[0])
        if (!object) throw new Error('DIDComm device-key object is unavailable; restore is required')
        let segmentKey = keys.get(object.segmentId)
        if (!segmentKey) {
          segmentKey = await this.options.segmentKeys.resolveSegmentKey(this.options.identityId, object.segmentId)
          keys.set(object.segmentId, segmentKey)
        }
        records.push(assertDidCommDeviceKeyRecord(event, object, await decryptVaultObject(segmentKey, object)))
      }
      return records
    } finally {
      for (const key of keys.values()) key.fill(0)
    }
  }

  /** The pairing for one specific MLS device kid, or undefined if none is known yet. */
  async forDeviceKid(deviceKid: string): Promise<DidCommDeviceKeyV1 | undefined> {
    return (await this.readAll()).find(record => record.deviceKid === deviceKid)
  }
}
