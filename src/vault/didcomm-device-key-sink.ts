import { sha256Bytes } from '../protocol/canonical.ts'
import type { LocalJmapProjectionV1, LocalJmapSnapshot } from '../local-jmap/gateway.ts'
import type { VaultEventSigner } from './events.ts'
import { encodeVaultDeliveryPack } from './delivery-pack.ts'
import { buildDidCommDeviceKeyRecord, type DeviceKeyBuildContext, type DidCommDeviceKeyV1 } from './didcomm-device-key.ts'
import type { LocalVaultMutationCommitter } from '../local-jmap/vault-mutation-sink.ts'
import { assertActiveVaultSegment, type ActiveVaultSegment } from './active-segment.ts'
import type { DeviceId, IdentityId, VaultEventId } from '../protocol/ids.ts'
import type { VaultEventV1 } from '../protocol/vault.ts'

export interface DidCommDeviceKeyVaultSinkOptions {
  identityId: IdentityId
  actorDeviceId: DeviceId
  nextActorSeq(): Promise<number>
  initialParents(): Promise<VaultEventId[]>
  activeSegment(): Promise<ActiveVaultSegment>
  currentSnapshot(): Promise<LocalJmapSnapshot>
  signer: VaultEventSigner
  committer: LocalVaultMutationCommitter
}

export interface DidCommDeviceKeyStoreResult {
  result: 'committed' | 'already-committed'
  event: VaultEventV1
}

/**
 * Writes this device's own (deviceKid, didCommKid) pairing through the same
 * atomic local-vault and shared-delivery outbox path as normal vault
 * changes, so every other trusted device eventually sees it too. Leaves the
 * user-visible JMAP projection unchanged -- see didcomm-device-key.ts's own
 * header for why this lives in the vault rather than routing.json.
 */
export class DidCommDeviceKeyVaultSink {
  constructor(private readonly options: DidCommDeviceKeyVaultSinkOptions) {
    if (!options.identityId || !options.actorDeviceId) throw new TypeError('DIDComm device-key sink identity is required')
  }

  async store(key: DidCommDeviceKeyV1): Promise<DidCommDeviceKeyStoreResult> {
    const segment = await this.options.activeSegment()
    assertActiveVaultSegment(this.options.identityId, segment, 'DIDComm device key')
    const record = await buildDidCommDeviceKeyRecord(key, {
      identityId: this.options.identityId,
      actorDeviceId: this.options.actorDeviceId,
      actorSeq: await this.options.nextActorSeq(),
      parents: await this.options.initialParents(),
      segmentId: segment.segmentId,
      segmentKey: segment.segmentKey,
    } satisfies DeviceKeyBuildContext, this.options.signer)
    const snapshot = await this.options.currentSnapshot()
    const projection: LocalJmapProjectionV1 = { version: 1, identityId: this.options.identityId, state: snapshot.state, mailboxes: snapshot.mailboxes, emails: snapshot.emails }
    const object = { ...record.object, identityId: this.options.identityId }
    const payload = encodeVaultDeliveryPack({ version: 1, identityId: this.options.identityId, objects: [object], events: [record.event], keyWraps: segment.keyWraps })
    const result = await this.options.committer.commitLocalMutation({
      identityId: this.options.identityId,
      objects: [object],
      events: [record.event],
      projection,
      jmapState: { state: projection.state },
      deliveryOutbox: { identityId: this.options.identityId, entryId: record.event.id, payload, payloadHash: sha256Bytes(payload), createdAt: key.createdAt, attempts: 0 },
    })
    return { result, event: record.event }
  }
}
