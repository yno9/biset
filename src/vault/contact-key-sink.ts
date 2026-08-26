import { sha256Bytes } from '../protocol/canonical.ts'
import type { LocalJmapProjectionV1, LocalJmapSnapshot } from '../local-jmap/gateway.ts'
import type { LocalVaultMutationCommitter } from '../local-jmap/vault-mutation-sink.ts'
import type { DeviceId, IdentityId, VaultEventId } from '../protocol/ids.ts'
import type { VaultEventV1 } from '../protocol/vault.ts'
import { assertActiveVaultSegment, type ActiveVaultSegment } from './active-segment.ts'
import { buildContactKeyRecord, type ContactKeyBuildContext, type ContactKeyV1 } from './contact-key.ts'
import { encodeVaultDeliveryPack } from './delivery-pack.ts'
import type { VaultEventSigner } from './events.ts'

export interface ContactKeyVaultSinkOptions {
  identityId: IdentityId
  actorDeviceId: DeviceId
  nextActorSeq(): Promise<number>
  initialParents(): Promise<VaultEventId[]>
  activeSegment(): Promise<ActiveVaultSegment>
  currentSnapshot(): Promise<LocalJmapSnapshot>
  signer: VaultEventSigner
  committer: LocalVaultMutationCommitter
}

export interface ContactKeyStoreResult {
  result: 'committed' | 'already-committed'
  event: VaultEventV1
}

export class ContactKeyVaultSink {
  constructor(private readonly options: ContactKeyVaultSinkOptions) {
    if (!options.identityId || !options.actorDeviceId) throw new TypeError('contact key sink identity is required')
  }

  async store(contactKey: ContactKeyV1): Promise<ContactKeyStoreResult> {
    const segment = await this.options.activeSegment()
    assertActiveVaultSegment(this.options.identityId, segment, 'contact key')
    const record = await buildContactKeyRecord(contactKey, {
      identityId: this.options.identityId,
      actorDeviceId: this.options.actorDeviceId,
      actorSeq: await this.options.nextActorSeq(),
      parents: await this.options.initialParents(),
      segmentId: segment.segmentId,
      segmentKey: segment.segmentKey,
    } satisfies ContactKeyBuildContext, this.options.signer)
    const snapshot = await this.options.currentSnapshot()
    const projection: LocalJmapProjectionV1 = {
      version: 1,
      identityId: this.options.identityId,
      state: snapshot.state,
      mailboxes: snapshot.mailboxes,
      emails: snapshot.emails,
    }
    const object = { ...record.object, identityId: this.options.identityId }
    const payload = encodeVaultDeliveryPack({ version: 1, identityId: this.options.identityId, objects: [object], events: [record.event], keyWraps: segment.keyWraps })
    const result = await this.options.committer.commitLocalMutation({
      identityId: this.options.identityId,
      objects: [object],
      events: [record.event],
      projection,
      jmapState: { state: projection.state },
      deliveryOutbox: {
        identityId: this.options.identityId,
        entryId: record.event.id,
        payload,
        payloadHash: sha256Bytes(payload),
        createdAt: contactKey.createdAt,
        attempts: 0,
      },
    })
    return { result, event: record.event }
  }
}
