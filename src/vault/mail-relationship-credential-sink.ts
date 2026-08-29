import { sha256Bytes } from '../protocol/canonical.ts'
import type { LocalJmapProjectionV1, LocalJmapSnapshot } from '../local-jmap/gateway.ts'
import type { VaultEventSigner } from './events.ts'
import { encodeVaultDeliveryPack } from './delivery-pack.ts'
import {
  buildMailRelationshipCredential, type MailRelationshipCredentialBuildContext, type MailRelationshipCredentialV1,
} from './mail-relationship-credential.ts'
import type { LocalVaultMutationCommitter } from '../local-jmap/vault-mutation-sink.ts'
import { assertActiveVaultSegment, type ActiveVaultSegment } from './active-segment.ts'
import type { DeviceId, IdentityId, VaultEventId } from '../protocol/ids.ts'
import type { VaultEventV1 } from '../protocol/vault.ts'

export interface MailRelationshipCredentialVaultSinkOptions {
  identityId: IdentityId
  actorDeviceId: DeviceId
  nextActorSeq(): Promise<number>
  initialParents(): Promise<VaultEventId[]>
  activeSegment(): Promise<ActiveVaultSegment>
  currentSnapshot(): Promise<LocalJmapSnapshot>
  signer: VaultEventSigner
  committer: LocalVaultMutationCommitter
}

export interface MailRelationshipCredentialStoreResult {
  result: 'committed' | 'already-committed'
  event: VaultEventV1
}

/**
 * Writes a newly generated or rotated per-mediator relationship credential
 * through the same atomic local-vault and shared-delivery outbox path as
 * normal vault changes -- same shape as vault/didcomm-credential-sink.ts.
 * Leaves the user-visible JMAP projection unchanged.
 */
export class MailRelationshipCredentialVaultSink {
  constructor(private readonly options: MailRelationshipCredentialVaultSinkOptions) {
    if (!options.identityId || !options.actorDeviceId) throw new TypeError('mail relationship credential sink identity is required')
  }

  async store(credential: MailRelationshipCredentialV1): Promise<MailRelationshipCredentialStoreResult> {
    const segment = await this.options.activeSegment()
    assertActiveVaultSegment(this.options.identityId, segment, 'mail relationship credential')
    const record = await buildMailRelationshipCredential(credential, {
      identityId: this.options.identityId,
      actorDeviceId: this.options.actorDeviceId,
      actorSeq: await this.options.nextActorSeq(),
      parents: await this.options.initialParents(),
      segmentId: segment.segmentId,
      segmentKey: segment.segmentKey,
    } satisfies MailRelationshipCredentialBuildContext, this.options.signer)
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
      deliveryOutbox: { identityId: this.options.identityId, entryId: record.event.id, payload, payloadHash: sha256Bytes(payload), createdAt: credential.createdAt, attempts: 0 },
    })
    return { result, event: record.event }
  }
}
