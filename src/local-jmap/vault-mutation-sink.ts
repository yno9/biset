import type { VaultEventSigner } from '../vault/events.ts'
import { buildVaultMutation, encodeVaultMutationObject } from '../vault/mutations.ts'
import type { DeviceId, IdentityId, SegmentId, VaultEventId } from '../protocol/ids.ts'
import type { VaultEventV1, VaultObjectV1 } from '../protocol/vault.ts'
import type { LocalJmapMutationSink, LocalJmapProjectionV1, LocalJmapSnapshot } from './gateway.ts'
import { emailSetToVaultMutationIntents } from './mutations.ts'
import { reduceLocalJmapProjection } from './reducer.ts'

export interface ActiveVaultSegment {
  segmentId: SegmentId
  segmentKey: Uint8Array
}

export interface LocalVaultMutationCommitter {
  commitLocalMutation(input: {
    identityId: IdentityId
    objects: Array<VaultObjectV1 & { identityId: IdentityId }>
    events: VaultEventV1[]
    projection: LocalJmapProjectionV1
    jmapState: unknown
  }): Promise<'committed' | 'already-committed'>
}

export interface VaultBackedLocalJmapMutationSinkOptions {
  accountId: string
  identityId: IdentityId
  actorDeviceId: DeviceId
  nextActorSeq(): Promise<number>
  initialParents(): Promise<VaultEventId[]>
  activeSegment(): Promise<ActiveVaultSegment>
  signer: VaultEventSigner
  committer: LocalVaultMutationCommitter
  now?: () => Date
}

/**
 * The local JMAP write bridge. It composes parser → encrypted objects → signed
 * events → deterministic projection → one commit. It never mutates the
 * projection in place and never lets the gateway see the SegmentKey.
 */
export class VaultBackedLocalJmapMutationSink implements LocalJmapMutationSink {
  private readonly now: () => Date

  constructor(private readonly options: VaultBackedLocalJmapMutationSinkOptions) {
    if (!options.accountId || !options.identityId || !options.actorDeviceId) throw new TypeError('local vault mutation identity is required')
    this.now = options.now ?? (() => new Date())
  }

  async emailSet(arguments_: Record<string, unknown>, snapshot: LocalJmapSnapshot): Promise<Record<string, unknown>> {
    const intents = emailSetToVaultMutationIntents(arguments_)
    const segment = await this.options.activeSegment()
    let parents = await this.options.initialParents()
    const records: Array<{ event: VaultEventV1; object: VaultObjectV1; plaintext: Uint8Array }> = []
    for (const intent of intents) {
      const record = await buildVaultMutation(intent, {
        identityId: this.options.identityId,
        actorDeviceId: this.options.actorDeviceId,
        actorSeq: await this.options.nextActorSeq(),
        parents,
        segmentId: segment.segmentId,
        segmentKey: segment.segmentKey,
        createdAt: this.now().toISOString(),
      }, this.options.signer)
      records.push({ ...record, plaintext: encodeVaultMutationObject(intent) })
      parents = [record.event.id]
    }
    const next = reduceLocalJmapProjection(this.options.identityId, {
      mailboxes: snapshot.mailboxes,
      emails: snapshot.emails,
    }, records)
    const projection: LocalJmapProjectionV1 = {
      version: 1,
      identityId: this.options.identityId,
      ...next,
    }
    await this.options.committer.commitLocalMutation({
      identityId: this.options.identityId,
      objects: records.map(record => ({ ...record.object, identityId: this.options.identityId })),
      events: records.map(record => record.event),
      projection,
      jmapState: { state: projection.state },
    })
    const destroyed = new Set(records.filter(record => record.event.kind === 'message.tombstone').flatMap(record => record.event.targetIds))
    const updated = new Set(records.filter(record => record.event.kind !== 'message.tombstone').flatMap(record => record.event.targetIds))
    return {
      accountId: this.options.accountId,
      oldState: snapshot.state,
      newState: projection.state,
      ...(updated.size === 0 ? {} : { updated: Object.fromEntries([...updated].map(id => [id, null])) }),
      ...(destroyed.size === 0 ? {} : { destroyed: [...destroyed] }),
    }
  }
}
