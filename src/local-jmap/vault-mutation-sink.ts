import type { VaultEventSigner } from '../vault/events.ts'
import { buildVaultMutation, encodeVaultMutationObject } from '../vault/mutations.ts'
import type { DeviceId, IdentityId, VaultEventId } from '../shared/protocol/ids.ts'
import type { VaultEventV1, VaultObjectV1 } from '../shared/protocol/vault.ts'
import { buildVaultCommit } from '../vault/commit.ts'
import { decryptVaultObject } from '../vault/objects.ts'
import { buildMailMessageAdd } from '../vault/mail-message.ts'
import type { LocalJmapEmail, LocalJmapMutationSink, LocalJmapProjectionV1, LocalJmapSnapshot } from './gateway.ts'
import { emailSetToVaultMutationIntents } from './mutations.ts'
import type { VaultMutationIntent } from './mutations.ts'
import { assertActiveVaultSegment, type ActiveVaultSegment } from '../vault/active-segment.ts'

export interface LocalVaultMutationCommitter {
  commitLocalMutation(input: {
    identityId: IdentityId
    objects: Array<VaultObjectV1 & { identityId: IdentityId }>
    events: VaultEventV1[]
    projection: LocalJmapProjectionV1
    jmapState: unknown
    deliveryOutbox: {
      identityId: IdentityId
      entryId: VaultEventId
      payload: Uint8Array
      payloadHash: Uint8Array
      createdAt: string
      attempts: number
    }
    /** One row per recipient -- a group message's single `message.add`
     * commit still needs N delivery-queue rows, one per fan-out target
     * (didcomm/group-chat.ts's own full-mesh design). A 1:1 chat message
     * is just the one-element case. */
    didCommOutbox?: Array<{
      identityId: IdentityId
      outboundEventId: VaultEventId
      emailId: string
      messageId: string
      toDid: string
      createdAt: string
      attempts: number
    }>
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
    return this.commitIntents(emailSetToVaultMutationIntents(arguments_), snapshot)
  }

  /**
   * The generic commit sequence `emailSet` is a thin JMAP-argument parser
   * on top of: build each intent into a signed event + encrypted object,
   * fold them into the projection, commit atomically alongside the delivery
   * outbox. Exposed directly so other callers with their own intents (mail
   * submission's `transport.result` + `mailbox.set` pair, see
   * identity/bootstrap.ts's buildMailSubmitter) reuse this exact,
   * already-tested pipeline instead of a parallel one.
   */
  async commitIntents(intents: VaultMutationIntent[], snapshot: LocalJmapSnapshot): Promise<Record<string, unknown>> {
    const segment = await this.options.activeSegment()
    assertActiveVaultSegment(this.options.identityId, segment, 'mutation')
    const createdAt = this.now().toISOString()
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
        createdAt,
      }, this.options.signer)
      records.push({ ...record, plaintext: encodeVaultMutationObject(intent) })
      parents = [record.event.id]
    }
    const commit = buildVaultCommit({
      identityId: this.options.identityId,
      objects: records.map(record => record.object),
      events: records.map(record => record.event),
      keyWraps: segment.keyWraps,
      createdAt,
      snapshot,
      reduce: records,
    })
    const projection = commit.projection
    await this.options.committer.commitLocalMutation({ identityId: this.options.identityId, ...commit })
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

  /**
   * Commits a locally-composed message (compose's send path, PLAN.md §7):
   * a `message.add` with two object refs (encrypted metadata + the opaque
   * raw RFC 5322 bytes), the same shape MailIngressProjector uses for
   * inbound mail via buildMailMessageAdd. commitIntents can't be reused
   * here -- VaultMutationIntent is a single-object-per-intent shape, and
   * message.add needs two (metadata + raw bytes).
   */
  async commitMailMessage(
    input: {
      email: Omit<LocalJmapEmail, 'blobId'>
      rawRfc5322: Uint8Array
      /** Atomically enqueue this local message for DIDComm delivery -- one
       * entry per recipient (a 1:1 chat message passes a single-element
       * array; a DIDComm group message's fan-out passes one per member). */
      didComm?: Array<{ messageId: string; toDid: string }>
    },
    snapshot: LocalJmapSnapshot,
  ): Promise<Record<string, unknown>> {
    const segment = await this.options.activeSegment()
    assertActiveVaultSegment(this.options.identityId, segment, 'mutation')
    const createdAt = this.now().toISOString()
    const record = await buildMailMessageAdd(input, {
      identityId: this.options.identityId,
      actorDeviceId: this.options.actorDeviceId,
      actorSeq: await this.options.nextActorSeq(),
      parents: await this.options.initialParents(),
      segmentId: segment.segmentId,
      segmentKey: segment.segmentKey,
      createdAt,
    }, this.options.signer)
    const plaintext = await decryptVaultObject(segment.segmentKey, record.metadataObject)
    const commit = buildVaultCommit({
      identityId: this.options.identityId,
      objects: [record.metadataObject, record.rawRfc5322Object],
      events: [record.event],
      keyWraps: segment.keyWraps,
      createdAt,
      snapshot,
      reduce: [{ event: record.event, plaintext }],
    })
    const projection = commit.projection
    await this.options.committer.commitLocalMutation({
      identityId: this.options.identityId,
      ...commit,
      ...(input.didComm?.length ? {
        didCommOutbox: input.didComm.map(entry => ({
          identityId: this.options.identityId,
          outboundEventId: record.event.id,
          emailId: input.email.id,
          messageId: entry.messageId,
          toDid: entry.toDid,
          createdAt,
          attempts: 0,
        })),
      } : {}),
    })
    return {
      accountId: this.options.accountId,
      oldState: snapshot.state,
      newState: projection.state,
      created: { [input.email.id]: { id: input.email.id } },
    }
  }
}
