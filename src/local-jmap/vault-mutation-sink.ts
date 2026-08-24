import { sha256Bytes } from '../protocol/canonical.ts'
import type { VaultEventSigner } from '../vault/events.ts'
import { buildVaultMutation, encodeVaultMutationObject } from '../vault/mutations.ts'
import type { DeviceId, IdentityId, VaultEventId } from '../protocol/ids.ts'
import type { VaultEventV1, VaultObjectV1 } from '../protocol/vault.ts'
import { encodeVaultDeliveryPack } from '../vault/delivery-pack.ts'
import { decryptVaultObject } from '../vault/objects.ts'
import { buildMailMessageAdd } from '../vault/mail-message.ts'
import type { LocalJmapEmail, LocalJmapMutationSink, LocalJmapProjectionV1, LocalJmapSnapshot } from './gateway.ts'
import { emailSetToVaultMutationIntents } from './mutations.ts'
import type { VaultMutationIntent } from './mutations.ts'
import { reduceLocalJmapProjection } from './reducer.ts'
import type { ActiveVaultSegment } from '../vault/active-segment.ts'

export type { ActiveVaultSegment } from '../vault/active-segment.ts'

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
    if (segment.keyWraps.length === 0) throw new TypeError('active vault segment has no current MLS key wrap')
    if (segment.keyWraps.some(wrap => wrap.identityId !== this.options.identityId || wrap.segmentId !== segment.segmentId)) {
      throw new TypeError('active vault segment key wrap does not match mutation identity or segment')
    }
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
    const next = reduceLocalJmapProjection(this.options.identityId, {
      mailboxes: snapshot.mailboxes,
      emails: snapshot.emails,
    }, records)
    const projection: LocalJmapProjectionV1 = {
      version: 1,
      identityId: this.options.identityId,
      ...next,
    }
    const objects = records.map(record => ({ ...record.object, identityId: this.options.identityId }))
    const events = records.map(record => record.event)
    const payload = encodeVaultDeliveryPack({
      version: 1,
      identityId: this.options.identityId,
      objects,
      events,
      keyWraps: segment.keyWraps,
    })
    await this.options.committer.commitLocalMutation({
      identityId: this.options.identityId,
      objects,
      events,
      projection,
      jmapState: { state: projection.state },
      deliveryOutbox: {
        identityId: this.options.identityId,
        entryId: events.at(-1)!.id,
        payload,
        payloadHash: sha256Bytes(payload),
        createdAt,
        attempts: 0,
      },
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

  /**
   * Commits a locally-composed message (compose's send path, PLAN.md §7):
   * a `message.add` with two object refs (encrypted metadata + the opaque
   * raw RFC 5322 bytes), the same shape MailIngressProjector uses for
   * inbound mail via buildMailMessageAdd. commitIntents can't be reused
   * here -- VaultMutationIntent is a single-object-per-intent shape, and
   * message.add needs two (metadata + raw bytes).
   */
  async commitMailMessage(
    input: { email: Omit<LocalJmapEmail, 'blobId'>; rawRfc5322: Uint8Array },
    snapshot: LocalJmapSnapshot,
  ): Promise<Record<string, unknown>> {
    const segment = await this.options.activeSegment()
    if (segment.keyWraps.length === 0) throw new TypeError('active vault segment has no current MLS key wrap')
    if (segment.keyWraps.some(wrap => wrap.identityId !== this.options.identityId || wrap.segmentId !== segment.segmentId)) {
      throw new TypeError('active vault segment key wrap does not match mutation identity or segment')
    }
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
    const next = reduceLocalJmapProjection(this.options.identityId, {
      mailboxes: snapshot.mailboxes,
      emails: snapshot.emails,
    }, [{ event: record.event, plaintext }])
    const projection: LocalJmapProjectionV1 = { version: 1, identityId: this.options.identityId, ...next }
    const objects = [
      { ...record.metadataObject, identityId: this.options.identityId },
      { ...record.rawRfc5322Object, identityId: this.options.identityId },
    ]
    const payload = encodeVaultDeliveryPack({ version: 1, identityId: this.options.identityId, objects, events: [record.event], keyWraps: segment.keyWraps })
    await this.options.committer.commitLocalMutation({
      identityId: this.options.identityId,
      objects,
      events: [record.event],
      projection,
      jmapState: { state: projection.state },
      deliveryOutbox: {
        identityId: this.options.identityId,
        entryId: record.event.id,
        payload,
        payloadHash: sha256Bytes(payload),
        createdAt,
        attempts: 0,
      },
    })
    return {
      accountId: this.options.accountId,
      oldState: snapshot.state,
      newState: projection.state,
      created: { [input.email.id]: { id: input.email.id } },
    }
  }
}
