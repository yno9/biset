import type { IngressAckV1 } from '../../../protocol/ingress.ts'
import type { DeviceId, IdentityId, SegmentId, VaultEventId, VaultObjectId } from '../../../protocol/ids.ts'
import type { VaultEventV1, VaultObjectV1 } from '../../../protocol/vault.ts'
import { rescueLegacyCrdtEvents } from './legacy-crdt-migration.ts'

const DATABASE_NAME = 'biset-vault-core'
const DATABASE_VERSION = 15

const STORES = {
  ingressReceipts: 'vault_ingress_receipts',
  objects: 'vault_objects',
  events: 'vault_events',
  chunks: 'vault_chunks',
  segments: 'vault_segments',
  manifests: 'vault_manifests',
  projection: 'vault_projection',
  jmapState: 'vault_jmap_state',
  outbox: 'vault_outbox',
  transportStatus: 'transport_status',
  didCommOutbox: 'didcomm_transport_outbox',
  actorSequences: 'vault_actor_sequences',
  projectionMeta: 'vault_projection_meta',
} as const

type StoreName = (typeof STORES)[keyof typeof STORES]

export interface VaultObjectRecord extends VaultObjectV1 {
  identityId: IdentityId
}

export interface VaultEventRecord extends VaultEventV1 {
  identityId: IdentityId
}

export interface IngressReceiptRecord {
  identityId: IdentityId
  ingressId: string
  protectedPayloadHash: Uint8Array
  vaultEventId: VaultEventId
  checkpointId: string
  committedAt: string
}

export interface IngressAckOutboxRecord {
  identityId: IdentityId
  ingressId: string
  ack: IngressAckV1
  attempts: number
  createdAt: string
}

/** Durable external-ingress ACK work. A failed network wake must not lose it. */
interface IngressAckOutboxReader {
  readIngressAckOutbox(identityId: IdentityId, recipientDeviceId: DeviceId, limit?: number): Promise<IngressAckOutboxRecord[]>
  removeIngressAckOutbox(identityId: IdentityId, ingressId: string): Promise<void>
  noteIngressAckOutboxAttempt(identityId: IdentityId, ingressId: string): Promise<void>
}

/** Durable DIDComm send intent. Message content stays in encrypted vault objects. */
export interface DidCommTransportOutboxRecord {
  identityId: IdentityId
  outboundEventId: VaultEventId
  emailId: string
  /** Raw body Vault object referenced by outboundEventId. Optional only for
   * rows written before it was stored directly; readDidCommOutbox repairs
   * those from the durable event rather than consulting the projection. */
  blobId?: string
  metadataBlobId?: string
  threadId?: string
  subject?: string
  sentAt?: string
  messageId: string
  toDid: string
  createdAt: string
  attempts: number
  lastAttemptAt?: string
}

interface DidCommTransportOutboxStore {
  readDidCommOutbox(identityId: IdentityId, limit?: number): Promise<DidCommTransportOutboxRecord[]>
  noteDidCommOutboxAttempt(identityId: IdentityId, outboundEventId: VaultEventId, toDid: string, attemptedAt: string): Promise<void>
  removeDidCommOutbox(identityId: IdentityId, outboundEventId: VaultEventId, toDid: string): Promise<void>
}

/**
 * All fields are written in one IndexedDB transaction. The caller may send the
 * ACK only after this promise resolves successfully.
 */
export interface IngressVaultCommit {
  identityId: IdentityId
  receipt: IngressReceiptRecord
  objects: VaultObjectRecord[]
  events: VaultEventRecord[]
  projection: unknown
  jmapState: unknown
  /** Core ingress requires this; transports with their own ACK protocol do not. */
  ackOutbox?: IngressAckOutboxRecord
}

export interface IngressReceiptReader {
  readIngressReceipt(identityId: IdentityId, ingressId: string): Promise<IngressReceiptRecord | undefined>
}

/** Local UI mutation commit: no ingress receipt/ACK, but the same atomicity. */
export interface LocalVaultMutationCommit {
  identityId: IdentityId
  objects: VaultObjectRecord[]
  events: VaultEventRecord[]
  projection: unknown
  jmapState: unknown
  /** One row per recipient -- a group message's single commit still needs
   * N delivery-queue rows, one per fan-out target
   * (didcomm/group-chat.ts's full-mesh design). A 1:1 chat message is the
   * one-element case. */
  didCommOutbox?: DidCommTransportOutboxRecord[]
}

export type IngressCommitResult = 'committed' | 'already-committed'

/** Narrow read boundary used by local projections without exposing IDB internals. */
export interface VaultProjectionReader {
  readProjection(identityId: IdentityId): Promise<unknown | undefined>
}

/**
 * Writes a projection/JMAP-state pair that was NOT derived from a batch of
 * new events -- the historical full-projection rebuild path
 * is the only caller: it recomputes the projection from records already
 * committed, so there is nothing new for `commitLocalMutation`/`commitIngress`/
 * `commitDelivery` (which all require at least one event) to commit
 * alongside it. Also the only way a brand-new identity's very first
 * (all-empty) projection row ever gets written, since nothing else seeds one.
 */
interface VaultProjectionWriter {
  writeProjection(identityId: IdentityId, projection: unknown, jmapState: unknown): Promise<void>
}

export interface VaultObjectReader {
  readObject(identityId: IdentityId, objectId: VaultObjectId): Promise<VaultObjectRecord | undefined>
}

/**
 * Narrow local-only index for non-JMAP credentials. Credential event bodies
 * remain encrypted vault objects; this exposes only their signed envelopes.
 */
export interface VaultCredentialEventReader {
  readCredentialEvents(identityId: IdentityId): Promise<VaultEventRecord[]>
}

/** Full ciphertext/event reader used only by peer restore and user archive export. */
export interface VaultRecordReader {
  readVaultEvents(identityId: IdentityId): Promise<VaultEventRecord[]>
  readVaultObjects(identityId: IdentityId): Promise<VaultObjectRecord[]>
}

export interface VaultSyncRecordReader extends VaultRecordReader {
  /** Every SegmentKey this device holds -- they travel to sibling devices
   * with the objects encrypted under them (Vault Sync, inside DIDComm). */
  readSegmentKeys(identityId: IdentityId): Promise<VaultSegmentKey[]>
}

/** A SegmentKey as it travels between this identity's devices. */
export interface VaultSegmentKey { segmentId: SegmentId; segmentKey: Uint8Array }

export interface IncomingVaultRecords {
  identityId: IdentityId
  objects: VaultObjectRecord[]
  events: VaultEventRecord[]
  segmentKeys: VaultSegmentKey[]
}

export interface IncomingVaultRecordsResult {
  addedEventIds: VaultEventId[]
  targetIds: string[]
}

export interface VaultProjectionMeta { identityId: IdentityId; tombstones: string[]; pending: string[] }

export interface DuplicateActorSequence {
  actorDeviceId: string
  actorSeq: number
  eventIds: VaultEventId[]
}

/** Atomic actor sequence reservations shared by every tab for one device. */
export interface ActorSequenceStore {
  reserveActorSeq(identityId: IdentityId, deviceId: string): Promise<number>
  findDuplicateActorSequences(identityId: IdentityId): Promise<DuplicateActorSequence[]>
}

/** One vault segment: the identifier/key pair every object encrypted under
 * it shares. Each device writes into one segment of its own (`sealed:
 * false`); segments that arrived from sibling devices are stored sealed and
 * only ever read. The key is held as is: it lives in the same browser
 * storage any wrapping key would. */
export interface VaultSegmentRecord {
  identityId: IdentityId
  segmentId: SegmentId
  segmentKey: Uint8Array
  sealed: boolean
  createdAt: string
}

export interface ActiveVaultSegmentStore {
  /** The current (not sealed) segment for this identity, or undefined if
   * none has ever been created. At most one segment is ever current per
   * identity — `sealAndActivateSegment` enforces that by construction. */
  currentSegment(identityId: IdentityId): Promise<VaultSegmentRecord | undefined>
  /** The key of any segment this device holds, its own or a sibling's. */
  readSegmentKey(identityId: IdentityId, segmentId: SegmentId): Promise<Uint8Array | undefined>
  /**
   * Atomically seals whatever segment is currently active for this
   * identity (a no-op if there is none) and activates `next` as the new
   * current one. The ONLY way a segment ever becomes current, and the ONLY
   * way one ever gets sealed — so "the active segment" and "the most
   * recently activated one" are always the same segment.
   */
  sealAndActivateSegment(next: VaultSegmentRecord): Promise<void>
}

export class IndexedDbVaultStore implements VaultProjectionReader, VaultProjectionWriter, VaultObjectReader, VaultCredentialEventReader, VaultRecordReader, ActorSequenceStore, ActiveVaultSegmentStore, IngressReceiptReader, IngressAckOutboxReader, DidCommTransportOutboxStore {
  private constructor(private readonly database: IDBDatabase) {}

  static async open(): Promise<IndexedDbVaultStore> {
    await rescueLegacyCrdtEvents()
    return new IndexedDbVaultStore(await openDatabase())
  }

  close(): void {
    this.database.close()
  }

  /**
   * Domain move (identity/webvh/move.ts) support: every store here is keyed
   * by identityId (KEY_PATHS above), which is the did:webvh string this
   * device's identity happens to resolve at right now -- a domain move
   * changes that string while the identity itself, and every row already
   * recorded under the old one, stays exactly the same. One multi-store
   * transaction covering every store, so a failure partway through never
   * leaves some stores moved and others still under the old key.
   */
  async rekeyIdentity(oldIdentityId: IdentityId, newIdentityId: IdentityId): Promise<void> {
    if (oldIdentityId === newIdentityId) return
    const storeNames = Object.values(STORES)
    const transaction = this.database.transaction(storeNames, 'readwrite')
    for (const name of storeNames) {
      const keyPath = KEY_PATHS[name]
      const store = transaction.objectStore(name)
      const rows = await requestValue<Array<Record<string, unknown>>>(store.getAll())
      for (const row of rows) {
        if (row.identityId !== oldIdentityId) continue
        const oldKey = Array.isArray(keyPath) ? keyPath.map(field => row[field]) : row[keyPath]
        store.put({ ...row, identityId: newIdentityId })
        store.delete(oldKey as IDBValidKey)
      }
    }
    await transactionDone(transaction)
  }

  /**
   * Idempotence is anchored by the ingress receipt's composite key. A repeated
   * ingress aborts before any object/event/projection mutation can commit.
   */
  async commitIngress(input: IngressVaultCommit): Promise<IngressCommitResult> {
    assertCommit(input)
    const stores: StoreName[] = [
      STORES.ingressReceipts,
      STORES.objects,
      STORES.events,
    ]
    if (input.ackOutbox) stores.push(STORES.outbox)
    const transaction = this.database.transaction(stores, 'readwrite')
    let duplicate = false
    const receiptStore = transaction.objectStore(STORES.ingressReceipts)
    const receiptRequest = receiptStore.add(copyReceipt(input.receipt))
    receiptRequest.onerror = () => {
      if (receiptRequest.error?.name === 'ConstraintError') duplicate = true
    }
    for (const object of input.objects) transaction.objectStore(STORES.objects).put(copyObject(object))
    for (const event of input.events) transaction.objectStore(STORES.events).put(copyEvent(event))
    if (input.ackOutbox) transaction.objectStore(STORES.outbox).put(copyOutbox(input.ackOutbox))

    try {
      await transactionDone(transaction)
      return 'committed'
    } catch (error) {
      if (duplicate) return 'already-committed'
      throw error
    }
  }

  async readIngressReceipt(identityId: IdentityId, ingressId: string): Promise<IngressReceiptRecord | undefined> {
    if (!identityId || !ingressId) throw new TypeError('ingress receipt identity and ID are required')
    const transaction = this.database.transaction(STORES.ingressReceipts, 'readonly')
    const completed = transactionDone(transaction)
    const receipt = await requestValue<IngressReceiptRecord | undefined>(transaction.objectStore(STORES.ingressReceipts).get([identityId, ingressId]))
    await completed
    return receipt && copyReceipt(receipt)
  }

  async readProjection(identityId: IdentityId): Promise<unknown | undefined> {
    if (!identityId) throw new TypeError('projection identity is required')
    const transaction = this.database.transaction(STORES.projection, 'readonly')
    const completed = transactionDone(transaction)
    const record = await requestValue<{ identityId: IdentityId; value: unknown } | undefined>(
      transaction.objectStore(STORES.projection).get(identityId),
    )
    await completed
    return record?.value
  }

  async writeProjection(identityId: IdentityId, projection: unknown, jmapState: unknown): Promise<void> {
    if (!identityId) throw new TypeError('projection identity is required')
    const transaction = this.database.transaction([STORES.projection, STORES.jmapState], 'readwrite')
    transaction.objectStore(STORES.projection).put({ identityId, value: projection })
    transaction.objectStore(STORES.jmapState).put({ identityId, value: jmapState })
    await transactionDone(transaction)
  }

  async readProjectionMeta(identityId: IdentityId): Promise<VaultProjectionMeta> {
    const transaction = this.database.transaction(STORES.projectionMeta, 'readonly')
    const completed = transactionDone(transaction)
    const value = await requestValue<VaultProjectionMeta | undefined>(transaction.objectStore(STORES.projectionMeta).get(identityId))
    await completed
    return value ? { identityId, tombstones: [...value.tombstones], pending: [...value.pending] } : { identityId, tombstones: [], pending: [] }
  }

  async writeProjectionMeta(value: VaultProjectionMeta): Promise<void> {
    const transaction = this.database.transaction(STORES.projectionMeta, 'readwrite')
    transaction.objectStore(STORES.projectionMeta).put({ identityId: value.identityId, tombstones: [...new Set(value.tombstones)].sort(), pending: [...new Set(value.pending)].sort() })
    await transactionDone(transaction)
  }

  async readEventsForTarget(identityId: IdentityId, targetId: string): Promise<VaultEventRecord[]> {
    const transaction = this.database.transaction(STORES.events, 'readonly')
    const completed = transactionDone(transaction)
    const values = await requestValue<VaultEventRecord[]>(transaction.objectStore(STORES.events).index('by_target_id').getAll(targetId))
    await completed
    return values.filter(value => value.identityId === identityId).map(copyEvent)
  }

  async readIngressAckOutbox(identityId: IdentityId, recipientDeviceId: DeviceId, limit = 32): Promise<IngressAckOutboxRecord[]> {
    if (!identityId || !recipientDeviceId || !Number.isSafeInteger(limit) || limit < 1) throw new TypeError('ingress ACK outbox query is invalid')
    const transaction = this.database.transaction(STORES.outbox, 'readonly')
    const completed = transactionDone(transaction)
    const values = await requestValue<IngressAckOutboxRecord[]>(transaction.objectStore(STORES.outbox).getAll())
    await completed
    return values.filter(value => value.identityId === identityId && value.ack.recipientDeviceId === recipientDeviceId)
      .sort((left, right) => left.createdAt.localeCompare(right.createdAt) || left.ingressId.localeCompare(right.ingressId))
      .slice(0, limit).map(copyOutbox)
  }

  async removeIngressAckOutbox(identityId: IdentityId, ingressId: string): Promise<void> {
    if (!identityId || !ingressId) throw new TypeError('ingress ACK outbox identity and ID are required')
    const transaction = this.database.transaction(STORES.outbox, 'readwrite')
    transaction.objectStore(STORES.outbox).delete([identityId, ingressId])
    await transactionDone(transaction)
  }

  async noteIngressAckOutboxAttempt(identityId: IdentityId, ingressId: string): Promise<void> {
    if (!identityId || !ingressId) throw new TypeError('ingress ACK outbox identity and ID are required')
    const transaction = this.database.transaction(STORES.outbox, 'readwrite')
    const store = transaction.objectStore(STORES.outbox)
    const record = await requestValue<IngressAckOutboxRecord | undefined>(store.get([identityId, ingressId]))
    if (record) store.put({ ...copyOutbox(record), attempts: record.attempts + 1 })
    await transactionDone(transaction)
  }

  /**
   * Object/event/projection/JMAP state commit for a local JMAP mutation. An
   * event ID collision makes the whole transaction idempotently a no-op.
   */
  async commitLocalMutation(input: LocalVaultMutationCommit): Promise<IngressCommitResult> {
    assertLocalCommit(input)
    const stores: StoreName[] = [
      STORES.objects,
      STORES.events,
    ]
    if (input.didCommOutbox?.length) stores.push(STORES.didCommOutbox)
    const transaction = this.database.transaction(stores, 'readwrite')
    let duplicate = false
    const eventStore = transaction.objectStore(STORES.events)
    for (const event of input.events) {
      const request = eventStore.add(copyEvent(event))
      request.onerror = () => {
        if (request.error?.name === 'ConstraintError') duplicate = true
      }
    }
    for (const object of input.objects) transaction.objectStore(STORES.objects).put(copyObject(object))
    for (const row of input.didCommOutbox ?? []) transaction.objectStore(STORES.didCommOutbox).put(copyDidCommOutbox(row))
    try {
      await transactionDone(transaction)
      return 'committed'
    } catch (error) {
      if (duplicate) return 'already-committed'
      throw error
    }
  }


  async readDidCommOutbox(identityId: IdentityId, limit = 32): Promise<DidCommTransportOutboxRecord[]> {
    if (!identityId || !Number.isSafeInteger(limit) || limit < 1) throw new TypeError('DIDComm outbox identity and positive limit are required')
    const transaction = this.database.transaction(STORES.didCommOutbox, 'readonly')
    const completed = transactionDone(transaction)
    const values = await requestValue<DidCommTransportOutboxRecord[]>(transaction.objectStore(STORES.didCommOutbox).getAll())
    await completed
    const selected = values.filter(value => value.identityId === identityId)
      .sort((left, right) => left.createdAt.localeCompare(right.createdAt) || left.outboundEventId.localeCompare(right.outboundEventId) || left.toDid.localeCompare(right.toDid))
      .slice(0, limit)
    const legacy = selected.filter(value => !value.blobId || !value.metadataBlobId)
    const eventById = new Map<VaultEventId, VaultEventRecord>()
    if (legacy.length) {
      const eventTransaction = this.database.transaction(STORES.events, 'readonly')
      const eventCompleted = transactionDone(eventTransaction)
      const eventStore = eventTransaction.objectStore(STORES.events)
      const events = await Promise.all(legacy.map(value => requestValue<VaultEventRecord | undefined>(eventStore.get([identityId, value.outboundEventId]))))
      await eventCompleted
      for (const event of events) if (event) eventById.set(event.id, event)
    }
    return selected.map(value => {
        const event = eventById.get(value.outboundEventId)
        const blobId = value.blobId ?? event?.objectRefs[1]
        const metadataBlobId = value.metadataBlobId ?? event?.objectRefs[0]
        return copyDidCommOutbox({ ...value, ...(blobId ? { blobId } : {}), ...(metadataBlobId ? { metadataBlobId } : {}) })
      })
  }

  async noteDidCommOutboxAttempt(identityId: IdentityId, outboundEventId: VaultEventId, toDid: string, attemptedAt: string): Promise<void> {
    if (!identityId || !outboundEventId || !toDid || Number.isNaN(Date.parse(attemptedAt))) throw new TypeError('DIDComm outbox attempt is invalid')
    const transaction = this.database.transaction(STORES.didCommOutbox, 'readwrite')
    const store = transaction.objectStore(STORES.didCommOutbox)
    const record = await requestValue<DidCommTransportOutboxRecord | undefined>(store.get([identityId, outboundEventId, toDid]))
    if (record) store.put(copyDidCommOutbox({ ...record, attempts: record.attempts + 1, lastAttemptAt: attemptedAt }))
    await transactionDone(transaction)
  }

  async removeDidCommOutbox(identityId: IdentityId, outboundEventId: VaultEventId, toDid: string): Promise<void> {
    if (!identityId || !outboundEventId || !toDid) throw new TypeError('DIDComm outbox identity, event ID, and recipient are required')
    const transaction = this.database.transaction(STORES.didCommOutbox, 'readwrite')
    transaction.objectStore(STORES.didCommOutbox).delete([identityId, outboundEventId, toDid])
    await transactionDone(transaction)
  }

  async readObject(identityId: IdentityId, objectId: VaultObjectId): Promise<VaultObjectRecord | undefined> {
    if (!identityId || !objectId) throw new TypeError('object identity and ID are required')
    const transaction = this.database.transaction(STORES.objects, 'readonly')
    const completed = transactionDone(transaction)
    const record = await requestValue<VaultObjectRecord | undefined>(
      transaction.objectStore(STORES.objects).get([identityId, objectId]),
    )
    await completed
    return record && copyObject(record)
  }

  async readCredentialEvents(identityId: IdentityId): Promise<VaultEventRecord[]> {
    if (!identityId) throw new TypeError('credential event identity is required')
    const transaction = this.database.transaction(STORES.events, 'readonly')
    const completed = transactionDone(transaction)
    const values = await requestValue<VaultEventRecord[]>(transaction.objectStore(STORES.events).getAll())
    await completed
    return values
      .filter(value => value.identityId === identityId && value.kind.startsWith('credential.'))
      .sort((left, right) => left.createdAt.localeCompare(right.createdAt) || left.id.localeCompare(right.id))
      .map(copyEvent)
  }

  async readVaultEvents(identityId: IdentityId): Promise<VaultEventRecord[]> {
    if (!identityId) throw new TypeError('vault event identity is required')
    const transaction = this.database.transaction(STORES.events, 'readonly')
    const completed = transactionDone(transaction)
    const values = await requestValue<VaultEventRecord[]>(transaction.objectStore(STORES.events).getAll())
    await completed
    return values.filter(value => value.identityId === identityId).sort((left, right) => left.id.localeCompare(right.id)).map(copyEvent)
  }

  async reserveActorSeq(identityId: IdentityId, deviceId: string): Promise<number> {
    if (!identityId || !deviceId) throw new TypeError('actor sequence identity and device are required')
    const transaction = this.database.transaction([STORES.actorSequences, STORES.events], 'readwrite')
    const counters = transaction.objectStore(STORES.actorSequences)
    const key = [identityId, deviceId]
    const current = await requestValue<{ nextSeq: number } | undefined>(counters.get(key))
    const latest = await requestValue<IDBCursorWithValue | null>(
      transaction.objectStore(STORES.events).index('by_actor_sequence').openCursor(
        IDBKeyRange.bound([identityId, deviceId, 0], [identityId, deviceId, Number.MAX_SAFE_INTEGER]),
        'prev',
      ),
    )
    // Imported/restored records can arrive after this counter was first
    // created, so the durable counter and R3 history are both lower bounds.
    const nextSeq = Math.max(current?.nextSeq ?? 1, ((latest?.value as VaultEventRecord | undefined)?.actorSeq ?? 0) + 1)
    if (!Number.isSafeInteger(nextSeq) || nextSeq < 1 || nextSeq === Number.MAX_SAFE_INTEGER) {
      transaction.abort()
      throw new RangeError('actor sequence is exhausted')
    }
    counters.put({ identityId, deviceId, nextSeq: nextSeq + 1 })
    await transactionDone(transaction)
    return nextSeq
  }

  async findDuplicateActorSequences(identityId: IdentityId): Promise<DuplicateActorSequence[]> {
    if (!identityId) throw new TypeError('actor sequence identity is required')
    const transaction = this.database.transaction(STORES.events, 'readonly')
    const completed = transactionDone(transaction)
    const events = await requestValue<VaultEventRecord[]>(transaction.objectStore(STORES.events).getAll())
    await completed
    const groups = new Map<string, VaultEventRecord[]>()
    for (const event of events) {
      if (event.identityId !== identityId) continue
      const key = `${event.actorDeviceId}\0${event.actorSeq}`
      const group = groups.get(key)
      if (group) group.push(event)
      else groups.set(key, [event])
    }
    return [...groups.values()].filter(group => group.length > 1).map(group => ({
      actorDeviceId: group[0]!.actorDeviceId,
      actorSeq: group[0]!.actorSeq,
      eventIds: group.map(event => event.id).sort(),
    })).sort((left, right) => left.actorDeviceId.localeCompare(right.actorDeviceId) || left.actorSeq - right.actorSeq)
  }

  async readVaultObjects(identityId: IdentityId): Promise<VaultObjectRecord[]> {
    if (!identityId) throw new TypeError('vault object identity is required')
    const transaction = this.database.transaction(STORES.objects, 'readonly')
    const completed = transactionDone(transaction)
    const values = await requestValue<VaultObjectRecord[]>(transaction.objectStore(STORES.objects).getAll())
    await completed
    return values.filter(value => value.identityId === identityId).sort((left, right) => left.objectId.localeCompare(right.objectId)).map(copyObject)
  }

  async readSegmentKeys(identityId: IdentityId): Promise<VaultSegmentKey[]> {
    if (!identityId) throw new TypeError('segment identity is required')
    const transaction = this.database.transaction(STORES.segments, 'readonly')
    const completed = transactionDone(transaction)
    const values = await requestValue<VaultSegmentRecord[]>(transaction.objectStore(STORES.segments).getAll())
    await completed
    return values.filter(value => value.identityId === identityId)
      .sort((left, right) => left.segmentId.localeCompare(right.segmentId))
      .map(value => ({ segmentId: value.segmentId, segmentKey: value.segmentKey.slice() }))
  }

  /** One idempotent R3 transaction. Validation deliberately happens before
   * this boundary so a bad record can be discarded without aborting its
   * valid siblings. Existing immutable keys are no-ops. */
  async commitIncomingRecords(input: IncomingVaultRecords): Promise<IncomingVaultRecordsResult> {
    if (!input.identityId) throw new TypeError('incoming Vault identity is required')
    for (const value of input.objects) if (value.identityId !== input.identityId) throw new TypeError('incoming object identity does not match')
    for (const value of input.events) if (value.identityId !== input.identityId) throw new TypeError('incoming event identity does not match')
    for (const value of input.segmentKeys) if (!value.segmentId || value.segmentKey.length !== 32) throw new TypeError('incoming segment key is invalid')
    const transaction = this.database.transaction([STORES.objects, STORES.events, STORES.segments], 'readwrite')
    const objectStore = transaction.objectStore(STORES.objects)
    const eventStore = transaction.objectStore(STORES.events)
    const segmentStore = transaction.objectStore(STORES.segments)
    const addedEvents: VaultEventRecord[] = []
    for (const object of input.objects) {
      if (!await requestValue<VaultObjectRecord | undefined>(objectStore.get([input.identityId, object.objectId]))) objectStore.add(copyObject(object))
    }
    for (const event of input.events) {
      if (!await requestValue<VaultEventRecord | undefined>(eventStore.get([input.identityId, event.id]))) {
        eventStore.add(copyEvent(event))
        addedEvents.push(event)
      }
    }
    // A sibling's segment is only ever read here, never written into.
    const receivedAt = new Date().toISOString()
    for (const value of input.segmentKeys) {
      if (!await requestValue<VaultSegmentRecord | undefined>(segmentStore.get([input.identityId, value.segmentId]))) {
        segmentStore.add({ identityId: input.identityId, segmentId: value.segmentId, segmentKey: value.segmentKey.slice(), sealed: true, createdAt: receivedAt })
      }
    }
    await transactionDone(transaction)
    return {
      addedEventIds: addedEvents.map(event => event.id),
      targetIds: [...new Set(addedEvents.flatMap(event => event.targetIds))].sort(),
    }
  }

  async currentSegment(identityId: IdentityId): Promise<VaultSegmentRecord | undefined> {
    if (!identityId) throw new TypeError('segment identity is required')
    const transaction = this.database.transaction(STORES.segments, 'readonly')
    const completed = transactionDone(transaction)
    const values = await requestValue<VaultSegmentRecord[]>(transaction.objectStore(STORES.segments).getAll())
    await completed
    const current = values.find(value => value.identityId === identityId && !value.sealed)
    return current && copySegmentRecord(current)
  }

  async readSegmentKey(identityId: IdentityId, segmentId: SegmentId): Promise<Uint8Array | undefined> {
    if (!identityId || !segmentId) throw new TypeError('segment identity and ID are required')
    const transaction = this.database.transaction(STORES.segments, 'readonly')
    const completed = transactionDone(transaction)
    const value = await requestValue<VaultSegmentRecord | undefined>(transaction.objectStore(STORES.segments).get([identityId, segmentId]))
    await completed
    return value?.segmentKey.slice()
  }

  async sealAndActivateSegment(next: VaultSegmentRecord): Promise<void> {
    assertSegmentRecord(next)
    if (next.sealed) throw new TypeError('a segment must be activated as not sealed')
    const transaction = this.database.transaction(STORES.segments, 'readwrite')
    const store = transaction.objectStore(STORES.segments)
    const values = await requestValue<VaultSegmentRecord[]>(store.getAll())
    for (const value of values) {
      if (value.identityId === next.identityId && !value.sealed) store.put({ ...copySegmentRecord(value), sealed: true })
    }
    store.put(copySegmentRecord(next))
    await transactionDone(transaction)
  }



}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE_NAME, DATABASE_VERSION)
    request.onupgradeneeded = event => {
      createStores(request.result)
      // v8 replaced the transitional routing-only Coordinator binding with
      // one that contains the actual Vault-specific private MLS state. A v7
      // row cannot be upgraded cryptographically, so discard only that
      // opt-in binding; local Vault content remains untouched and can be
      // provisioned again after an explicit login. Coordinator itself (and
      // the object store's own schema entry) is gone as of this version, so
      // createStores above no longer creates 'vault_coordinator_binding' --
      // a client already past v8 still physically has it (the schema that
      // created it was live when their DB was last upgraded) and this still
      // clears it by its literal name, but a client jumping straight from
      // well before v8 (nothing here ever created the store for them) must
      // not blindly call .objectStore() on a name that was never created --
      // that throws synchronously and aborts the WHOLE upgrade transaction,
      // not just this cleanup step, taking every other store's migration
      // down with it.
      if (event.oldVersion > 0 && event.oldVersion < 8 && request.transaction?.objectStoreNames.contains('vault_coordinator_binding')) {
        request.transaction.objectStore('vault_coordinator_binding').clear()
      }
      // v10 widened the DIDComm outbox's key from [identityId,
      // outboundEventId] to [identityId, outboundEventId, toDid] -- one
      // logical message can now need N delivery-queue rows (one per
      // fan-out recipient, didcomm/group-chat.ts's full-mesh design), which
      // the old 2-part key could not distinguish. IndexedDB cannot alter an
      // existing store's keyPath in place, so a client upgrading from
      // before v10 gets its rows preserved by hand: every existing row
      // already carries a `toDid` field, just not as part of its key yet,
      // so re-putting it under the new store recovers the identical
      // composite key with no data loss (an in-flight queued send must not
      // silently vanish on upgrade).
      // >= 6, not > 0: the store itself didn't exist before v6, so a
      // client older than that gets a freshly-created, already-correctly-
      // keyed store from createStores above -- nothing to migrate.
      if (event.oldVersion >= 6 && event.oldVersion < 10 && request.transaction?.objectStoreNames.contains(STORES.didCommOutbox)) {
        const legacy = request.transaction.objectStore(STORES.didCommOutbox)
        const getAll = legacy.getAll()
        getAll.onsuccess = () => {
          const rows = getAll.result as DidCommTransportOutboxRecord[]
          request.result.deleteObjectStore(STORES.didCommOutbox)
          const fresh = request.result.createObjectStore(STORES.didCommOutbox, { keyPath: KEY_PATHS[STORES.didCommOutbox] })
          for (const row of rows) fresh.put(row)
        }
      }
      const events = request.transaction?.objectStore(STORES.events)
      if (events && !events.indexNames.contains('by_target_id')) events.createIndex('by_target_id', 'targetIds', { multiEntry: true })
      if (events && !events.indexNames.contains('by_actor_sequence')) events.createIndex('by_actor_sequence', ['identityId', 'actorDeviceId', 'actorSeq'])
      if (event.oldVersion > 0 && event.oldVersion < 14 && request.result.objectStoreNames.contains('vault_crdt_state')) request.result.deleteObjectStore('vault_crdt_state')
      // v15: SegmentKeys are kept in vault_segments and travel inside Vault
      // Sync; the Vault-Content-Key wraps and the MIMI-era shared-delivery
      // stores are gone.
      for (const retired of ['vault_key_wraps', 'vault_delivery_outbox', 'vault_delivery_receipts', 'vault_delivery_ack_outbox', 'vault_delivery_state']) {
        if (request.result.objectStoreNames.contains(retired)) request.result.deleteObjectStore(retired)
      }
    }
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error ?? new Error('failed to open vault database'))
    request.onblocked = () => reject(new Error('vault database upgrade is blocked by another client'))
  })
}

// Every store's keyPath, `identityId` first (sole key, or the first element
// of a compound one) -- the single source of truth for createStores below
// AND rekeyIdentity (IndexedDbVaultStore's own method), which needs to know
// each store's exact key shape to move a row from its old key to its new
// one. Kept as one table specifically so the two never drift apart.
const KEY_PATHS: Record<StoreName, string | string[]> = {
  [STORES.ingressReceipts]: ['identityId', 'ingressId'],
  [STORES.objects]: ['identityId', 'objectId'],
  [STORES.events]: ['identityId', 'id'],
  [STORES.chunks]: ['identityId', 'objectId', 'chunkIndex'],
  [STORES.segments]: ['identityId', 'segmentId'],
  [STORES.manifests]: 'identityId',
  [STORES.projection]: 'identityId',
  [STORES.jmapState]: 'identityId',
  [STORES.outbox]: ['identityId', 'ingressId'],
  [STORES.transportStatus]: ['identityId', 'outboundEventId'],
  [STORES.didCommOutbox]: ['identityId', 'outboundEventId', 'toDid'],
  [STORES.actorSequences]: ['identityId', 'deviceId'],
  [STORES.projectionMeta]: 'identityId',
}

function createStores(database: IDBDatabase): void {
  for (const name of Object.values(STORES)) createStore(database, name, KEY_PATHS[name])
}

function createStore(database: IDBDatabase, name: StoreName, keyPath: string | string[]): void {
  if (!database.objectStoreNames.contains(name)) database.createObjectStore(name, { keyPath })
}

function transactionDone(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve()
    transaction.onabort = () => reject(transaction.error ?? new Error('vault transaction aborted'))
    transaction.onerror = () => undefined
  })
}

function requestValue<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error ?? new Error('IndexedDB request failed'))
  })
}

function assertCommit(input: IngressVaultCommit): void {
  if (!input.identityId || input.receipt.identityId !== input.identityId || (input.ackOutbox && input.ackOutbox.identityId !== input.identityId)) {
    throw new TypeError('ingress commit identity does not match')
  }
  if (input.ackOutbox && (input.receipt.ingressId !== input.ackOutbox.ingressId || input.receipt.ingressId !== input.ackOutbox.ack.ingressId)) {
    throw new TypeError('ingress receipt and ACK outbox do not match')
  }
  for (const object of input.objects) if (object.identityId !== input.identityId) throw new TypeError('object identity does not match')
  for (const event of input.events) if (event.identityId !== input.identityId) throw new TypeError('event identity does not match')
}

function assertLocalCommit(input: LocalVaultMutationCommit): void {
  if (!input.identityId || input.events.length === 0) throw new TypeError('local mutation commit needs matching identity and events')
  for (const value of input.didCommOutbox ?? []) {
    const event = input.events.find(event => event.id === value.outboundEventId)
    if (value.identityId !== input.identityId || !event || !value.emailId || !value.blobId || event.objectRefs[1] !== value.blobId || !value.metadataBlobId || event.objectRefs[0] !== value.metadataBlobId || !value.threadId || !value.messageId || !value.toDid.startsWith('did:') || value.attempts !== 0 || Number.isNaN(Date.parse(value.createdAt))) {
      throw new TypeError('local mutation DIDComm outbox is invalid')
    }
  }
  for (const object of input.objects) if (object.identityId !== input.identityId) throw new TypeError('local mutation object identity does not match')
  for (const event of input.events) if (event.identityId !== input.identityId) throw new TypeError('local mutation event identity does not match')
}

function copyReceipt(value: IngressReceiptRecord): IngressReceiptRecord {
  return { ...value, protectedPayloadHash: value.protectedPayloadHash.slice() }
}

function copyObject(value: VaultObjectRecord): VaultObjectRecord {
  return {
    ...value,
    nonce: value.nonce.slice(),
    ciphertext: value.ciphertext.slice(),
    ciphertextHash: value.ciphertextHash.slice(),
    aad: value.aad.slice(),
  }
}

function copyEvent(value: VaultEventRecord): VaultEventRecord {
  return { ...value, targetIds: [...value.targetIds], objectRefs: [...value.objectRefs], parents: [...value.parents] }
}

function copyOutbox(value: IngressAckOutboxRecord): IngressAckOutboxRecord {
  return {
    ...value,
    ack: {
      ...value.ack,
      protectedPayloadHash: value.ack.protectedPayloadHash.slice(),
      signature: value.ack.signature.slice(),
    },
  }
}

function copyDidCommOutbox(value: DidCommTransportOutboxRecord): DidCommTransportOutboxRecord {
  return { ...value }
}

function assertCanonicalTimestamp(value: string, name: string): void {
  if (!Number.isFinite(Date.parse(value)) || new Date(value).toISOString() !== value) throw new TypeError(`${name} must be a canonical ISO timestamp`)
}

function assertSegmentRecord(value: VaultSegmentRecord): void {
  if (!value.identityId || !value.segmentId || value.segmentKey.length !== 32) {
    throw new TypeError('invalid vault segment record')
  }
  if (Number.isNaN(Date.parse(value.createdAt))) throw new TypeError('vault segment createdAt must be an ISO date string')
}

function copySegmentRecord(value: VaultSegmentRecord): VaultSegmentRecord {
  return { ...value, segmentKey: value.segmentKey.slice() }
}
