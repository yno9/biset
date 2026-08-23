import type { IngressAckV1 } from '../protocol/ingress.ts'
import { equalBytes } from '../protocol/canonical.ts'
import type { DeliverySeq, DeviceId, IdentityId, MlsEpoch, SegmentId, VaultEventId, VaultObjectId } from '../protocol/ids.ts'
import type { DeliveryPullResult, RestoreOfferV1, RestoreRequestV1, SegmentKeyWrapV1, VaultDeliveryAckV1, VaultDeliveryItemV1, VaultEventV1, VaultObjectV1 } from '../protocol/vault.ts'
import { assertRestoreOffer, assertRestoreRequest } from '../protocol/validate.ts'
import type { RestoreTransferChunkCommit, RestoreTransferReceiverStore, RestoreTransferSessionV1 } from './restore-transfer-receiver.ts'

const DATABASE_NAME = 'biset-vault-core'
const DATABASE_VERSION = 5

const STORES = {
  ingressReceipts: 'vault_ingress_receipts',
  objects: 'vault_objects',
  events: 'vault_events',
  chunks: 'vault_chunks',
  segments: 'vault_segments',
  keyWraps: 'vault_key_wraps',
  manifests: 'vault_manifests',
  projection: 'vault_projection',
  jmapState: 'vault_jmap_state',
  outbox: 'vault_outbox',
  deliveryOutbox: 'vault_delivery_outbox',
  deliveryReceipts: 'vault_delivery_receipts',
  deliveryAckOutbox: 'vault_delivery_ack_outbox',
  deliveryState: 'vault_delivery_state',
  restoreState: 'vault_restore_state',
  restoreOfferOutbox: 'vault_restore_offer_outbox',
  restoreTransferState: 'vault_restore_transfer_state',
  transportStatus: 'transport_status',
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
export interface IngressAckOutboxReader {
  readIngressAckOutbox(identityId: IdentityId, recipientDeviceId: DeviceId, limit?: number): Promise<IngressAckOutboxRecord[]>
  removeIngressAckOutbox(identityId: IdentityId, ingressId: string): Promise<void>
  noteIngressAckOutboxAttempt(identityId: IdentityId, ingressId: string): Promise<void>
}

/**
 * Locally durable work waiting to become one mediator delivery item. Its body
 * is an encrypted shared-vault pack; recipient snapshots and expiry belong to
 * the mediator append operation and are deliberately absent here.
 */
export interface VaultDeliveryOutboxRecord {
  identityId: IdentityId
  entryId: VaultEventId
  payload: Uint8Array
  payloadHash: Uint8Array
  createdAt: string
  attempts: number
}

export interface VaultDeliveryReceiptRecord {
  identityId: IdentityId
  recipientDeviceId: DeviceId
  seq: DeliverySeq
  payloadHash: Uint8Array
  checkpointId: string
  committedAt: string
}

export interface VaultDeliveryAckOutboxRecord {
  identityId: IdentityId
  recipientDeviceId: DeviceId
  seq: DeliverySeq
  ack: VaultDeliveryAckV1
  attempts: number
  createdAt: string
}

/** Durable client-side intent to ask a trusted peer for a foreground restore. */
export interface VaultRestoreRequestStateRecord {
  identityId: IdentityId
  deviceId: DeviceId
  request: RestoreRequestV1
  gap: Extract<DeliveryPullResult, { kind: 'restoreRequired' }>
  status: 'pending' | 'submitted'
  attempts: number
  createdAt: string
  lastAttemptAt?: string
  submittedAt?: string
}

/** Durable, user-approved peer offer; it contains no manifest or vault bytes. */
export interface VaultRestoreOfferOutboxRecord {
  identityId: IdentityId
  requestId: string
  responderDeviceId: DeviceId
  offer: RestoreOfferV1
  status: 'pending' | 'submitted'
  attempts: number
  createdAt: string
  lastAttemptAt?: string
  submittedAt?: string
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
  /** Present when the endpoint has made the external item part of shared vault state. */
  deliveryOutbox?: VaultDeliveryOutboxRecord
  ackOutbox: IngressAckOutboxRecord
}

/** Local UI mutation commit: no ingress receipt/ACK, but the same atomicity. */
export interface LocalVaultMutationCommit {
  identityId: IdentityId
  objects: VaultObjectRecord[]
  events: VaultEventRecord[]
  projection: unknown
  jmapState: unknown
  deliveryOutbox: VaultDeliveryOutboxRecord
}

/**
 * Receive-side counterpart of LocalVaultMutationCommit. The acknowledgement
 * becomes sendable only after every listed vault record and the derived local
 * projection are durably committed together.
 */
export interface VaultDeliveryCommit {
  identityId: IdentityId
  receipt: VaultDeliveryReceiptRecord
  delivery: VaultDeliveryItemV1
  objects: VaultObjectRecord[]
  events: VaultEventRecord[]
  keyWraps: SegmentKeyWrapV1[]
  projection: unknown
  jmapState: unknown
  ackOutbox: VaultDeliveryAckOutboxRecord
}

/** Raw archive records are committed together; projection rebuild is a later explicit step. */
export interface RecoveryArchiveImportCommit {
  identityId: IdentityId
  objects: VaultObjectRecord[]
  events: VaultEventRecord[]
  keyWraps: SegmentKeyWrapV1[]
}

export type IngressCommitResult = 'committed' | 'already-committed'

/** Narrow read boundary used by local projections without exposing IDB internals. */
export interface VaultProjectionReader {
  readProjection(identityId: IdentityId): Promise<unknown | undefined>
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

export interface RecoveryArchiveImportStore {
  commitRecoveryArchive(input: RecoveryArchiveImportCommit): Promise<void>
}

export interface SegmentKeyWrapReader {
  readSegmentKeyWrap(identityId: IdentityId, segmentId: string, recipientEpoch: string): Promise<SegmentKeyWrapV1 | undefined>
}

export interface SegmentKeyWrapWriter {
  writeSegmentKeyWrap(wrap: SegmentKeyWrapV1): Promise<void>
}

/** One vault segment: the identifier/key pair every object encrypted under
 * it shares. `sealed` records whether new objects may still be appended to
 * it — PLAN.md §4.2's "seal the active segment after an MLS commit" is
 * exactly this record turning `sealed: true` the moment a newer one becomes
 * current (`sealAndActivateSegment`, below, is the only way that ever
 * happens).
 *
 * `epoch` is NOT "the epoch this segment was created in" — it is the most
 * RECENT self-group epoch this identity holds a `SegmentKeyWrap` for, for
 * THIS segment. A sealed segment's epoch only ever advances when
 * `recordSegmentRewrapped` runs after a fresh self-grant (PLAN.md §4.2's
 * restore-grant machinery, `identity/bootstrap.ts`'s `maintainSelfGroup`,
 * applied to this identity's OWN segments): a `StoredSegmentKeyResolver`
 * only ever looks up a wrap for the self group's CURRENT epoch, so a sealed
 * segment whose only wrap is for a long-superseded epoch is unreadable
 * until something re-wraps it for the current one. Tracking "the epoch we
 * last confirmed a wrap for" here is what lets that re-wrap step find the
 * right SOURCE wrap without a separate index. */
export interface VaultSegmentRecord {
  identityId: IdentityId
  segmentId: SegmentId
  segmentKey: Uint8Array
  selfGroupId: string
  epoch: MlsEpoch
  sealed: boolean
  createdAt: string
}

export interface ActiveVaultSegmentStore {
  /** The current (not sealed) segment for this identity, or undefined if
   * none has ever been created. At most one segment is ever current per
   * identity — `sealAndActivateSegment` enforces that by construction. */
  currentSegment(identityId: IdentityId): Promise<VaultSegmentRecord | undefined>
  /** Every segment (sealed or not) this identity has ever created — for
   * `maintainSelfGroup`'s self-grant sweep, which must reach every segment
   * whose wrap might have fallen behind the self group's current epoch, not
   * only the current one. */
  allSegments(identityId: IdentityId): Promise<VaultSegmentRecord[]>
  /**
   * Atomically seals whatever segment is currently active for this
   * identity (a no-op if there is none) and activates `next` as the new
   * current one. The ONLY way a segment ever becomes current, and the ONLY
   * way one ever gets sealed — so "the active segment" and "the most
   * recently activated one" are always the same segment.
   */
  sealAndActivateSegment(next: VaultSegmentRecord): Promise<void>
  /** Records that this segment's wrap is now confirmed current as of
   * `epoch` — called after a successful self-grant re-wrap
   * (`maintainSelfGroup`). Never changes `sealed`. */
  recordSegmentRewrapped(identityId: IdentityId, segmentId: SegmentId, epoch: MlsEpoch): Promise<void>
}

/** The client retry loop sees only its own encrypted, local append work. */
export interface VaultDeliveryOutboxReader {
  readDeliveryOutbox(identityId: IdentityId, limit?: number): Promise<VaultDeliveryOutboxRecord[]>
  removeDeliveryOutbox(identityId: IdentityId, entryId: VaultEventId): Promise<void>
  noteDeliveryOutboxAttempt(identityId: IdentityId, entryId: VaultEventId): Promise<void>
}

export interface VaultDeliveryCursorReader {
  readDeliveryCursor(identityId: IdentityId, recipientDeviceId: DeviceId): Promise<DeliverySeq>
}

/** ACKs are durable work items, independent of whether a push/network wake succeeds. */
export interface VaultDeliveryAckOutboxReader {
  readDeliveryAckOutbox(identityId: IdentityId, recipientDeviceId: DeviceId, limit?: number): Promise<VaultDeliveryAckOutboxRecord[]>
  removeDeliveryAckOutbox(identityId: IdentityId, recipientDeviceId: DeviceId, seq: DeliverySeq): Promise<void>
  noteDeliveryAckOutboxAttempt(identityId: IdentityId, recipientDeviceId: DeviceId, seq: DeliverySeq): Promise<void>
}

/** Restore requests are local durable state, not a core-side vault archive. */
export interface VaultRestoreRequestStateStore {
  readRestoreRequestState(identityId: IdentityId, deviceId: DeviceId): Promise<VaultRestoreRequestStateRecord | undefined>
  writeRestoreRequestState(value: VaultRestoreRequestStateRecord): Promise<void>
  noteRestoreRequestAttempt(identityId: IdentityId, deviceId: DeviceId, attemptedAt: string): Promise<void>
  markRestoreRequestSubmitted(identityId: IdentityId, deviceId: DeviceId, submittedAt: string): Promise<void>
  clearRestoreRequestState(identityId: IdentityId, deviceId: DeviceId): Promise<void>
}

export interface VaultRestoreOfferOutboxStore {
  readRestoreOfferOutbox(identityId: IdentityId, requestId: string, responderDeviceId: DeviceId): Promise<VaultRestoreOfferOutboxRecord | undefined>
  writeRestoreOfferOutbox(value: VaultRestoreOfferOutboxRecord): Promise<void>
  noteRestoreOfferAttempt(identityId: IdentityId, requestId: string, responderDeviceId: DeviceId, attemptedAt: string): Promise<void>
  markRestoreOfferSubmitted(identityId: IdentityId, requestId: string, responderDeviceId: DeviceId, submittedAt: string): Promise<void>
  clearRestoreOfferOutbox(identityId: IdentityId, requestId: string, responderDeviceId: DeviceId): Promise<void>
}

export class IndexedDbVaultStore implements VaultProjectionReader, VaultObjectReader, VaultCredentialEventReader, VaultRecordReader, RecoveryArchiveImportStore, SegmentKeyWrapReader, SegmentKeyWrapWriter, ActiveVaultSegmentStore, IngressAckOutboxReader, VaultDeliveryOutboxReader, VaultDeliveryCursorReader, VaultDeliveryAckOutboxReader, VaultRestoreRequestStateStore, VaultRestoreOfferOutboxStore, RestoreTransferReceiverStore {
  private constructor(private readonly database: IDBDatabase) {}

  static async open(): Promise<IndexedDbVaultStore> {
    return new IndexedDbVaultStore(await openDatabase())
  }

  close(): void {
    this.database.close()
  }

  /**
   * Idempotence is anchored by the ingress receipt's composite key. A repeated
   * ingress aborts before any object/event/projection mutation can commit.
   */
  async commitIngress(input: IngressVaultCommit): Promise<IngressCommitResult> {
    assertCommit(input)
    const transaction = this.database.transaction([
      STORES.ingressReceipts,
      STORES.objects,
      STORES.events,
      STORES.projection,
      STORES.jmapState,
      STORES.outbox,
      STORES.deliveryOutbox,
    ], 'readwrite')
    let duplicate = false
    const receiptStore = transaction.objectStore(STORES.ingressReceipts)
    const receiptRequest = receiptStore.add(copyReceipt(input.receipt))
    receiptRequest.onerror = () => {
      if (receiptRequest.error?.name === 'ConstraintError') duplicate = true
    }
    for (const object of input.objects) transaction.objectStore(STORES.objects).put(copyObject(object))
    for (const event of input.events) transaction.objectStore(STORES.events).put(copyEvent(event))
    transaction.objectStore(STORES.projection).put({ identityId: input.identityId, value: input.projection })
    transaction.objectStore(STORES.jmapState).put({ identityId: input.identityId, value: input.jmapState })
    transaction.objectStore(STORES.outbox).put(copyOutbox(input.ackOutbox))
    if (input.deliveryOutbox) transaction.objectStore(STORES.deliveryOutbox).put(copyDeliveryOutbox(input.deliveryOutbox))

    try {
      await transactionDone(transaction)
      return 'committed'
    } catch (error) {
      if (duplicate) return 'already-committed'
      throw error
    }
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
    const transaction = this.database.transaction([
      STORES.objects,
      STORES.events,
      STORES.projection,
      STORES.jmapState,
      STORES.deliveryOutbox,
    ], 'readwrite')
    let duplicate = false
    const eventStore = transaction.objectStore(STORES.events)
    for (const event of input.events) {
      const request = eventStore.add(copyEvent(event))
      request.onerror = () => {
        if (request.error?.name === 'ConstraintError') duplicate = true
      }
    }
    for (const object of input.objects) transaction.objectStore(STORES.objects).put(copyObject(object))
    transaction.objectStore(STORES.projection).put({ identityId: input.identityId, value: input.projection })
    transaction.objectStore(STORES.jmapState).put({ identityId: input.identityId, value: input.jmapState })
    transaction.objectStore(STORES.deliveryOutbox).put(copyDeliveryOutbox(input.deliveryOutbox))
    try {
      await transactionDone(transaction)
      return 'committed'
    } catch (error) {
      if (duplicate) return 'already-committed'
      throw error
    }
  }

  async commitDelivery(input: VaultDeliveryCommit): Promise<IngressCommitResult> {
    assertDeliveryCommit(input)
    const transaction = this.database.transaction([
      STORES.deliveryReceipts,
      STORES.objects,
      STORES.events,
      STORES.keyWraps,
      STORES.projection,
      STORES.jmapState,
      STORES.deliveryState,
      STORES.deliveryAckOutbox,
    ], 'readwrite')
    let duplicate = false
    const receipt = transaction.objectStore(STORES.deliveryReceipts).add(copyDeliveryReceipt(input.receipt))
    receipt.onerror = () => {
      if (receipt.error?.name === 'ConstraintError') duplicate = true
    }
    for (const object of input.objects) transaction.objectStore(STORES.objects).put(copyObject(object))
    for (const event of input.events) transaction.objectStore(STORES.events).put(copyEvent(event))
    for (const wrap of input.keyWraps) transaction.objectStore(STORES.keyWraps).put(copyKeyWrap(wrap))
    transaction.objectStore(STORES.projection).put({ identityId: input.identityId, value: input.projection })
    transaction.objectStore(STORES.jmapState).put({ identityId: input.identityId, value: input.jmapState })
    transaction.objectStore(STORES.deliveryState).put({
      identityId: input.identityId,
      deviceId: input.receipt.recipientDeviceId,
      cursor: input.receipt.seq,
      checkpointId: input.receipt.checkpointId,
      committedAt: input.receipt.committedAt,
    })
    transaction.objectStore(STORES.deliveryAckOutbox).put(copyDeliveryAckOutbox(input.ackOutbox))
    try {
      await transactionDone(transaction)
      return 'committed'
    } catch (error) {
      if (duplicate) return 'already-committed'
      throw error
    }
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

  async readVaultObjects(identityId: IdentityId): Promise<VaultObjectRecord[]> {
    if (!identityId) throw new TypeError('vault object identity is required')
    const transaction = this.database.transaction(STORES.objects, 'readonly')
    const completed = transactionDone(transaction)
    const values = await requestValue<VaultObjectRecord[]>(transaction.objectStore(STORES.objects).getAll())
    await completed
    return values.filter(value => value.identityId === identityId).sort((left, right) => left.objectId.localeCompare(right.objectId)).map(copyObject)
  }

  async writeSegmentKeyWrap(wrap: SegmentKeyWrapV1): Promise<void> {
    assertKeyWrap(wrap)
    const transaction = this.database.transaction(STORES.keyWraps, 'readwrite')
    transaction.objectStore(STORES.keyWraps).put(copyKeyWrap(wrap))
    await transactionDone(transaction)
  }

  async readSegmentKeyWrap(identityId: IdentityId, segmentId: string, recipientEpoch: string): Promise<SegmentKeyWrapV1 | undefined> {
    if (!identityId || !segmentId || !recipientEpoch) throw new TypeError('key wrap identity, segment, and epoch are required')
    const transaction = this.database.transaction(STORES.keyWraps, 'readonly')
    const completed = transactionDone(transaction)
    const wrap = await requestValue<SegmentKeyWrapV1 | undefined>(
      transaction.objectStore(STORES.keyWraps).get([identityId, segmentId, recipientEpoch]),
    )
    await completed
    return wrap && copyKeyWrap(wrap)
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

  async allSegments(identityId: IdentityId): Promise<VaultSegmentRecord[]> {
    if (!identityId) throw new TypeError('segment identity is required')
    const transaction = this.database.transaction(STORES.segments, 'readonly')
    const completed = transactionDone(transaction)
    const values = await requestValue<VaultSegmentRecord[]>(transaction.objectStore(STORES.segments).getAll())
    await completed
    return values.filter(value => value.identityId === identityId).map(copySegmentRecord)
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

  async recordSegmentRewrapped(identityId: IdentityId, segmentId: SegmentId, epoch: MlsEpoch): Promise<void> {
    if (!identityId || !segmentId || !epoch) throw new TypeError('segment rewrap identity, segment, and epoch are required')
    const transaction = this.database.transaction(STORES.segments, 'readwrite')
    const store = transaction.objectStore(STORES.segments)
    const existing = await requestValue<VaultSegmentRecord | undefined>(store.get([identityId, segmentId]))
    if (!existing) throw new Error('recordSegmentRewrapped: no such segment')
    store.put({ ...copySegmentRecord(existing), epoch })
    await transactionDone(transaction)
  }

  async readDeliveryOutbox(identityId: IdentityId, limit = 32): Promise<VaultDeliveryOutboxRecord[]> {
    if (!identityId || !Number.isSafeInteger(limit) || limit < 1) throw new TypeError('delivery outbox identity and positive limit are required')
    const transaction = this.database.transaction(STORES.deliveryOutbox, 'readonly')
    const completed = transactionDone(transaction)
    const values = await requestValue<VaultDeliveryOutboxRecord[]>(transaction.objectStore(STORES.deliveryOutbox).getAll())
    await completed
    return values
      .filter(value => value.identityId === identityId)
      .sort((left, right) => left.createdAt.localeCompare(right.createdAt) || left.entryId.localeCompare(right.entryId))
      .slice(0, limit)
      .map(copyDeliveryOutbox)
  }

  async removeDeliveryOutbox(identityId: IdentityId, entryId: VaultEventId): Promise<void> {
    if (!identityId || !entryId) throw new TypeError('delivery outbox identity and entry ID are required')
    const transaction = this.database.transaction(STORES.deliveryOutbox, 'readwrite')
    transaction.objectStore(STORES.deliveryOutbox).delete([identityId, entryId])
    await transactionDone(transaction)
  }

  async noteDeliveryOutboxAttempt(identityId: IdentityId, entryId: VaultEventId): Promise<void> {
    if (!identityId || !entryId) throw new TypeError('delivery outbox identity and entry ID are required')
    const transaction = this.database.transaction(STORES.deliveryOutbox, 'readwrite')
    const store = transaction.objectStore(STORES.deliveryOutbox)
    const request = store.get([identityId, entryId])
    request.onsuccess = () => {
      const record = request.result as VaultDeliveryOutboxRecord | undefined
      if (!record) return
      store.put({ ...copyDeliveryOutbox(record), attempts: record.attempts + 1 })
    }
    await transactionDone(transaction)
  }

  async readDeliveryCursor(identityId: IdentityId, recipientDeviceId: DeviceId): Promise<DeliverySeq> {
    if (!identityId || !recipientDeviceId) throw new TypeError('delivery cursor identity and device are required')
    const transaction = this.database.transaction(STORES.deliveryState, 'readonly')
    const completed = transactionDone(transaction)
    const record = await requestValue<{ cursor?: DeliverySeq } | undefined>(
      transaction.objectStore(STORES.deliveryState).get([identityId, recipientDeviceId]),
    )
    await completed
    return record?.cursor ?? '0'
  }

  async readDeliveryAckOutbox(identityId: IdentityId, recipientDeviceId: DeviceId, limit = 32): Promise<VaultDeliveryAckOutboxRecord[]> {
    if (!identityId || !recipientDeviceId || !Number.isSafeInteger(limit) || limit < 1) throw new TypeError('delivery ACK outbox identity, device, and positive limit are required')
    const transaction = this.database.transaction(STORES.deliveryAckOutbox, 'readonly')
    const completed = transactionDone(transaction)
    const values = await requestValue<VaultDeliveryAckOutboxRecord[]>(transaction.objectStore(STORES.deliveryAckOutbox).getAll())
    await completed
    return values
      .filter(value => value.identityId === identityId && value.recipientDeviceId === recipientDeviceId)
      .sort((left, right) => BigInt(left.seq) < BigInt(right.seq) ? -1 : BigInt(left.seq) > BigInt(right.seq) ? 1 : 0)
      .slice(0, limit)
      .map(copyDeliveryAckOutbox)
  }

  async removeDeliveryAckOutbox(identityId: IdentityId, recipientDeviceId: DeviceId, seq: DeliverySeq): Promise<void> {
    if (!identityId || !recipientDeviceId || !seq) throw new TypeError('delivery ACK outbox identity, device, and sequence are required')
    const transaction = this.database.transaction(STORES.deliveryAckOutbox, 'readwrite')
    transaction.objectStore(STORES.deliveryAckOutbox).delete([identityId, recipientDeviceId, seq])
    await transactionDone(transaction)
  }

  async noteDeliveryAckOutboxAttempt(identityId: IdentityId, recipientDeviceId: DeviceId, seq: DeliverySeq): Promise<void> {
    if (!identityId || !recipientDeviceId || !seq) throw new TypeError('delivery ACK outbox identity, device, and sequence are required')
    const transaction = this.database.transaction(STORES.deliveryAckOutbox, 'readwrite')
    const store = transaction.objectStore(STORES.deliveryAckOutbox)
    const request = store.get([identityId, recipientDeviceId, seq])
    request.onsuccess = () => {
      const record = request.result as VaultDeliveryAckOutboxRecord | undefined
      if (!record) return
      store.put({ ...copyDeliveryAckOutbox(record), attempts: record.attempts + 1 })
    }
    await transactionDone(transaction)
  }

  async readRestoreRequestState(identityId: IdentityId, deviceId: DeviceId): Promise<VaultRestoreRequestStateRecord | undefined> {
    if (!identityId || !deviceId) throw new TypeError('restore request identity and device are required')
    const transaction = this.database.transaction(STORES.restoreState, 'readonly')
    const completed = transactionDone(transaction)
    const record = await requestValue<VaultRestoreRequestStateRecord | undefined>(transaction.objectStore(STORES.restoreState).get([identityId, deviceId]))
    await completed
    return record && copyRestoreRequestState(record)
  }

  async writeRestoreRequestState(value: VaultRestoreRequestStateRecord): Promise<void> {
    assertRestoreRequestState(value)
    const transaction = this.database.transaction(STORES.restoreState, 'readwrite')
    transaction.objectStore(STORES.restoreState).put(copyRestoreRequestState(value))
    await transactionDone(transaction)
  }

  async noteRestoreRequestAttempt(identityId: IdentityId, deviceId: DeviceId, attemptedAt: string): Promise<void> {
    if (!identityId || !deviceId || Number.isNaN(Date.parse(attemptedAt))) throw new TypeError('restore request attempt is invalid')
    const transaction = this.database.transaction(STORES.restoreState, 'readwrite')
    const store = transaction.objectStore(STORES.restoreState)
    const request = store.get([identityId, deviceId])
    request.onsuccess = () => {
      const record = request.result as VaultRestoreRequestStateRecord | undefined
      if (!record || record.status !== 'pending') return
      store.put({ ...copyRestoreRequestState(record), attempts: record.attempts + 1, lastAttemptAt: attemptedAt })
    }
    await transactionDone(transaction)
  }

  async markRestoreRequestSubmitted(identityId: IdentityId, deviceId: DeviceId, submittedAt: string): Promise<void> {
    if (!identityId || !deviceId || Number.isNaN(Date.parse(submittedAt))) throw new TypeError('restore request submission is invalid')
    const transaction = this.database.transaction(STORES.restoreState, 'readwrite')
    const store = transaction.objectStore(STORES.restoreState)
    const request = store.get([identityId, deviceId])
    request.onsuccess = () => {
      const record = request.result as VaultRestoreRequestStateRecord | undefined
      if (!record) return
      store.put({ ...copyRestoreRequestState(record), status: 'submitted', submittedAt })
    }
    await transactionDone(transaction)
  }

  async clearRestoreRequestState(identityId: IdentityId, deviceId: DeviceId): Promise<void> {
    if (!identityId || !deviceId) throw new TypeError('restore request identity and device are required')
    const transaction = this.database.transaction(STORES.restoreState, 'readwrite')
    transaction.objectStore(STORES.restoreState).delete([identityId, deviceId])
    await transactionDone(transaction)
  }

  async readRestoreOfferOutbox(identityId: IdentityId, requestId: string, responderDeviceId: DeviceId): Promise<VaultRestoreOfferOutboxRecord | undefined> {
    if (!identityId || !requestId || !responderDeviceId) throw new TypeError('restore offer identity, request, and responder are required')
    const transaction = this.database.transaction(STORES.restoreOfferOutbox, 'readonly')
    const completed = transactionDone(transaction)
    const record = await requestValue<VaultRestoreOfferOutboxRecord | undefined>(transaction.objectStore(STORES.restoreOfferOutbox).get([identityId, requestId, responderDeviceId]))
    await completed
    return record && copyRestoreOfferOutbox(record)
  }

  async writeRestoreOfferOutbox(value: VaultRestoreOfferOutboxRecord): Promise<void> {
    assertRestoreOfferOutbox(value)
    const transaction = this.database.transaction(STORES.restoreOfferOutbox, 'readwrite')
    transaction.objectStore(STORES.restoreOfferOutbox).put(copyRestoreOfferOutbox(value))
    await transactionDone(transaction)
  }

  async noteRestoreOfferAttempt(identityId: IdentityId, requestId: string, responderDeviceId: DeviceId, attemptedAt: string): Promise<void> {
    if (!identityId || !requestId || !responderDeviceId || Number.isNaN(Date.parse(attemptedAt))) throw new TypeError('restore offer attempt is invalid')
    const transaction = this.database.transaction(STORES.restoreOfferOutbox, 'readwrite')
    const store = transaction.objectStore(STORES.restoreOfferOutbox)
    const request = store.get([identityId, requestId, responderDeviceId])
    request.onsuccess = () => {
      const record = request.result as VaultRestoreOfferOutboxRecord | undefined
      if (!record || record.status !== 'pending') return
      store.put({ ...copyRestoreOfferOutbox(record), attempts: record.attempts + 1, lastAttemptAt: attemptedAt })
    }
    await transactionDone(transaction)
  }

  async markRestoreOfferSubmitted(identityId: IdentityId, requestId: string, responderDeviceId: DeviceId, submittedAt: string): Promise<void> {
    if (!identityId || !requestId || !responderDeviceId || Number.isNaN(Date.parse(submittedAt))) throw new TypeError('restore offer submission is invalid')
    const transaction = this.database.transaction(STORES.restoreOfferOutbox, 'readwrite')
    const store = transaction.objectStore(STORES.restoreOfferOutbox)
    const request = store.get([identityId, requestId, responderDeviceId])
    request.onsuccess = () => {
      const record = request.result as VaultRestoreOfferOutboxRecord | undefined
      if (!record) return
      store.put({ ...copyRestoreOfferOutbox(record), status: 'submitted', submittedAt })
    }
    await transactionDone(transaction)
  }

  async clearRestoreOfferOutbox(identityId: IdentityId, requestId: string, responderDeviceId: DeviceId): Promise<void> {
    if (!identityId || !requestId || !responderDeviceId) throw new TypeError('restore offer identity, request, and responder are required')
    const transaction = this.database.transaction(STORES.restoreOfferOutbox, 'readwrite')
    transaction.objectStore(STORES.restoreOfferOutbox).delete([identityId, requestId, responderDeviceId])
    await transactionDone(transaction)
  }

  async readRestoreTransferSession(identityId: IdentityId, requesterDeviceId: string): Promise<RestoreTransferSessionV1 | undefined> {
    if (!identityId || !requesterDeviceId) throw new TypeError('restore transfer identity and requester are required')
    const transaction = this.database.transaction(STORES.restoreTransferState, 'readonly')
    const completed = transactionDone(transaction)
    const value = await requestValue<RestoreTransferSessionV1 | undefined>(transaction.objectStore(STORES.restoreTransferState).get([identityId, requesterDeviceId]))
    await completed
    return value && copyRestoreTransferSession(value)
  }

  /** Records and the resume cursor are one transaction; a crash cannot advance one without the other. */
  async commitRestoreTransferChunk(input: RestoreTransferChunkCommit): Promise<void> {
    assertRestoreTransferChunkCommit(input)
    const transaction = this.database.transaction([STORES.objects, STORES.events, STORES.keyWraps, STORES.restoreTransferState], 'readwrite')
    for (const object of input.objects) transaction.objectStore(STORES.objects).put(copyObject({ ...object, identityId: input.session.identityId }))
    for (const event of input.events) transaction.objectStore(STORES.events).put(copyEvent({ ...event, identityId: input.session.identityId }))
    for (const wrap of input.keyWraps) transaction.objectStore(STORES.keyWraps).put(copyKeyWrap(wrap))
    transaction.objectStore(STORES.restoreTransferState).put(copyRestoreTransferSession(input.session))
    await transactionDone(transaction)
  }

  /**
   * Does not write projection/JMAP state: callers must cryptographically
   * rebuild that view before declaring archive restore complete.
   */
  async commitRecoveryArchive(input: RecoveryArchiveImportCommit): Promise<void> {
    assertRecoveryArchiveImportCommit(input)
    const transaction = this.database.transaction([STORES.objects, STORES.events, STORES.keyWraps], 'readwrite')
    for (const object of input.objects) transaction.objectStore(STORES.objects).put(copyObject(object))
    for (const event of input.events) transaction.objectStore(STORES.events).put(copyEvent(event))
    for (const wrap of input.keyWraps) transaction.objectStore(STORES.keyWraps).put(copyKeyWrap(wrap))
    await transactionDone(transaction)
  }
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE_NAME, DATABASE_VERSION)
    request.onupgradeneeded = () => createStores(request.result)
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error ?? new Error('failed to open vault database'))
    request.onblocked = () => reject(new Error('vault database upgrade is blocked by another client'))
  })
}

function createStores(database: IDBDatabase): void {
  createStore(database, STORES.ingressReceipts, ['identityId', 'ingressId'])
  createStore(database, STORES.objects, ['identityId', 'objectId'])
  createStore(database, STORES.events, ['identityId', 'id'])
  createStore(database, STORES.chunks, ['identityId', 'objectId', 'chunkIndex'])
  createStore(database, STORES.segments, ['identityId', 'segmentId'])
  createStore(database, STORES.keyWraps, ['identityId', 'segmentId', 'recipientEpoch'])
  createStore(database, STORES.manifests, 'identityId')
  createStore(database, STORES.projection, 'identityId')
  createStore(database, STORES.jmapState, 'identityId')
  createStore(database, STORES.outbox, ['identityId', 'ingressId'])
  createStore(database, STORES.deliveryOutbox, ['identityId', 'entryId'])
  createStore(database, STORES.deliveryReceipts, ['identityId', 'recipientDeviceId', 'seq'])
  createStore(database, STORES.deliveryAckOutbox, ['identityId', 'recipientDeviceId', 'seq'])
  createStore(database, STORES.deliveryState, ['identityId', 'deviceId'])
  createStore(database, STORES.restoreState, ['identityId', 'deviceId'])
  createStore(database, STORES.restoreOfferOutbox, ['identityId', 'requestId', 'responderDeviceId'])
  createStore(database, STORES.restoreTransferState, ['identityId', 'requesterDeviceId'])
  createStore(database, STORES.transportStatus, ['identityId', 'outboundEventId'])
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
  if (!input.identityId || input.receipt.identityId !== input.identityId || input.ackOutbox.identityId !== input.identityId) {
    throw new TypeError('ingress commit identity does not match')
  }
  if (input.receipt.ingressId !== input.ackOutbox.ingressId || input.receipt.ingressId !== input.ackOutbox.ack.ingressId) {
    throw new TypeError('ingress receipt and ACK outbox do not match')
  }
  for (const object of input.objects) if (object.identityId !== input.identityId) throw new TypeError('object identity does not match')
  for (const event of input.events) if (event.identityId !== input.identityId) throw new TypeError('event identity does not match')
  if (input.deliveryOutbox) assertDeliveryOutbox(input.identityId, input.events, input.deliveryOutbox, 'ingress')
}

function assertLocalCommit(input: LocalVaultMutationCommit): void {
  if (!input.identityId || input.events.length === 0 || input.deliveryOutbox.identityId !== input.identityId) throw new TypeError('local mutation commit needs matching identity and events')
  assertDeliveryOutbox(input.identityId, input.events, input.deliveryOutbox, 'local mutation')
  for (const object of input.objects) if (object.identityId !== input.identityId) throw new TypeError('local mutation object identity does not match')
  for (const event of input.events) if (event.identityId !== input.identityId) throw new TypeError('local mutation event identity does not match')
}

function assertDeliveryOutbox(identityId: IdentityId, events: VaultEventRecord[], outbox: VaultDeliveryOutboxRecord, source: string): void {
  if (outbox.identityId !== identityId || !events.some(event => event.id === outbox.entryId)
    || !outbox.entryId || outbox.payload.length === 0 || outbox.payloadHash.length === 0
    || !Number.isSafeInteger(outbox.attempts) || outbox.attempts < 0 || Number.isNaN(Date.parse(outbox.createdAt))) {
    throw new TypeError(`${source} delivery outbox is invalid`)
  }
}

function assertDeliveryCommit(input: VaultDeliveryCommit): void {
  if (!input.identityId || input.delivery.identityId !== input.identityId || input.receipt.identityId !== input.identityId || input.ackOutbox.identityId !== input.identityId) {
    throw new TypeError('delivery commit identity does not match')
  }
  if (input.receipt.seq !== input.delivery.seq || input.ackOutbox.seq !== input.delivery.seq || input.ackOutbox.ack.seq !== input.delivery.seq || input.ackOutbox.recipientDeviceId !== input.receipt.recipientDeviceId || input.ackOutbox.ack.recipientDeviceId !== input.receipt.recipientDeviceId) {
    throw new TypeError('delivery commit receipt and ACK do not match')
  }
  if (!equalBytes(input.receipt.payloadHash, input.delivery.payloadHash) || !equalBytes(input.ackOutbox.ack.payloadHash, input.delivery.payloadHash)) {
    throw new TypeError('delivery commit payload hashes do not match')
  }
  if (!input.receipt.checkpointId || !input.receipt.recipientDeviceId || input.receipt.payloadHash.length === 0 || !input.receipt.committedAt || input.ackOutbox.attempts !== 0) {
    throw new TypeError('delivery receipt or ACK outbox is invalid')
  }
  for (const object of input.objects) if (object.identityId !== input.identityId) throw new TypeError('delivery object identity does not match')
  for (const event of input.events) if (event.identityId !== input.identityId) throw new TypeError('delivery event identity does not match')
  for (const wrap of input.keyWraps) if (wrap.identityId !== input.identityId) throw new TypeError('delivery key wrap identity does not match')
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
  return { ...value, targetIds: [...value.targetIds], objectRefs: [...value.objectRefs], parents: [...value.parents], signature: value.signature.slice() }
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

function copyDeliveryOutbox(value: VaultDeliveryOutboxRecord): VaultDeliveryOutboxRecord {
  return { ...value, payload: value.payload.slice(), payloadHash: value.payloadHash.slice() }
}

function copyDeliveryReceipt(value: VaultDeliveryReceiptRecord): VaultDeliveryReceiptRecord {
  return { ...value, payloadHash: value.payloadHash.slice() }
}

function copyDeliveryAckOutbox(value: VaultDeliveryAckOutboxRecord): VaultDeliveryAckOutboxRecord {
  return {
    ...value,
    ack: { ...value.ack, payloadHash: value.ack.payloadHash.slice(), signature: value.ack.signature.slice() },
  }
}

function assertKeyWrap(value: SegmentKeyWrapV1): void {
  if (value.version !== 1 || !value.identityId || !value.selfGroupId || !value.segmentId || !value.recipientEpoch) {
    throw new TypeError('invalid SegmentKeyWrap')
  }
}

function assertSegmentRecord(value: VaultSegmentRecord): void {
  if (!value.identityId || !value.segmentId || !value.selfGroupId || !value.epoch || value.segmentKey.length !== 32) {
    throw new TypeError('invalid vault segment record')
  }
  if (Number.isNaN(Date.parse(value.createdAt))) throw new TypeError('vault segment createdAt must be an ISO date string')
}

function copySegmentRecord(value: VaultSegmentRecord): VaultSegmentRecord {
  return { ...value, segmentKey: value.segmentKey.slice() }
}

function assertRestoreRequestState(value: VaultRestoreRequestStateRecord): void {
  if (!value.identityId || !value.deviceId || value.request.identityId !== value.identityId || value.request.requesterDeviceId !== value.deviceId) throw new TypeError('restore request state identity does not match')
  assertRestoreRequest(value.request)
  if (value.status !== 'pending' && value.status !== 'submitted') throw new TypeError('restore request state status is invalid')
  if (!Number.isSafeInteger(value.attempts) || value.attempts < 0 || Number.isNaN(Date.parse(value.createdAt))) throw new TypeError('restore request state metadata is invalid')
  if (value.lastAttemptAt !== undefined && Number.isNaN(Date.parse(value.lastAttemptAt))) throw new TypeError('restore request last attempt is invalid')
  if (value.submittedAt !== undefined && Number.isNaN(Date.parse(value.submittedAt))) throw new TypeError('restore request submission is invalid')
  if (value.gap.kind !== 'restoreRequired' || value.gap.reason !== value.request.reason) throw new TypeError('restore request state gap is invalid')
}

function assertRestoreOfferOutbox(value: VaultRestoreOfferOutboxRecord): void {
  if (!value.identityId || !value.requestId || !value.responderDeviceId || value.offer.identityId !== value.identityId || value.offer.requestId !== value.requestId || value.offer.responderDeviceId !== value.responderDeviceId) throw new TypeError('restore offer outbox identity does not match')
  assertRestoreOffer(value.offer)
  if (value.status !== 'pending' && value.status !== 'submitted') throw new TypeError('restore offer outbox status is invalid')
  if (!Number.isSafeInteger(value.attempts) || value.attempts < 0 || Number.isNaN(Date.parse(value.createdAt))) throw new TypeError('restore offer outbox metadata is invalid')
  if (value.lastAttemptAt !== undefined && Number.isNaN(Date.parse(value.lastAttemptAt))) throw new TypeError('restore offer last attempt is invalid')
  if (value.submittedAt !== undefined && Number.isNaN(Date.parse(value.submittedAt))) throw new TypeError('restore offer submission is invalid')
}

function assertRestoreTransferChunkCommit(input: RestoreTransferChunkCommit): void {
  const { session, chunk } = input
  if (session.version !== 1 || !session.identityId || !session.requesterDeviceId || session.identityId !== chunk.identityId || session.sourceManifest.identityId !== session.identityId || session.requesterManifest.identityId !== session.identityId || session.lastChunkHash !== chunk.chunkHash || session.completed !== (chunk.next === undefined)) throw new TypeError('restore transfer session does not match chunk')
  if (!sameStringLists(input.objects.map(object => object.objectId), chunk.objects.map(object => object.objectId)) || !sameStringLists(input.events.map(event => event.id), chunk.events.map(event => event.id)) || !sameStringLists(input.keyWraps.map(wrap => `${wrap.segmentId}\u0000${wrap.recipientEpoch}`), chunk.keyWraps.map(wrap => `${wrap.segmentId}\u0000${wrap.recipientEpoch}`))) throw new TypeError('restore transfer records do not match verified chunk')
  for (const object of input.objects) if (object.objectId.length === 0) throw new TypeError('restore transfer object is invalid')
  for (const event of input.events) if (event.identityId !== session.identityId) throw new TypeError('restore transfer event identity does not match')
  for (const wrap of input.keyWraps) if (wrap.identityId !== session.identityId) throw new TypeError('restore transfer key wrap identity does not match')
}

function assertRecoveryArchiveImportCommit(input: RecoveryArchiveImportCommit): void {
  if (!input.identityId || input.keyWraps.length === 0) throw new TypeError('recovery archive import is invalid')
  for (const object of input.objects) if (object.identityId !== input.identityId) throw new TypeError('recovery archive object identity does not match')
  for (const event of input.events) if (event.identityId !== input.identityId) throw new TypeError('recovery archive event identity does not match')
  for (const wrap of input.keyWraps) if (wrap.identityId !== input.identityId) throw new TypeError('recovery archive key wrap identity does not match')
}

function sameStringLists(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index])
}

function copyKeyWrap(value: SegmentKeyWrapV1): SegmentKeyWrapV1 {
  return {
    ...value,
    nonce: value.nonce.slice(),
    aad: value.aad.slice(),
    wrappedSegmentKey: value.wrappedSegmentKey.slice(),
    signature: value.signature.slice(),
  }
}

function copyRestoreRequestState(value: VaultRestoreRequestStateRecord): VaultRestoreRequestStateRecord {
  return { ...value, request: { ...value.request, signature: value.request.signature.slice() }, gap: { ...value.gap } }
}

function copyRestoreOfferOutbox(value: VaultRestoreOfferOutboxRecord): VaultRestoreOfferOutboxRecord {
  return { ...value, offer: { ...value.offer, signature: value.offer.signature.slice() } }
}

function copyRestoreTransferSession(value: RestoreTransferSessionV1): RestoreTransferSessionV1 {
  return { ...value, sourceManifest: { ...value.sourceManifest, eventIds: [...value.sourceManifest.eventIds], objectIds: [...value.sourceManifest.objectIds] }, requesterManifest: { ...value.requesterManifest, eventIds: [...value.requesterManifest.eventIds], objectIds: [...value.requesterManifest.objectIds] }, ...(value.next === undefined ? {} : { next: { ...value.next } }) }
}
