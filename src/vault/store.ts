import type { IngressAckV1 } from '../protocol/ingress.ts'
import { equalBytes } from '../protocol/canonical.ts'
import type { DeliverySeq, DeviceId, IdentityId, VaultEventId, VaultObjectId } from '../protocol/ids.ts'
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

export type IngressCommitResult = 'committed' | 'already-committed'

/** Narrow read boundary used by local projections without exposing IDB internals. */
export interface VaultProjectionReader {
  readProjection(identityId: IdentityId): Promise<unknown | undefined>
}

export interface VaultObjectReader {
  readObject(identityId: IdentityId, objectId: VaultObjectId): Promise<VaultObjectRecord | undefined>
}

export interface SegmentKeyWrapReader {
  readSegmentKeyWrap(identityId: IdentityId, segmentId: string, recipientEpoch: string): Promise<SegmentKeyWrapV1 | undefined>
}

export interface SegmentKeyWrapWriter {
  writeSegmentKeyWrap(wrap: SegmentKeyWrapV1): Promise<void>
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

export class IndexedDbVaultStore implements VaultProjectionReader, VaultObjectReader, SegmentKeyWrapReader, SegmentKeyWrapWriter, VaultDeliveryOutboxReader, VaultDeliveryCursorReader, VaultDeliveryAckOutboxReader, VaultRestoreRequestStateStore, VaultRestoreOfferOutboxStore, RestoreTransferReceiverStore {
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
}

function assertLocalCommit(input: LocalVaultMutationCommit): void {
  if (!input.identityId || input.events.length === 0 || input.deliveryOutbox.identityId !== input.identityId) throw new TypeError('local mutation commit needs matching identity and events')
  if (!input.deliveryOutbox.entryId || input.deliveryOutbox.payload.length === 0 || input.deliveryOutbox.payloadHash.length === 0 || !Number.isSafeInteger(input.deliveryOutbox.attempts) || input.deliveryOutbox.attempts < 0 || Number.isNaN(Date.parse(input.deliveryOutbox.createdAt))) {
    throw new TypeError('local mutation delivery outbox is invalid')
  }
  for (const object of input.objects) if (object.identityId !== input.identityId) throw new TypeError('local mutation object identity does not match')
  for (const event of input.events) if (event.identityId !== input.identityId) throw new TypeError('local mutation event identity does not match')
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
