import type { IngressAckV1 } from '../protocol/ingress.ts'
import type { IdentityId, VaultEventId, VaultObjectId } from '../protocol/ids.ts'
import type { SegmentKeyWrapV1, VaultEventV1, VaultObjectV1 } from '../protocol/vault.ts'

const DATABASE_NAME = 'biset-vault-core'
const DATABASE_VERSION = 2

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
  deliveryState: 'vault_delivery_state',
  restoreState: 'vault_restore_state',
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

export class IndexedDbVaultStore implements VaultProjectionReader, VaultObjectReader, SegmentKeyWrapReader, SegmentKeyWrapWriter {
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
  createStore(database, STORES.deliveryState, ['identityId', 'deviceId'])
  createStore(database, STORES.restoreState, ['identityId', 'deviceId'])
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

function assertKeyWrap(value: SegmentKeyWrapV1): void {
  if (value.version !== 1 || !value.identityId || !value.selfGroupId || !value.segmentId || !value.recipientEpoch) {
    throw new TypeError('invalid SegmentKeyWrap')
  }
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
