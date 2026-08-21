import type { IngressAckV1 } from '../protocol/ingress.ts'
import type { IdentityId, VaultEventId, VaultObjectId } from '../protocol/ids.ts'
import type { VaultEventV1, VaultObjectV1 } from '../protocol/vault.ts'

const DATABASE_NAME = 'biset-vault-core'
const DATABASE_VERSION = 1

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

export type IngressCommitResult = 'committed' | 'already-committed'

export class IndexedDbVaultStore {
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
