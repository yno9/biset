import type { IngressAckV1 } from '../protocol/ingress.ts'
import { equalBytes } from '../protocol/canonical.ts'
import type { DeliverySeq, DeviceId, IdentityId, MlsEpoch, SegmentId, VaultEventId, VaultId, VaultMemberId, VaultObjectId } from '../protocol/ids.ts'
import type { DeliveryPullResult, RestoreOfferV1, RestoreRequestV1, SegmentKeyWrapV1, VaultDeliveryAckV1, VaultDeliveryItemV1, VaultEventV1, VaultObjectV1 } from '../protocol/vault.ts'
import { assertRestoreOffer, assertRestoreRequest } from '../protocol/validate.ts'
import { ed25519 } from '@noble/curves/ed25519.js'
import type { RestoreTransferChunkCommit, RestoreTransferReceiverStore, RestoreTransferSessionV1 } from './restore-transfer-receiver.ts'

const DATABASE_NAME = 'biset-vault-core'
const DATABASE_VERSION = 10

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
  didCommOutbox: 'didcomm_transport_outbox',
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

/** Durable DIDComm send intent. Message content stays in encrypted vault objects. */
export interface DidCommTransportOutboxRecord {
  identityId: IdentityId
  outboundEventId: VaultEventId
  emailId: string
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

interface VaultDeliveryReceiptRecord {
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
  deliveryOutbox: VaultDeliveryOutboxRecord
  /** One row per recipient -- a group message's single commit still needs
   * N delivery-queue rows, one per fan-out target
   * (didcomm/group-chat.ts's full-mesh design). A 1:1 chat message is the
   * one-element case. */
  didCommOutbox?: DidCommTransportOutboxRecord[]
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

/**
 * Writes a projection/JMAP-state pair that was NOT derived from a batch of
 * new events -- `rebuildLocalJmapProjection` (vault/projection-rebuild.ts)
 * is the only caller: it recomputes the projection from records already
 * committed, so there is nothing new for `commitLocalMutation`/`commitIngress`/
 * `commitDelivery` (which all require at least one event) to commit
 * alongside it. Also the only way a brand-new identity's very first
 * (all-empty) projection row ever gets written, since nothing else seeds one.
 */
export interface VaultProjectionWriter {
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
  recordSegmentRewrapped(identityId: IdentityId, segmentId: SegmentId, epoch: MlsEpoch, selfGroupId?: string): Promise<void>
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

export class IndexedDbVaultStore implements VaultProjectionReader, VaultProjectionWriter, VaultObjectReader, VaultCredentialEventReader, VaultRecordReader, RecoveryArchiveImportStore, SegmentKeyWrapReader, SegmentKeyWrapWriter, ActiveVaultSegmentStore, IngressReceiptReader, IngressAckOutboxReader, DidCommTransportOutboxStore, VaultDeliveryOutboxReader, VaultDeliveryCursorReader, VaultDeliveryAckOutboxReader, VaultRestoreRequestStateStore, VaultRestoreOfferOutboxStore, RestoreTransferReceiverStore {
  private constructor(private readonly database: IDBDatabase) {}

  static async open(): Promise<IndexedDbVaultStore> {
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
      STORES.projection,
      STORES.jmapState,
      STORES.deliveryOutbox,
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
    transaction.objectStore(STORES.projection).put({ identityId: input.identityId, value: input.projection })
    transaction.objectStore(STORES.jmapState).put({ identityId: input.identityId, value: input.jmapState })
    if (input.ackOutbox) transaction.objectStore(STORES.outbox).put(copyOutbox(input.ackOutbox))
    if (input.deliveryOutbox) transaction.objectStore(STORES.deliveryOutbox).put(copyDeliveryOutbox(input.deliveryOutbox))

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
      STORES.projection,
      STORES.jmapState,
      STORES.deliveryOutbox,
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
    transaction.objectStore(STORES.projection).put({ identityId: input.identityId, value: input.projection })
    transaction.objectStore(STORES.jmapState).put({ identityId: input.identityId, value: input.jmapState })
    transaction.objectStore(STORES.deliveryOutbox).put(copyDeliveryOutbox(input.deliveryOutbox))
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
    return values.filter(value => value.identityId === identityId)
      .sort((left, right) => left.createdAt.localeCompare(right.createdAt) || left.outboundEventId.localeCompare(right.outboundEventId) || left.toDid.localeCompare(right.toDid))
      .slice(0, limit).map(copyDidCommOutbox)
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
      .filter(value => value.identityId === identityId && (value.kind.startsWith('credential.') || value.kind === 'contact-key.set'))
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

  async recordSegmentRewrapped(identityId: IdentityId, segmentId: SegmentId, epoch: MlsEpoch, selfGroupId?: string): Promise<void> {
    if (!identityId || !segmentId || !epoch) throw new TypeError('segment rewrap identity, segment, and epoch are required')
    const transaction = this.database.transaction(STORES.segments, 'readwrite')
    const store = transaction.objectStore(STORES.segments)
    const existing = await requestValue<VaultSegmentRecord | undefined>(store.get([identityId, segmentId]))
    if (!existing) throw new Error('recordSegmentRewrapped: no such segment')
    store.put({ ...copySegmentRecord(existing), epoch, ...(selfGroupId === undefined ? {} : { selfGroupId }) })
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

  /** Advances a restored device to the remote checkpoint's covered
   * sequence only after records and projection are durable. */
  async advanceDeliveryCursor(identityId: IdentityId, recipientDeviceId: DeviceId, cursor: DeliverySeq, checkpointId: string, committedAt: string): Promise<void> {
    if (!identityId || !recipientDeviceId || !cursor || !checkpointId || Number.isNaN(Date.parse(committedAt))) throw new TypeError('restored delivery cursor is invalid')
    const transaction = this.database.transaction(STORES.deliveryState, 'readwrite')
    const store = transaction.objectStore(STORES.deliveryState)
    const existing = await requestValue<{ cursor?: DeliverySeq } | undefined>(store.get([identityId, recipientDeviceId]))
    if (existing?.cursor && BigInt(existing.cursor) > BigInt(cursor)) {
      transaction.abort()
      throw new TypeError('restored delivery cursor cannot move backwards')
    }
    store.put({ identityId, deviceId: recipientDeviceId, cursor, checkpointId, committedAt })
    await transactionDone(transaction)
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
  [STORES.keyWraps]: ['identityId', 'segmentId', 'recipientEpoch'],
  [STORES.manifests]: 'identityId',
  [STORES.projection]: 'identityId',
  [STORES.jmapState]: 'identityId',
  [STORES.outbox]: ['identityId', 'ingressId'],
  [STORES.deliveryOutbox]: ['identityId', 'entryId'],
  [STORES.deliveryReceipts]: ['identityId', 'recipientDeviceId', 'seq'],
  [STORES.deliveryAckOutbox]: ['identityId', 'recipientDeviceId', 'seq'],
  [STORES.deliveryState]: ['identityId', 'deviceId'],
  [STORES.restoreState]: ['identityId', 'deviceId'],
  [STORES.restoreOfferOutbox]: ['identityId', 'requestId', 'responderDeviceId'],
  [STORES.restoreTransferState]: ['identityId', 'requesterDeviceId'],
  [STORES.transportStatus]: ['identityId', 'outboundEventId'],
  [STORES.didCommOutbox]: ['identityId', 'outboundEventId', 'toDid'],
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
  if (input.deliveryOutbox) assertDeliveryOutbox(input.identityId, input.events, input.deliveryOutbox, 'ingress')
}

function assertLocalCommit(input: LocalVaultMutationCommit): void {
  if (!input.identityId || input.events.length === 0 || input.deliveryOutbox.identityId !== input.identityId) throw new TypeError('local mutation commit needs matching identity and events')
  assertDeliveryOutbox(input.identityId, input.events, input.deliveryOutbox, 'local mutation')
  for (const value of input.didCommOutbox ?? []) {
    if (value.identityId !== input.identityId || !input.events.some(event => event.id === value.outboundEventId) || !value.emailId || !value.messageId || !value.toDid.startsWith('did:') || value.attempts !== 0 || Number.isNaN(Date.parse(value.createdAt))) {
      throw new TypeError('local mutation DIDComm outbox is invalid')
    }
  }
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
  return { ...value, ...(value.actorCredential ? { actorCredential: value.actorCredential.slice() } : {}), targetIds: [...value.targetIds], objectRefs: [...value.objectRefs], parents: [...value.parents], signature: value.signature.slice() }
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

function copyDidCommOutbox(value: DidCommTransportOutboxRecord): DidCommTransportOutboxRecord {
  return { ...value }
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

function assertCanonicalTimestamp(value: string, name: string): void {
  if (!Number.isFinite(Date.parse(value)) || new Date(value).toISOString() !== value) throw new TypeError(`${name} must be a canonical ISO timestamp`)
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
