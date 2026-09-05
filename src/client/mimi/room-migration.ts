/**
 * Client-side control state for moving a conversation to a fresh anonymous
 * MIMI room.  These messages travel over an existing E2E room; no provider
 * receives the old room ID, participant identities, or ciphertext history.
 */
const MIMI_ROOM_MIGRATION_OFFER = 'https://biset.md/mimi/1.0/room-migration-offer'
const MIMI_ROOM_MIGRATION_ACCEPT = 'https://biset.md/mimi/1.0/room-migration-accept'
const MIMI_ROOM_MIGRATION_CUTOVER = 'https://biset.md/mimi/1.0/room-migration-cutover'

export interface MimiRoomMigrationOffer {
  version: 1
  migrationId: string
  newRoomId: string
  targetMode: 'anon'
  offeredAt: string
  expiresAt: string
}

export interface MimiRoomMigrationAcceptance { version: 1; migrationId: string; acceptedAt: string }
export interface MimiRoomMigrationCutover { version: 1; migrationId: string; cutoverAt: string }

export interface MimiRoomMigrationRecord {
  /** Local-only; never serialize this record into an E2E migration message. */
  oldRoomId: string
  newRoomId: string
  migrationId: string
  status: 'offered' | 'accepted' | 'cutover' | 'cancelled'
  expiresAt: string
}

interface MimiRoomMigrationStateStore {
  save(record: MimiRoomMigrationRecord): Promise<void>
  load(oldRoomId: string): Promise<MimiRoomMigrationRecord | undefined>
}

/** Device-local persistent mapping.  It has no provider transport API. */
export class IndexedDbMimiRoomMigrationStore implements MimiRoomMigrationStateStore {
  private databasePromise: Promise<IDBDatabase> | null = null

  async save(record: MimiRoomMigrationRecord): Promise<void> {
    const database = await this.database()
    const transaction = database.transaction(['migrations'], 'readwrite')
    transaction.objectStore('migrations').put(record)
    await transactionDone(transaction)
  }

  async load(oldRoomId: string): Promise<MimiRoomMigrationRecord | undefined> {
    const database = await this.database()
    const transaction = database.transaction(['migrations'], 'readonly')
    return requestResult<MimiRoomMigrationRecord | undefined>(transaction.objectStore('migrations').get(oldRoomId))
  }

  close(): void { this.databasePromise?.then(database => database.close()).catch(() => {}) }

  private database(): Promise<IDBDatabase> {
    if (!this.databasePromise) this.databasePromise = new Promise<IDBDatabase>((resolve, reject) => {
      const request = indexedDB.open('biset-mimi-room-migration', 1)
      request.onupgradeneeded = () => { if (!request.result.objectStoreNames.contains('migrations')) request.result.createObjectStore('migrations', { keyPath: 'oldRoomId' }) }
      request.onsuccess = () => resolve(request.result)
      request.onerror = () => reject(request.error ?? new Error('failed to open MIMI migration store'))
    }).catch(error => { this.databasePromise = null; throw error })
    return this.databasePromise
  }
}

export function createMimiRoomMigrationOffer(oldRoomId: string, newRoomId: string, now: Date, expiresAt: Date, migrationId = crypto.randomUUID()): { offer: MimiRoomMigrationOffer; local: MimiRoomMigrationRecord } {
  requireRoomIds(oldRoomId, newRoomId)
  if (!migrationId || expiresAt <= now) throw new TypeError('migration offer expiry is invalid')
  const offer: MimiRoomMigrationOffer = { version: 1, migrationId, newRoomId, targetMode: 'anon', offeredAt: now.toISOString(), expiresAt: expiresAt.toISOString() }
  return { offer, local: { oldRoomId, newRoomId, migrationId, status: 'offered', expiresAt: offer.expiresAt } }
}

export function acceptMimiRoomMigration(local: MimiRoomMigrationRecord, acceptance: MimiRoomMigrationAcceptance, now: Date): MimiRoomMigrationRecord {
  if (local.status !== 'offered' || acceptance.version !== 1 || acceptance.migrationId !== local.migrationId) throw new TypeError('migration acceptance does not match an offered migration')
  if (Date.parse(local.expiresAt) <= now.valueOf()) throw new TypeError('migration offer has expired')
  return { ...local, status: 'accepted' }
}

/** Cutover is allowed only after local MLS verification has accepted the new room. */
export function cutOverMimiRoomMigration(local: MimiRoomMigrationRecord, cutover: MimiRoomMigrationCutover, newRoomVerified: boolean): MimiRoomMigrationRecord {
  if (local.status !== 'accepted' || cutover.version !== 1 || cutover.migrationId !== local.migrationId) throw new TypeError('migration cutover does not match an accepted migration')
  if (!newRoomVerified) throw new TypeError('new anonymous room is not locally verified')
  return { ...local, status: 'cutover' }
}

/** Safe wire projection for the existing room's E2E control message. */
export function migrationOfferBody(offer: MimiRoomMigrationOffer): Record<string, unknown> {
  if (offer.version !== 1 || offer.targetMode !== 'anon' || !offer.migrationId || !offer.newRoomId || Date.parse(offer.expiresAt) <= Date.parse(offer.offeredAt)) throw new TypeError('migration offer is invalid')
  return { version: offer.version, migrationId: offer.migrationId, newRoomId: offer.newRoomId, targetMode: offer.targetMode, offeredAt: offer.offeredAt, expiresAt: offer.expiresAt }
}

function requireRoomIds(oldRoomId: string, newRoomId: string): void {
  if (!oldRoomId || !newRoomId || oldRoomId === newRoomId) throw new TypeError('migration requires distinct old and new room IDs')
}

function requestResult<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error ?? new Error('MIMI migration store request failed'))
  })
}

function transactionDone(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve()
    transaction.onerror = () => reject(transaction.error ?? new Error('MIMI migration store transaction failed'))
    transaction.onabort = () => reject(transaction.error ?? new Error('MIMI migration store transaction aborted'))
  })
}
