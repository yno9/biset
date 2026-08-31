// Where a device's Conversation Group MLS state lives between page loads --
// the group-scoped counterpart of self-group `store.ts`'s
// `IndexedDbMlsSelfGroupStore`. Kept in its OWN IndexedDB database (not
// self-group's, not vault/store.ts's) for the same reason self-group's own
// store is separate from vault/store.ts: this holds key material whose loss
// means losing forward access to a group, and a device may belong to many
// Conversation Groups at once (unlike self-group's one-row-per-identity
// shape), so the schema differs enough to want its own migrations.
import { decodeState, encodeState } from './group.ts'
import type { ClientState } from './vendor/index.ts'

const DATABASE_NAME = 'biset-mls-conversation-group'
const DATABASE_VERSION = 1
const STORE_NAME = 'conversation-group-state'

interface StoredConversationGroup {
  groupId: string
  state: Uint8Array
  /** The highest `ConversationLogEntry.seq` (mls-ds/store.ts) this device
   * has already applied for this group -- the cursor a poll-based catch-up
   * (`pullDeliveries(..., afterSeq: lastSeenSeq)`) resumes from, and what a
   * push-delivered message-notify entry's own `seq` is checked against
   * before applying (out-of-order/duplicate delivery must not double-apply
   * a commit against already-advanced state). */
  lastSeenSeq: number
  updatedAt: number
}

export interface LoadedConversationGroup {
  state: ClientState
  lastSeenSeq: number
}

export interface MlsConversationGroupStateStore {
  save(groupId: string, state: ClientState, lastSeenSeq: number): Promise<void>
  load(groupId: string): Promise<LoadedConversationGroup | undefined>
  /** Every group this device currently holds state for -- the poll-based
   * catch-up loop's own "which groups do I even need to ask about" list,
   * since there is no single-owner identity to look this up from (contrast
   * self-group, where the identity itself names the one group). */
  listGroupIds(): Promise<string[]>
}

export class IndexedDbMlsConversationGroupStore implements MlsConversationGroupStateStore {
  private databasePromise: Promise<IDBDatabase> | null = null

  private database(): Promise<IDBDatabase> {
    // Don't cache a rejection -- see self-group store.ts's own note (a
    // transient open failure would otherwise poison every later call for
    // the life of the page).
    if (!this.databasePromise) this.databasePromise = openDatabase().catch(error => { this.databasePromise = null; throw error })
    return this.databasePromise
  }

  close(): void {
    this.databasePromise?.then(db => db.close()).catch(() => {})
  }

  async save(groupId: string, state: ClientState, lastSeenSeq: number): Promise<void> {
    const database = await this.database()
    const record: StoredConversationGroup = { groupId, state: encodeState(state), lastSeenSeq, updatedAt: Date.now() }
    const transaction = database.transaction([STORE_NAME], 'readwrite')
    transaction.objectStore(STORE_NAME).put(record)
    await transactionDone(transaction)
  }

  async load(groupId: string): Promise<LoadedConversationGroup | undefined> {
    const database = await this.database()
    const transaction = database.transaction([STORE_NAME], 'readonly')
    const record = await requestResult<StoredConversationGroup | undefined>(transaction.objectStore(STORE_NAME).get(groupId))
    return record === undefined ? undefined : { state: decodeState(record.state), lastSeenSeq: record.lastSeenSeq }
  }

  async listGroupIds(): Promise<string[]> {
    const database = await this.database()
    const transaction = database.transaction([STORE_NAME], 'readonly')
    return requestResult<string[]>(transaction.objectStore(STORE_NAME).getAllKeys() as unknown as IDBRequest<string[]>)
  }
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE_NAME, DATABASE_VERSION)
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(STORE_NAME)) request.result.createObjectStore(STORE_NAME, { keyPath: 'groupId' })
    }
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error ?? new Error('failed to open MLS Conversation Group database'))
    request.onblocked = () => reject(new Error('MLS Conversation Group database upgrade is blocked by another client'))
  })
}

function transactionDone(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve()
    transaction.onerror = () => reject(transaction.error ?? new Error('MLS Conversation Group transaction failed'))
    transaction.onabort = () => reject(transaction.error ?? new Error('MLS Conversation Group transaction aborted'))
  })
}

function requestResult<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error ?? new Error('MLS Conversation Group request failed'))
  })
}
