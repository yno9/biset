// Where a device's DIDComm group-chat roster lives between page loads --
// the group-chat counterpart of mls/conversation-group-store.ts, but far
// simpler: there is no MLS ClientState, no key material, no Delivery
// Service to reconnect to. A group's actual crypto rides on each member's
// own pairwise ContactKeyV1 relationship (vault/contact-key.ts), which
// already syncs across this identity's own devices through the ordinary
// vault path -- this store holds only the group's METADATA (who's in it,
// what it's called), and does NOT sync across a user's own multiple
// devices in v1 (same accepted limitation conversation-group-store.ts's
// own header documents for the same reason: this is a device-local cache
// with its own migration lifecycle, kept in its own IndexedDB database
// rather than vault/store.ts's). A second device of the same identity can
// still send/receive on a group once it separately learns the roster
// (e.g. by receiving a GROUP_MESSAGE/GROUP_INVITE itself) -- it just won't
// show the thread until it does.
const DATABASE_NAME = 'biset-didcomm-group-chat'
const DATABASE_VERSION = 1
const STORE_NAME = 'didcomm-group-roster'

export interface DidCommGroupRoster {
  groupId: string
  name?: string
  members: string[]
  createdAt: string
  updatedAt: string
}

interface DidCommGroupChatStore {
  save(roster: DidCommGroupRoster): Promise<void>
  /** Unions `patch.members` into whatever roster is already stored (keeping
   * the existing name unless `patch.name` is given, keeping the original
   * `createdAt`) -- the same "merge, don't clobber" rule
   * conversation-group-store.ts's own `save` applies to `groupName`. This
   * is also what makes a REDELIVERED GROUP_INVITE idempotent for free: the
   * same member set unioned into itself is a no-op. */
  merge(groupId: string, patch: { members: string[]; name?: string; updatedAt: string }): Promise<void>
  load(groupId: string): Promise<DidCommGroupRoster | undefined>
  listGroupIds(): Promise<string[]>
  close(): void
}

export class IndexedDbDidCommGroupChatStore implements DidCommGroupChatStore {
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

  async save(roster: DidCommGroupRoster): Promise<void> {
    const database = await this.database()
    const transaction = database.transaction([STORE_NAME], 'readwrite')
    transaction.objectStore(STORE_NAME).put(roster)
    await transactionDone(transaction)
  }

  async merge(groupId: string, patch: { members: string[]; name?: string; updatedAt: string }): Promise<void> {
    const database = await this.database()
    const transaction = database.transaction([STORE_NAME], 'readwrite')
    const store = transaction.objectStore(STORE_NAME)
    const existing = await requestResult<DidCommGroupRoster | undefined>(store.get(groupId))
    const members = existing ? [...new Set([...existing.members, ...patch.members])] : [...new Set(patch.members)]
    const name = patch.name ?? existing?.name
    const record: DidCommGroupRoster = {
      groupId, members, ...(name !== undefined ? { name } : {}),
      createdAt: existing?.createdAt ?? patch.updatedAt, updatedAt: patch.updatedAt,
    }
    store.put(record)
    await transactionDone(transaction)
  }

  async load(groupId: string): Promise<DidCommGroupRoster | undefined> {
    const database = await this.database()
    const transaction = database.transaction([STORE_NAME], 'readonly')
    return requestResult<DidCommGroupRoster | undefined>(transaction.objectStore(STORE_NAME).get(groupId))
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
    request.onerror = () => reject(request.error ?? new Error('failed to open DIDComm group chat database'))
    request.onblocked = () => reject(new Error('DIDComm group chat database upgrade is blocked by another client'))
  })
}

function transactionDone(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve()
    transaction.onerror = () => reject(transaction.error ?? new Error('DIDComm group chat transaction failed'))
    transaction.onabort = () => reject(transaction.error ?? new Error('DIDComm group chat transaction aborted'))
  })
}

function requestResult<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error ?? new Error('DIDComm group chat request failed'))
  })
}
