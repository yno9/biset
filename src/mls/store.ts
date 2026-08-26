// Where a device's MLS self-group state lives between page loads.
//
// This is the browser half of the MLS layer (group.ts is platform-free).
// Unlike the pre-rewrite `src.bak/mls/store.ts`, this holds only what the
// roster/vault-epoch path (PLAN.md §4.1) needs — the encoded `ClientState`
// for this identity's self group — and none of the pre-rewrite DS routing
// fields (`dsDid`/`dsUrl`) or the key-package pool, both of which belong to
// the DS-communication rewrite (KeyPackage directory / GroupInfo / Commit
// submission against the new core API) that is still open.
//
// A separate IndexedDB database from `vault/store.ts` on purpose: this store
// holds MLS group state (key material, in the sense that losing it means
// losing forward access to the group without another member's help), not
// vault content, and keeping it out of the vault database means neither
// schema's migrations ever have to reason about the other's stores.
import { decodeState, encodeState, epochOf, exportSecret } from './group.ts'
import type { ClientState } from './vendor/index.ts'
import { mlsEpoch } from '../protocol/ids.ts'
import type { MlsEpochExporter, MlsSelfGroupProvider } from './vault-epoch.ts'

const DATABASE_NAME = 'biset-mls-self-group'
const DATABASE_VERSION = 1
const STORE_NAME = 'self-group-state'

interface StoredMlsSelfGroup {
  identityId: string
  selfGroupId: string
  state: Uint8Array
  updatedAt: number
}

export interface LoadedMlsSelfGroup {
  selfGroupId: string
  state: ClientState
}

export interface MlsSelfGroupStateStore {
  save(identityId: string, selfGroupId: string, state: ClientState): Promise<void>
  load(identityId: string): Promise<LoadedMlsSelfGroup | undefined>
}

export class IndexedDbMlsSelfGroupStore implements MlsSelfGroupStateStore {
  private databasePromise: Promise<IDBDatabase> | null = null

  private database(): Promise<IDBDatabase> {
    // Don't cache a rejection — a transient open failure would otherwise
    // poison every later call for the life of the page.
    if (!this.databasePromise) this.databasePromise = openDatabase().catch(error => { this.databasePromise = null; throw error })
    return this.databasePromise
  }

  /** Releases this instance's connection -- see keypackage-store.ts's own
   * close() for why this exists (connection accumulation across logout/
   * signup-retry cycles, found live 2026-08-26). */
  close(): void {
    this.databasePromise?.then(db => db.close()).catch(() => {})
  }

  async save(identityId: string, selfGroupId: string, state: ClientState): Promise<void> {
    const database = await this.database()
    const record: StoredMlsSelfGroup = { identityId, selfGroupId, state: encodeState(state), updatedAt: Date.now() }
    const transaction = database.transaction([STORE_NAME], 'readwrite')
    transaction.objectStore(STORE_NAME).put(record)
    await transactionDone(transaction)
  }

  async load(identityId: string): Promise<LoadedMlsSelfGroup | undefined> {
    const database = await this.database()
    const transaction = database.transaction([STORE_NAME], 'readonly')
    const record = await requestResult<StoredMlsSelfGroup | undefined>(transaction.objectStore(STORE_NAME).get(identityId))
    return record === undefined ? undefined : { selfGroupId: record.selfGroupId, state: decodeState(record.state) }
  }

  /** Domain move (identity/webvh/move.ts) support: after
   * mls/self-group.ts's migrateSelfGroupCredential has already saved this
   * identity's migrated state under the NEW identityId, the caller uses
   * this to drop the now-stale row still sitting under the old one --
   * plain deletion, not a rekey, because migrateSelfGroupCredential's own
   * save already put the correct (migrated, not merely relabeled) state in
   * place. */
  async delete(identityId: string): Promise<void> {
    const database = await this.database()
    const transaction = database.transaction([STORE_NAME], 'readwrite')
    transaction.objectStore(STORE_NAME).delete(identityId)
    await transactionDone(transaction)
  }
}

/**
 * The concrete `MlsSelfGroupProvider` (`vault-epoch.ts`) `MlsVaultEpochKeyResolver`
 * needs: reads this identity's stored `ClientState` and exposes only its
 * `exportSecret` — the store, and the decoded state, never leave this
 * function's closure.
 */
export class StoredMlsSelfGroupProvider implements MlsSelfGroupProvider {
  constructor(private readonly store: MlsSelfGroupStateStore) {}

  async currentSelfGroup(identityId: string): Promise<MlsEpochExporter> {
    const stored = await this.store.load(identityId)
    if (!stored) throw new Error(`StoredMlsSelfGroupProvider: no self-group state for ${identityId}`)
    const { selfGroupId, state } = stored
    return {
      selfGroupId,
      epoch: mlsEpoch(epochOf(state)),
      exportSecret: (label, context, length) => exportSecret(state, label, context, length),
    }
  }
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE_NAME, DATABASE_VERSION)
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(STORE_NAME)) request.result.createObjectStore(STORE_NAME, { keyPath: 'identityId' })
    }
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error ?? new Error('failed to open MLS self-group database'))
    request.onblocked = () => reject(new Error('MLS self-group database upgrade is blocked by another client'))
  })
}

function transactionDone(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve()
    transaction.onerror = () => reject(transaction.error ?? new Error('MLS self-group transaction failed'))
    transaction.onabort = () => reject(transaction.error ?? new Error('MLS self-group transaction aborted'))
  })
}

function requestResult<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error ?? new Error('MLS self-group request failed'))
  })
}
