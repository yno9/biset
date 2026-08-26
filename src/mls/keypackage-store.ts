// Where this device's own MLS KeyPackage private halves live between page
// loads — key material, not cache: an MLS KeyPackage is single-use, so once
// its private half is gone, so is this device's ability to have ever been
// welcomed with it.
//
// Ported at the storage-shape level from src.bak/mls/store.ts's
// mintKeyPackages/takeKeyPackageForWelcome. A separate IndexedDB database
// from both `vault/store.ts` and `mls/store.ts`'s self-group state, same
// reasoning as `mls/store.ts`'s own header: unrelated key material, unrelated
// migrations.
import { decodeKeyPackage, encodeKeyPackage, generateOwnKeyPackage, keyPackageRefOf, welcomeRecipientRefs, type OwnKeyPackage } from './group.ts'

/** How many unused key packages this device keeps published — a key package
 * is single-use, so the pool is what lets several devices invite this one
 * to several groups before it next comes online to refill. */
export const KEY_PACKAGE_POOL_TARGET = 5

const DATABASE_NAME = 'biset-mls-keypackages'
const DATABASE_VERSION = 1
const STORE_NAME = 'own-key-packages'

interface StoredKeyPackage {
  ref: string // hex key package ref -- the primary key
  kid: string
  publicWire: Uint8Array
  privatePackage: OwnKeyPackage['privatePackage']
  createdAt: number
}

export interface MlsKeyPackageStore {
  /** Mints `count` fresh key packages, keeps their private halves, and
   * returns them (public + private) for the caller to publish. */
  mint(kid: string, count: number): Promise<OwnKeyPackage[]>
  /** Finds and consumes the key package a Welcome was addressed to.
   * Undefined when none of the Welcome's recipients is us — an ordinary
   * outcome (a resent Welcome after this device already joined and deleted
   * its key package), not an error. */
  takeForWelcome(welcomeBytes: Uint8Array): Promise<OwnKeyPackage | undefined>
}

export class IndexedDbMlsKeyPackageStore implements MlsKeyPackageStore {
  private databasePromise: Promise<IDBDatabase> | null = null

  private database(): Promise<IDBDatabase> {
    if (!this.databasePromise) this.databasePromise = openDatabase().catch(error => { this.databasePromise = null; throw error })
    return this.databasePromise
  }

  /** Releases this instance's connection -- every `new IndexedDbMlsKeyPackageStore()`
   * opens its own, and nothing closed any of them anywhere in this codebase
   * until now (vault/store.ts's IndexedDbVaultStore was the one exception,
   * logout()'s own vaultStore.close()). A signup retry (account-create.ts's
   * submit handler creates a fresh instance per attempt) or a logout/
   * re-login cycle left the old connection open indefinitely otherwise --
   * found live, 2026-08-26: after several logout/signup cycles in one tab,
   * a brand-new `indexedDB.open()` call on this exact database stopped
   * firing ANY event at all (not onsuccess, not onblocked, not onerror),
   * hanging every later signup silently forever; a fresh Incognito window
   * (no accumulated connections) worked fine every time, confirming this
   * was connection accumulation, not a logic bug. */
  close(): void {
    this.databasePromise?.then(db => db.close()).catch(() => {})
  }

  async mint(kid: string, count: number): Promise<OwnKeyPackage[]> {
    const database = await this.database()
    const minted: OwnKeyPackage[] = []
    for (let i = 0; i < count; i++) {
      const own = await generateOwnKeyPackage(kid)
      const rec: StoredKeyPackage = {
        ref: await keyPackageRefOf(own.publicPackage),
        kid,
        publicWire: encodeKeyPackage(own.publicPackage),
        privatePackage: own.privatePackage,
        createdAt: Date.now(),
      }
      const transaction = database.transaction([STORE_NAME], 'readwrite')
      transaction.objectStore(STORE_NAME).put(rec)
      await transactionDone(transaction)
      minted.push(own)
    }
    return minted
  }

  async takeForWelcome(welcomeBytes: Uint8Array): Promise<OwnKeyPackage | undefined> {
    const database = await this.database()
    for (const ref of welcomeRecipientRefs(welcomeBytes)) {
      const transaction = database.transaction([STORE_NAME], 'readwrite')
      const store = transaction.objectStore(STORE_NAME)
      const rec = await requestResult<StoredKeyPackage | undefined>(store.get(ref))
      if (!rec) { await transactionDone(transaction); continue }
      store.delete(ref)
      await transactionDone(transaction)
      return { publicPackage: decodeKeyPackage(rec.publicWire), privatePackage: rec.privatePackage }
    }
    return undefined
  }

  /** Domain move (identity/webvh/move.ts) support. Every already-minted
   * package in the pool carries a `kid` baked into its own SIGNED credential
   * (mls/group.ts's generateOwnKeyPackage) — unlike a plain JSON field, that
   * can't be rewritten in place after a move: the credential would no
   * longer match its own signature. The pool has no other identity-scoping
   * (its keyPath is the package `ref`, not identityId — this store
   * implicitly serves whichever one identity this device has), so the only
   * correct move is to discard the whole pool and let ensureKeyPackagePool
   * (identity/bootstrap.ts) refill it under the new kid on next boot. */
  async clear(): Promise<void> {
    const database = await this.database()
    const transaction = database.transaction([STORE_NAME], 'readwrite')
    transaction.objectStore(STORE_NAME).clear()
    await transactionDone(transaction)
  }
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE_NAME, DATABASE_VERSION)
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(STORE_NAME)) request.result.createObjectStore(STORE_NAME, { keyPath: 'ref' })
    }
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error ?? new Error('failed to open MLS key package database'))
    request.onblocked = () => reject(new Error('MLS key package database upgrade is blocked by another client'))
  })
}

function transactionDone(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve()
    transaction.onerror = () => reject(transaction.error ?? new Error('MLS key package transaction failed'))
    transaction.onabort = () => reject(transaction.error ?? new Error('MLS key package transaction aborted'))
  })
}

function requestResult<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error ?? new Error('MLS key package request failed'))
  })
}
