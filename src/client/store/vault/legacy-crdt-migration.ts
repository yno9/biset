import * as Y from 'yjs'
import type { VaultEventV1 } from '../../../protocol/vault.ts'

const DATABASE = 'biset-vault-core'
const LEGACY_STORE = 'vault_crdt_state'
const EVENT_STORE = 'vault_events'

/**
 * One-time bridge for schema <=13. It deliberately runs before the v14
 * upgrade deletes the Yjs store, so an update that arrived only through the
 * retired delta path is copied into the immutable R3 event set first.
 */
export async function rescueLegacyCrdtEvents(): Promise<void> {
  const database = await openCurrentDatabase()
  try {
    if (!database.objectStoreNames.contains(LEGACY_STORE)) return
    if (!database.objectStoreNames.contains(EVENT_STORE)) throw new Error('legacy Vault CRDT exists without the event store')
    const read = database.transaction(LEGACY_STORE, 'readonly')
    const rows = await requestValue<Array<{ identityId: string; update: Uint8Array }>>(read.objectStore(LEGACY_STORE).getAll())
    await transactionDone(read)
    const rescued: Array<VaultEventV1 & { identityId: string }> = []
    for (const row of rows) {
      if (!row.identityId || !(row.update instanceof Uint8Array) || !row.update.length) throw new TypeError('legacy Vault CRDT row is invalid')
      const document = new Y.Doc()
      try {
        Y.applyUpdate(document, row.update)
        for (const value of document.getArray<unknown>('vault-events').toArray()) {
          const event = value as VaultEventV1
          if (!event || event.version !== 1 || !event.id || event.identityId !== row.identityId || !Array.isArray(event.targetIds) || !Array.isArray(event.objectRefs)) throw new TypeError('legacy Vault CRDT event is invalid')
          rescued.push({ ...structuredClone(event), identityId: row.identityId })
        }
      } finally { document.destroy() }
    }
    if (!rescued.length) return
    const write = database.transaction(EVENT_STORE, 'readwrite'); const store = write.objectStore(EVENT_STORE)
    for (const event of rescued) store.put(event)
    await transactionDone(write)
  } finally { database.close() }
}

function openCurrentDatabase(): Promise<IDBDatabase> { return new Promise((resolve, reject) => { const request = indexedDB.open(DATABASE); request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error); request.onblocked = () => reject(new Error('legacy Vault migration is blocked')) }) }
function requestValue<T>(request: IDBRequest<T>): Promise<T> { return new Promise((resolve, reject) => { request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error) }) }
function transactionDone(transaction: IDBTransaction): Promise<void> { return new Promise((resolve, reject) => { transaction.oncomplete = () => resolve(); transaction.onabort = transaction.onerror = () => reject(transaction.error) }) }
