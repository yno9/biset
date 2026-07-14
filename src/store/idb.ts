// Browser-local cache (IndexedDB) for JMAP data — messages, threads,
// mailboxes, identities, and per-relay sync cursors (querystate). Unlike the
// file-system vault (vault/persist.ts), this is always on and needs no user
// action, so a plain page refresh has last-sync data immediately and
// sync/session.ts's querystate-driven delta sync runs instead of a full
// historical re-fetch (+ re-decrypt of every PGP message).
const DB_NAME = 'biset-cache'
const DB_VERSION = 3

export const STORES = {
  messages: 'messages',     // keyPath: ['_account', 'id']
  threads: 'threads',       // keyPath: 'id'
  mailboxes: 'mailboxes',   // out-of-line key 'all' (single blob, matches vault's one mailboxes.json)
  identities: 'identities', // out-of-line key 'all'
  contacts: 'contacts',     // out-of-line key 'all' (JSContact Cards, matches vault's one contacts.json)
  querystate: 'querystate', // keyPath: 'acctKey'
  // Mirror of context.ts's loadStoredAccounts() (out-of-line key 'all'). The
  // Service Worker (sw.ts) has no localStorage access, but needs relay
  // credentials to recompute the unread badge on a background push — this is
  // the only channel it can read them from. Same trust boundary as
  // localStorage already has (same origin), so mirroring plaintext isn't a
  // new exposure.
  accounts: 'accounts',
} as const

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION)
    req.onupgradeneeded = () => {
      const db = req.result
      if (!db.objectStoreNames.contains(STORES.messages)) db.createObjectStore(STORES.messages, { keyPath: ['_account', 'id'] })
      if (!db.objectStoreNames.contains(STORES.threads)) db.createObjectStore(STORES.threads, { keyPath: 'id' })
      if (!db.objectStoreNames.contains(STORES.mailboxes)) db.createObjectStore(STORES.mailboxes)
      if (!db.objectStoreNames.contains(STORES.identities)) db.createObjectStore(STORES.identities)
      if (!db.objectStoreNames.contains(STORES.contacts)) db.createObjectStore(STORES.contacts)
      if (!db.objectStoreNames.contains(STORES.querystate)) db.createObjectStore(STORES.querystate, { keyPath: 'acctKey' })
      if (!db.objectStoreNames.contains(STORES.accounts)) db.createObjectStore(STORES.accounts)
    }
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error)
  })
}

let dbPromise: Promise<IDBDatabase> | null = null
function db(): Promise<IDBDatabase> {
  // Don't cache a rejected open — a transient failure (or a delete racing an
  // open, see deleteDB below) would otherwise poison every call for the rest
  // of the page's life instead of retrying.
  if (!dbPromise) dbPromise = openDB().catch(err => { dbPromise = null; throw err })
  return dbPromise
}

export async function put(store: string, value: unknown, key?: IDBValidKey): Promise<void> {
  const d = await db()
  return new Promise((resolve, reject) => {
    const objStore = d.transaction(store, 'readwrite').objectStore(store)
    const req = key === undefined ? objStore.put(value) : objStore.put(value, key)
    req.onsuccess = () => resolve()
    req.onerror = () => reject(req.error)
  })
}

export async function getAll(store: string): Promise<unknown[]> {
  const d = await db()
  return new Promise((resolve, reject) => {
    const req = d.transaction(store, 'readonly').objectStore(store).getAll()
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error)
  })
}

export async function get(store: string, key: IDBValidKey): Promise<unknown> {
  const d = await db()
  return new Promise((resolve, reject) => {
    const req = d.transaction(store, 'readonly').objectStore(store).get(key)
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error)
  })
}

export async function del(store: string, key: IDBValidKey): Promise<void> {
  const d = await db()
  return new Promise((resolve, reject) => {
    const req = d.transaction(store, 'readwrite').objectStore(store).delete(key)
    req.onsuccess = () => resolve()
    req.onerror = () => reject(req.error)
  })
}

export async function delRange(store: string, range: IDBKeyRange): Promise<void> {
  const d = await db()
  return new Promise((resolve, reject) => {
    const req = d.transaction(store, 'readwrite').objectStore(store).delete(range)
    req.onsuccess = () => resolve()
    req.onerror = () => reject(req.error)
  })
}

export async function deleteDB(): Promise<void> {
  // deleteDatabase() blocks (onblocked, never fires onsuccess) while any
  // connection to it is still open — including our own, cached in dbPromise.
  // Close it first, or a delete right before navigating (logout()) can leave
  // the delete pending when the next page's openDB() runs, queuing that open
  // behind it and hanging the whole app (no error, sync just never starts).
  if (dbPromise) {
    try { (await dbPromise).close() } catch { /* already closed/failed */ }
    dbPromise = null
  }
  return new Promise((resolve) => {
    const req = indexedDB.deleteDatabase(DB_NAME)
    req.onsuccess = () => resolve()
    req.onerror = () => resolve()
    req.onblocked = () => resolve()
  })
}
