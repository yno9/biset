// IndexedDB persistence for derived identity keys — mirrors src/pgp/keys.ts's
// pattern deliberately (same DB shape, same plaintext-at-rest trust model: the
// PGP private key already lives unencrypted in IndexedDB, so this isn't a new
// exposure). Only the DERIVED keys are stored, never the master seed itself —
// the seed is used transiently at creation/login time (see cryptenv.ts's
// masterSecret) and discarded, exactly like `kek` already is.
const DB_NAME = 'biset-did'
const DB_VERSION = 1
const STORE = 'keys'

export interface DidRecord {
  email: string
  did: string
  rootPublicKey: string // hex
  rootPrivateKey: string // hex
  nostrPublicKey: string // hex
  nostrPrivateKey: string // hex
}

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION)
    req.onupgradeneeded = () => req.result.createObjectStore(STORE, { keyPath: 'email' })
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error)
  })
}

function dbGet(db: IDBDatabase, email: string): Promise<DidRecord | undefined> {
  return new Promise((resolve, reject) => {
    const req = db.transaction(STORE, 'readonly').objectStore(STORE).get(email)
    req.onsuccess = () => resolve(req.result as DidRecord | undefined)
    req.onerror = () => reject(req.error)
  })
}

function dbPut(db: IDBDatabase, record: DidRecord): Promise<void> {
  return new Promise((resolve, reject) => {
    const req = db.transaction(STORE, 'readwrite').objectStore(STORE).put(record)
    req.onsuccess = () => resolve()
    req.onerror = () => reject(req.error)
  })
}

export async function getDidRecord(email: string): Promise<DidRecord | null> {
  try {
    const db = await openDB()
    return (await dbGet(db, email)) ?? null
  } catch { return null }
}

export async function storeDidRecord(record: DidRecord): Promise<void> {
  const db = await openDB()
  await dbPut(db, record)
}

export async function deleteDidRecord(email: string): Promise<void> {
  try {
    const db = await openDB()
    await new Promise<void>((resolve, reject) => {
      const req = db.transaction(STORE, 'readwrite').objectStore(STORE).delete(email)
      req.onsuccess = () => resolve()
      req.onerror = () => reject(req.error)
    })
  } catch { /* best-effort */ }
}
