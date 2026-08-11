import * as openpgp from 'openpgp'

const DB_NAME = 'biset-pgp'
const DB_VERSION = 1
const STORE = 'keys'

export interface KeyRecord { email: string; privateKey: string; publicKey: string }

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION)
    req.onupgradeneeded = () => req.result.createObjectStore(STORE, { keyPath: 'email' })
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error)
  })
}

function dbGet(db: IDBDatabase, email: string): Promise<KeyRecord | undefined> {
  return new Promise((resolve, reject) => {
    const req = db.transaction(STORE, 'readonly').objectStore(STORE).get(email)
    req.onsuccess = () => resolve(req.result as KeyRecord | undefined)
    req.onerror = () => reject(req.error)
  })
}

function dbPut(db: IDBDatabase, record: KeyRecord): Promise<void> {
  return new Promise((resolve, reject) => {
    const req = db.transaction(STORE, 'readwrite').objectStore(STORE).put(record)
    req.onsuccess = () => resolve()
    req.onerror = () => reject(req.error)
  })
}

export async function getKeyRecord(email: string): Promise<KeyRecord | null> {
  try {
    const db = await openDB()
    return (await dbGet(db, email)) ?? null
  } catch { return null }
}

export async function storeKeyPair(email: string, privateKey: string, publicKey: string): Promise<void> {
  const db = await openDB()
  await dbPut(db, { email, privateKey, publicKey })
}

export async function generateAndStoreKeyPair(email: string, name: string): Promise<string> {
  const { privateKey, publicKey } = await openpgp.generateKey({
    type: 'ecc',
    curve: 'curve25519Legacy',
    userIDs: [{ name: name || email, email }],
    format: 'armored',
  })
  await storeKeyPair(email, privateKey as string, publicKey as string)
  return publicKey as string
}

export async function storeRecoveredKeyPair(email: string, armoredPrivKey: string): Promise<string> {
  const privKeyObj = await openpgp.readPrivateKey({ armoredKey: armoredPrivKey })
  const publicKey = await privKeyObj.toPublic().armor()
  await storeKeyPair(email, armoredPrivKey, publicKey)
  return publicKey
}

export async function deleteKey(email: string): Promise<void> {
  try {
    const db = await openDB()
    await new Promise<void>((resolve, reject) => {
      const req = db.transaction(STORE, 'readwrite').objectStore(STORE).delete(email)
      req.onsuccess = () => resolve()
      req.onerror = () => reject(req.error)
    })
  } catch { /* best-effort */ }
}

export function deleteAllKeys(): Promise<void> {
  return new Promise((resolve) => {
    const req = indexedDB.deleteDatabase(DB_NAME)
    req.onsuccess = () => resolve()
    req.onerror = () => resolve()
    req.onblocked = () => resolve()
  })
}
