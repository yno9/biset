// Where this device keeps its own identity's root key material between page
// loads. Ported at the shape level from src.bak/did/store.ts's DidRecord,
// trimmed to what Vault Core's identity bootstrap actually needs — no
// mail/AP relay fields, no pre-rotation signingPrivateKey, no per-device
// DIDComm/JMAP keys (all DIDComm-adapter or relay-adapter concerns this
// rewrite does not carry forward yet).
//
// Stored in the clear for now. src.bak/did/prf.ts's passkey-sealed-at-rest
// protection (AES-GCM over masterSeed/rootPrivateKey, keyed by a WebAuthn
// PRF output) is real, wanted, and NOT yet ported — this store's shape
// (a single `sealed` blob replacing the two plaintext fields) is meant to
// accept it without a migration, but until it's ported this is plaintext
// key material at rest, same exposure as any other browser-local secret.
export interface IdentityRecord {
  did: string
  /** BIP39 master seed (hex) — see identity/seed.ts. Absent only for a
   * record type this store does not yet produce (kept optional to match
   * the eventual `sealed` variant's shape, not because a caller should ever
   * omit it today). */
  masterSeed?: string
  rootPublicKey: string // hex
  rootPrivateKey: string // hex
  /** This device's own self-group verification method fragment
   * (identity/webvh/add-device-verification-method.ts's `fragment`, and the
   * MLS credential kid's suffix) once it has one. Absent until this device
   * has actually registered a device key for this identity. */
  deviceKid?: string
}

export interface IdentityRecordStore {
  get(did: string): Promise<IdentityRecord | undefined>
  put(record: IdentityRecord): Promise<void>
  list(): Promise<IdentityRecord[]>
}

const DATABASE_NAME = 'biset-identity'
const DATABASE_VERSION = 1
const STORE_NAME = 'records'

export class IndexedDbIdentityRecordStore implements IdentityRecordStore {
  private databasePromise: Promise<IDBDatabase> | null = null

  private database(): Promise<IDBDatabase> {
    if (!this.databasePromise) this.databasePromise = openDatabase().catch(error => { this.databasePromise = null; throw error })
    return this.databasePromise
  }

  async get(did: string): Promise<IdentityRecord | undefined> {
    const database = await this.database()
    const transaction = database.transaction([STORE_NAME], 'readonly')
    return requestResult<IdentityRecord | undefined>(transaction.objectStore(STORE_NAME).get(did))
  }

  async put(record: IdentityRecord): Promise<void> {
    const database = await this.database()
    const transaction = database.transaction([STORE_NAME], 'readwrite')
    transaction.objectStore(STORE_NAME).put(record)
    await transactionDone(transaction)
  }

  async list(): Promise<IdentityRecord[]> {
    const database = await this.database()
    const transaction = database.transaction([STORE_NAME], 'readonly')
    return requestResult<IdentityRecord[]>(transaction.objectStore(STORE_NAME).getAll())
  }
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE_NAME, DATABASE_VERSION)
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(STORE_NAME)) request.result.createObjectStore(STORE_NAME, { keyPath: 'did' })
    }
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error ?? new Error('failed to open identity record database'))
    request.onblocked = () => reject(new Error('identity record database upgrade is blocked by another client'))
  })
}

function transactionDone(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve()
    transaction.onerror = () => reject(transaction.error ?? new Error('identity record transaction failed'))
    transaction.onabort = () => reject(transaction.error ?? new Error('identity record transaction aborted'))
  })
}

function requestResult<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result)
    request.onerror = () => reject(request.error ?? new Error('identity record request failed'))
  })
}
