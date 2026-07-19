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
  // THIS DEVICE's own DIDComm key (PLAN.md "Key material"/"DIDComm transport
  // identity" — did:dht direct path). Generated randomly per device the first
  // time it registers with a mediator (create-standalone.ts), never derived
  // from the seed — a multi-device identity needs each device to hold a
  // DIFFERENT key (see document.ts's DidKeyAgreement), since the mediator
  // queues per-kid and a shared key would let one device silently starve
  // another's deliveries.
  didCommPublicKey?: string // hex
  didCommPrivateKey?: string // hex
  // This device's stable positional slot in the published document's
  // keyAgreement list (did-dht numbers them k1, k2, ... — kid = "#k<n>", e.g.
  // "#k2"). Remembered rather than recomputed each publish, so this device's
  // kid never shifts as sibling devices come and go (mediator registrations
  // and any sender's cached routing are keyed by kid string).
  didCommOwnKid?: string
  // Other devices' registered DIDComm keys, learned by resolving the
  // identity's published document once at registration time (create-
  // standalone.ts's syncDevicePosition). A routine republish (publishOwnDids,
  // every boot) never resolves — publish.ts's buildOwnDocument note explains
  // why (a transient resolve failure must not erase a real list) — so without
  // this cache, republishing from any one device would silently drop every
  // OTHER device's key from the document.
  didCommSiblingKeys?: Array<{ kid: string; publicKey: string }> // publicKey hex
  // Which mediator this identity registered its DIDComm keys with, if any.
  // Unlike the keys these aren't derivable — they're registration state, and
  // they must be persisted precisely because publish.ts rebuilds the whole
  // document from local state on every app start: a document built without
  // them would republish over (i.e. silently cancel) the DIDComm registration.
  didCommMediatorUrl?: string
  didCommRoutingKey?: string // the mediator's own keyAgreement kid
  // A relay-less identity (DID⊥relay) has no relay to hold its cryptenv
  // envelope, so it keeps one here instead: the password-wrapped master secret,
  // so operations that need the seed (adding a relay) unlock with a password
  // like every other account, not the 24-word phrase. Uploaded to the relay the
  // normal way once one is added.
  envelope?: import('../cryptenv.ts').Envelope
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
