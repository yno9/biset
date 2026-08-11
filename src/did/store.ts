// IndexedDB persistence for derived identity keys — mirrors src/pgp/keys.ts's
// pattern deliberately (same DB shape, same plaintext-at-rest trust model: the
// PGP private key already lives unencrypted in IndexedDB, so this isn't a new
// exposure). Only the DERIVED keys are stored, never the master seed itself —
// the seed is used transiently at creation/login time (see cryptenv.ts's
// masterSecret) and discarded, exactly like `kek` already is.
//
// Keyed by `did`, not an address: did is the essential identity concept here
// (biset's own decision record — [[project_biset_did_relay_orthogonality]]),
// mail/AP addresses are an optional add-on a DID may or may not have. Every
// identity gets exactly one record regardless of how many (if any) relay
// addresses it later grows — no more "keyed by email, except when there is no
// email" special case, and no more mirroring a second copy of the record
// under a newly-added address (see custom-domain.ts). v1 was keyed by email
// (or, for a relay-less identity, the DID string standing in for one) —
// bumping to v2 drops that store outright rather than migrating it: no
// backward compatibility is owed here, existing accounts start over.
import { stableIdKey } from './idkey.ts'

const DB_NAME = 'biset-did'
const DB_VERSION = 2
const STORE = 'keys'

export interface DidRecord {
  // A known mail/AP address for this identity, if it has any — informational
  // only (display, lazy-migration bookkeeping), never the lookup key.
  email?: string
  did: string
  rootPublicKey: string // hex
  rootPrivateKey: string // hex
  nostrPublicKey: string // hex
  nostrPrivateKey: string // hex
  // THIS DEVICE's own DIDComm key (PLAN.md "Key material"/"DIDComm transport
  // identity" — did:dht direct path). Generated randomly per device the first
  // time it registers with a mediator (didcomm-devices.ts), never derived
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
  // Kids deliberately removed via the devices-list trash icon
  // (didcomm-devices.ts's removeDeviceKey) — checked by syncDevicePosition
  // so a later resolve that still shows a removed sibling (a lagging gateway,
  // or this same device's own next boot) can't silently re-absorb it: grow-
  // only merging has no other way to distinguish "never seen before" from
  // "seen, and deliberately dropped". Kid numbers are never reused (always
  // max+1), so a tombstone here is unambiguous and never needs to expire.
  didCommRemovedKeys?: string[]
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
  // did:webvh domain-move rotation state (PLANWEBVH.md §5.1): set on the NEW
  // DID's record right after webvh/publish.ts's moveDidToNewDomain. The
  // from_prior JWT is built once, at move time (rotation.ts's buildFromPrior
  // — its own note: iat should be the rotation's datetime, not the sending
  // time, which is exactly what "built once, reused" gives for free), then
  // attached to outgoing messages until movedFromExpiresAt passes — so a
  // peer that hasn't re-resolved this identity yet still learns of the move
  // from the message itself, not only by noticing the old DID went stale.
  movedFromJwt?: string
  movedFromExpiresAt?: number // epoch ms
  // THIS DEVICE's own JMAP login key (this session's account-model redesign,
  // src/did/devicebind.ts's file header) — the per-device credential a relay
  // vouches for once (provision.ts's vouchThisDevice) and this device then
  // signs fresh session logins with (deviceSessionLogin), instead of a
  // single masterSecret-derived password shared and un-revocable across
  // every device. Random, never seed-derived — same reasoning as
  // didCommPublicKey/didCommPrivateKey just above: a shared key here would
  // make per-device revocation impossible.
  jmapDevicePublicKey?: string // hex
  jmapDevicePrivateKey?: string // hex
  // THIS DEVICE's own ML-KEM-768 keyAgreement key (PLAN.md "did:webvh
  // PQハイブリッド化" Phase 1/2) — paired by slot number with didCommPublicKey/
  // didCommPrivateKey at the same `didCommOwnKid` (webvh/document.ts's
  // `#kk<n>` alongside `#k<n>`). did:webvh only (did:dht can't carry a
  // 1184-byte key in a 1000-byte BEP44 record). Random per device, same
  // reasoning as didCommPrivateKey. Its lifecycle rides entirely on the
  // X25519 key's: it is minted/dropped alongside didCommPublicKey/
  // didCommPrivateKey and never gets its own tombstone/prune pass — see
  // didcomm-devices.ts's syncDevicePosition note on why an independent
  // removal path for this key would just be a second, divergent copy of
  // logic that already exists once for `didCommOwnKid`.
  mlkemPublicKey?: string // hex
  mlkemPrivateKey?: string // hex
  // Other devices' ML-KEM-768 keys, keyed by SLOT NUMBER (not kid string,
  // unlike didCommSiblingKeys) — a sibling may not have published one yet
  // (pre-PQ device), so absence at a given `n` just means "that device isn't
  // PQ-capable yet", not an error. Learned the same way didCommSiblingKeys
  // is (syncDevicePosition resolving the published document), but merged
  // and pruned purely by following whichever `n`s didCommSiblingKeys/
  // didCommRemovedKeys already decided are live — no separate merge/
  // tombstone state of its own.
  didCommMlkemSiblingKeys?: Array<{ n: number; publicKey: string }> // publicKey hex
}

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION)
    req.onupgradeneeded = () => {
      const db = req.result
      // v1 was keyPath 'email' — drop it outright (no migration owed, see the
      // file header) so the v2 store can use 'did' cleanly. try/catch rather
      // than an objectStoreNames.contains() guard: harmless either way (no
      // store yet on a first-ever open, an old v1 store to replace on an
      // upgrade), and keeps this working against the test suite's minimal
      // IndexedDB fakes, which don't all implement objectStoreNames.
      try { db.deleteObjectStore(STORE) } catch { /* didn't exist yet */ }
      db.createObjectStore(STORE, { keyPath: 'did' })
    }
    // Found live: a real account already had a v1 (keyPath 'email') database
    // open in another tab/window when v2 shipped — the browser fires
    // `blocked` on this request and waits for that other connection to
    // close, which never happens on its own, so with neither handler set
    // this promise (and everything built on it: getDidRecord, initDid,
    // restore) simply hung forever with zero error, indistinguishable from a
    // slow network call. `blocked` now rejects with a clear, actionable
    // message instead of hanging; `onversionchange` on the connection this
    // call itself opens makes THIS tab close gracefully if some future
    // version bump needs to open past it, so it can't be the one blocking
    // the next tab the same way.
    req.onblocked = () => reject(new Error('openDB: blocked by another open biset tab/window on an older DB version — close every other biset tab and reload'))
    req.onsuccess = () => {
      const db = req.result
      db.onversionchange = () => db.close()
      resolve(db)
    }
    req.onerror = () => reject(req.error)
  })
}

function dbGet(db: IDBDatabase, did: string): Promise<DidRecord | undefined> {
  return new Promise((resolve, reject) => {
    const req = db.transaction(STORE, 'readonly').objectStore(STORE).get(did)
    req.onsuccess = () => resolve(req.result as DidRecord | undefined)
    req.onerror = () => reject(req.error)
  })
}

function dbGetAll(db: IDBDatabase): Promise<DidRecord[]> {
  return new Promise((resolve, reject) => {
    const req = db.transaction(STORE, 'readonly').objectStore(STORE).getAll()
    req.onsuccess = () => resolve((req.result as DidRecord[] | undefined) ?? [])
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

// Serializes read-modify-write access to one identity's record. Found live:
// buildOwnDocument's routine republish (every app boot) reads the record,
// then does a multi-second network resolve (syncDevicePosition) before
// writing it back — and an explicit action that reads-edits-writes in
// between (didcomm-devices.ts's removeDeviceKey, deleting a device key)
// finishes first, only to have the routine call's stale, pre-edit snapshot
// overwrite it moments later when ITS write finally lands. Last-write-wins
// on a full-record IndexedDB put means whichever read-modify-write started
// EARLIER but finishes LATER (the slow, network-bound one) silently erases
// the other's change. Every place that reads a DidRecord meaning to write it
// back must run that whole sequence under the same identity's lock, or this
// happens again — see buildOwnDocument, removeDeviceKey, unregisterFromMediator.
// Bounds how long a holder may occupy the lock — a stuck fn() (a fetch that
// never settles; browsers don't universally time these out) would otherwise
// wedge every future caller for this identity for the rest of the page's
// life, no reload short of a hard refresh recovers it. The timeout only
// releases the LOCK; it doesn't cancel fn() itself, which keeps running and
// still writes if it eventually finishes — this exists purely so one hung
// caller can't starve every other one forever.
const LOCK_TIMEOUT_MS = 15_000
const locks = new Map<string, Promise<unknown>>()
export function withDidLock<T>(identityKey: string, fn: () => Promise<T>): Promise<T> {
  const prev = locks.get(identityKey) ?? Promise.resolve()
  const run = prev.then(fn, fn)
  const timeout = new Promise<never>((_, reject) => {
    setTimeout(() => reject(new Error(`withDidLock: timed out waiting for ${identityKey}`)), LOCK_TIMEOUT_MS)
  })
  locks.set(identityKey, Promise.race([run, timeout]).then(() => {}, () => {}))
  return run
}

// Looked up by the exact DID first, then — only on a miss — by stable identity
// key (did/idkey.ts, PLANWEBVH.md §3.1). The IndexedDB keyPath stays `did`
// deliberately: the CURRENT DID string is what every publish, resolve and
// mediator registration actually needs, so it belongs as the stored key, and
// leaving it alone avoids a schema migration for what is a lookup concern.
// The fallback is what makes the record survive a did:webvh domain move — any
// caller still holding the pre-move DID string (a stale UI reference, an
// in-flight operation) finds the same identity instead of silently getting
// null and re-deriving a fresh one. A linear scan is fine here: this store
// holds one record per identity, i.e. single digits.
export async function getDidRecord(did: string): Promise<DidRecord | null> {
  try {
    const db = await openDB()
    const exact = await dbGet(db, did)
    if (exact) return exact
    const key = stableIdKey(did)
    if (key === did) return null // no normalization happened — nothing a scan could find
    return (await dbGetAll(db)).find(r => stableIdKey(r.did) === key) ?? null
  } catch { return null }
}

export async function storeDidRecord(record: DidRecord): Promise<void> {
  const db = await openDB()
  await dbPut(db, record)
}

export async function deleteDidRecord(did: string): Promise<void> {
  try {
    const db = await openDB()
    await new Promise<void>((resolve, reject) => {
      const req = db.transaction(STORE, 'readwrite').objectStore(STORE).delete(did)
      req.onsuccess = () => resolve()
      req.onerror = () => reject(req.error)
    })
  } catch { /* best-effort */ }
}
