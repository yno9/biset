// IndexedDB persistence for identity keys — mirrors src/pgp/keys.ts's pattern
// deliberately (same DB shape, same plaintext-at-rest trust model: the PGP
// private key already lives unencrypted in IndexedDB, so this isn't a new
// exposure).
//
// **The master seed is stored too, since 2026-08-14** — it deliberately was
// not, and the reversal is worth stating plainly because it reads like a
// downgrade and isn't:
//
//   - `rootPrivateKey` sits in this same store, in plaintext, and it IS the
//     identity: it signs document updates (so it can rotate keys, move
//     domains, deactivate), signs `bind:` proofs (so it can claim addresses
//     at relays under this DID), and signs device vouches (so it can
//     authorize new devices for JMAP login). Anyone who can read this store
//     already owns the identity completely. Withholding the seed from them
//     protects nothing about it.
//   - The seed's only other derivations are Nostr (unused) and a reserved
//     PGP path (unimplemented), so it grants no capability the root key
//     doesn't already grant.
//   - What NOT storing it did cost was real and one-directional: the 24-word
//     phrase could be shown exactly once, at creation, and never again — no
//     password exists to unseal it with and nothing was on disk to unseal.
//     Miss that one screen and the identity is gone permanently.
//
// Storing it does NOT by itself put the phrase back on screen; that is a
// separate decision (a "show recovery phrase" affordance carries its own,
// human-factor risks — social engineering above all) and is deliberately not
// taken here. This is the data-collection half, done first because it has a
// lead time: an identity created before this change has no seed anywhere to
// recover, so every day without it is a day of accounts that can never be
// offered the option.
//
// If at-rest protection is ever wanted, the target is `rootPrivateKey`, not
// the seed — encrypting one while the other lies in plaintext beside it is
// theatre, since an attacker simply takes the root key instead.
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
import { aesGcmSeal, aesGcmOpen } from '../cryptenv.ts'
import { enrollPrfKey, unlockPrfKey, hasPrfCredential } from './prf.ts'

const DB_NAME = 'biset-did'
const DB_VERSION = 2
const STORE = 'keys'

export interface DidRecord {
  // A known mail/AP address for this identity, if it has any — informational
  // only (display, lazy-migration bookkeeping), never the lookup key.
  email?: string
  did: string
  // The BIP39 master seed every key below is derived from (see this file's
  // header for why it is kept at all). Optional because identities created
  // before 2026-08-14 have none and no way to acquire one except a login
  // through the recovery phrase, which fills it in (`localDidRecord`).
  masterSeed?: string // hex
  rootPublicKey: string // hex
  rootPrivateKey: string // hex
  /** Whichever key currently holds updateKeys authority, when it differs
   * from rootPublicKey/rootPrivateKey above — absent for the common case
   * (pre-rotation never used, or activated but never yet rotated), present
   * once a rotate/deactivate/revoke has moved updateKeys to a pre-rotation
   * spare (did/webvh/prerotation.ts). Set the first time ui/prerotation.ts's
   * revealCurrentSigner verifies a phrase against it, so routine publishing
   * (Sync, avatar, mediator registration) doesn't need that phrase re-typed
   * on every call — the key was already in this device's memory the instant
   * it was typed in to authorize that one verified operation, so persisting
   * it durably (sealed alongside rootPrivateKey when this device has
   * passkey protection) creates no NEW exposure beyond what
   * rootPrivateKey/jmapDevicePrivateKey already accept. What this does NOT
   * touch is the pre-rotation model's actual protection: a FUTURE,
   * not-yet-revealed spare (generateSpareKeypair's freshly minted one) is
   * still shown once and never stored anywhere (2026-08-17 design
   * discussion — the table this session worked out: every state where
   * updateKeys != root was requiring a fresh phrase on every single Sync,
   * with no remaining security reason once the key had already been
   * revealed once and verified). */
  signingPrivateKey?: string // hex
  signingPublicKey?: string // hex
  /** Present INSTEAD of `masterSeed`/`rootPrivateKey` once this device has a
   * passkey guarding them (did/prf.ts): AES-GCM over the two, keyed by the
   * passkey's PRF output, base64. `getDidRecord` merges them back in for the
   * rest of the session after `unlockIdentitySecrets` has run, so consumers
   * that just read `rec.rootPrivateKey` keep working — unlocked. */
  sealed?: string
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
  /** @deprecated Other devices' keys, learned by merging a resolved document
   * (grow-only gossip). The MLS self group decides membership now
   * (mls/self-group.ts) and `didcomm-devices.ts`'s publish reads that, not
   * this. Kept only so a record written by an older build still loads; nothing
   * writes it any more, and nothing may start again — reintroducing a second
   * answer to "which devices exist" is the whole class of bug this removed. */
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
  // PQハイブリッド化" Phase 1/2) — paired with didCommPublicKey/
  // didCommPrivateKey by sharing this device's kid suffix (webvh/document.ts's
  // `#kk…` alongside `#k…`). did:webvh only (did:dht can't carry a
  // 1184-byte key in a 1000-byte BEP44 record). Random per device, same
  // reasoning as didCommPrivateKey. Its lifecycle rides entirely on the
  // X25519 key's: it is minted/dropped alongside didCommPublicKey/
  // didCommPrivateKey and never gets its own tombstone/prune pass — see
  // didcomm-devices.ts's syncDevicePosition note on why an independent
  // removal path for this key would just be a second, divergent copy of
  // logic that already exists once for `didCommOwnKid`.
  mlkemPublicKey?: string // hex
  mlkemPrivateKey?: string // hex
  /** @deprecated Counterpart of didCommSiblingKeys, and dead for the same
   * reason: a device's ML-KEM-768 key travels in its own MLS leaf now
   * (mls/transport-keys.ts), so nothing learns or publishes this. */
  didCommMlkemSiblingKeys?: Array<{ kid: string; publicKey: string }> // publicKey hex
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
    if (exact) return unsealForSession(exact)
    const key = stableIdKey(did)
    if (key === did) return null // no normalization happened — nothing a scan could find
    const scanned = (await dbGetAll(db)).find(r => stableIdKey(r.did) === key) ?? null
    return scanned ? await unsealForSession(scanned) : null
  } catch { return null }
}

export async function storeDidRecord(record: DidRecord): Promise<void> {
  const db = await openDB()
  await dbPut(db, await sealIfProtected(record))
}

// ── At-rest sealing of the seed + root key (did/prf.ts) ─────────────────────
// The PRF-derived key for THIS page load. Never persisted: that is the whole
// point — on disk there is only ciphertext, and getting the key back costs a
// user-verification gesture. Cached for the session so that gesture happens
// once rather than on every signature.
let sessionKey: Uint8Array | null = null

/** True when this device has opted into passkey protection at all. */
export function identityProtectionEnabled(): boolean {
  return hasPrfCredential()
}

export function identityUnlocked(): boolean {
  return sessionKey !== null
}

/** Turns protection ON for this device: enrols a passkey and re-writes every
 * stored record sealed. Returns false when the platform declines (no
 * authenticator, PRF unsupported, user cancelled) — an ordinary outcome, and
 * the records simply stay plaintext (this file's header on why that fallback
 * is deliberate). */
export async function enableIdentityProtection(userName: string): Promise<boolean> {
  const key = await enrollPrfKey(userName)
  if (!key) return false
  sessionKey = key
  try {
    const db = await openDB()
    for (const rec of await dbGetAll(db)) await dbPut(db, await sealIfProtected(rec))
    return true
  } catch {
    // Enrolled but couldn't re-write: leave the credential in place (the next
    // write seals normally) rather than reporting a failure that already
    // half-happened.
    return true
  }
}

/** Prompts for the passkey and caches its PRF output for this page load, so
 * records read afterwards come back with `masterSeed`/`rootPrivateKey`
 * populated. No-op (true) when already unlocked or when this device never
 * enabled protection — callers can invoke it unconditionally before any
 * root-key operation. */
export async function unlockIdentitySecrets(): Promise<boolean> {
  if (sessionKey) return true
  if (!hasPrfCredential()) return true // nothing sealed on this device
  const key = await unlockPrfKey()
  if (!key) return false
  sessionKey = key
  return true
}

/** The master seed in the clear, for the one operation that shows it to a
 * human (the recovery phrase). **Re-authenticates every time, ignoring the
 * session cache** — unlike unlockIdentitySecrets, which exists so that
 * signing doesn't prompt on every signature. Putting the identity's whole
 * secret on screen is not in that category: it should cost a fresh gesture
 * even inside an already-unlocked session, or the protection reduces to
 * "whoever reaches the device after the first Sync of the day".
 *
 * Null when the record has no seed at all (an identity created before seeds
 * were stored, and never logged into with the phrase since) or when the
 * gesture is refused. On a device without passkey protection the seed is
 * plaintext anyway, so it is simply returned — refusing there would hide
 * something devtools can read regardless (2026-08-14 decision: A). */
export async function revealMasterSeed(did: string): Promise<string | null> {
  const db = await openDB().catch(() => null)
  if (!db) return null
  const stored = await dbGet(db, did).catch(() => null)
  if (!stored) return null
  if (!stored.sealed) return stored.masterSeed ?? null
  const key = await unlockPrfKey()
  if (!key) return null
  try {
    const blob = Uint8Array.from(atob(stored.sealed), c => c.charCodeAt(0))
    const secrets = JSON.parse(new TextDecoder().decode(await aesGcmOpen(key, blob))) as SealedSecrets
    return secrets.masterSeed ?? null
  } catch {
    return null
  }
}

/** Drops the session key — logout's counterpart to unlock. The ciphertext
 * stays; only the ability to read it this page load goes away. */
export function lockIdentitySecrets(): void {
  sessionKey = null
}

interface SealedSecrets { masterSeed?: string; rootPrivateKey: string; signingPrivateKey?: string }

async function sealIfProtected(record: DidRecord): Promise<DidRecord> {
  if (!sessionKey || !record.rootPrivateKey) return record
  const secrets: SealedSecrets = {
    rootPrivateKey: record.rootPrivateKey,
    ...(record.masterSeed ? { masterSeed: record.masterSeed } : {}),
    ...(record.signingPrivateKey ? { signingPrivateKey: record.signingPrivateKey } : {}),
  }
  const blob = await aesGcmSeal(sessionKey, new TextEncoder().encode(JSON.stringify(secrets)))
  const out: DidRecord = { ...record, sealed: btoa(String.fromCharCode(...blob)) }
  delete out.masterSeed
  delete (out as { rootPrivateKey?: string }).rootPrivateKey
  delete out.signingPrivateKey
  return out
}

/** Merges the sealed secrets back in when the session is unlocked. A sealed
 * record read while LOCKED comes back without them — deliberately: the
 * alternative is prompting for a gesture from whatever background path
 * happened to read the record first (boot, a DIDComm poll), which is exactly
 * what the device keys are kept in plaintext to avoid. Consumers that need
 * the root key call unlockIdentitySecrets() first; one that forgets gets a
 * legible failure from requireRootPrivateKey rather than a signature over
 * `undefined`. */
async function unsealForSession(record: DidRecord): Promise<DidRecord> {
  if (!record.sealed || !sessionKey) return record
  try {
    const blob = Uint8Array.from(atob(record.sealed), c => c.charCodeAt(0))
    const secrets = JSON.parse(new TextDecoder().decode(await aesGcmOpen(sessionKey, blob))) as SealedSecrets
    return {
      ...record,
      rootPrivateKey: secrets.rootPrivateKey,
      ...(secrets.masterSeed ? { masterSeed: secrets.masterSeed } : {}),
      ...(secrets.signingPrivateKey ? { signingPrivateKey: secrets.signingPrivateKey } : {}),
    }
  } catch {
    return record // wrong key / corrupt blob — same as locked, never a crash
  }
}

/** The one place a missing root key turns into a message a human can act on.
 * A sealed-but-locked record reaches signing code with `rootPrivateKey`
 * undefined, and @noble would otherwise throw something opaque about byte
 * lengths. */
export function requireRootPrivateKey(record: DidRecord): string {
  if (!record.rootPrivateKey) {
    throw new Error('This identity is locked — unlock it with your passkey to sign as it')
  }
  return record.rootPrivateKey
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
