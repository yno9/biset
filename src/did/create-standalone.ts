// Relay-less identity (DID⊥relay orthogonality, project memory): create a DID
// that has NO relay account at all — reachable only through the DIDComm mediator
// — and add relays later as an optional step. This is the symmetric counterpart
// to anchorless relays (a relay with no DID); here, a DID with no relay.
//
// Everything a normal account needs a relay for is skipped:
//   - no envelope (that is password-recovery state a relay stores; recovery here
//     is the mnemonic alone)
//   - no provisionAccount (that binds the DID to a relay-hosted address)
//   - no relay gateways to publish through — the DID document goes to the PUBLIC
//     pkarr fallbacks, and reachability comes from the mediator, not a relay.
//
// The identity lives ONLY as a DidRecord (keyed by the DID itself, since there
// is no email address yet) plus a localStorage marker so boot can find it with
// zero StoredAccounts present.
//
// Multi-device (document.ts's DidKeyAgreement note): each device that
// registers with the mediator mints its OWN random DIDComm key and holds its
// own positional slot (kid `#k<n>`) in the published document — not one shared
// key derived from the seed, which would let two devices collide and starve
// each other at the mediator's per-kid delivery queue. `ensureDeviceKey` mints
// this device's key once; `syncDevicePosition` resolves the currently-
// published document (best-effort, ONCE per device registration) to learn its
// own stable slot and cache every sibling device's key, so a routine republish
// from this device alone (which never resolves — see publish.ts's
// buildOwnDocument note) doesn't silently drop the others.
import { deriveRootKey, didFromRootPublicKey, generateDeviceDidCommKey } from './keys.ts'
import { initDid } from './index.ts'
import { getDidRecord, storeDidRecord, type DidRecord } from './store.ts'
import { buildBisetDocument, keyAgreementKeysFromHex, kidN, type DidDocument } from './document.ts'
import { registerDidCommViaDht } from './didcomm/register.ts'
import { resolve, publishDocument, PUBLIC_PKARR_FALLBACKS } from './resolver.ts'
import { hexToBytes } from '../utils.ts'

const MARKER = 'biset_standalone_did'
const bytesToHex = (b: Uint8Array): string => [...b].map(x => x.toString(16).padStart(2, '0')).join('')

/** Which DIDComm mediator this deployment registers standalone identities with.
 * Not in relay config (a standalone identity has no relay), so it is derived
 * from the app host — anchor.<apex> — or taken from an explicit config key. */
export function mediatorUrl(): string {
  const cfg = (window as any).__BISET_CONFIG__ || {}
  if (cfg.mediator_url) return cfg.mediator_url
  const host: string = cfg.hostname || ''
  const apex = host.split('.').slice(-2).join('.') // t.biset.md -> biset.md
  return apex ? `https://anchor.${apex}` : ''
}

/** The DID of the standalone identity this browser holds, if any. */
export function standaloneDid(): string | null {
  return localStorage.getItem(MARKER)
}

export function clearStandalone(): void {
  localStorage.removeItem(MARKER)
}

/** Mints THIS device's own DIDComm key if it doesn't have one yet. Random, not
 * seed-derived — see the file header. No-op (and no network) if already set. */
async function ensureDeviceKey(rec: DidRecord): Promise<DidRecord> {
  if (rec.didCommPrivateKey && rec.didCommPublicKey) return rec
  const kp = generateDeviceDidCommKey()
  rec.didCommPublicKey = bytesToHex(kp.publicKey)
  rec.didCommPrivateKey = bytesToHex(kp.privateKey)
  await storeDidRecord(rec)
  return rec
}

/** Establishes this device's stable positional slot and refreshes the sibling
 * cache, by resolving whatever document is currently published (best-effort —
 * a resolve failure just means this call learns nothing new, safe to retry
 * later). Only needs to run ONCE per device to establish `didCommOwnKid`
 * (kept stable afterward); safe to call again to pick up devices registered
 * elsewhere since — it only ever grows the cache, never removes an entry. */
async function syncDevicePosition(rec: DidRecord, gatewayUrls: string[]): Promise<DidRecord> {
  let resolved: DidDocument | null = null
  try { resolved = await resolve(rec.did, gatewayUrls) } catch { /* best-effort */ }
  const existing = resolved?.keyAgreementKeys ?? []

  if (!rec.didCommOwnKid) {
    // Already published under this exact key (this device registered before,
    // record survived, but didCommOwnKid was never set — e.g. a pre-multi-
    // device record)? Reuse that slot instead of taking a new one.
    const mine = existing.find(k => bytesToHex(k.publicKey) === rec.didCommPublicKey)
    const nextN = existing.length ? Math.max(...existing.map(k => k.n)) + 1 : 1
    rec.didCommOwnKid = mine ? `#k${mine.n}` : `#k${nextN}`
  }
  const myN = kidN(rec.didCommOwnKid)

  const siblingMap = new Map((rec.didCommSiblingKeys ?? []).map(s => [s.kid, s]))
  for (const k of existing) {
    if (k.n === myN) continue // that's us, not a sibling
    siblingMap.set(`#k${k.n}`, { kid: `#k${k.n}`, publicKey: bytesToHex(k.publicKey) })
  }
  rec.didCommSiblingKeys = [...siblingMap.values()]
  await storeDidRecord(rec)
  return rec
}

/** This device's own entry + every known sibling's, as the array a document
 * publish carries — reads purely from the cached record (see the file header
 * for why buildOwnDocument/this never resolve on a routine publish). */
function fullKeyAgreementKeys(rec: DidRecord) {
  return keyAgreementKeysFromHex(
    rec.didCommPublicKey && rec.didCommOwnKid ? { kid: rec.didCommOwnKid, publicKeyHex: rec.didCommPublicKey } : null,
    (rec.didCommSiblingKeys ?? []).map(s => ({ kid: s.kid, publicKeyHex: s.publicKey })),
  )
}

// Publish the record's document (no relays, mediator service only) to the public
// gateways and (re-)register with the mediator. Idempotent: registerDidCommViaDht
// REPLACES the DIDCommMessaging service rather than appending, so calling it on
// every boot just refreshes the (hours-lived) DHT record and the mediation.
async function publishAndRegister(rec: DidRecord): Promise<void> {
  await ensureDeviceKey(rec)
  const rootPriv = hexToBytes(rec.rootPrivateKey)
  const rootPub = hexToBytes(rec.rootPublicKey)

  const mUrl = rec.didCommMediatorUrl || mediatorUrl()
  if (mUrl) {
    try {
      // Resolve to establish this device's slot + learn siblings only the
      // FIRST time it registers (didCommOwnKid unset) — this runs on every
      // boot (refreshStandalone), so an already-established device publishes
      // from cached local state only, same as buildOwnDocument's normal
      // republish (its note explains why: a transient resolve failure must
      // never look like "no siblings"). A device that goes offline during its
      // very first registration falls back to slot #k1 unconditionally
      // (existing = [] either way) — a possible collision with a sibling it
      // simply couldn't see, self-correcting on the next successful resolve
      // from either device, not silent data loss.
      if (!rec.didCommOwnKid) await syncDevicePosition(rec, PUBLIC_PKARR_FALLBACKS)
      const base: DidDocument = { ...buildBisetDocument(rec.did, rootPub, [], []), keyAgreementKeys: fullKeyAgreementKeys(rec) }
      const reg = await registerDidCommViaDht(hexToBytes(rec.didCommPrivateKey!), kidN(rec.didCommOwnKid!), rootPriv, base, mUrl, PUBLIC_PKARR_FALLBACKS)
      // Persist mediator wiring so a later publishOwnDids rebuilds the document
      // WITH the DIDComm service instead of republishing it away — see store.ts.
      rec.didCommMediatorUrl = reg.mediator.url
      rec.didCommRoutingKey = reg.mediator.doc.keyAgreement?.[0]
      await storeDidRecord(rec)
      return
    } catch (e) {
      console.warn('[standalone] mediator registration skipped (not yet reachable):', e instanceof Error ? e.message : e)
    }
  }

  // No mediator configured, or registration failed: still publish the bare
  // document (identity + this device's key) so the DID exists on the DHT —
  // this publish is the load-bearing step, so it must succeed against at
  // least one public gateway.
  const base: DidDocument = { ...buildBisetDocument(rec.did, rootPub, [], []), keyAgreementKeys: fullKeyAgreementKeys(rec) }
  const published = await publishDocument(rootPriv, base, PUBLIC_PKARR_FALLBACKS)
  if (published === 0) throw new Error('no pkarr gateway accepted the DID document')
}

/** Create a brand-new relay-less identity. Like a normal #new account it takes a
 * password and builds a cryptenv envelope — a relay-less identity is just a
 * normal identity with zero relays — but stores the envelope locally (in its
 * DidRecord) since there is no relay to hold it yet. Returns the master secret so
 * the caller can show the mnemonic (the ultimate backup; the password is the
 * everyday unlock). */
export async function createStandaloneIdentity(password: string): Promise<{ did: string; masterSecret: Uint8Array }> {
  const { buildEnvelope } = await import('../cryptenv.ts')
  const { envelope, masterSecret } = await buildEnvelope(password)
  const did = await registerStandaloneIdentity(masterSecret, envelope)
  return { did, masterSecret }
}

/** Store + publish + mediator-register a relay-less identity from its seed,
 * marking it standalone. Shared by createStandaloneIdentity (fresh, with an
 * envelope) and restore (from the mnemonic, no local envelope — add-relay falls
 * back to the phrase there). Idempotent: initDid returns any existing record. */
export async function registerStandaloneIdentity(masterSecret: Uint8Array, envelope?: import('../cryptenv.ts').Envelope): Promise<string> {
  const root = deriveRootKey(masterSecret)
  const did = didFromRootPublicKey(root.publicKey)
  // Key the DidRecord by the DID itself (no email address exists yet). initDid
  // derives + persists the root/nostr keys from the seed — NOT the DIDComm key,
  // which is this device's own concern (ensureDeviceKey, below).
  const rec = await initDid(did, masterSecret)
  if (!rec) throw new Error('registerStandaloneIdentity: initDid returned null')
  if (envelope) rec.envelope = envelope
  await storeDidRecord(rec)
  await publishAndRegister(rec)
  localStorage.setItem(MARKER, did)
  return did
}

/** Register the CURRENT identity (a logged-in account's, or the relay-less
 * standalone one) with a DIDComm mediator at `mediatorUrl` and persist the
 * result. A mediator needs no account — the DID's own key authenticates — so
 * this is the whole "add a mediator" operation. Shared by the account page's
 * "+ New Relay" mediator branch and the DIDComm debug page. Returns the
 * registration so callers that go on to send/pickup don't need to rebuild it. */
export async function registerWithMediator(rawMediatorUrl: string): Promise<{ own: import('./didcomm/message.ts').DidCommSender; mediator: import('./didcomm/coordinate.ts').MediatorInfo }> {
  // A scheme-less "anchor.biset.md" would otherwise be fetched RELATIVE to the
  // page (file://…/anchor.biset.md, or the app's own origin) — force https.
  const mUrl = /^https?:\/\//i.test(rawMediatorUrl) ? rawMediatorUrl : 'https://' + rawMediatorUrl
  const { sessions } = await import('../context.ts')
  const key = sessions[0]?.account.email ?? standaloneDid()
  if (!key) throw new Error('no identity to register')
  let rec = await getDidRecord(key)
  if (!rec) throw new Error(`no local DID record for ${key}`)
  rec = await ensureDeviceKey(rec)

  // Base document: live session state when there are relays, else the record
  // alone (relay-less: no relays, no address).
  const { buildOwnDocument } = await import('./publish.ts')
  const own = await buildOwnDocument(key)
  const gateways = [...(own?.gateways ?? []), ...PUBLIC_PKARR_FALLBACKS]

  // Establish/refresh this device's slot + siblings before building the doc —
  // see syncDevicePosition's note.
  rec = await syncDevicePosition(rec, gateways)
  const doc: DidDocument = { ...(own?.doc ?? buildBisetDocument(rec.did, hexToBytes(rec.rootPublicKey), [], [])), keyAgreementKeys: fullKeyAgreementKeys(rec) }
  const rootPriv = own?.rootPrivateKey ?? hexToBytes(rec.rootPrivateKey)

  const reg = await registerDidCommViaDht(hexToBytes(rec.didCommPrivateKey!), kidN(rec.didCommOwnKid!), rootPriv, doc, mUrl, gateways)
  rec.didCommMediatorUrl = reg.mediator.url
  rec.didCommRoutingKey = reg.mediator.doc.keyAgreement?.[0]
  await storeDidRecord(rec)
  return { own: reg.own, mediator: reg.mediator }
}

/** Deregister the current identity's device key from its mediator
 * (keylist-update 'remove') and forget the mediator locally. Mirrors
 * registerWithMediator: the mediator card's "Log out" — unlike a relay's,
 * which only forgets local credentials — actually withdraws the forwarding
 * authorization server-side, since there is no account to simply stop using.
 * Leaves the device's key + slot in place (rec.didCommOwnKid survives), so a
 * later re-Register reuses the same slot rather than taking a new one. */
export async function unregisterFromMediator(): Promise<void> {
  const { sessions } = await import('../context.ts')
  const key = sessions[0]?.account.email ?? standaloneDid()
  if (!key) throw new Error('no identity')
  const rec = await getDidRecord(key)
  if (!rec?.didCommMediatorUrl || !rec.didCommPrivateKey || !rec.didCommOwnKid) throw new Error('not registered with a mediator')
  const { fetchMediatorInfo, updateKeylist } = await import('./didcomm/coordinate.ts')
  const mediator = await fetchMediatorInfo(rec.didCommMediatorUrl)
  const ownKid = `${rec.did}${rec.didCommOwnKid}`
  const own = { did: rec.did, xKid: ownKid, xPriv: hexToBytes(rec.didCommPrivateKey) }
  await updateKeylist(mediator, own, ownKid, 'remove')
  delete rec.didCommMediatorUrl
  delete rec.didCommRoutingKey
  await storeDidRecord(rec)
}

/** True if `url` serves a DIDComm mediator (its /.well-known/did.json is a
 * did:peer) rather than a JMAP relay — so the account page can offer a
 * credential-less "Register" instead of Sign up / Log in. */
export async function isMediatorUrl(url: string): Promise<boolean> {
  try {
    const base = (/^https?:\/\//i.test(url) ? url : 'https://' + url).replace(/\/$/, '')
    const resp = await fetch(base + '/.well-known/did.json')
    if (!resp.ok) return false
    const doc = await resp.json()
    return typeof doc?.id === 'string' && doc.id.startsWith('did:peer:')
  } catch { return false }
}

/** Boot-time refresh: if this browser holds a standalone identity, republish its
 * document + renew mediation, and return its DID. No seed needed — every key is
 * already in the DidRecord. Best-effort: a failed republish must not block boot
 * (the identity still exists locally; it just may be briefly unresolvable). */
export async function refreshStandalone(): Promise<string | null> {
  const did = standaloneDid()
  if (!did) return null
  const rec = await getDidRecord(did)
  if (!rec) { clearStandalone(); return null }
  try { await publishAndRegister(rec) } catch (e) { console.warn('[standalone] republish failed:', e) }
  return did
}
