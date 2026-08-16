// Multi-device DIDComm key management (DID⊥relay orthogonality, project
// memory): shared by every identity's mediator registration, regardless of
// whether it has any mail/AP relay, and regardless of DID method (did:dht /
// did:webvh — PLANWEBVH.md §5.3). did is the essential key concept here
// (store.ts's file header) — mail/AP is an optional add-on, so nothing below
// branches on "does this identity have a relay" beyond what liveRelayInputs
// itself already handles (a relay-less identity simply builds with no
// services).
//
// There is deliberately no separate "standalone identity" creation path
// anymore, and no separate always-on keep-alive for one either: an identity
// with zero relays is created exactly like any other (account-create.ts) and
// kept alive exactly like any other — setupDidCommChannel's
// reassertKeylistRegistration (channel.ts), called at every boot for
// whichever DID this device holds, already republishes the full document
// (mail/AP services if any, plus the DIDComm layer) whenever a mediator is
// registered, and does nothing when one isn't. A publish that isn't backing
// a registered mediator only ever happens via the explicit "Republish"
// action (left-pane.ts) — never automatically — so an identity nobody has
// asked to be reachable stays economical: zero network traffic.
//
// Multi-device (dht/document.ts's DidKeyAgreement note): each device that
// registers with the mediator mints its OWN random DIDComm key and holds its
// own positional slot (kid `#k<n>`) in the published document — not one
// shared key derived from the seed, which would let two devices collide and
// starve each other at the mediator's per-kid delivery queue. `ensureDeviceKey`
// mints this device's key once; `syncDevicePosition` resolves the
// currently-published document (best-effort) to learn its own stable slot
// and cache every sibling device's key. Runs at registration AND on every
// routine republish (dht/publish.ts's buildOwnDocument) — it used to run
// only once, at registration, which meant a device that registered BEFORE a
// sibling existed never learned about it and kept erasing that sibling's
// key on every one of its own later boots (found live: two of one
// identity's own browsers, neither could reach the other, because whichever
// reopened most recently republished a document that had never heard of the
// other one).
//
// Method dispatch (this file's own addition, PLANWEBVH.md §5.3): the sibling
// merge / removed-key tombstone / mediator keylist-query prune logic below is
// ONE implementation shared by both did:dht and did:webvh — only the
// document-build-and-publish step (`MethodOps.publishFull`) differs per
// method, and each method's implementation lives in its own directory
// (dht/method-ops.ts, webvh/method-ops.ts) rather than being copied here.
import { generateDeviceDidCommKey, generateDeviceMlkemKey } from './keys.ts'
import { getDidRecord, storeDidRecord, withDidLock, type DidRecord } from './store.ts'
import { keyAgreementKeysFromHex, type DidKeyAgreement } from './document.ts'
import type { DidMlkemKeyAgreement } from './webvh/document.ts'
import { relaysForId, isApRelay, isDidCommRelay } from '../context.ts'
import * as identityStore from '../store/identities.ts'
import { fetchMediatorInfo, requestMediation, updateKeylist, queryKeylist, type MediatorInfo } from './didcomm/coordinate.ts'
import type { DidCommSender } from './didcomm/message.ts'
import { hexToBytes } from '../utils.ts'
import { deviceKidFragment, isLegacyKid, fragmentOf } from './devicekid.ts'
import { generateOwnKeyPackage, memberTransportKeys, type OwnKeyPackage } from '../mls/group.ts'
import { ensureSelfGroup, selfGroupTransportKeys, selfGroupIdHex, selfGroupDevices, removeDeviceFromSelfGroup, leaveSelfGroup } from '../mls/self-group.ts'
import { forgetDevices } from '../mls/authservice.ts'
import { loadGroup, saveGroup, deleteGroup, mintKeyPackages, KEY_PACKAGE_POOL_TARGET } from '../mls/store.ts'
import { publishKeyPackages } from '../mls/transport.ts'
import type { ClientState } from '../mls/vendor/index.ts'
import { reportDeviceProjection } from '../mls/device-projection.ts'

const OWN_DID_KEY = 'biset_own_did'
const bytesToHex = (b: Uint8Array): string => [...b].map(x => x.toString(16).padStart(2, '0')).join('')

/** Which DIDComm mediator this deployment registers identities with by
 * default. Not in relay config (an identity may have no relay at all), so it
 * is derived from the app host — anchor.<apex> — or taken from an explicit
 * config key. */
export function mediatorUrl(): string {
  const cfg = (window as any).__BISET_CONFIG__ || {}
  if (cfg.mediator_url) return cfg.mediator_url
  const host: string = cfg.hostname || ''
  const apex = host.split('.').slice(-2).join('.') // t.biset.md -> biset.md
  return apex ? `https://anchor.${apex}` : ''
}

/** Whether this deployment's anchor (mediatorUrl above) is actually reachable
 * from the client right now — account-create.ts's #new signup uses this to
 * pick did:webvh (anchor required — its log lives only there) vs did:dht
 * (fully anchorless, self-certifying) automatically, instead of a manual
 * toggle: the choice was never really the user's to make, it's a property of
 * the deployment. No URL configured at all (mediatorUrl() empty) or the fetch
 * failing outright (network error, DNS, CORS) both mean "no anchor" — any
 * actual HTTP response, success or not, proves the host is up. */
export async function anchorReachable(): Promise<boolean> {
  const url = mediatorUrl()
  if (!url) return false
  try {
    await fetch(url.replace(/\/$/, '') + '/.well-known/did.json')
    return true
  } catch {
    return false
  }
}

/** This browser's own identity DID, persisted so boot can find it even with
 * zero relay sessions (a relay-backed identity's DID is also always
 * available via sessions[].account.did — this is the fallback for when
 * there are none, not a "standalone-only" concept). Set once at identity
 * creation (account-create.ts) regardless of whether a relay is ever added,
 * and never cleared: harmless to keep once a relay exists too, since it is
 * only ever consulted as a fallback. */
export function ownDid(): string | null {
  return localStorage.getItem(OWN_DID_KEY)
}

export function setOwnDid(did: string): void {
  localStorage.setItem(OWN_DID_KEY, did)
}

/** Mints THIS device's own DIDComm key if it doesn't have one yet. Random, not
 * seed-derived — see the file header. No-op (and no network) if already set.
 *
 * Locked, and takes a `did` rather than a caller-supplied DidRecord: it used
 * to write back whatever snapshot its caller happened to be holding, which is
 * the same clobbering read-modify-write race provision.ts's ensureJmapDeviceKey
 * documents in full (2026-07-27) — just from the other direction. During
 * restore, registerWithMediator reads a record, this mints a key into that
 * (possibly already stale) copy and persists it, wiping any field a
 * concurrent writer added in between — chiefly the jmapDevicePrivateKey
 * vouchThisDevice mints on the very same tick. Re-reading inside the lock
 * makes each side see the other's write instead of overwriting it. */
async function ensureDeviceKey(did: string): Promise<DidRecord> {
  return withDidLock(did, async () => {
    const rec = await getDidRecord(did)
    if (!rec) throw new Error('ensureDeviceKey: no local DID record for ' + did)
    let changed = false
    if (!rec.didCommPrivateKey || !rec.didCommPublicKey) {
      const kp = generateDeviceDidCommKey()
      rec.didCommPublicKey = bytesToHex(kp.publicKey)
      rec.didCommPrivateKey = bytesToHex(kp.privateKey)
      changed = true
    }
    // ML-KEM-768 (PLAN.md "did:webvh PQハイブリッド化" Phase 1), did:webvh
    // only — checked independently of the X25519 key above (not `else if`),
    // so an identity that already had a DIDComm key before PQ support existed
    // gets its ML-KEM-768 key minted on the next call instead of only ever
    // getting one at first-ever registration.
    if (did.startsWith('did:webvh:') && !rec.mlkemPrivateKey) {
      const kp = generateDeviceMlkemKey()
      rec.mlkemPublicKey = bytesToHex(kp.publicKey)
      rec.mlkemPrivateKey = bytesToHex(kp.privateKey)
      changed = true
    }
    if (!changed) return rec
    await storeDidRecord(rec)
    return rec
  })
}

// ── method dispatch ─────────────────────────────────────────────────────────

export interface RelayServiceInput { id: string; serverUrl: string; protocol?: string; address?: string }
export interface RelayInput { services: RelayServiceInput[]; addresses: string[]; name?: string }

function relayId(serverUrl: string): string {
  try { return new URL(serverUrl).hostname.split('.')[0] } catch { return 'relay' }
}

/** This identity's LIVE relay sessions on THIS device, in the shape both
 * dht/document.ts's buildBisetDocument and webvh/document.ts's
 * buildBisetWebvhState take — null when there is no live session for this
 * identity right now (relay-less identity, or a device mid-logout), which
 * every MethodOps.publishFull implementation reads as "carry forward
 * whatever's already published" rather than "publish empty services"
 * (dht/publish.ts's buildOwnDocument has the same distinction and the same
 * reasoning against guessing). Excludes the synthetic DIDComm session
 * (didcomm/channel.ts) — it has no real relay behind it. */
function liveRelayInputs(did: string): RelayInput | null {
  const relaySessions = relaysForId(did).filter(s => !isDidCommRelay(s.account.serverUrl))
  if (!relaySessions.length) return null
  const services = relaySessions.map(s => ({
    id: relayId(s.account.serverUrl), serverUrl: s.account.serverUrl,
    protocol: isApRelay(s.account.serverUrl) ? 'activitypub' : 'mail', address: s.account.email,
  }))
  const addresses = [...new Set(relaySessions.map(s => s.account.email))]
  const name = identityStore.all().find(i => relaySessions.some(s => s.account.email === i.email))?.name
  return { services, addresses, name }
}

export interface PublishFullOpts {
  keyAgreementKeys: DidKeyAgreement[]
  // ML-KEM-768 keys (PLAN.md "did:webvh PQハイブリッド化" Phase 1) — did:webvh
  // only. dht/method-ops.ts's publishFull simply ignores this field (did:dht
  // has nowhere to put a 1184-byte key); webvh/method-ops.ts's threads it
  // into buildBisetWebvhState's mlkemKeyAgreementKeys.
  mlkemKeyAgreementKeys?: DidMlkemKeyAgreement[]
  didCommService?: { mediatorUrl: string; routingKey: string }
  /** Actively REMOVE any DIDCommMessaging service the published document
   * still carries, rather than merely not writing one. The distinction is
   * did:dht-specific and load-bearing: that method's publishFull carries a
   * resolved document's whole `service` array forward, so an absent
   * `didCommService` leaves a previously-published one standing (which is
   * exactly what registerWithMediator's Phase 1 wants). publishCurrentState
   * sets this when the identity has NO keyAgreement keys left to publish —
   * see the invariant note there. */
  removeDidCommService?: boolean
}

/** The one thing each DID method implements differently: build this
 * identity's current document (from `relayInput`, or resolve-and-carry-
 * forward when it's null) and publish/update it. Everything ELSE in this
 * file — sibling merge, tombstones, mediator keylist pruning, the 2-phase
 * "publish keys, then register, then publish again with the service" mediator
 * registration sequence — is method-agnostic and lives here exactly once. */
export interface MethodOps {
  resolveKeyAgreement(did: string, gatewayUrls: string[]): Promise<{
    keyAgreementKeys: DidKeyAgreement[]
    // Present (possibly empty) for did:webvh, always absent for did:dht — a
    // method that never returns this is read as "no PQ keys, and never will
    // be" (dht/method-ops.ts doesn't set it at all).
    mlkemKeyAgreementKeys?: DidMlkemKeyAgreement[]
  } | null>
  resolveConfirmedAbsent(did: string, gatewayUrls: string[]): Promise<boolean>
  gatewayUrls(relaySessions: Array<{ account: { serverUrl: string } }>, mediatorUrl?: string): string[]
  publishFull(rec: DidRecord, relayInput: RelayInput | null, opts: PublishFullOpts): Promise<number>
}

// Cached after first resolution — dynamic-import-backed purely to break the
// module-init cycle (webvh/method-ops.ts imports TYPES from this file; this
// file needs its concrete implementation), not to defer work on every call.
// Every exported function below calls ensureMethodOpsLoaded() first; it's
// cheap after the first call since the module cache short-circuits every
// subsequent import().
let webvhOps: MethodOps | undefined
let methodOpsLoaded: Promise<void> | undefined
async function ensureMethodOpsLoaded(): Promise<void> {
  if (!methodOpsLoaded) {
    methodOpsLoaded = import('./webvh/method-ops.ts').then(m => { webvhOps = m.webvhMethodOps })
  }
  await methodOpsLoaded
}

/** The method implementation for a DID.
 *
 * There is one method, so an unrecognised DID gets no silent fallback: it used
 * to fall through to the did:dht ops, which is how a `did:webvh` string that
 * failed the prefix test would still have been published to the DHT. */
function methodOpsFor(did: string): MethodOps {
  if (!did.startsWith('did:webvh:')) throw new Error(`didcomm-devices: no method implementation for ${did}`)
  if (!webvhOps) throw new Error('didcomm-devices: MethodOps not yet loaded — this indicates a bug (every exported function awaits ensureMethodOpsLoaded() first)')
  return webvhOps
}

// ── device slot / sibling sync (method-agnostic) ────────────────────────────


// ---------------------------------------------------------------- MLS bridge
//
// The DID document's device list is an OUTPUT of the MLS self group now, not
// an input to anything. These three functions are the whole of the join
// between the two layers: mint this device's key package with its transport
// keys inside, and read the group's devices back out in the shape a publish
// expects.

/** This device's MLS key package, carrying its DIDComm transport keys in its
 * own leaf (mls/transport-keys.ts) — which is what lets any member of the
 * group publish the identity's document without reading it first. */
async function ownKeyPackageFor(rec: DidRecord): Promise<OwnKeyPackage> {
  if (!rec.didCommOwnKid || !rec.didCommPublicKey) throw new Error('ownKeyPackageFor: this device has no kid yet')
  return generateOwnKeyPackage(`${rec.did}${rec.didCommOwnKid}`, {
    x25519: hexToBytes(rec.didCommPublicKey),
    mlkem: rec.mlkemPublicKey ? hexToBytes(rec.mlkemPublicKey) : undefined,
  })
}

/** The keyAgreement entries to publish, taken from group state. */
function deviceKeysFromGroup(state: ClientState, did: string): DidKeyAgreement[] {
  return memberTransportKeys(state, did).map(d => ({ kid: fragmentOf(d.kid), publicKey: d.x25519 }))
}

/** The ML-KEM-768 entries to publish. Only devices that announced one appear —
 * absence means "not PQ-capable", exactly as before. */
function mlkemKeysFromGroup(state: ClientState, did: string): DidMlkemKeyAgreement[] {
  return memberTransportKeys(state, did)
    .filter((d): d is typeof d & { mlkem: Uint8Array } => !!d.mlkem)
    .map(d => ({ kid: fragmentOf(d.kid), publicKey: d.mlkem }))
}

/** Settle this device's own identity fields, and nothing else.
 *
 * This used to be the identity's device-list authority: it merged a resolved
 * document with a local sibling cache (grow-only gossip), subtracted
 * tombstones, forgave entries that reappeared, and finally asked the
 * mediator's keylist to break ties. All of that is gone. Membership is decided
 * by the MLS self group (mls/self-group.ts) — a device joins by a commit the
 * Delivery Service ordered and leaves by a Remove commit, so there is nothing
 * for a merge to reconcile and nothing a stale republish could resurrect.
 *
 * What is left is the part MLS has no opinion about: this device's own kid,
 * derived from its own key (did/devicekid.ts), and the retirement of a kid it
 * used before that derivation existed.
 *
 * It no longer reads the network at all, which is why `gatewayUrls` is gone
 * from its signature. */
export async function syncDevicePosition(rec: DidRecord): Promise<DidRecord> {
  if (!rec.didCommPublicKey) throw new Error('syncDevicePosition: this device has no DIDComm key yet')

  // The kid is a function of the key: no allocation, no view of the network,
  // no possibility of two devices claiming one name.
  const derivedKid = deviceKidFragment(hexToBytes(rec.didCommPublicKey))
  rec.didCommOwnKid = derivedKid

  await storeDidRecord(rec)
  return rec
}



/** What the mediator knows about each of this identity's device slots, keyed
 * by local kid fragment (`#kN`): whether it is still registered at all, and
 * when that device last picked mail up (coordinate.ts's KeylistEntry —
 * undefined means never, or a mediator that doesn't report it).
 *
 * Read-only and purely for display (the account page's device list). It is
 * deliberately NOT wired into any pruning decision: the mediator's keylist
 * stays the authority on what's live, and "hasn't polled in a while" is a
 * phone that's been switched off just as often as it is a dead slot — the
 * point is to show the user which rows are worth removing by hand, not to
 * decide for them. Null when this identity has no mediator/key to ask with,
 * or the query fails: "couldn't ask" must not render as "never seen". */
export interface MediatorDeviceActivity {
  /** Local kid fragment (`#kN`) → what the mediator knows. Membership alone
   * means "still registered"; `lastSeen` is only meaningful when
   * `reportsLastSeen` is true. */
  byKid: Map<string, { lastSeen?: number }>
  /** Whether this mediator reports last-pickup times AT ALL. An older anchor
   * simply omits the field, which is indistinguishable per-kid from "this
   * device has genuinely never collected anything" — and reading the first as
   * the second labels every live device a ghost (user-caught immediately:
   * a device sitting right there, polling, shown as "never picked up").
   * True when at least one kid carries a time, which any mediator that
   * supports it satisfies within one poll interval of the first device
   * checking in. */
  reportsLastSeen: boolean
}

export async function mediatorDeviceActivity(did: string): Promise<MediatorDeviceActivity | null> {
  const rec = await getDidRecord(did)
  if (!rec?.didCommMediatorUrl || !rec.didCommPrivateKey || !rec.didCommOwnKid) return null
  try {
    const mediator = await fetchMediatorInfo(rec.didCommMediatorUrl)
    const own = { did: rec.did, xKid: `${rec.did}${rec.didCommOwnKid}`, xPriv: hexToBytes(rec.didCommPrivateKey) }
    const entries = await queryKeylist(mediator, own)
    const byKid = new Map<string, { lastSeen?: number }>()
    for (const e of entries) {
      const [localKid] = queryKeylistToLocalKids([e.kid])
      byKid.set(localKid!, e.lastSeen === undefined ? {} : { lastSeen: e.lastSeen })
    }
    return { byKid, reportsLastSeen: entries.some(e => e.lastSeen !== undefined) }
  } catch (e) {
    console.warn('[didcomm-devices] keylist-query for device activity failed:', e instanceof Error ? e.message : e)
    return null
  }
}

/** Mediator keylist entries are full kid URLs (`did:...#kN`); this file's
 * sibling map keys them by fragment (`#kN`). Strip to the fragment so the two
 * can be compared. */
function queryKeylistToLocalKids(kids: string[]): string[] {
  return kids.map(k => { const i = k.indexOf('#'); return i === -1 ? k : k.slice(i) })
}

/** The keyAgreement entries this identity publishes.
 *
 * TWO sources, and the split is the whole design:
 *
 *   - **The MLS self group** decides who can READ. Its leaves carry each
 *     device's transport key (mls/transport-keys.ts), so a member can build
 *     this list without reading the document back.
 *   - **The mediator's keylist** decides who can be ADDRESSED. A device that
 *     is registered is one senders must still be able to encrypt an envelope
 *     to, whether or not it has joined the group yet.
 *
 * Publishing only the group was wrong, and wrong in a way that deadlocked two
 * devices of one identity (found live 2026-08-13). A device outside the group
 * was dropped from the document; the mediator authenticates a sender by
 * resolving its kid IN that document; so the dropped device could no longer
 * talk to the mediator at all — and its only route back, an external commit,
 * goes through the mediator. Each device kept unpublishing the other, and
 * neither could recover. "It will re-add itself" assumed a recovery path that
 * the drop itself had closed.
 *
 * Keeping a registered non-member addressable is safe precisely because MLS is
 * the read authority now: it receives envelopes it cannot open. What removes a
 * device is removing it from BOTH — a Remove commit and a keylist removal,
 * which is what `removeDeviceKey` and `unregisterFromMediator` each do.
 *
 * Every lookup here is best-effort. A device that cannot reach the mediator,
 * or resolve its own document, publishes what it knows rather than nothing:
 * the failure mode of this function must never be "shorten the list".
 */
export async function fullKeyAgreementKeys(rec: DidRecord): Promise<DidKeyAgreement[]> {
  await ensureMethodOpsLoaded()
  const entries = new Map<string, { kid: string; publicKeyHex: string }>()

  // This device, always. It is the one entry that cannot be wrong.
  if (rec.didCommPublicKey && rec.didCommOwnKid) {
    entries.set(rec.didCommOwnKid, { kid: rec.didCommOwnKid, publicKeyHex: rec.didCommPublicKey })
  }

  // Group members, with the keys their own leaves carry.
  const fromGroup = await selfGroupTransportKeys(rec.did).catch(() => undefined)
  for (const d of fromGroup ?? []) {
    const kid = fragmentOf(d.kid)
    if (!entries.has(kid)) entries.set(kid, { kid, publicKeyHex: bytesToHex(d.x25519) })
  }

  // Anything else the mediator still holds a registration for. Its key comes
  // from the currently published document — the keylist carries kids only,
  // and a kid alone cannot be published.
  for (const [kid, publicKeyHex] of await registeredButUnknown(rec, entries)) {
    entries.set(kid, { kid, publicKeyHex })
  }

  return keyAgreementKeysFromHex(null, [...entries.values()])
}

/** Published devices that are still registered with the mediator and are not
 * already accounted for. Empty when this device has no mediator to ask, or
 * when the ask fails — never a reason to publish a shorter list. */
async function registeredButUnknown(
  rec: DidRecord,
  known: Map<string, { kid: string; publicKeyHex: string }>,
): Promise<Array<[string, string]>> {
  if (!rec.didCommMediatorUrl || !rec.didCommPrivateKey || !rec.didCommOwnKid) return []
  try {
    const mediator = await fetchMediatorInfo(rec.didCommMediatorUrl)
    const own: DidCommSender = { did: rec.did, xKid: `${rec.did}${rec.didCommOwnKid}`, xPriv: hexToBytes(rec.didCommPrivateKey) }
    const registered = new Set((await queryKeylist(mediator, own)).map(e => fragmentOf(e.kid)))
    if (registered.size === 0) return []
    const ops = methodOpsFor(rec.did)
    // The identity's own gateways first (its relays, plus the mediator's own
    // pkarr endpoint) — the public fallbacks are slower and are not where a
    // relay-backed identity's document most reliably lives. Reading the live
    // relay list can itself fail outside a browser, and a failure here must
    // not take the whole lookup down: the mediator is already known, and its
    // gateway alone is enough to resolve.
    let gateways: string[] = []
    try {
      const relayInput = liveRelayInputs(rec.did)
      gateways = ops.gatewayUrls(relayInput?.services.map(s => ({ account: { serverUrl: s.serverUrl } })) ?? [], rec.didCommMediatorUrl)
    } catch {
      gateways = ops.gatewayUrls([], rec.didCommMediatorUrl)
    }
    const resolved = await ops.resolveKeyAgreement(rec.did, gateways).catch(() => null)
    return (resolved?.keyAgreementKeys ?? [])
      .filter(k => registered.has(k.kid) && !known.has(k.kid))
      .map(k => [k.kid, bytesToHex(k.publicKey)] as [string, string])
  } catch (e) {
    console.warn('[did] could not check which devices are still registered:', e instanceof Error ? e.message : e)
    return []
  }
}

/** ML-KEM-768 counterpart, from the same source. A device that has not minted
 * a PQ key simply announced none in its leaf, and is absent here — which is
 * how "not PQ-capable yet" has always been expressed. */
export async function fullMlkemKeyAgreementKeys(rec: DidRecord): Promise<DidMlkemKeyAgreement[]> {
  const fromGroup = await selfGroupTransportKeys(rec.did).catch(() => undefined)
  if (fromGroup?.length) {
    return fromGroup
      .filter((d): d is typeof d & { mlkem: Uint8Array } => !!d.mlkem)
      .map(d => ({ kid: fragmentOf(d.kid), publicKey: d.mlkem }))
  }
  return rec.mlkemPublicKey && rec.didCommOwnKid
    ? [{ kid: rec.didCommOwnKid, publicKey: hexToBytes(rec.mlkemPublicKey) }]
    : []
}

// ── publish / register / revoke (method-agnostic) ───────────────────────────

/** Publishes this identity's current document: live relay session state when
 * there is one on this device, otherwise resolve-and-carry-forward
 * (MethodOps.publishFull's own contract) rather than guessing empty
 * services. Covers what used to be two separate call sites
 * (publishBareOrCurrent, and buildOwnDocument's live-session branch) — the
 * distinction was never in the CALLER's control anyway, only in whether
 * `liveRelayInputs` finds a session, so one function suffices. */
export async function publishCurrentState(rec: DidRecord): Promise<number> {
  await ensureMethodOpsLoaded()
  const ops = methodOpsFor(rec.did)
  const relayInput = liveRelayInputs(rec.did)
  // Self-heal a kid collision (syncDevicePosition's own note: two devices
  // registering for the first time near-simultaneously can each pick #k1
  // before either has seen the other's key) on every ordinary Sync, not
  // just at registration. Was only wired into registerWithMediator (a
  // one-time call) and dht's routine republish — did:webvh's publishFull had
  // no call to it at all, so clicking Sync on a webvh identity republished
  // whatever kid this device already believed it owned, collision and all,
  // forever (found live 2026-08-11, two devices stuck sharing #k1 with
  // different keys, neither self-healing no matter how many times Sync was
  // pressed on either). Best-effort: a resolve failure here just means this
  // pass learns nothing new, same as registerWithMediator's own use.
  if (rec.didCommOwnKid) {
    const gateways = relayInput
      ? ops.gatewayUrls(relayInput.services.map(s => ({ account: { serverUrl: s.serverUrl } })), rec.didCommMediatorUrl)
      : ops.gatewayUrls([], rec.didCommMediatorUrl)
    rec = await syncDevicePosition(rec).catch(() => rec)
  }
  const keyAgreementKeys = await fullKeyAgreementKeys(rec)
  // THE INVARIANT: a DIDCommMessaging service and at least one keyAgreement
  // key stand or fall together. A document advertising the service with zero
  // keys says "reach me over DIDComm" while offering nothing to encrypt to —
  // and a sender hitting that gets a hard error (send.ts's
  // DidCommUnreachableError) with no fallback, which is how the whole
  // conversation dies rather than degrading.
  //
  // Not hypothetical: found live 2026-08-05 on 7 of 21 published identities on
  // t.biset.md (plus one did:dht), all in exactly this shape, all unreachable
  // and all making every correspondent's send fail. The route in is ordinary —
  // unregisterFromMediator deliberately KEEPS didCommMediatorUrl/
  // didCommRoutingKey (they belong to the identity, not to this device, so one
  // device's logout must not drop the service for its siblings), so when the
  // device logging out was the LAST one, the very next publish emitted the
  // service with an empty key list.
  //
  // Keeping the two in lockstep here means that case now publishes neither:
  // correspondents fall back to mail/AP (and the [DID] pill stops being
  // offered) instead of hitting a dead end, and re-registering from any device
  // restores both at once.
  //
  // The rule was enforced in ONE direction only — service dropped when there
  // were no keys — and the other direction produced the mirror-image failure,
  // seen live on y@biset.md (2026-08-13): twelve keyAgreement entries and no
  // DIDCommMessaging service at all. A sender resolving that gets the same
  // hard `DidCommUnreachableError`; the document advertises a dozen devices
  // and no way to reach any of them.
  //
  // It happens whenever a device that never completed registration (or lost
  // its mediator fields — restore used to drop them, see ARC.md) publishes:
  // it has keys to publish and no service to publish with them.
  //
  // Publishing NEITHER is not an option here the way it is above: the key list
  // belongs to the identity, not to this device, so emitting an empty one
  // would unpublish every other device over a local gap in THIS device's
  // record. So this publish is refused outright. Nothing gets worse — whatever
  // is currently published stays — and the remedy is the one the person can
  // actually take: register with a mediator again.
  const canRoute = !!(rec.didCommMediatorUrl && rec.didCommRoutingKey)
  if (keyAgreementKeys.length && !canRoute) {
    console.warn(`[did] refusing to publish ${rec.did}: it has device keys but no mediator to route them to — register with a mediator to restore the DIDComm service`)
    return 0
  }
  const didCommService = keyAgreementKeys.length && canRoute
    ? { mediatorUrl: rec.didCommMediatorUrl!, routingKey: rec.didCommRoutingKey! } : undefined
  const published = await ops.publishFull(rec, relayInput, {
    keyAgreementKeys, mlkemKeyAgreementKeys: await fullMlkemKeyAgreementKeys(rec),
    didCommService, removeDidCommService: keyAgreementKeys.length === 0,
  })
  // Same reason as registerWithMediator's own call: what a device may claim
  // has just changed, and a stale "no such device" is how a legitimate leaf
  // gets refused by the Authentication Service.
  if (published > 0) forgetDevices(rec.did)
  return published
}

/** Alias kept for the "no live relay session, carry forward" call sites that
 * want to be explicit about it (unregisterFromMediator, removeDeviceKey's
 * fallback) — behaves identically to publishCurrentState, since
 * liveRelayInputs already returns null in exactly that situation. */
export const publishBareOrCurrent = publishCurrentState


/** Register the CURRENT identity (relay-backed or with zero relays — same
 * call either way) with a DIDComm mediator at `mediatorUrl` and persist the
 * result. A mediator needs no account — the DID's own key authenticates — so
 * this is the whole "add a mediator" operation, and the moment an identity
 * opts into being DIDComm-reachable at all (see the file header: nothing
 * publishes automatically before this has happened at least once). Shared by
 * the account page's "+ New Relay" mediator branch and the DIDComm debug
 * page. Returns the registration so callers that go on to send/pickup don't
 * need to rebuild it.
 *
 * Three-phase (method-agnostic, same reasoning for did:webvh as for
 * did:dht's original BEP44-size-driven ordering): the mediator must be able
 * to resolve OUR key to encrypt mediate-grant back to us, which means it has
 * to already be resolvable BEFORE mediate-request is sent — publishing it
 * together with the mediator's own service (which we only learn about FROM
 * that same mediate-request) is a chicken-and-egg ordering bug. So: publish
 * the keys alone first, then register, then republish with the
 * DIDCommMessaging service added. */
export async function registerWithMediator(rawMediatorUrl: string): Promise<{ own: DidCommSender; mediator: MediatorInfo }> {
  await ensureMethodOpsLoaded()
  // A scheme-less "anchor.biset.md" would otherwise be fetched RELATIVE to the
  // page (file://…/anchor.biset.md, or the app's own origin) — force https.
  const mUrl = /^https?:\/\//i.test(rawMediatorUrl) ? rawMediatorUrl : 'https://' + rawMediatorUrl
  const { sessions } = await import('../context.ts')
  const key = sessions[0]?.account.did ?? ownDid()
  if (!key) throw new Error('no identity to register')
  // ensureDeviceKey re-reads under the lock and returns the FRESH record — so
  // this must not pre-read one of its own to pass in (the stale-snapshot
  // write-back that function's own note describes).
  const rec = await ensureDeviceKey(key)
  const ops = methodOpsFor(key)

  const relayInput = liveRelayInputs(key)
  const gateways = relayInput
    ? ops.gatewayUrls(relayInput.services.map(s => ({ account: { serverUrl: s.serverUrl } })), rec.didCommMediatorUrl)
    : ops.gatewayUrls([], mUrl)

  return withDidLock(key, async () => {
    let fresh = await getDidRecord(key)
    if (!fresh) throw new Error(`no local DID record for ${key}`)
    fresh = await syncDevicePosition(fresh)
    let keyAgreementKeys = await fullKeyAgreementKeys(fresh)
    let mlkemKeyAgreementKeys = await fullMlkemKeyAgreementKeys(fresh)

    // Phase 1: publish current keys (no service yet) so the mediator can
    // resolve this device's key before it's ever asked to encrypt to it.
    const publishedTo = await ops.publishFull(fresh, relayInput, { keyAgreementKeys, mlkemKeyAgreementKeys })
    if (publishedTo === 0) throw new Error('registerWithMediator: no gateway/endpoint accepted the key publish')
    // The MLS Authentication Service answers "is this kid a listed device of
    // that DID" from a cached resolve (mls/authservice.ts). This publish is
    // what makes THIS device listed, so the cached answer is now wrong — and
    // wrong in the one direction that matters: the very next step creates or
    // joins the self group, and the AS would reject this device's own leaf
    // against a document snapshot taken before it existed. That is exactly
    // what happened live (2026-08-13: "self group unavailable at
    // registration: Could not validate credential").
    forgetDevices(fresh.did)

    // Phase 2: mediate-request + keylist-update (method-agnostic protocol —
    // coordinate.ts only needs {did, xKid, xPriv}, either method satisfies it).
    // Mediator authentication itself stays X25519-only — the mediator is a
    // did:peer identity outside this PLAN's scope (PLAN.md §1: this hybrid
    // effort targets did:webvh keyAgreement, not the mediator relationship).
    const mediator = await fetchMediatorInfo(mUrl)
    const ownKid = `${fresh.did}${fresh.didCommOwnKid}`
    const own: DidCommSender = { did: fresh.did, xKid: ownKid, xPriv: hexToBytes(fresh.didCommPrivateKey!), mlkemPriv: fresh.mlkemPrivateKey ? hexToBytes(fresh.mlkemPrivateKey) : undefined }
    await requestMediation(mediator, own)
    await updateKeylist(mediator, own, ownKid, 'add')
    const routingKey = mediator.doc.keyAgreement?.[0]
    if (!routingKey) throw new Error('registerWithMediator: mediator DID doc has no keyAgreement')

    // Join (or create) this identity's MLS self group, now that the mediator
    // knows this device and can act as its Delivery Service. HERE and not in
    // syncDevicePosition, for the reason the keylist prune used to be here
    // too: until Phase 1 published this device's key and Phase 2 registered
    // it, the mediator can neither resolve this device nor answer it.
    //
    // The group is what decides which devices this identity has. It replaced
    // an authoritative keylist prune that itself replaced a gossip merge —
    // and the failure that motivated both is now structurally impossible: a
    // restored device cannot absorb long-dead devices as "siblings", because
    // it does not learn membership from the published document at all.
    //
    // Failure is tolerated. A device that cannot reach its group is still
    // registered and still reachable; only the device LIST waits, and the
    // republish below simply carries what this device already knows.
    const selfGroup = await ensureSelfGroup(mediator, own, await ownKeyPackageFor(fresh)).catch((e: unknown) => {
      console.warn('[mls] self group unavailable at registration:', e instanceof Error ? e.message : e)
      return undefined
    })
    if (selfGroup) {
      keyAgreementKeys = deviceKeysFromGroup(selfGroup, fresh.did)
      mlkemKeyAgreementKeys = mlkemKeysFromGroup(selfGroup, fresh.did)
    }

    // Top up and publish this device's key packages.
    //
    // A key package is how someone ELSE adds this device to a group while it
    // is offline — the asynchronous half of MLS, and the only way an
    // invitation can reach a browser that is closed. Without it a device is
    // invitable only in the seconds it happens to be running, which for a
    // browser is almost never.
    //
    // This is not what the self group uses (a device of ours joins by external
    // commit, needing no key package at all), so it is best-effort: a failure
    // costs invitations, not this registration.
    try {
      // publishKeyPackages transport.ts's own way: an empty publish is a
      // QUERY (mls-ds.ts's own note), so this asks the store how many are
      // left before minting the difference — only the store knows the real
      // count, since a key package is consumed there and this device keeps
      // the private half until a Welcome uses one (mintKeyPackages's note).
      const remaining = await publishKeyPackages(mediator, own, ownKid, [])
      const short = KEY_PACKAGE_POOL_TARGET - remaining
      if (short > 0) {
        const pool = await mintKeyPackages(ownKid, short)
        await publishKeyPackages(mediator, own, ownKid, pool)
      }
    } catch (e) {
      console.warn('[mls] could not publish key packages:', e instanceof Error ? e.message : e)
    }

    // Phase 3: republish with the DIDCommMessaging service added — REPLACING
    // any existing one rather than appending (each MethodOps.publishFull
    // implementation is responsible for that; registering twice must not
    // stack duplicate service entries).
    await ops.publishFull(fresh, relayInput, { keyAgreementKeys, mlkemKeyAgreementKeys, didCommService: { mediatorUrl: mediator.url, routingKey } })

    fresh.didCommMediatorUrl = mediator.url
    fresh.didCommRoutingKey = routingKey
    await storeDidRecord(fresh)
    return { own, mediator }
  })
}

/** Deregister the current identity's device key from its mediator
 * (keylist-update 'remove') AND revoke this device's key from the published
 * DID document — the mediator card's "Log out". Unlike a relay's "Log out",
 * which only forgets local credentials because the account keeps existing
 * server-side regardless, there is no account here to simply stop using: the
 * keyAgreement entry this device published is the only record of it, and
 * this device is the only one who can ever prove it owns that slot to remove
 * it. Skipping this left every logged-out device's key sitting in the
 * document forever — permanent garbage nobody would ever clean up, since
 * nothing else in the system is in a position to.
 *
 * Two things found live, both fixed here:
 *
 * 1. keylist-update can fail — found live, right after a device's own key
 *    had only just propagated and the mediator's own resolve of it still
 *    404'd — and this used to treat that as fatal, aborting BEFORE the local
 *    cleanup + republish ran at all. The document-side removal matters far
 *    more than the mediator-side one (nobody will ever address a kid that's
 *    not in the document any more, so an orphaned keylist entry is inert;
 *    the reverse — gone from the mediator's keylist but still published — is
 *    what actually breaks things), so keylist-update is now best-effort: log
 *    and continue, always reach the republish below regardless.
 *
 * 2. Used to delete didCommMediatorUrl/didCommRoutingKey along with this
 *    device's own key/kid — but those two fields aren't this device's
 *    private state, they're the IDENTITY's one shared mediator (every device
 *    of one identity registers with the same one — send.ts's own note).
 *    `publishCurrentState` decides whether to publish the "didcomm" SERVICE
 *    block at all by checking exactly those two fields on whichever record
 *    happens to run the republish — so clearing them here meant the device
 *    doing its OWN logout would, in the same stroke, drop DIDComm messaging
 *    for the ENTIRE identity out of the document, even with other devices
 *    still live and registered (found live: revoking one device dropped the
 *    "didcomm" service block entirely, breaking every other still-registered
 *    device in one shot). Only this device's own key/kid are cleared now.
 *
 * `identityDid` (a DidRecord's own key, always) defaults to the CURRENT
 * session's/this device's own DID for the mediator card's own "Log out"
 * button, but a caller acting on an identity that's already being logged out
 * elsewhere (left-pane.ts's removeRelayLocally, signing out of an identity's
 * LAST relay) must pass it explicitly — by the time that caller could call
 * this, sessions[] no longer contains the identity being removed, so the
 * implicit lookup would silently resolve to the wrong identity (or none)
 * instead of throwing. */
export async function unregisterFromMediator(identityDid?: string): Promise<void> {
  await ensureMethodOpsLoaded()
  const { sessions } = await import('../context.ts')
  const key = identityDid ?? sessions[0]?.account.did ?? ownDid()
  if (!key) throw new Error('no identity')
  const rec = await getDidRecord(key)
  if (!rec?.didCommMediatorUrl || !rec.didCommPrivateKey || !rec.didCommOwnKid) throw new Error('not registered with a mediator')
  const ownKid = `${rec.did}${rec.didCommOwnKid}`
  console.log('[logout] unregisterFromMediator start', { key, did: rec.did, ownKid, mediatorUrl: rec.didCommMediatorUrl })
  try {
    const mediator = await fetchMediatorInfo(rec.didCommMediatorUrl)
    const own = { did: rec.did, xKid: ownKid, xPriv: hexToBytes(rec.didCommPrivateKey) }
    // Leave the MLS self group FIRST, while this device can still authenticate
    // and still holds its group state.
    //
    // MLS has no way for a member to remove itself — a commit may not remove
    // its own committer (RFC 9420 §12.4, enforced in vendor/clientState.ts) —
    // so this can only be a PROPOSAL, and someone else has to commit it. That
    // is the honest shape of the operation and the code says so rather than
    // pretending the device is gone the moment it asks:
    //
    //   - Another device online now receives the proposal and commits it
    //     immediately (channel.ts's poll loop).
    //   - If this is the LAST device, nobody can. The Delivery Service keeps
    //     the declaration, and the next device to join carries it out
    //     (self-group.ts's applyPendingRemovals). Without that path a sole
    //     device's logout could never take effect at all — it would stay in
    //     the tree, and every restore would add one more dead leaf.
    const stored = await loadGroup(selfGroupIdHex(rec.did))
    if (stored) {
      try {
        await leaveSelfGroup(mediator, own, stored.state)
      } catch (e) {
        console.warn('[logout] could not declare this device gone to its group:', e instanceof Error ? e.message : e)
      }
      // The local group state goes regardless: this device is leaving, and
      // keeping a key schedule it has renounced would only let it keep reading
      // whatever arrives before the removal is committed.
      await deleteGroup(selfGroupIdHex(rec.did)).catch(() => {})
    }
    await updateKeylist(mediator, own, ownKid, 'remove')
    console.log('[logout] keylist-update remove CONFIRMED by mediator for', ownKid)
  } catch (e) {
    // NOT swallowed to a vague warn — this is the exact step whose silent
    // failure left a logged-out device permanently in the mediator's keylist
    // (found live: keylist retained k1..k6 while every doc-side tombstone
    // landed, so keylist-query prune had nothing to prune). Surface the real
    // error and the kid it was for, loudly.
    console.error(`[logout] keylist-update remove FAILED for ${ownKid} — this device stays in the mediator keylist:`, e instanceof Error ? (e.stack ?? e.message) : e)
  }

  // Locked: a concurrent routine republish might already be mid-flight,
  // holding a rec snapshot read before this logout — waiting for the lock
  // means it finishes (and writes back) first, so this delete then applies
  // on top of it instead of racing to be overwritten by it. See store.ts's
  // withDidLock note.
  await withDidLock(key, async () => {
    const fresh = await getDidRecord(key)
    if (!fresh) return
    // Tombstone this kid before clearing it — found live: without this, a
    // logged-out device's OWN kid carried no removal signal at all (only
    // removeDeviceKey's sibling-removal path did), so every OTHER still-
    // active device of this identity kept it cached in ITS OWN
    // didCommSiblingKeys and simply republished it right back on its own
    // next routine boot — the logout looked like it worked here and then
    // silently reappeared from a different device, same class of bug as the
    // sibling-removal one this same tombstone mechanism already fixed.
    delete fresh.didCommOwnKid
    delete fresh.didCommPublicKey
    delete fresh.didCommPrivateKey
    // Same revocation as the X25519 key above — this device's ML-KEM-768 key
    // (if it had one) rides on the same kid/tombstone, per store.ts's
    // didCommMlkemSiblingKeys note.
    delete fresh.mlkemPublicKey
    delete fresh.mlkemPrivateKey
    await storeDidRecord(fresh)
  })

  // Republish now, not just leave it to the next routine cycle — the whole
  // point is that this entry must not sit published a moment longer than
  // necessary. Re-read post-lock, not the pre-lock `rec` above — that
  // snapshot still has this device's own kid/key set (the lock's delete
  // happened to a separately-fetched copy), so publishing from it here
  // would republish the very key this call exists to remove. Must actually
  // land somewhere, or the revoke only ever existed locally — found live:
  // this used to swallow a total publish failure into a console.warn with
  // no way for the caller to know, so a device could "successfully" log out
  // (local state cleared, no error shown) while its key sat published
  // indefinitely, same silent-failure shape removeDeviceKey's own
  // accepted-count check already guards against.
  const fresh = await getDidRecord(key)
  if (!fresh) return
  const accepted = await publishCurrentState(fresh)
  if (accepted === 0) throw new Error('no gateway accepted the revoke — this device\'s key may still be published')
}

/** Removes ONE device's key from the published DID document — the DIDComm
 * card's per-device trash icon. `isSelf` — supplied by the CALLER, which
 * already knows which on-screen row was clicked (left-pane.ts's device list
 * tags every entry when it builds them) — decides whether this delegates to
 * unregisterFromMediator (self-removal: mediator keylist-update + local key
 * cleanup + republish) or removes a sibling from the local cache.
 *
 * Found live: this used to re-derive "is this self" by comparing `kid`
 * against rec.didCommOwnKid — which breaks the moment there's a DUPLICATE
 * entry at the same kid (dht/document.ts's keyAgreementKeysFromHex note on
 * how that happens: a stale sibling-cache entry surviving at the same number
 * a self-heal just claimed). With a duplicate, `kid` alone can't say which
 * of the two on-screen rows was clicked — both share the same string — so
 * clicking the clearly-labeled "not this device" ghost row silently
 * self-logged this device out instead, because its kid happened to match.
 * Trusting the caller's already-disambiguated isSelf instead of re-deriving
 * it from an ambiguous string comparison is the actual fix.
 *
 * A sibling's kid is removed straight out of the local cache and republished
 * immediately WITHOUT an intervening syncDevicePosition resync — otherwise
 * the very next resolve-and-remerge inside the SAME publish would re-absorb
 * the entry straight off the still-stale published document, undoing the
 * removal before it ever reaches the network. publishCurrentState never
 * calls syncDevicePosition itself (only registerWithMediator does, and only
 * once, explicitly) so this concern no longer needs a special skip flag —
 * it's just the normal path.
 *
 * No revocation proof is asked of the caller: whoever holds this identity's
 * root key can already rewrite the whole document unilaterally (this is a
 * targeted removal of that same authority, not a new one) — see PLAN.md's
 * note on why this stays a human-confirmed action rather than an automatic
 * one keyed off mediator inactivity. */
export async function removeDeviceKey(identityDid: string | undefined, kid: string, isSelf: boolean): Promise<void> {
  const { sessions } = await import('../context.ts')
  const key = identityDid ?? sessions[0]?.account.did ?? ownDid()
  if (!key) throw new Error('no identity')
  if (isSelf) return unregisterFromMediator(key)

  // Locked (store.ts's withDidLock): read-check-edit-write as one atomic
  // step relative to any concurrent routine republish — found live, this
  // exact scenario: the routine republish (page boot) reads the record,
  // starts its multi-second network resolve, and THIS delete's
  // read-edit-write completes first; without the shared lock, the routine
  // call's stale (pre-delete) snapshot then finishes and overwrites the
  // deletion when IT saves. Waiting for the lock means it's forced to start
  // (and see) after this delete, not race it.
  // Removing another device is an MLS **Remove commit**, not a cache edit.
  //
  // The difference is the whole reason the self group exists. Editing the
  // local list and republishing only stopped future senders from ADDRESSING
  // that device: its key stayed valid, so anyone still holding a cached
  // document kept encrypting messages it could read. A Remove advances the
  // group's epoch without it, and it cannot read anything sent afterwards no
  // matter what any document says.
  //
  // Two more things still have to happen, because MLS cannot do them: the
  // mediator must stop queueing for that kid (it is not in the group and has
  // no idea what a Remove is), and the document must be republished so
  // senders stop addressing it at all. Neither is what makes the removal
  // effective — they just stop wasted delivery.
  const outcome = await withDidLock(key, async () => {
    const rec = await getDidRecord(key)
    if (!rec) throw new Error('no DID record')
    if (!rec.didCommMediatorUrl || !rec.didCommPrivateKey || !rec.didCommOwnKid) throw new Error('this identity is not registered with a mediator')
    const group = await loadGroup(selfGroupIdHex(rec.did))
    const fullKid = kid.startsWith('did:') ? kid : `${rec.did}${kid}`
    const isMember = !!group && selfGroupDevices(group.state, rec.did).includes(fullKid)

    const mediator = await fetchMediatorInfo(rec.didCommMediatorUrl)
    const own: DidCommSender = { did: rec.did, xKid: `${rec.did}${rec.didCommOwnKid}`, xPriv: hexToBytes(rec.didCommPrivateKey) }

    // A device that is in the group is removed FROM it — that is the part that
    // makes the removal cryptographic.
    //
    // One that is not is still worth removing, and refusing would leave no way
    // to. Registrations outlive the devices that made them: a device whose
    // local storage was cleared, or one that logged out while it could not
    // reach the mediator, leaves a keylist entry nothing else will ever clean
    // up — and an entry there is what keeps a device addressable and its key
    // packages handed out. Eleven such entries had accumulated on one identity
    // by 2026-08-13. So a non-member removal does the half that applies.
    if (isMember) {
      const nextState = await removeDeviceFromSelfGroup(mediator, own, group!.state, fullKid)
      await saveGroup({ ...group!, state: nextState })
    }

    // Best-effort, and deliberately after the commit: a mediator that cannot
    // be told still leaves the removed device unable to READ, which is the
    // part that matters. The keylist entry only costs it deliveries it can do
    // nothing with.
    await updateKeylist(mediator, own, fullKid, 'remove').catch(e => {
      console.warn(`[devices] removed ${fullKid} from the group, but the mediator still lists it:`, e instanceof Error ? e.message : e)
    })
    await storeDidRecord(rec)
    return 'removed' as const
  })
  void outcome

  const rec = await getDidRecord(key)
  if (!rec) throw new Error('no DID record')

  // Withdraw the sibling from the MEDIATOR's keylist too, not just from the
  // document — mandatory now that pruneSiblingsByKeylist treats that keylist
  // as authoritative: a kid the mediator still lists is deemed live and gets
  // re-absorbed as a sibling on the next registration, silently undoing this
  // removal. Without this the trash icon only ever won until the next
  // restore (user-caught 2026-07-27: a sole-device identity kept republishing
  // a long-dead #k4 through repeated logout/restore cycles, because nothing
  // had ever removed it from the keylist — the prune, doing exactly what it
  // was told, kept ruling it alive).
  //
  // Permitted by construction: the mediator's ConnectionStore is keyed by the
  // identity's DID (shared across its devices), not per-device, so any
  // authenticated device of the identity may update the identity's keylist —
  // the same authority this function's header already notes the root key
  // carries over the document. Best-effort: an unreachable mediator must not
  // block the document-side removal, which is the half that actually stops
  // senders addressing the dead device.
  if (rec.didCommMediatorUrl && rec.didCommPrivateKey && rec.didCommOwnKid) {
    try {
      const mediator = await fetchMediatorInfo(rec.didCommMediatorUrl)
      const own: DidCommSender = { did: rec.did, xKid: `${rec.did}${rec.didCommOwnKid}`, xPriv: hexToBytes(rec.didCommPrivateKey) }
      await updateKeylist(mediator, own, `${rec.did}${kid}`, 'remove')
    } catch (e) {
      console.warn('[didcomm-devices] mediator keylist-update remove failed for', kid, '— it may be re-absorbed on a later registration:', e instanceof Error ? e.message : e)
    }
  }

  // Publish must actually land somewhere, or the removal only ever existed
  // locally — found live: a publish that accepts 0 gateways/endpoints doesn't
  // throw on its own (the right default for a routine best-effort republish),
  // but this is a deliberate, user-confirmed action; silently reporting
  // success when nothing reached the network is what let three rapid
  // deletes look like they'd worked while the document never actually
  // changed underneath them.
  const accepted = await publishCurrentState(rec)
  if (accepted === 0) throw new Error('no gateway accepted the update')
}

/** Whether `url` serves a DIDComm mediator (its /.well-known/did.json is a
 * did:peer) rather than a JMAP relay — so the account page can offer a
 * credential-less "Register" instead of Sign up / Log in.
 *
 * 'unknown' means the probe itself failed (network error, CORS, 5xx) — this
 * is NOT the same as a confirmed "not a mediator", and callers must not
 * treat it as one. A transient fetch failure used to silently fall through
 * to relay-apex expansion (expandDualRelay), which for a mediator hostname
 * fabricates nonexistent mail./ap. subdomains and probes those instead. */
export async function isMediatorUrl(url: string): Promise<'mediator' | 'not-mediator' | 'unknown'> {
  const base = (/^https?:\/\//i.test(url) ? url : 'https://' + url).replace(/\/$/, '')
  let resp: Response
  try {
    resp = await fetch(base + '/.well-known/did.json')
  } catch {
    return 'unknown'
  }
  if (!resp.ok) return resp.status >= 500 ? 'unknown' : 'not-mediator'
  try {
    const doc = await resp.json()
    return typeof doc?.id === 'string' && doc.id.startsWith('did:peer:') ? 'mediator' : 'not-mediator'
  } catch {
    return 'unknown'
  }
}
