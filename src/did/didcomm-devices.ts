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
import { kidN, keyAgreementKeysFromHex, type DidKeyAgreement } from './dht/document.ts'
import type { DidMlkemKeyAgreement } from './webvh/document.ts'
import { relaysForId, isApRelay, isDidCommRelay } from '../context.ts'
import * as identityStore from '../store/identities.ts'
import { fetchMediatorInfo, requestMediation, updateKeylist, queryKeylist, type MediatorInfo } from './didcomm/coordinate.ts'
import type { DidCommSender } from './didcomm/message.ts'
import { hexToBytes } from '../utils.ts'

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
  removedKeyNs?: number[]
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
    removedKeyNs?: number[]
  } | null>
  resolveConfirmedAbsent(did: string, gatewayUrls: string[]): Promise<boolean>
  gatewayUrls(relaySessions: Array<{ account: { serverUrl: string } }>, mediatorUrl?: string): string[]
  publishFull(rec: DidRecord, relayInput: RelayInput | null, opts: PublishFullOpts): Promise<number>
}

// Cached after first resolution — dynamic-import-backed purely to break the
// module-init cycle (dht/method-ops.ts and webvh/method-ops.ts both import
// TYPES from this file; this file needs their concrete implementations),
// not to defer work on every call. Every exported function below calls
// ensureMethodOpsLoaded() first; it's cheap after the first call since the
// module cache short-circuits every subsequent import().
let dhtOps: MethodOps | undefined
let webvhOps: MethodOps | undefined
let methodOpsLoaded: Promise<void> | undefined
async function ensureMethodOpsLoaded(): Promise<void> {
  if (!methodOpsLoaded) {
    methodOpsLoaded = Promise.all([
      import('./dht/method-ops.ts').then(m => { dhtOps = m.dhtMethodOps }),
      import('./webvh/method-ops.ts').then(m => { webvhOps = m.webvhMethodOps }),
    ]).then(() => {})
  }
  await methodOpsLoaded
}

function methodOpsFor(did: string): MethodOps {
  const ops = did.startsWith('did:webvh:') ? webvhOps : dhtOps
  if (!ops) throw new Error('didcomm-devices: MethodOps not yet loaded — this indicates a bug (every exported function awaits ensureMethodOpsLoaded() first)')
  return ops
}

// ── device slot / sibling sync (method-agnostic) ────────────────────────────

/** Establishes this device's stable positional slot and refreshes the sibling
 * cache, by resolving whatever document is currently published (best-effort —
 * a resolve failure just means this call learns nothing new, safe to retry
 * later). Establishes `didCommOwnKid` once (kept stable afterward); safe to
 * call again and again to pick up devices registered elsewhere since — and,
 * on a resolve that actually succeeds, to drop a device that's been
 * legitimately REVOKED (unregisterFromMediator) too: the cache is REPLACED
 * with whatever a successful resolve returns, not merged with what was
 * there before, so a revoke actually sticks instead of getting silently
 * restored by the next device that still remembers it. A resolve that
 * fails outright changes nothing (no fresher information to replace the
 * cache with), which is what makes repeating this safe — a transient outage
 * can't be mistaken for "everyone else disappeared". Exported: dht/publish.ts's
 * buildOwnDocument calls this on every routine republish now, not just once
 * at registration — see that file's own note on why skipping it was a real
 * bug, not just an approximation. */
export async function syncDevicePosition(rec: DidRecord, gatewayUrls: string[]): Promise<DidRecord> {
  await ensureMethodOpsLoaded()
  const ops = methodOpsFor(rec.did)
  let resolved: { keyAgreementKeys: DidKeyAgreement[]; mlkemKeyAgreementKeys?: DidMlkemKeyAgreement[]; removedKeyNs?: number[] } | null = null
  // skipCache semantics are the implementation's own concern — this function's
  // whole job is establishing ground truth for slot assignment (the
  // `!rec.didCommOwnKid` branch below) — found live, a new device registering
  // within a resolve cache's window of ANY earlier resolve (a routine poll,
  // another device's sync, anything) picked a slot number from THAT stale
  // snapshot's highest-seen `n`, silently REUSING a number a since-retired
  // device had already vacated. Numbers being permanent and never reused is
  // the one invariant the whole removal/tombstone system (removedKeyNs)
  // depends on — a cache-induced reuse collides two unrelated devices'
  // history onto the same kid and corrupts it irrecoverably, unlike ordinary
  // sibling-list staleness which just self-corrects on the next sync.
  try { resolved = await ops.resolveKeyAgreement(rec.did, gatewayUrls) } catch { /* best-effort */ }
  const existing = resolved?.keyAgreementKeys ?? []

  if (!rec.didCommOwnKid) {
    // A failed resolve here (null) is NOT the same as "this identity has
    // never published anything" — it's just as likely a rate-limited or
    // CORS-blocked gateway telling us nothing. Assuming the latter used to
    // default nextN to 1 unconditionally — found live: a brand-new device
    // registered during a relay.pkarr.org 429/CORS spell, silently claimed
    // slot #k1 as if the identity were fresh, and stomped another device's
    // already-live #k1 (that device only found out on its own next sync,
    // self-healing onto yet another number — see the `else if` branch below
    // — a visible, confusing slot-number game of musical chairs). Only
    // proceed past a failed resolve when confirmed absent (genuinely nothing
    // published, safe to start at #k1). Otherwise refuse to guess: throw, so
    // the registration attempt fails visibly and can be retried once the
    // network is actually healthy, instead of silently corrupting slot
    // assignment.
    if (!resolved && !(await ops.resolveConfirmedAbsent(rec.did, gatewayUrls).catch(() => false))) {
      throw new Error('cannot assign a device slot: this identity\'s DID document is unreachable right now (network error or every gateway rate-limited) — try again shortly')
    }
    // Already published under this exact key (this device registered before,
    // record survived, but didCommOwnKid was never set — e.g. a pre-multi-
    // device record)? Reuse that slot instead of taking a new one.
    const mine = existing.find(k => bytesToHex(k.publicKey) === rec.didCommPublicKey)
    // Numbers must never be reused even once every LIVE entry is gone (the
    // sole-device "register, log out, restore" cycle empties `existing`
    // entirely) — this used to compute nextN from `existing` alone, so an
    // identity with zero currently-published keys always restarted at #k1,
    // silently reassigning a genuinely-retired number to a brand-new key.
    // The mediator's own resolved-key cache keys purely by kid string and
    // treats a kid as a permanently stable key once seen (server.ts's
    // resolveViaCache, "biset's keys are rotation-less ... safe to cache") —
    // reusing a number while that cache entry is still warm hands a
    // DIFFERENT key the SAME kid, so the mediator derives ECDH against the
    // stale cached key and every subsequent authcrypt to/from this device
    // fails AEAD decryption ("integrity check failed") until the cache
    // entry ages out. `removedKeyNs` (published in the document specifically
    // to make this permanent, this function's own comment above) is exactly
    // the tombstone that closes this — reproduced live (2026-07-27) via
    // register → log out → restore on a single-device identity.
    const usedNs = [...existing.map(k => k.n), ...(resolved?.removedKeyNs ?? [])]
    const nextN = usedNs.length ? Math.max(...usedNs) + 1 : 1
    rec.didCommOwnKid = mine ? `#k${mine.n}` : `#k${nextN}`
  } else if (resolved) {
    // The slot this device already claims might not actually be OURS on the
    // network any more — found live: a device whose local didCommOwnKid/
    // didCommPublicKey had drifted from what's published at that slot (root
    // cause unclear — plausibly a failed resolve at some earlier registration
    // defaulted to #k1 while another device already legitimately held it, per
    // the note below on that exact race). The mediator and every sender only
    // ever trust the PUBLISHED key for a kid, never what a device claims
    // locally — so a mismatch here means this device can never decrypt
    // anything addressed to "its own" kid, silently and permanently, no
    // matter how many times it re-registers under the same wrong slot.
    // Self-heal by disowning the slot and taking a fresh one, exactly like a
    // brand-new device would — only when `resolved` is non-null (a resolve
    // that failed must not be read as "the slot doesn't exist", which would
    // make this fire on every transient network hiccup and reassign kids
    // that were never actually wrong).
    const myN = kidN(rec.didCommOwnKid)
    const published = existing.find(k => k.n === myN)
    if (published && bytesToHex(published.publicKey) !== rec.didCommPublicKey) {
      const nextN = Math.max(...existing.map(k => k.n)) + 1
      rec.didCommOwnKid = `#k${nextN}`
    }
  }
  const myN = kidN(rec.didCommOwnKid)

  // REVERTED to grow-only (never remove an entry, only ever add) — a
  // "replace with whatever a successful resolve returns" version of this
  // was live briefly and caused real, near-unrecoverable damage: a resolve
  // can return a validly-signed payload and STILL not reflect every other
  // device — mid-propagation, an incomplete gateway list at that specific
  // call, a race right after a fresh registration hasn't reached every
  // gateway yet — "the request succeeded" is not the same guarantee as
  // "this is the complete, current truth," and trusting it as such let one
  // device's ordinary republish wipe two other real, live devices' keys off
  // the document in one shot. Silently resurrecting a revoked device (the
  // problem this was trying to solve) is a real but recoverable annoyance;
  // silently destroying a live device's key is not. Revocation needs a
  // design that can't fail this way — not resolved here — so it stays a
  // known gap: `unregisterFromMediator` removes a device from the document
  // at the moment it runs, but another device's stale sibling cache can
  // still bring it back on its own next republish, same as before this file
  // ever mentioned replace-on-success.
  // Union of what THIS device has ever removed and what the resolved
  // document's own removed-key field carries — the latter is how a removal
  // performed on a DIFFERENT device of this same identity reaches this one:
  // without it, this device's own local didCommSiblingKeys cache (seeded
  // below) would just keep re-affirming a slot every OTHER device already
  // agreed is gone, since grow-only alone has no way to un-learn something
  // purely from a resolve going quiet on it.
  const removed = new Set([...(rec.didCommRemovedKeys ?? []), ...(resolved?.removedKeyNs ?? []).map(n => `#k${n}`)])
  // Never let THIS device's own kid end up in its own removed set — found
  // live: another device's bulk removal (e.g. from the devices-list trash
  // icon) can legitimately include a kid that's actually still live, and
  // the removed-key field propagates that to every device INCLUDING the one
  // it names. Every OTHER device forgives it the moment it sees that kid
  // still present in `existing` (below) — but that forgive check is inside
  // the `k.n === myN` branch's `continue`, which skips itself before ever
  // reaching it, so THIS device could never forgive an entry naming its own
  // kid. Once poisoned it stayed poisoned forever: every future sync
  // re-absorbed it right back from rec.didCommRemovedKeys, and every
  // republish broadcast the removal for its own kid to everyone else.
  // Self-removal has its own correct path (unregisterFromMediator clears
  // didCommOwnKid entirely) — this set must never be how it happens.
  removed.delete(`#k${myN}`)
  // Filtered on the way IN too, not just when adding — a removal learned only
  // just now must also evict whatever this device already had cached locally
  // from before it heard about it. Also strips any STALE entry at this
  // device's OWN (possibly just-self-healed) kid — found live: self-heal
  // above only ever changes didCommOwnKid, never touches didCommSiblingKeys,
  // so a device that renamed itself onto a number its own cache still
  // remembered as some OTHER (ghost) device's slot ended up publishing BOTH
  // — two keyAgreementKeys entries at the same `n`, visibly duplicated in
  // left-pane.ts's device list and ambiguous on the wire
  // (dht/document.ts's keyAgreementKeysFromHex now also dedupes defensively,
  // but the stale entry has no business surviving in this device's own
  // cache at all once it's the one sitting at that slot).
  const myKid = `#k${myN}`
  const siblingMap = new Map(
    (rec.didCommSiblingKeys ?? []).filter(s => !removed.has(s.kid) && s.kid !== myKid).map(s => [s.kid, s]),
  )
  for (const k of existing) {
    if (k.n === myN) continue // that's us, not a sibling
    const kid = `#k${k.n}`
    if (removed.has(kid)) {
      // Tombstoned, but it just showed up again in a freshly resolved,
      // validly-signed document — proof it's actually still alive, not the
      // ghost the removal assumed (found live: a device deliberately removed
      // for looking dead kept legitimately republishing itself; the
      // tombstone, once it also started propagating, made every device
      // permanently blind to it regardless). Forgive: a removal only needs
      // to survive long enough that a stale snapshot from right around the
      // delete can't immediately undo it (withDidLock + this removal wave
      // already cover that window) — it was never meant to out-rank the
      // removed device proving itself alive afterward, or "recoverable
      // annoyance" stops being recoverable.
      removed.delete(kid)
    }
    siblingMap.set(kid, { kid, publicKey: bytesToHex(k.publicKey) })
  }

  rec.didCommSiblingKeys = [...siblingMap.values()]
  // Carry the union forward: this device now also knows about anything it
  // just learned, so ITS next publish keeps propagating the full removed
  // set too — the same gossip-by-republish mechanism siblings already use
  // to learn about each other, applied to removals.
  rec.didCommRemovedKeys = [...removed]
  // Authoritative prune (below) on whatever mediator this device already
  // knows about. A device registering for the FIRST time on this install
  // has none yet — registerWithMediator runs its own prune pass once Phase 2
  // has made this device queryable, see that function.
  await pruneSiblingsByKeylist(rec, rec.didCommMediatorUrl ?? '')

  // ML-KEM-768 siblings (PLAN.md "did:webvh PQハイブリッド化" Phase 1) — rides
  // entirely on the X25519 decision just above (post-prune, so a sibling the
  // keylist-prune just dropped doesn't get its ML-KEM key resurrected here).
  syncMlkemSiblings(rec, resolved?.mlkemKeyAgreementKeys)

  await storeDidRecord(rec)
  return rec
}

/** Keeps didCommMlkemSiblingKeys in sync with whatever the X25519 side (this
 * device's own kid + didCommSiblingKeys) just decided is live, merging in any
 * newly-resolved ML-KEM-768 keys. Called after EVERY point that can change
 * the X25519 live set (syncDevicePosition's merge above, and
 * registerWithMediator's own authoritative prune below) so the two can't
 * drift apart. See store.ts's didCommMlkemSiblingKeys note on why this rides
 * on the X25519 decision rather than keeping independent tombstone state:
 * an `n` that's a live X25519 sibling (or this device's own) MAY also carry
 * a ML-KEM-768 entry — one that isn't never does, even if a stale
 * `freshlyResolved` still lists it. */
function syncMlkemSiblings(rec: DidRecord, freshlyResolved?: DidMlkemKeyAgreement[]): void {
  const myN = rec.didCommOwnKid ? kidN(rec.didCommOwnKid) : undefined
  const liveNs = new Set([myN, ...(rec.didCommSiblingKeys ?? []).map(s => kidN(s.kid))])
  const map = new Map(
    (rec.didCommMlkemSiblingKeys ?? []).filter(k => k.n !== myN && liveNs.has(k.n)).map(k => [k.n, k]),
  )
  for (const k of freshlyResolved ?? []) {
    if (k.n === myN || !liveNs.has(k.n)) continue
    map.set(k.n, { n: k.n, publicKey: bytesToHex(k.publicKey) })
  }
  rec.didCommMlkemSiblingKeys = [...map.values()]
}

/** AUTHORITATIVE removal via the mediator's keylist — the backstop that makes
 * a logout actually converge. syncDevicePosition's merge above is gossip: each
 * device merges its own cache with a resolved snapshot and republishes the
 * union, highest-seq/version-wins. That can never reliably REMOVE anything — a
 * device still holding a pre-logout snapshot (mid poll/republish cycle)
 * re-publishes the removed key right back, and the `forgive` step above then
 * sees it "alive" and un-tombstones it everywhere (found live: a logged-out
 * #k1 kept reappearing with its tombstone silently dropped, because a sibling
 * republished the stale set after the logout landed). The mediator's keylist
 * is not gossip: a logout's keylist-update remove reaches it directly and
 * point-to-point, no last-writer-wins race. So a sibling the mediator no
 * longer lists is authoritatively gone — drop it from the published keys AND
 * tombstone it, regardless of what the resolved document or this device's
 * cache still claims, overriding the forgive above.
 *
 * Best-effort and fail-CLOSED-toward-safety: a query that can't be made (no
 * mediator, missing local key, network/transport error) prunes NOTHING —
 * "couldn't ask" must never read as "zero live devices", same principle as
 * resolveConfirmedAbsent. Never prunes this device's own kid. Returns whether
 * anything actually changed, so a caller that already computed a key list from
 * `rec` knows to recompute it.
 *
 * Extracted from syncDevicePosition (2026-07-27) precisely so registerWithMediator
 * can run the SAME pass at a point syncDevicePosition structurally cannot: this
 * whole check needs a mediator that can already authenticate us, and on a fresh
 * restore neither is true when syncDevicePosition runs — didCommMediatorUrl
 * isn't stored until registration completes, and this device's key isn't
 * published until Phase 1. Two copies of this logic would be exactly the kind
 * of divergence one shared function exists to prevent. */
async function pruneSiblingsByKeylist(rec: DidRecord, mediatorUrl: string): Promise<boolean> {
  if (!mediatorUrl || !rec.didCommPrivateKey || !rec.didCommOwnKid) return false
  const myKid = rec.didCommOwnKid
  try {
    const mediator = await fetchMediatorInfo(mediatorUrl)
    const own = { did: rec.did, xKid: `${rec.did}${myKid}`, xPriv: hexToBytes(rec.didCommPrivateKey) }
    const live = new Set(queryKeylistToLocalKids((await queryKeylist(mediator, own)).map(e => e.kid)))
    const removed = new Set(rec.didCommRemovedKeys ?? [])
    const kept: NonNullable<DidRecord['didCommSiblingKeys']> = []
    let changed = false
    for (const s of rec.didCommSiblingKeys ?? []) {
      if (s.kid !== myKid && !live.has(s.kid)) {
        removed.add(s.kid) // propagate the removal too, for anyone who can't query
        changed = true
        continue
      }
      kept.push(s)
    }
    if (!changed) return false
    rec.didCommSiblingKeys = kept
    rec.didCommRemovedKeys = [...removed]
    return true
  } catch (e) {
    // Fail closed: keep whatever the gossip merge produced, prune nothing.
    console.warn('[didcomm-devices] keylist-query prune skipped (continuing with gossip-only view):', e instanceof Error ? e.message : e)
    return false
  }
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

/** This device's own entry + every known sibling's, as the array a document
 * publish carries — reads purely from the cached record (no resolve here —
 * see MethodOps.publishFull's own note on why a routine publish doesn't
 * resolve). Method-agnostic: `#k<n>` kid numbering is shared by both
 * did:dht (dht/document.ts's DidKeyAgreement) and did:webvh
 * (webvh/document.ts's webvhKeyAgreementId), so keyAgreementKeysFromHex
 * (dht/document.ts) applies unchanged to either. */
function fullKeyAgreementKeys(rec: DidRecord): DidKeyAgreement[] {
  return keyAgreementKeysFromHex(
    rec.didCommPublicKey && rec.didCommOwnKid ? { kid: rec.didCommOwnKid, publicKeyHex: rec.didCommPublicKey } : null,
    (rec.didCommSiblingKeys ?? []).map(s => ({ kid: s.kid, publicKeyHex: s.publicKey })),
  )
}

/** ML-KEM-768 counterpart of fullKeyAgreementKeys — this device's own entry
 * (if it has minted one, did:webvh only) plus every sibling's cached one.
 * did:dht callers naturally get an empty array (mlkemPublicKey/
 * didCommMlkemSiblingKeys are never set for that method — ensureDeviceKey's
 * `did.startsWith('did:webvh:')` gate), which dht/method-ops.ts's publishFull
 * ignores anyway. */
function fullMlkemKeyAgreementKeys(rec: DidRecord): DidMlkemKeyAgreement[] {
  const out: DidMlkemKeyAgreement[] = []
  if (rec.mlkemPublicKey && rec.didCommOwnKid) out.push({ n: kidN(rec.didCommOwnKid), publicKey: hexToBytes(rec.mlkemPublicKey) })
  for (const k of rec.didCommMlkemSiblingKeys ?? []) out.push({ n: k.n, publicKey: hexToBytes(k.publicKey) })
  return out
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
    rec = await syncDevicePosition(rec, gateways).catch(() => rec)
  }
  const removedKeyNs = rec.didCommRemovedKeys?.length ? rec.didCommRemovedKeys.map(kidN) : undefined
  const keyAgreementKeys = fullKeyAgreementKeys(rec)
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
  const didCommService = keyAgreementKeys.length && rec.didCommMediatorUrl && rec.didCommRoutingKey
    ? { mediatorUrl: rec.didCommMediatorUrl, routingKey: rec.didCommRoutingKey } : undefined
  return ops.publishFull(rec, relayInput, {
    keyAgreementKeys, mlkemKeyAgreementKeys: fullMlkemKeyAgreementKeys(rec),
    removedKeyNs, didCommService, removeDidCommService: keyAgreementKeys.length === 0,
  })
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
    fresh = await syncDevicePosition(fresh, gateways)
    let keyAgreementKeys = fullKeyAgreementKeys(fresh)
    let mlkemKeyAgreementKeys = fullMlkemKeyAgreementKeys(fresh)

    // Phase 1: publish current keys (no service yet) so the mediator can
    // resolve this device's key before it's ever asked to encrypt to it.
    const publishedTo = await ops.publishFull(fresh, relayInput, { keyAgreementKeys, mlkemKeyAgreementKeys })
    if (publishedTo === 0) throw new Error('registerWithMediator: no gateway/endpoint accepted the key publish')

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

    // Authoritative prune, HERE and not inside syncDevicePosition above —
    // this is the first moment it's possible at all on a fresh install:
    // pruneSiblingsByKeylist needs a mediator that can authenticate us, and
    // until Phase 1 published this device's key and Phase 2 registered it,
    // the mediator can neither resolve our sender key nor answer a
    // keylist-query from us. syncDevicePosition additionally has no
    // didCommMediatorUrl to work from yet (it's only stored below, once
    // registration succeeds), so its own prune call no-ops on a restore.
    // Without this pass a restored device absorbed every key still published
    // — including ones a previous logout had already removed from the
    // mediator's keylist — as a "sibling" via the grow-only gossip merge,
    // then republished them in Phase 3, permanently resurrecting a dead
    // device slot (user-caught 2026-07-27: a sole-device identity whose
    // document listed both #k4 and #k8 after a logout/restore cycle).
    if (await pruneSiblingsByKeylist(fresh, mediator.url)) {
      keyAgreementKeys = fullKeyAgreementKeys(fresh)
      syncMlkemSiblings(fresh) // keep didCommMlkemSiblingKeys from drifting off the pruned X25519 set
      mlkemKeyAgreementKeys = fullMlkemKeyAgreementKeys(fresh)
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
    if (fresh.didCommOwnKid) {
      fresh.didCommRemovedKeys = [...new Set([...(fresh.didCommRemovedKeys ?? []), fresh.didCommOwnKid])]
    }
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
  const outcome = await withDidLock(key, async () => {
    const rec = await getDidRecord(key)
    if (!rec) throw new Error('no DID record')
    const before = rec.didCommSiblingKeys ?? []
    const after = before.filter(s => s.kid !== kid)
    if (after.length === before.length) return 'noop' as const
    rec.didCommSiblingKeys = after
    // Tombstoned BEFORE the publish below, not after: syncDevicePosition
    // checks this set on the very next resolve (including one triggered
    // elsewhere), so it has to be in place before any resolve can happen,
    // not just before this function returns.
    rec.didCommRemovedKeys = [...new Set([...(rec.didCommRemovedKeys ?? []), kid])]
    // Drop the ML-KEM-768 sibling at the same slot too, if there was one —
    // syncMlkemSiblings would filter it out on the very next sync anyway
    // (its `n` no longer being in didCommSiblingKeys), but doing it here
    // keeps the two fields consistent without waiting for that.
    rec.didCommMlkemSiblingKeys = (rec.didCommMlkemSiblingKeys ?? []).filter(k => k.n !== kidN(kid))
    await storeDidRecord(rec)
    return 'removed' as const
  })
  if (outcome === 'noop') return

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
