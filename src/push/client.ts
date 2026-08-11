// Window-side half of Web Push: register the Service Worker, subscribe/
// unsubscribe PushManager, and register the resulting subscription with every
// relay the identity has an account on (see push/api.ts and sw.ts for the
// other halves). Kept separate from left-pane.ts so the notif-toggle handler
// there stays a thin caller.

import { sessions, isDidCommRelay } from '../context.ts'
import { registerMediatorPush, unregisterMediatorPush, mediatorVapidPublicKey, pokeDidCommPoll, setDidCommPushArmed } from '../did/didcomm/channel.ts'
import * as idb from '../store/idb.ts'
import { SW_KEYS } from './shared.ts'
import { postPushSubscribe, postPushUnsubscribe, fetchVapidPublicKey, urlBase64ToUint8Array } from './api.ts'

let swReg: ServiceWorkerRegistration | null = null

async function getRegistration(): Promise<ServiceWorkerRegistration | null> {
  if (!('serviceWorker' in navigator)) return null
  if (swReg) { swReg.update().catch(() => {}); return swReg }
  try {
    swReg = await navigator.serviceWorker.register('/sw.js')
    // Force an immediate update check on every boot. register() alone reuses
    // an existing registration and may not re-fetch sw.js within the browser's
    // update-throttle window — an explicit update(), against the no-cache
    // headers the relay now sends, guarantees a new sw.js is picked up and
    // (via skipWaiting/clients.claim in sw.ts) activated right away, instead of
    // a fix sitting undeployed on a sticky iOS PWA worker for hours.
    swReg.update().catch(() => {})
  } catch { return null }
  return swReg
}

// JMAP relays only. The DIDComm channel appears in `sessions` as a synthetic
// entry with no HTTP endpoint behind it (channel.ts's ensureDidCommSession) —
// it registers for push over DIDComm instead, further down.
function uniqueRelaySessions() {
  const seen = new Set<string>()
  return sessions.filter(s => {
    if (isDidCommRelay(s.account.serverUrl)) return false
    if (seen.has(s.account.serverUrl)) return false
    seen.add(s.account.serverUrl)
    return true
  })
}

/** This client holds exactly one identity (context.ts's "one client session =
 * one identity"), so any session names its DID. */
function activeDid(): string | null {
  return sessions.find(s => s.account.did)?.account.did ?? null
}

// Idempotent: safe to call on every boot where the notif toggle is already on
// (see syncNotifToggle), not just right after the user flips it — a no-op if
// already subscribed, and self-healing if a relay lost the registration
// (e.g. it restarted before SetPersistDir was wired up, or push_subs.json
// was cleared) or if the OS dropped the subscription while the app was closed
// (Safari never fires pushsubscriptionchange, so this boot-time re-subscribe
// is the only recovery path there).
//
// Returns false when the identity ends up with no relay registration at all —
// every subscribe POST having failed used to be indistinguishable from success,
// leaving the toggle on and no push ever arriving.
export async function enablePush(): Promise<boolean> {
  const reg = await getRegistration()
  if (!reg) { console.warn('[push] no SW registration — skipping'); return false }
  if (!sessions.length) { console.warn('[push] no sessions yet — skipping'); return false }
  const did = activeDid()
  let sub = await reg.pushManager.getSubscription()
  if (!sub) {
    // Every relay serving this identity is expected to share the same VAPID
    // keypair (see go-jmapserver/ARC.md) — but during a staggered rollout one
    // relay may not have it configured yet, so try each until one answers
    // rather than only trusting sessions[0]. The DIDComm mediator is
    // configured with that SAME keypair (it has to be — one Service Worker
    // registration, one subscription, one applicationServerKey), so it is a
    // valid source for the key too, and the only one a relay-less identity has.
    let publicKey = ''
    for (const s of uniqueRelaySessions()) {
      publicKey = await fetchVapidPublicKey(s.account.serverUrl)
      if (publicKey) break
    }
    if (!publicKey && did) {
      publicKey = await mediatorVapidPublicKey(did).catch(() => '')
    }
    if (!publicKey) { console.warn('[push] no relay or mediator has VAPID keys configured — skipping'); return false }
    try {
      sub = await reg.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: urlBase64ToUint8Array(publicKey) as BufferSource,
      })
    } catch (e) { console.warn('[push] subscribe failed', e); return false }
  }
  const json = sub.toJSON() as { endpoint: string; keys: { p256dh: string; auth: string } }
  const [relayResults, mediatorOk] = await Promise.all([
    Promise.all(uniqueRelaySessions().map(s =>
      postPushSubscribe(s.account.serverUrl, s.account.email, s.account.password, json)
        .then(() => true)
        .catch(e => { console.warn('[push] subscribe registration failed', s.account.serverUrl, e); return false })
    )),
    // The mediator holds the same subscription against this device's kid, so
    // a DIDComm message queued for it wakes the browser. Without this an
    // identity whose conversations run over DIDComm gets no notification at
    // all, however well the relay side works.
    did
      ? registerMediatorPush(did, json).catch(e => { console.warn('[push] mediator registration failed', e); return false })
      : Promise.resolve(false),
  ])
  // Only the mediator's answer decides the DIDComm poll cadence: with it, a
  // push arrives the moment something is queued and the timer is just a
  // backstop; without it, that timer is the only way anything is ever
  // collected and must stay fast.
  setDidCommPushArmed(mediatorOk)
  return relayResults.some(Boolean) || mediatorOk
}

export async function disablePush(): Promise<void> {
  const reg = swReg ?? (('serviceWorker' in navigator) ? await navigator.serviceWorker.getRegistration() ?? null : null)
  if (!reg) return
  const sub = await reg.pushManager.getSubscription()
  if (!sub) return
  const endpoint = sub.endpoint
  for (const s of uniqueRelaySessions()) {
    postPushUnsubscribe(s.account.serverUrl, s.account.email, s.account.password, endpoint).catch(() => {})
  }
  const did = activeDid()
  if (did) unregisterMediatorPush(did, endpoint).catch(() => {})
  setDidCommPushArmed(false)
  await sub.unsubscribe().catch(() => {})
}

// Which conversation the window is showing, as a permalink hash (utils.ts's
// inboxToHash), or null for anything else — a menu page, or a hidden tab.
// The Service Worker reads this to skip notifying for the thread the user is
// literally looking at; that check is the only reason it exists, and it is
// paired there with a "is any window actually focused" test, so a stale record
// left by a closed window suppresses nothing.
export function setActiveConversation(hash: string | null): void {
  idb.put(idb.STORES.accounts, hash ?? '', SW_KEYS.activeView).catch(() => {})
}

/** Publishes the window's unread count, split the way the Service Worker
 * rebuilds the badge (sw.ts): it can recompute the JMAP half itself and
 * prefers to, but has no way to see the DIDComm half and no way to recover the
 * JMAP half when a relay is unreachable. Called wherever the window computes
 * the badge, so the two sides stay one number rather than two answers that
 * overwrite each other. */
export function publishUnreadCounts(jmap: number, didcomm: number): void {
  idb.put(idb.STORES.accounts, jmap, SW_KEYS.localJmapUnread).catch(() => {})
  idb.put(idb.STORES.accounts, didcomm, SW_KEYS.localDidcommUnread).catch(() => {})
}

// The two things the Service Worker tells an open page about.
//
//   biset:open    — a notification was tapped. Focus is already handled there;
//                   this carries which conversation to show. Writing
//                   location.hash re-enters main.ts's existing hashchange
//                   router, so no separate navigation path is needed
//                   (WindowClient.navigate() is not dependable across engines).
//   biset:didcomm — the mediator has queued something. The worker can't collect
//                   it (no DIDComm crypto there, deliberately), but this page
//                   can: pick up immediately instead of waiting for the poll
//                   timer, which is what lets that timer be a slow backstop.
export function listenForServiceWorkerMessages(): void {
  if (!('serviceWorker' in navigator)) return
  navigator.serviceWorker.addEventListener('message', (event: MessageEvent) => {
    const data = event.data as { type?: string; hash?: string } | undefined
    if (data?.type === 'biset:didcomm') { pokeDidCommPoll(); return }
    if (data?.type !== 'biset:open' || !data.hash) return
    if (location.hash === data.hash) window.dispatchEvent(new HashChangeEvent('hashchange'))
    else location.hash = data.hash
  })
}
