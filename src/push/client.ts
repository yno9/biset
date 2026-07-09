// Window-side half of Web Push: register the Service Worker, subscribe/
// unsubscribe PushManager, and register the resulting subscription with every
// relay the identity has an account on (see push/api.ts and sw.ts for the
// other halves). Kept separate from left-pane.ts so the notif-toggle handler
// there stays a thin caller.

import { sessions } from '../context.ts'
import { postPushSubscribe, postPushUnsubscribe, fetchVapidPublicKey, urlBase64ToUint8Array } from './api.ts'

let swReg: ServiceWorkerRegistration | null = null

async function getRegistration(): Promise<ServiceWorkerRegistration | null> {
  if (!('serviceWorker' in navigator)) return null
  if (swReg) return swReg
  try { swReg = await navigator.serviceWorker.register('/sw.js') } catch { return null }
  return swReg
}

function uniqueRelaySessions() {
  const seen = new Set<string>()
  return sessions.filter(s => {
    if (seen.has(s.account.serverUrl)) return false
    seen.add(s.account.serverUrl)
    return true
  })
}

// Idempotent: safe to call on every boot where the notif toggle is already on
// (see syncNotifToggle), not just right after the user flips it — a no-op if
// already subscribed, and self-healing if a relay lost the registration
// (e.g. it restarted before SetPersistDir was wired up, or push_subs.json
// was cleared).
export async function enablePush(): Promise<void> {
  const reg = await getRegistration()
  if (!reg) { console.warn('[push] no SW registration — skipping'); return }
  if (!sessions.length) { console.warn('[push] no sessions yet — skipping'); return }
  let sub = await reg.pushManager.getSubscription()
  if (!sub) {
    // Every relay serving this identity is expected to share the same VAPID
    // keypair (see go-jmapserver/ARC.md) — but during a staggered rollout one
    // relay may not have it configured yet, so try each until one answers
    // rather than only trusting sessions[0].
    let publicKey = ''
    for (const s of uniqueRelaySessions()) {
      publicKey = await fetchVapidPublicKey(s.account.serverUrl)
      if (publicKey) break
    }
    if (!publicKey) { console.warn('[push] no relay has VAPID keys configured — skipping'); return }
    try {
      sub = await reg.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: urlBase64ToUint8Array(publicKey) as BufferSource,
      })
    } catch (e) { console.warn('[push] subscribe failed', e); return }
  }
  const json = sub.toJSON() as { endpoint: string; keys: { p256dh: string; auth: string } }
  for (const s of uniqueRelaySessions()) {
    postPushSubscribe(s.account.serverUrl, s.account.email, s.account.password, json).catch(() => {})
  }
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
  await sub.unsubscribe().catch(() => {})
}
