// Shared by both the main app (subscribe/unsubscribe UI, left-pane.ts) and the
// Service Worker (sw.ts, pushsubscriptionchange) — kept in one place so the
// wire format to go-jmapserver's /jmap/push/* endpoints can't drift between
// the two call sites.

export interface PushSubscriptionJSON {
  endpoint: string
  keys: { p256dh: string; auth: string }
}

function authHeader(email: string, password: string): string {
  return 'Basic ' + btoa(email + ':' + password)
}

export async function postPushSubscribe(serverUrl: string, email: string, password: string, sub: PushSubscriptionJSON): Promise<void> {
  await fetch(serverUrl.replace(/\/$/, '') + '/jmap/push/subscribe', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: authHeader(email, password) },
    body: JSON.stringify(sub),
  })
}

export async function postPushUnsubscribe(serverUrl: string, email: string, password: string, endpoint: string): Promise<void> {
  await fetch(serverUrl.replace(/\/$/, '') + '/jmap/push/unsubscribe', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: authHeader(email, password) },
    body: JSON.stringify({ endpoint }),
  })
}

export async function fetchVapidPublicKey(serverUrl: string): Promise<string> {
  const res = await fetch(serverUrl.replace(/\/$/, '') + '/jmap/push/vapid-public-key')
  if (!res.ok) return ''
  return (await res.text()).trim()
}

// Web Push applicationServerKey must be a Uint8Array, but the VAPID public
// key is served as a base64url string — this is the standard conversion.
export function urlBase64ToUint8Array(base64url: string): Uint8Array {
  const padding = '='.repeat((4 - (base64url.length % 4)) % 4)
  const base64 = (base64url + padding).replace(/-/g, '+').replace(/_/g, '/')
  const raw = atob(base64)
  const arr = new Uint8Array(raw.length)
  for (let i = 0; i < raw.length; i++) arr[i] = raw.charCodeAt(i)
  return arr
}
