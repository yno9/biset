// Service Worker — background Web Push handling for the home-screen icon
// badge and a "new message" notification. Built and deployed as its own
// standalone file (dist/sw.js) — unlike the rest of the app, a Service Worker
// cannot be inlined into index.html; it must be a real same-origin script so
// the browser can register it (see scripts/inline.mjs / package.json build).
//
// Runs in a separate global scope with no access to the page's localStorage.
// StoredAccount credentials are mirrored into IndexedDB by context.ts's
// saveStoredAccounts() for exactly this reason (store/idb.ts STORES.accounts)
// — same trust boundary as localStorage already has (same origin), so this
// isn't a new exposure.
//
// The push payload itself is deliberately empty (see go-jmapserver's
// Hub.pushAll): an identity can span multiple relays (mail + ActivityPub), so
// only this handler — which knows about all of them — can compute the true
// unread total. Every push still shows a generic notification: the relay
// never has plaintext to put in it (PGP end-to-end encryption), and Apple's/
// Chrome's push policies require a visible notification per push anyway.

import * as idb from './store/idb.ts'
import type { StoredAccount } from './types.ts'
import { postPushSubscribe } from './push/api.ts'

// TS's DOM lib (see tsconfig.json) doesn't know ServiceWorkerGlobalScope —
// this file isn't type-checked against "webworker" lib to avoid conflicting
// with the rest of the app's "dom" lib, so the global scope is cast to `any`.
const sw = self as any

sw.addEventListener('install', () => { sw.skipWaiting() })
sw.addEventListener('activate', (event: any) => { event.waitUntil(sw.clients.claim()) })

async function loadAccounts(): Promise<StoredAccount[]> {
  const [accounts] = await idb.getAll(idb.STORES.accounts) as [StoredAccount[] | undefined]
  return accounts ?? []
}

async function fetchUnreadCount(account: StoredAccount): Promise<number> {
  try {
    const res = await fetch(account.serverUrl.replace(/\/$/, '') + '/jmap/api/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Basic ' + btoa(account.email + ':' + account.password),
      },
      body: JSON.stringify({
        using: ['urn:ietf:params:jmap:core', 'urn:ietf:params:jmap:mail'],
        methodCalls: [
          ['Email/query', { accountId: account.email, limit: 2000 }, '0'],
          ['Email/get', {
            accountId: account.email,
            '#ids': { resultOf: '0', name: 'Email/query', path: '/ids' },
            properties: ['keywords', 'from'],
          }, '1'],
        ],
      }),
    })
    if (!res.ok) return 0
    const data = await res.json()
    const getResp = (data.methodResponses ?? []).find((r: any) => r[0] === 'Email/get')
    const list: any[] = getResp?.[1]?.list ?? []
    // Own sent mail never carries $seen (mirrors app.ts's loadInboxSummaries) —
    // counting it would keep every conversation permanently "unread".
    return list.filter(e => {
      const fromEmail = e.from?.[0]?.email ?? ''
      return fromEmail !== account.email && !e.keywords?.['$seen']
    }).length
  } catch {
    return 0
  }
}

async function refreshBadge(): Promise<void> {
  const accounts = await loadAccounts()
  const counts = await Promise.all(accounts.map(fetchUnreadCount))
  const total = counts.reduce((a, b) => a + b, 0)
  const nav = sw.navigator
  if (total > 0) await nav?.setAppBadge?.(total).catch(() => {})
  else await nav?.clearAppBadge?.().catch(() => {})
}

sw.addEventListener('push', (event: any) => {
  event.waitUntil((async () => {
    await sw.registration.showNotification('biset', {
      body: '新着メッセージがあります',
      tag: 'biset-push',
      renotify: false,
    })
    await refreshBadge()
  })())
})

sw.addEventListener('notificationclick', (event: any) => {
  event.notification.close()
  event.waitUntil((async () => {
    const clients = await sw.clients.matchAll({ type: 'window', includeUncontrolled: true })
    if (clients.length) { clients[0].focus(); return }
    await sw.clients.openWindow('/')
  })())
})

// Browsers occasionally rotate a subscription's endpoint/keys (expiry, OS
// push-service churn) and fire this instead of silently dropping it — refresh
// with the same applicationServerKey and re-register with every relay we know
// about, or badge/push updates would go silent until the user re-toggles.
sw.addEventListener('pushsubscriptionchange', (event: any) => {
  event.waitUntil((async () => {
    const key = event.oldSubscription?.options?.applicationServerKey
    if (!key) return
    const newSub = await sw.registration.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: key })
    const accounts = await loadAccounts()
    const seenRelays = new Set<string>()
    for (const account of accounts) {
      if (seenRelays.has(account.serverUrl)) continue
      seenRelays.add(account.serverUrl)
      try { await postPushSubscribe(account.serverUrl, account.email, account.password, newSub.toJSON()) } catch { /* best-effort */ }
    }
  })())
})
