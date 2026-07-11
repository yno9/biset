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
// unread total (and the actual sender to show) itself, via the same
// authenticated JMAP queries the main app already makes.
//
// This handler also DECRYPTS each candidate message (the PGP private key lives
// in IndexedDB, same as the main app reads it — see pgp/keys.ts): reactions and
// edit-requests are only distinguishable by a header INSIDE the encrypted body,
// which the relay can't see (end-to-end encrypted), so it fires a push for a
// reaction just like a real message. Without decrypting, this handler would
// notify for a mere 👍 and count it toward the badge — the same reaction
// inflation the foreground already fixes at sync time (sync/session.ts).
// Decrypting lets the background path reach the same answer: reactions/edits
// are marked $seen and excluded, so the badge stays consistent with the
// foreground and no notification nags for them. The body still shows only the
// sender, never a content preview.

import * as idb from './store/idb.ts'
import type { StoredAccount } from './types.ts'
import { postPushSubscribe, postPushUnsubscribe } from './push/api.ts'
import { isSecurejoinEmail, readChatEditTarget } from './deltachat/protocol.ts'
import { isReaction, isReactionDisposition } from './mail/reactions.ts'
import { decryptAndParse } from './pgp/crypto.ts'

// TS's DOM lib (see tsconfig.json) doesn't know ServiceWorkerGlobalScope —
// this file isn't type-checked against "webworker" lib to avoid conflicting
// with the rest of the app's "dom" lib, so the global scope is cast to `any`.
const sw = self as any

// Bump on each meaningful sw.ts change so /debug (main thread) can confirm
// WHICH sw.js the device actually has active — iOS PWA service workers update
// stickily, and a stale one silently produces old behaviour.
const SW_VERSION = 'reaction-decrypt-5'

// Persisted (in the accounts store, out-of-line keyed) so it survives the SW
// being killed between pushes: the receivedAt of the newest REAL message we've
// already notified for. A push whose newest real message isn't past this is
// reaction/edit-only (or nothing genuinely new) → no notification.
const LAST_NOTIFIED_KEY = 'sw_last_notified_ts'
// A record of what the LAST push actually did, read back by /debug — the only
// window into whether the active SW ran this code and whether decryption /
// reaction-classification worked in the SW context.
const LAST_PUSH_DEBUG_KEY = 'sw_last_push_debug'

sw.addEventListener('install', () => { sw.skipWaiting() })
sw.addEventListener('activate', (event: any) => {
  event.waitUntil((async () => {
    await sw.clients.claim()
    // Record which version is now ACTIVE (distinct from LAST_PUSH_DEBUG_KEY's
    // version, which only updates when a push is processed) so /debug can tell
    // whether a new sw.js has actually taken over even before any push arrives.
    await idb.put(idb.STORES.accounts, SW_VERSION, 'sw_active_version').catch(() => {})
  })())
})

async function loadAccounts(): Promise<StoredAccount[]> {
  const [accounts] = await idb.getAll(idb.STORES.accounts) as [StoredAccount[] | undefined]
  return accounts ?? []
}

function emailBody(e: any): string {
  const partId = e.textBody?.[0]?.partId
  if (partId && e.bodyValues?.[partId]) return e.bodyValues[partId].value ?? ''
  const vals = Object.values(e.bodyValues ?? {}) as any[]
  return vals[0]?.value ?? ''
}

// Per-push instrumentation (reset at the top of each push) so /debug can see
// what the SW actually did: how many candidates, how many bodies had PGP, how
// many decrypts succeeded, and the reaction/edit/real split.
const dbg = { candidates: 0, pgp: 0, decryptOk: 0, decryptFail: 0, reaction: 0, edit: 0, real: 0, lastHdrKeys: '', lastDisp: '' }

// reaction / edit / real — the two "noise" kinds are hidden from every inbox
// (reactions attach to their target, edits overwrite their target's text) so
// they must not notify or count. The relay can't tell them apart (the marker
// is a header INSIDE the PGP body — end-to-end encrypted), so it pushes for a
// reaction just like a real message; only a decrypt here can distinguish them.
// The cleartext-reaction case is already handled by the isReaction pre-filter.
async function classify(e: any, selfEmail: string): Promise<'reaction' | 'edit' | 'real'> {
  dbg.candidates++
  const body = emailBody(e)
  if (!body.includes('-----BEGIN PGP MESSAGE-----')) { dbg.real++; return 'real' }
  dbg.pgp++
  const dec = await decryptAndParse(body, selfEmail)
  if (!dec?.headers) { dbg.decryptFail++; dbg.real++; return 'real' }
  dbg.decryptOk++
  // Capture the actual decrypted headers of the LAST classified message so
  // /debug can show why a reaction was (mis)classified — the disposition value
  // and which header keys parseMIME surfaced.
  dbg.lastHdrKeys = Object.keys(dec.headers).join(',')
  dbg.lastDisp = (dec.headers['content-disposition'] ?? '(none)').slice(0, 40)
  if (isReactionDisposition(dec.headers)) { dbg.reaction++; return 'reaction' }
  if (readChatEditTarget(dec.headers)) { dbg.edit++; return 'edit' }
  dbg.real++
  return 'real'
}

async function markSeen(account: StoredAccount, ids: string[]): Promise<void> {
  if (!ids.length) return
  const update: Record<string, any> = {}
  for (const id of ids) update[id] = { 'keywords/$seen': true }
  try {
    await fetch(account.serverUrl.replace(/\/$/, '') + '/jmap/api/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Basic ' + btoa(account.email + ':' + account.password),
      },
      body: JSON.stringify({
        using: ['urn:ietf:params:jmap:core', 'urn:ietf:params:jmap:mail'],
        methodCalls: [['Email/set', { accountId: account.email, update }, '0']],
      }),
    })
  } catch { /* best-effort — the foreground sync will mark it too */ }
}

interface RealMsg { id: string; from: string; ts: number }

interface AccountUnread {
  // Every real unread message (id + sender + ts). Its length is the badge
  // count (unread messages), and the push handler diffs these ids against the
  // set it has already notified for, so each real message notifies exactly
  // once — robust to out-of-order delivery in a way the old "newest ts > last
  // notified ts" watermark was not (a message arriving with an earlier
  // receivedAt than one already notified would have been silently dropped).
  real: RealMsg[]
}

async function fetchAccountUnread(account: StoredAccount): Promise<AccountUnread> {
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
            properties: ['id', 'keywords', 'from', 'receivedAt', 'headers', 'bodyValues', 'textBody'],
            fetchAllBodyValues: true,
          }, '1'],
        ],
      }),
    })
    if (!res.ok) return { real: [] }
    const data = await res.json()
    const getResp = (data.methodResponses ?? []).find((r: any) => r[0] === 'Email/get')
    const list: any[] = getResp?.[1]?.list ?? []
    // Own sent mail never carries $seen (mirrors app.ts's loadInboxSummaries);
    // SecureJoin handshake noise and cleartext reactions are inbox-hidden too.
    const candidates = list.filter(e => {
      if (isSecurejoinEmail(e) || isReaction(e)) return false
      const fromEmail = e.from?.[0]?.email ?? ''
      return fromEmail !== account.email && !e.keywords?.['$seen']
    })
    const noiseIds: string[] = []
    const real: RealMsg[] = []
    for (const e of candidates) {
      const kind = await classify(e, account.email)
      if (kind !== 'real') { noiseIds.push(e.id); continue }
      const from = e.from?.[0]?.email ?? ''
      real.push({ id: e.id, from, ts: e.receivedAt ? new Date(e.receivedAt).getTime() : 0 })
    }
    // Same durable fix the foreground sync applies (sync/session.ts): mark the
    // inbox-hidden reactions/edits $seen so they leave the unread set for good,
    // keeping the badge and every future push accurate without waiting for the
    // app to be opened.
    await markSeen(account, noiseIds)
    return { real }
  } catch {
    return { real: [] }
  }
}

async function checkForNewMessages(): Promise<{ total: number; real: RealMsg[] }> {
  const accounts = await loadAccounts()
  const results = await Promise.all(accounts.map(fetchAccountUnread))
  const real: RealMsg[] = []
  for (const r of results) real.push(...r.real)
  // Badge = total unread MESSAGES, matching the foreground (left-pane.ts
  // renderLeftInboxes) now that both count messages, not conversations.
  return { total: real.length, real }
}

sw.addEventListener('push', (event: any) => {
  event.waitUntil((async () => {
    dbg.candidates = 0; dbg.pgp = 0; dbg.decryptOk = 0; dbg.decryptFail = 0
    dbg.reaction = 0; dbg.edit = 0; dbg.real = 0; dbg.lastHdrKeys = ''; dbg.lastDisp = ''
    const { total, real } = await checkForNewMessages()
    const nav = sw.navigator
    if (total > 0) await nav?.setAppBadge?.(total).catch(() => {})
    else await nav?.clearAppBadge?.().catch(() => {})

    // Notify once per real message, tracked by id. Diff the current real-unread
    // ids against the ids we've already notified for; a push carrying only a
    // reaction/edit adds nothing to `real` (classify routed it to $seen) so
    // there's nothing new to notify. Persist the CURRENT real-unread id set as
    // the new baseline — messages the user reads leave `real`, so the set
    // self-prunes and never grows unbounded. (Platform push policy prefers a
    // visible notification per push; reaction-only pushes skip it, staying
    // within the silent-push budget, and the badge update above is still a
    // user-visible response.)
    const prevNotified: string[] = (await idb.get(idb.STORES.accounts, LAST_NOTIFIED_KEY).catch(() => [])) as string[] ?? []
    const prevSet = new Set(prevNotified)
    const fresh = real.filter(m => !prevSet.has(m.id))
    const willNotify = fresh.length > 0
    if (willNotify) {
      const newest = fresh.reduce((a, b) => (b.ts > a.ts ? b : a))
      await sw.registration.showNotification('biset', {
        body: newest.from ? `${newest.from}: 新着メッセージがあります` : '新着メッセージがあります',
        tag: 'biset-push',
        renotify: false,
      })
    }
    await idb.put(idb.STORES.accounts, real.map(m => m.id), LAST_NOTIFIED_KEY).catch(() => {})
    // Ground-truth record for /debug: which SW ran, what it saw, what it did.
    await idb.put(idb.STORES.accounts, {
      version: SW_VERSION, at: Date.now(), badge: total, willNotify,
      realCount: real.length, freshCount: fresh.length, ...dbg,
    }, LAST_PUSH_DEBUG_KEY).catch(() => {})
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
    // Endpoint the browser is rotating away from. Drop it from every relay so
    // the old (now-dead) subscription doesn't linger in push_subs.json getting
    // pushed to forever — the browser has already discarded it, so only the
    // server copy remains to clean up.
    const oldEndpoint = event.oldSubscription?.endpoint
    const newSub = await sw.registration.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: key })
    const accounts = await loadAccounts()
    const seenRelays = new Set<string>()
    for (const account of accounts) {
      if (seenRelays.has(account.serverUrl)) continue
      seenRelays.add(account.serverUrl)
      try { await postPushSubscribe(account.serverUrl, account.email, account.password, newSub.toJSON()) } catch { /* best-effort */ }
      if (oldEndpoint) {
        try { await postPushUnsubscribe(account.serverUrl, account.email, account.password, oldEndpoint) } catch { /* best-effort */ }
      }
    }
  })())
})
