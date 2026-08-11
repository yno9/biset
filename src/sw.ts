// Service Worker — background Web Push handling for the home-screen icon
// badge and a "new message" notification. Built and deployed as its own
// standalone file (dist/sw.js) — unlike the rest of the app, a Service Worker
// cannot be inlined into index.html; it must be a real same-origin script so
// the browser can register it (see scripts/inline.mjs / package.json build).
//
// Runs in a separate global scope with no access to the page's localStorage.
// Credentials are mirrored into IndexedDB for exactly this reason (store/idb.ts
// STORES.accounts) — same trust boundary as localStorage already has (same
// origin), so this isn't a new exposure. Two mirrors, and the difference
// matters: context.ts's saveStoredAccounts() writes the DURABLE accounts,
// whose password is empty for a DID-bound account, while mirrorSessionAccounts()
// writes the live sessions' credentials including the device-signed session
// token those accounts actually log in with. loadAccounts() below prefers the
// latter.
//
// The push payload itself is deliberately empty (see go-jmapserver's
// Hub.pushAll): an identity can span multiple relays (mail + ActivityPub), so
// only this handler — which knows about all of them — can compute the true
// unread total (and the actual sender to show) itself, via the same
// authenticated JMAP queries the main app already makes.
//
// This handler also DECRYPTS each candidate message (the PGP private key lives
// in IndexedDB, same as the main app reads it — see pgp/keys.ts): reactions,
// edit- and delete-requests are only distinguishable by a header INSIDE the
// encrypted body, which the relay can't see (end-to-end encrypted), so it
// fires a push for a reaction just like a real message. Without decrypting,
// this handler would notify for a mere 👍 and count it toward the badge — the
// same reaction inflation the foreground already fixes at sync time
// (sync/session.ts). The body of the notification still shows only the
// sender, never a content preview.
//
// ── Budget ───────────────────────────────────────────────────────────────────
// Everything below is shaped by one constraint: on iOS this whole file is
// fetched, parsed and run from cold on every background push, inside a hard
// (and short) time budget, with the app closed. Blowing that budget doesn't
// error — the notification simply never appears, which reads exactly like
// "push doesn't work in the background". So the JMAP fetch is two-staged
// (cheap metadata for everything, bodies only for the handful of unread
// candidates) and decryption is capped at SCAN_LIMIT messages.

import * as idb from './store/idb.ts'
import type { StoredAccount } from './types.ts'
import { postPushSubscribe, postPushUnsubscribe, fetchVapidPublicKey, urlBase64ToUint8Array } from './push/api.ts'
import { isSecurejoinEmail, readChatEditTarget, readChatDeleteTarget, readGroupHeaders, CHAT_GROUP_ID } from './deltachat/protocol.ts'
import { isReaction, isReactionDisposition } from './mail/reactions.ts'
import { decryptAndParse } from './pgp/crypto.ts'
import { SW_KEYS, syncAppBadge, conversationHash, notificationOptions } from './push/shared.ts'
import type { NotificationTarget } from './push/shared.ts'

// TS's DOM lib (see tsconfig.json) doesn't know ServiceWorkerGlobalScope —
// this file isn't type-checked against "webworker" lib to avoid conflicting
// with the rest of the app's "dom" lib, so the global scope is cast to `any`.
const sw = self as any

// Bump on each meaningful sw.ts change so /debug (main thread) can confirm
// WHICH sw.js the device actually has active — iOS PWA service workers update
// stickily, and a stale one silently produces old behaviour.
const SW_VERSION = 'didcomm-poke-first-1'

// How many unread candidates (newest first) get bodies fetched and decrypted
// on one push. Everything past this still counts toward the badge but can't
// raise a notification: those are old unread messages, already notified for
// when they arrived. Bounds the per-push cost — see the budget note above.
const SCAN_LIMIT = 50

// At most this many conversations raise a banner on a single push, newest
// first. A backlog delivered at once (a device coming back from offline)
// should not produce a screenful of notifications. The rest still count
// toward the badge, and are recorded as notified so they don't pile up onto
// the next push either.
const MAX_NOTIFICATIONS = 3

sw.addEventListener('install', () => { sw.skipWaiting() })
sw.addEventListener('activate', (event: any) => {
  event.waitUntil((async () => {
    await sw.clients.claim()
    // Record which version is now ACTIVE (distinct from SW_KEYS.debug's
    // version, which only updates when a push is processed) so /debug can tell
    // whether a new sw.js has actually taken over even before any push arrives.
    await idb.put(idb.STORES.accounts, SW_VERSION, SW_KEYS.version).catch(() => {})
  })())
})

async function loadAccounts(): Promise<StoredAccount[]> {
  // The live sessions' credentials first: a DID-bound account's durable record
  // carries an EMPTY password (it logs in with a device-signed session token —
  // jmap/client.ts's initSession), so reading the durable list alone meant a
  // 401 on every call and an unread scan that silently contributed nothing.
  // Falls back to it for an identity that predates DID-bound accounts.
  //
  // Keyed reads, NOT getAll()[0]: this store also holds the SW's own
  // bookkeeping entries, so "first value in the store" only happened to be the
  // account list because 'all' sorts before 'sw_…'.
  const live = await idb.get(idb.STORES.accounts, SW_KEYS.sessionAccounts).catch(() => undefined)
  const accounts = (Array.isArray(live) && live.length)
    ? live
    : await idb.get(idb.STORES.accounts, SW_KEYS.accounts).catch(() => undefined)
  // `didcomm:` is a synthetic serverUrl with no HTTP endpoint behind it
  // (context.ts's DIDCOMM_SERVER_URL). It shouldn't reach the mirror, but if
  // one ever did, every JMAP fetch for it would fail and take `complete` — and
  // therefore the badge — down with it.
  return ((accounts as StoredAccount[] | undefined) ?? []).filter(a => !a.serverUrl.startsWith('didcomm:'))
}

// ── JMAP ─────────────────────────────────────────────────────────────────────

// One place that speaks JMAP for this file (the unread scan and the $seen
// write both went through their own hand-rolled copy of this before).
// Returns null on any failure — callers must treat that as "unknown", never
// as "nothing unread".
async function jmapCall(account: StoredAccount, methodCalls: unknown[], dbg: Debug): Promise<any | null> {
  const host = (() => { try { return new URL(account.serverUrl).host } catch { return account.serverUrl } })()
  try {
    const res = await fetch(account.serverUrl.replace(/\/$/, '') + '/jmap/api/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Basic ' + btoa(account.email + ':' + account.password),
      },
      body: JSON.stringify({
        using: ['urn:ietf:params:jmap:core', 'urn:ietf:params:jmap:mail'],
        methodCalls,
      }),
    })
    if (!res.ok) { dbg.calls.push(`${host}:HTTP${res.status}`); return null }
    return await res.json()
  } catch (e) {
    // The reason matters and is otherwise invisible from the main thread: a
    // failing scan silently contributes 0 unread, which used to subtract every
    // unread mail from the badge with nothing to show for it.
    dbg.calls.push(`${host}:${e instanceof Error ? e.name : 'error'}`)
    return null
  }
}

function methodResult(data: any, name: string): any {
  return (data?.methodResponses ?? []).find((r: any) => r[0] === name)?.[1]
}

async function markSeen(account: StoredAccount, ids: string[], dbg: Debug): Promise<void> {
  if (!ids.length) return
  const update: Record<string, any> = {}
  for (const id of ids) update[id] = { 'keywords/$seen': true }
  // Best-effort — the foreground sync will mark it too.
  await jmapCall(account, [['Email/set', { accountId: account.email, update }, '0']], dbg)
}

// ── Classification ───────────────────────────────────────────────────────────

function emailBody(e: any): string {
  const partId = e.textBody?.[0]?.partId
  if (partId && e.bodyValues?.[partId]) return e.bodyValues[partId].value ?? ''
  const vals = Object.values(e.bodyValues ?? {}) as any[]
  return vals[0]?.value ?? ''
}

type Kind = 'noise' | 'real'
interface Classified { kind: Kind; groupId?: string }

// reaction / edit / delete are all inbox-hidden (a reaction attaches to its
// target, an edit overwrites its target's text, a delete removes it) so they
// must neither notify nor count. The relay can't tell them apart — the marker
// is a header INSIDE the PGP body, end-to-end encrypted — so it pushes for a
// reaction just like a real message; only a decrypt here can distinguish them.
// SecureJoin handshake noise is filtered earlier, on the cheap metadata pass.
async function classify(e: any, selfEmail: string, dbg: Debug): Promise<Classified> {
  dbg.candidates++
  // Cleartext reaction: Content-Disposition is a plain outer header.
  if (isReaction(e)) { dbg.noise++; return { kind: 'noise' } }
  const outerGroupId = readGroupHeaders(e).id
  const body = emailBody(e)
  if (!body.includes('-----BEGIN PGP MESSAGE-----')) { dbg.real++; return { kind: 'real', groupId: outerGroupId } }
  dbg.pgp++
  const dec = await decryptAndParse(body, selfEmail)
  if (!dec?.headers) { dbg.decryptFail++; dbg.real++; return { kind: 'real', groupId: outerGroupId } }
  dbg.decryptOk++
  // Capture the actual decrypted headers of the LAST classified message so
  // /debug can show why a reaction was (mis)classified.
  dbg.lastHdrKeys = Object.keys(dec.headers).join(',')
  dbg.lastDisp = (dec.headers['content-disposition'] ?? '(none)').slice(0, 40)
  if (isReactionDisposition(dec.headers) || readChatEditTarget(dec.headers) || readChatDeleteTarget(dec.headers)) {
    dbg.noise++
    return { kind: 'noise' }
  }
  dbg.real++
  return { kind: 'real', groupId: dec.headers[CHAT_GROUP_ID.toLowerCase()]?.trim() || outerGroupId }
}

// ── Unread scan ──────────────────────────────────────────────────────────────

interface RealMsg { id: string; from: string; ts: number; hash: string; title: string }

// `ok: false` means this account's state is UNKNOWN this round (network, auth,
// a relay restart). It is not the same as "nothing unread", and the caller
// must not let it clear the badge or forget which messages were notified —
// doing exactly that is what made one old unread message re-notify forever.
type AccountUnread =
  | { ok: true; total: number; real: RealMsg[] }
  | { ok: false }

async function fetchAccountUnread(account: StoredAccount, dbg: Debug): Promise<AccountUnread> {
  // Stage 1 — metadata only. Bodies are deliberately NOT requested here: with
  // fetchAllBodyValues over the whole mailbox this single call used to pull
  // every message the account has ever received, on every push.
  const head = await jmapCall(account, [
    ['Email/query', { accountId: account.email, limit: 2000 }, '0'],
    ['Email/get', {
      accountId: account.email,
      '#ids': { resultOf: '0', name: 'Email/query', path: '/ids' },
      properties: ['id', 'keywords', 'from', 'receivedAt', 'subject'],
    }, '1'],
  ], dbg)
  if (!head) return { ok: false }
  const list: any[] = methodResult(head, 'Email/get')?.list ?? []
  // Own sent mail never carries $seen (mirrors app.ts's loadInboxSummaries);
  // SecureJoin handshake noise is inbox-hidden too. `subject` is fetched above
  // purely so isSecurejoinEmail can see it — it wasn't, so that filter had
  // silently never matched anything here.
  const candidates = list.filter(e => {
    if (isSecurejoinEmail(e)) return false
    const fromEmail = e.from?.[0]?.email ?? ''
    return fromEmail !== account.email && !e.keywords?.['$seen']
  })
  if (!candidates.length) return { ok: true, total: 0, real: [] }

  // Stage 2 — bodies for the newest unread candidates only (Email/query is
  // sorted newest-first). Typically a handful; SCAN_LIMIT caps the worst case.
  const scan = candidates.slice(0, SCAN_LIMIT)
  const full = await jmapCall(account, [
    ['Email/get', {
      accountId: account.email,
      ids: scan.map(e => e.id),
      properties: ['id', 'headers', 'bodyValues', 'textBody'],
      fetchAllBodyValues: true,
    }, '0'],
  ], dbg)
  if (!full) return { ok: false }
  const detail = new Map<string, any>()
  for (const e of methodResult(full, 'Email/get')?.list ?? []) detail.set(e.id, e)

  const noiseIds: string[] = []
  const real: RealMsg[] = []
  for (const e of scan) {
    const merged = { ...e, ...(detail.get(e.id) ?? {}) }
    const { kind, groupId } = await classify(merged, account.email, dbg)
    if (kind === 'noise') { noiseIds.push(e.id); continue }
    const from = e.from?.[0]?.email ?? ''
    real.push({
      id: e.id,
      from,
      ts: e.receivedAt ? new Date(e.receivedAt).getTime() : 0,
      hash: conversationHash(from, groupId),
      title: from,
    })
  }
  // Same durable fix the foreground sync applies (sync/session.ts): mark the
  // inbox-hidden noise $seen so it leaves the unread set for good, keeping the
  // badge and every future push accurate without waiting for the app to open.
  await markSeen(account, noiseIds, dbg)
  // Candidates past SCAN_LIMIT are counted but unclassified: they're older
  // unread messages, and any noise among them gets marked $seen as it moves
  // into the scan window on a later push.
  return { ok: true, total: candidates.length - noiseIds.length, real }
}

// ── Notified-id bookkeeping ──────────────────────────────────────────────────

async function loadNotifiedIds(): Promise<string[]> {
  const cur = await idb.get(idb.STORES.accounts, SW_KEYS.notifiedIds).catch(() => undefined)
  if (Array.isArray(cur)) return cur as string[]
  // First run after the rename — seed from the old key so this update doesn't
  // re-notify everything that is currently unread.
  const legacy = await idb.get(idb.STORES.accounts, SW_KEYS.legacyNotifiedIds).catch(() => undefined)
  await idb.del(idb.STORES.accounts, SW_KEYS.legacyNotifiedIds).catch(() => {})
  return Array.isArray(legacy) ? legacy as string[] : []
}

// What the user is looking at RIGHT NOW: whether the app is on screen at all,
// and which conversation it is showing (push/client.ts's setActiveConversation
// records the latter). Both matter and they answer different questions — a
// record left behind by a since-closed window must suppress nothing, so `hash`
// is only meaningful when `focused` holds.
async function activeView(): Promise<{ focused: boolean; hash: string | null }> {
  try {
    const clients = await sw.clients.matchAll({ type: 'window' })
    const focused = clients.some((c: any) => c.focused || c.visibilityState === 'visible')
    if (!focused) return { focused: false, hash: null }
    const hash = await idb.get(idb.STORES.accounts, SW_KEYS.activeView).catch(() => null)
    return { focused: true, hash: typeof hash === 'string' && hash ? hash : null }
  } catch { return { focused: false, hash: null } }
}

// ── Push ─────────────────────────────────────────────────────────────────────

interface Debug {
  candidates: number; pgp: number; decryptOk: number; decryptFail: number
  noise: number; real: number; lastHdrKeys: string; lastDisp: string
  /** One entry per FAILED JMAP call, as `host:reason`. Empty when every call
   * succeeded — so an empty list next to a zero unread count means there was
   * genuinely nothing unread, not that the scan never got off the ground. */
  calls: string[]
}
function newDebug(): Debug {
  return { candidates: 0, pgp: 0, decryptOk: 0, decryptFail: 0, noise: 0, real: 0, lastHdrKeys: '', lastDisp: '', calls: [] }
}

/** What the sender put in the push, when it put anything there at all.
 *
 * The relays send an EMPTY payload on purpose (go-jmapserver's pushAccounts):
 * an identity can span several of them, so only this handler can compute the
 * true unread total, and it does that with its own JMAP queries below.
 *
 * The DIDComm mediator can't work that way — its queue is not something this
 * handler can query without carrying DID resolution and the whole unpack path
 * into the Service Worker bundle, which would blow the background budget the
 * two-stage JMAP fetch above exists to stay inside. So it sends a count
 * instead: `{ t: 'didcomm', n }`. It deliberately does NOT send a sender — a
 * Forward's contents are opaque to the mediator and its envelope is anoncrypt,
 * so there is no sender to name even in principle. */
interface PushPayload { t: 'didcomm'; n: number }

function readPayload(event: any): PushPayload | null {
  try {
    const data = event.data?.json?.()
    if (data?.t === 'didcomm') return { t: 'didcomm', n: Number(data.n) || 0 }
  } catch { /* empty or non-JSON payload — the relay case */ }
  return null
}

/** Tells any open page to run its DIDComm pickup NOW. The worker can't do it
 * itself — that needs DID resolution and the whole unpack path, which is
 * exactly what must not be dragged into a bundle that cold-starts inside the
 * background push budget — but a page that is already running has all of it
 * loaded. This is what lets the page's own poll interval drop from 4s to a
 * once-a-minute backstop: the push IS the signal now, and the timer only has
 * to catch one that never arrived. Sent regardless of focus, since a
 * backgrounded-but-alive page should still catch up. */
async function pokeDidCommClients(): Promise<void> {
  for (const client of await sw.clients.matchAll({ type: 'window' })) {
    try { client.postMessage({ type: 'biset:didcomm' }) } catch { /* best-effort */ }
  }
}

async function handlePush(payload: PushPayload | null): Promise<void> {
  const didcommQueued = payload?.t === 'didcomm' ? payload.n : 0
  // FIRST, before anything else this handler does. It used to be sent after
  // the JMAP unread scan below — two round trips per account plus a PGP
  // decrypt of up to SCAN_LIMIT messages — so the page was told to collect its
  // DIDComm message only once work that has nothing to do with DIDComm had
  // finished. On a cold iOS worker that is seconds, and they land squarely in
  // the gap between the notification appearing and the message appearing in
  // the thread. Nothing below depends on this having happened.
  if (didcommQueued > 0) await pokeDidCommClients()

  const dbg = newDebug()
  const accounts = await loadAccounts()
  const results = await Promise.all(accounts.map(a => fetchAccountUnread(a, dbg)))
  const complete = results.length > 0 && results.every(r => r.ok)

  let total = 0
  const real: RealMsg[] = []
  for (const r of results) {
    if (!r.ok) continue
    total += r.total
    real.push(...r.real)
  }

  // The badge has three disjoint parts, and this handler can only compute one
  // of them from scratch:
  //   total          — unread in the JMAP accounts, scanned above.
  //   localDidcomm   — DIDComm messages already picked up and unread in the
  //                    local store. Invisible from here (no JMAP account holds
  //                    them), so the window publishes the number instead.
  //   didcommQueued  — still in the mediator's queue, straight off the payload.
  // Leaving the middle term out is what made a background arrival drop the
  // badge to just itself, then jump back up the moment the app was opened.
  const localDidcomm = Number(await idb.get(idb.STORES.accounts, SW_KEYS.localDidcommUnread).catch(() => 0)) || 0
  // A failed scan knows nothing, which is not the same as knowing there is
  // nothing. Fall back to what the window last saw rather than contributing a
  // zero that quietly subtracts every unread mail from the badge.
  const publishedJmap = Number(await idb.get(idb.STORES.accounts, SW_KEYS.localJmapUnread).catch(() => 0)) || 0
  const jmapUnread = complete ? total : publishedJmap
  const badge = jmapUnread + localDidcomm + didcommQueued

  // Every term now has a source or a fallback, so the badge is writable even
  // when a relay is down — but not when there is no basis at all (no accounts
  // AND nothing published AND no payload), where writing would just clear a
  // badge the window had set correctly.
  if (complete || didcommQueued > 0 || publishedJmap > 0 || localDidcomm > 0) syncAppBadge(badge)

  const prev = await loadNotifiedIds()
  const prevSet = new Set(prev)
  const fresh = real.filter(m => !prevSet.has(m.id))

  // One banner per conversation, newest conversations first.
  const view = await activeView()
  const suppressed = view.hash
  const byHash = new Map<string, NotificationTarget & { ts: number }>()
  for (const m of fresh) {
    if (m.hash === suppressed) continue
    const cur = byHash.get(m.hash)
    if (cur) { cur.count++; if (m.ts > cur.ts) { cur.ts = m.ts; cur.title = m.title } }
    else byHash.set(m.hash, { hash: m.hash, title: m.title, count: 1, ts: m.ts })
  }
  const targets = [...byHash.values()].sort((a, b) => b.ts - a.ts).slice(0, MAX_NOTIFICATIONS)

  // A DIDComm arrival gets one generic banner: the mediator can't tell us who
  // sent it (see PushPayload), so there is no conversation to name or open —
  // the tag is fixed so consecutive arrivals replace rather than stack, and
  // the click target is the app itself. Skipped whenever a window is on screen
  // at all: the app's own pickup will surface it, and unlike the JMAP case
  // there is no per-conversation check available to be more precise than that.
  if (didcommQueued > 0 && !view.focused) {
    // Empty title: there is no sender to put in iOS's "from …" line, and
    // naming the app there instead read as though biset itself had written.
    const [title, options] = notificationOptions({ hash: '', title: '', count: didcommQueued })
    await sw.registration.showNotification(title, options)
  }

  for (const t of targets) {
    const [title, options] = notificationOptions(t)
    await sw.registration.showNotification(title, options)
  }

  // New baseline. On a complete picture it is exactly the current real-unread
  // set, so ids the user has read drop out and it can't grow unbounded. On a
  // partial one it is the UNION with what we already knew — forgetting an id
  // here is what made a single old unread message notify again on every push.
  const seenIds = real.map(m => m.id)
  const next = complete ? seenIds : [...new Set([...prev, ...seenIds])]
  await idb.put(idb.STORES.accounts, next, SW_KEYS.notifiedIds).catch(() => {})

  // Ground-truth record for /debug: which SW ran, what it saw, what it did.
  await idb.put(idb.STORES.accounts, {
    version: SW_VERSION, at: Date.now(), badge, complete,
    notified: targets.length + (didcommQueued > 0 && !view.focused ? 1 : 0),
    realCount: real.length, freshCount: fresh.length,
    accounts: accounts.length, jmapUnread, jmapScanned: total, publishedJmap,
    localDidcomm, didcommQueued,
    suppressed: suppressed ?? '', ...dbg,
  }, SW_KEYS.debug).catch(() => {})
}

// Push events are serialized. Two pushes landing together would otherwise both
// read the notified-id set before either wrote it back, and both would notify
// for the same message. The payload has to be read synchronously here — the
// event's data isn't available once the handler's turn is over.
let pushQueue: Promise<void> = Promise.resolve()
sw.addEventListener('push', (event: any) => {
  const payload = readPayload(event)
  const next = () => handlePush(payload)
  const run = pushQueue.then(next, next)
  pushQueue = run.catch(() => {})
  event.waitUntil(run)
})

sw.addEventListener('notificationclick', (event: any) => {
  event.notification.close()
  const hash: string = event.notification.data?.hash ?? ''
  event.waitUntil((async () => {
    const clients = await sw.clients.matchAll({ type: 'window', includeUncontrolled: true })
    const client = clients[0]
    if (client) {
      // postMessage rather than WindowClient.navigate(): navigate() is patchy
      // across engines (and a no-op for a same-URL-different-hash move), while
      // the app already routes off the hash — push/client.ts turns this into a
      // location.hash write, which the existing hashchange router picks up.
      try { client.postMessage({ type: 'biset:open', hash }) } catch { /* best-effort */ }
      await client.focus()
      return
    }
    await sw.clients.openWindow(hash ? '/' + hash : '/')
  })())
})

// Browsers occasionally rotate a subscription's endpoint/keys (expiry, OS
// push-service churn) and fire this instead of silently dropping it — refresh
// with the same applicationServerKey and re-register with every relay we know
// about, or badge/push updates would go silent until the user re-toggles.
// (Safari doesn't implement this event at all; there, recovery is the
// re-subscribe enablePush() does on every boot.)
sw.addEventListener('pushsubscriptionchange', (event: any) => {
  event.waitUntil((async () => {
    const accounts = await loadAccounts()
    // Endpoint the browser is rotating away from. Drop it from every relay so
    // the old (now-dead) subscription doesn't linger in push_subs.json getting
    // pushed to forever — the browser has already discarded it, so only the
    // server copy remains to clean up.
    const oldEndpoint = event.oldSubscription?.endpoint
    // Prefer the key the old subscription was created with; fall back to
    // asking a relay, so a subscription the browser handed us without one
    // (or one dropped outright) can still be rebuilt.
    let key: BufferSource | null = event.oldSubscription?.options?.applicationServerKey ?? null
    if (!key) {
      for (const account of accounts) {
        const pub = await fetchVapidPublicKey(account.serverUrl)
        if (pub) { key = urlBase64ToUint8Array(pub) as BufferSource; break }
      }
    }
    if (!key) return
    const newSub = await sw.registration.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: key })
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
