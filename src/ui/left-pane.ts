import { currentInbox, setCurrentInbox, activeSession, sessionFor, sessionForRelay, relaysFor, relaysForId, accountKey, identityKey, identityKeyForEmail, identityIds, sessions, loadStoredAccounts, saveStoredAccounts, setVaultHandle, isApRelay, isDidCommRelay, relayProtocolLabel, DIDCOMM_SERVER_URL } from '../context.ts'
import { standaloneDid } from '../did/create-standalone.ts'
import { currentIdentityDid, ownGateways } from '../did/didcomm/channel.ts'
import { resolve as resolveDidFull, PUBLIC_PKARR_FALLBACKS } from '../did/resolver.ts'
import { getDidRecord } from '../did/store.ts'
import {
  lastLeftInboxes, setLastLeftInboxes,
  processedMessages, renderedKeys,
  setLastTs, setIsFirstFetch,
  focusedThreadKey, setFocusedThreadKey,
  notifEnabled, setNotifEnabled,
  lastTs, groupMessages,
} from '../state.ts'
import { esc, formatTime, avatarStyle, inboxToHash, syncAppBadge, mailboxNameFromId, hexToBytes, expandDualRelay } from '../utils.ts'
import { displayLabelFor, nameForContact, shortDid } from '../did/contacts.ts'
import type { InboxSummary } from '../types.ts'
import type { Email } from 'jmap-rfc-types'
// Circular (safe — used only in function bodies):
import { render, syncDockPosition, scrollToFocused, updateScrollSpacer } from './thread.ts'
import { fetchMessages, showSysMsg, startPolling } from './shell.ts'
// From app.ts (safe — called only inside async functions):
import { loadInboxSummaries, initSession, initPGPForSession, logout, jmapCreateEmail } from '../app.ts'
import { fetchEnvelope, unsealEnvelope, relayAuth } from '../cryptenv.ts'
import { decryptAndParse, prefetchRecipientKey } from '../pgp/index.ts'
import { deleteKey } from '../pgp/keys.ts'
import type { OutgoingAttachment } from '../pgp/crypto.ts'
import { clearIdentity as clearIdentityCache } from '../store/cache.ts'
import { avatarDataUrl, saveAvatar } from '../deltachat/avatar.ts'
import { advertiseOwnAvatarForEmail } from '../ap/avatar.ts'
import * as jmapEmail from '../jmap/email.ts'
import * as messages from '../store/messages.ts'
import * as identities from '../store/identities.ts'
import * as idb from '../store/idb.ts'
import { loadFromVault, flushAll, flushMessage, removeMessage } from '../vault/persist.ts'
import * as querystate from '../jmap/querystate.ts'
import { startWatch } from '../vault/watch.ts'
import { newGroupId, isSecurejoinEmail, readGroupHeaders, isEdit } from '../deltachat/protocol.ts'
import { isReaction } from '../mail/reactions.ts'
import { newInviteUrl } from '../deltachat/securejoin.ts'
import { enablePush, disablePush } from '../push/client.ts'

// ── InboxSummary key ──────────────────────────────────────────────────────────
function isk(i: InboxSummary): string { return i.user + '\0' + i.mailbox + '\0' + i.contact }

// Resolves a DID's full document via the SAME gateway set the send path uses
// (channel.ts's ownGateways — this browser's own relay /pkarr endpoints,
// plus this identity's own mediator if it has a pkarr token, ahead of the
// public Pkarr fallbacks). Shared by the compose To-field's DID pill lookup
// and the #account page's own-document viewer — the latter used to
// reimplement this a second way (relay-sessions-only, silently empty for a
// relay-less identity, since it has no relay session to draw a /pkarr
// gateway from at all), which is why a standalone identity's own #account
// page permanently reported "No document found" despite the record
// resolving fine everywhere else (own anchor, public gateways).
async function resolveDidDocFull(did: string) {
  const gateways = await ownGateways(currentIdentityDid())
  return await resolveDidFull(did, [...gateways, ...PUBLIC_PKARR_FALLBACKS])
}


// ── Preview cache / decrypt ───────────────────────────────────────────────────

const _previewCache = new Map<string, string>()

function fmtPreview(body: string): string {
  return esc(body.replace(/[\r\n\t]+/g, ' ').trim().slice(0, 60))
}

function previewFor(body: string): { text: string; needsDecrypt: boolean } {
  if (!body) return { text: '', needsDecrypt: false }
  if (!body.includes('-----BEGIN PGP MESSAGE-----')) {
    return { text: fmtPreview(body), needsDecrypt: false }
  }
  const cached = _previewCache.get(body)
  if (cached !== undefined) return { text: fmtPreview(cached), needsDecrypt: false }
  return { text: '🔒', needsDecrypt: true }
}

// Decrypt with the INBOX'S OWN identity key (selfEmail = item.user), not the
// active session — otherwise previews of conversations other than the open one
// decrypt with the wrong account's key and come out blank. Failed decrypts are
// not cached (the key may just not be loaded yet), so they retry on next render.
async function decryptPreviewInto(body: string, el: Element, selfEmail: string) {
  if (_previewCache.has(body)) {
    el.innerHTML = fmtPreview(_previewCache.get(body)!)
    return
  }
  const res = await decryptAndParse(body, selfEmail)
  const text = res?.body ?? ''
  if (res != null) _previewCache.set(body, text)
  el.innerHTML = fmtPreview(text)
}

// ── Module state ──────────────────────────────────────────────────────────────

export let lpNavIdx = -1
let _lpFocusedKey: string | null = null  // 'inbox:KEY' | 'thread:KEY'
let _inMenuMode = false
export function inMenuMode(): boolean { return _inMenuMode }
let _menuResizeObserver: ResizeObserver | null = null
let _showMenuPageFn: ((name: string) => void) | null = null
export function showMenuPage(name: string) { _showMenuPageFn?.(name) }

// Open the compose page with the To field pre-filled. Consumed once by the
// compose page's onShow (composePrefillTo). Backs the /<user>/ entry point: start
// a message to that user. URL becomes #compose/<addr> so it's shareable.
let composePrefillTo: string | null = null
export function openComposeTo(addr: string) {
  composePrefillTo = addr
  showMenuPage('/compose')
  // On mobile, showApp defaults a fresh (message-less) account to the left pane;
  // opening compose is an explicit intent to see the form, so reveal the right
  // column instead.
  document.getElementById('app')?.classList.remove('show-left')
  try { history.replaceState(null, '', '/#compose/' + encodeURIComponent(addr).replace(/%40/g, '@')) } catch { /* file:// */ }
  // Focus the body. A single deferred focus() is unreliable here — the compose
  // page renders across the #new→app transition and something (search box / polling
  // re-render) can steal focus right after — so re-assert it a few times over the
  // first ~0.8s. preventScroll avoids the page jumping on each refocus.
  const focusBody = () => {
    const ta = document.querySelector<HTMLTextAreaElement>('#focused-thread-card #new-body')
    ta?.focus({ preventScroll: true })
  }
  for (const d of [0, 60, 150, 300, 500, 800]) setTimeout(focusBody, d)
}
let _renderAccountsListFn: (() => void) | null = null
export function refreshAccountsList() { _renderAccountsListFn?.() }
let _openInboxMenuFn: ((item: InboxSummary, anchor: HTMLElement) => void) | null = null
export function openInboxMenuFor(item: InboxSummary, anchor: HTMLElement) { _openInboxMenuFn?.(item, anchor) }
export let menuTargetInbox: InboxSummary | null = null
const _expandedInboxKeys = new Set<string>()

// Downscales an image File to a square-ish avatar (max 192px, DeltaChat-sized) and
// returns a compact JPEG data: URL, keeping the inlined base64 header small.
function imageFileToAvatarDataUrl(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const url = URL.createObjectURL(file)
    const img = new Image()
    img.onload = () => {
      URL.revokeObjectURL(url)
      const max = 192
      const scale = Math.min(1, max / Math.max(img.width, img.height))
      const w = Math.max(1, Math.round(img.width * scale))
      const h = Math.max(1, Math.round(img.height * scale))
      const canvas = document.createElement('canvas')
      canvas.width = w; canvas.height = h
      const ctx = canvas.getContext('2d')
      if (!ctx) { reject(new Error('no 2d context')); return }
      ctx.drawImage(img, 0, 0, w, h)
      // JPEG has no alpha channel, so a transparent source (e.g. a PNG logo)
      // would flatten onto black. Detect any transparency and keep PNG in that
      // case; otherwise use JPEG for a smaller payload.
      let hasAlpha = false
      try {
        const data = ctx.getImageData(0, 0, w, h).data
        for (let i = 3; i < data.length; i += 4) { if (data[i] < 255) { hasAlpha = true; break } }
      } catch { /* tainted canvas — assume opaque */ }
      resolve(hasAlpha ? canvas.toDataURL('image/png') : canvas.toDataURL('image/jpeg', 0.85))
    }
    img.onerror = () => { URL.revokeObjectURL(url); reject(new Error('image load failed')) }
    img.src = url
  })
}

// Opens a file picker and sets the identity's avatar — one session = one
// identity (ARC.md 2026-07-14), so the avatar is a property of the DID, not
// any one address. Every consumer that reads avatarDataUrl(email) (thread.ts,
// DeltaChat's Chat-User-Avatar header, AP actor icon) is still keyed by
// address, so the same picture is saved under every known address of this
// DID rather than re-keying that whole cache by DID.
function pickAndSetIdentityAvatar(did: string): void {
  const input = document.createElement('input')
  input.type = 'file'
  input.accept = 'image/*'
  input.addEventListener('change', async () => {
    const file = input.files?.[0]
    if (!file) return
    try {
      const dataUrl = await imageFileToAvatarDataUrl(file)
      const addrs = loadStoredAccounts().filter(a => a.did === did).map(a => a.email)
      await Promise.all(addrs.map(addr => saveAvatar(addr, dataUrl)))
      // Push the new picture to this identity's AP relay(s) so the fediverse
      // actor document advertises it.
      for (const addr of addrs) advertiseOwnAvatarForEmail(addr)
      refreshAccountsList()
      loadLeftInboxes()
    } catch (e) { console.log('[avatar] set identity failed', e) }
  })
  input.click()
}

export function updateUrlForThread(_threadKey: string) {
  // URL updates omitted for InboxSummary-native version
}

function fmtThreadTs(ts: number): string {
  if (!ts) return ''
  const d = new Date(ts)
  return String(d.getMonth() + 1).padStart(2, '0') + '/' +
    String(d.getDate()).padStart(2, '0') + ' ' +
    String(d.getHours()).padStart(2, '0') + ':' +
    String(d.getMinutes()).padStart(2, '0')
}

export function renderThreadAccordion() {
  if (!currentInbox) return
  const currentKey = isk(currentInbox)
  const itemEl = [...document.querySelectorAll<HTMLElement>('#left-list .lp-item')]
    .find(el => el.dataset.inboxKey === currentKey)
  if (!itemEl) return
  const container = itemEl.querySelector<HTMLElement>('.lp-thread-list')
  if (!container) return
  // If not expanded, only pre-populate rows (for CSS highlight); don't call syncNavFocus
  const isExpanded = _expandedInboxKeys.has(currentKey)
  const groups = groupMessages().sort((a, b) => {
    const ta = a.messages.length ? a.messages[a.messages.length - 1].msg.ts : 0
    const tb = b.messages.length ? b.messages[b.messages.length - 1].msg.ts : 0
    return tb - ta
  })
  // Wire delegated click once (container persists across row rebuilds)
  if (!container.dataset.delegated) {
    container.dataset.delegated = '1'
    container.addEventListener('click', (e) => {
      const row = (e.target as HTMLElement).closest<HTMLElement>('.lp-thread-row')
      if (!row) return
      e.preventDefault(); e.stopPropagation()
      lpFocusEl(row)
      if (window.innerWidth <= 520) {
        // Mobile navigates away from the list entirely — refocusing its
        // search input (desktop convenience, list stays visible there) used
        // to silently no-op back when the pane went display:none on nav; now
        // that it's just transformed off-screen (for the slide animation),
        // the same call actually succeeds and pops the keyboard.
        document.getElementById('app')?.classList.remove('show-left')
      } else {
        document.getElementById('lp-search')?.focus()
      }
    })
  }

  container.innerHTML = ''

  for (const g of groups) {
    const row = document.createElement('div')
    row.className = 'lp-thread-row'
    row.dataset.threadKey = g.key
    const lastTs = g.messages.length ? g.messages[g.messages.length - 1].msg.ts : 0
    const title = document.createElement('span')
    title.className = 'lp-thread-row-title'
    title.textContent = g.subject || '(no title)'
    const ts = document.createElement('span')
    ts.className = 'lp-thread-row-ts'
    ts.textContent = fmtThreadTs(lastTs)
    row.append(title, ts)
    row.addEventListener('mouseenter', () => { if (window.innerWidth > 520) lpFocusEl(row) })
    container.appendChild(row)
  }
  if (isExpanded) syncNavFocus()
}

// ── Inbox cache ───────────────────────────────────────────────────────────────

export const inboxCache = new Map<string, {
  processed: any[],
  renderedKeys: Set<string>,
  lastTs: number,
  focusedThreadKey: string | null,
}>()

export function saveCurrentInbox() {
  if (!currentInbox) return
  inboxCache.set(isk(currentInbox), {
    processed: processedMessages.slice(),
    renderedKeys: new Set(renderedKeys),
    lastTs,
    focusedThreadKey,
  })
}

export function loadInboxState(item: InboxSummary) {
  const c = inboxCache.get(isk(item))
  processedMessages.length = 0
  renderedKeys.clear()
  if (c) {
    processedMessages.push(...c.processed)
    c.renderedKeys.forEach(k => renderedKeys.add(k))
    setLastTs(c.lastTs)
    setFocusedThreadKey(c.focusedThreadKey)
  } else {
    setLastTs(0)
    setFocusedThreadKey(null)
  }
}

// ── Core inbox actions ────────────────────────────────────────────────────────

export async function loadLeftInboxes() {
  const sess = activeSession()
  if (!sess) return
  try {
    const inboxes = await loadInboxSummaries()
    if (inboxes?.length) renderLeftInboxes(inboxes)
  } catch {}
}

export async function switchInbox(item: InboxSummary): Promise<void> {
  const wasInMenuMode = _inMenuMode
  _inMenuMode = false
  _menuResizeObserver?.disconnect()
  const $convMeta = document.getElementById('conv-meta')
  if ($convMeta) $convMeta.style.display = ''
  // No dock.style.display touch here — #reply-dock:empty{display:none}
  // (style.css) already makes visibility a pure function of whether it HAS
  // a reply-box in it, and render() below (thread.ts) is the one place
  // that populates/clears that content. Manually toggling display in
  // multiple places (here, renderMenuInboxImpl, hideCmdPage) alongside that
  // was the actual source of this whole day's bugs — ordering between them
  // could drift, this can't (2026-07-14, user: "この単純なロジックはないわけ？").

  const prev = currentInbox
  if (prev && prev.user === item.user && prev.mailbox === item.mailbox && prev.contact === item.contact) {
    document.getElementById('app')?.classList.remove('show-left')
    if (wasInMenuMode) render()
    return
  }
  saveCurrentInbox()
  setCurrentInbox(item)
  // Warm the DID cache for this contact too (TTL-guarded, see discovery.ts).
  // Previously DID discovery only ran on send (shell.ts), so it was
  // one-sided: the sender's side learned the recipient's DID (and showed the
  // [DID] badge), but a recipient who never replies never triggered the same
  // lookup for the sender — leaving their conversation unbadged even though
  // the same DID relationship exists on both ends.
  if (item.contact && item.inbox_type !== 'group') {
    import('../did/discovery.ts').then(m => m.refreshContact(item.contact)).catch(() => {})
  }
  // Reflect the selected inbox in the URL. Shared encoder (inboxToHash) keeps this
  // identical to the router's permalinks. replaceState avoids firing hashchange,
  // so this doesn't re-enter routing.
  try { history.replaceState(null, '', inboxToHash(item)) } catch { /* non-fatal */ }
  setIsFirstFetch(true)
  loadInboxState(item)
  document.getElementById('app')?.classList.remove('show-left')
  if (lastLeftInboxes.length) renderLeftInboxes(lastLeftInboxes)
  render()
  fetchMessages()
  markRead(item)
}

// Open (or create) a 1:1 ActivityPub conversation with `target` (a full handle
// like y@non.md) and switch to it. Backs the /<user>/ landing page: clicking a
// user's URL drops you straight into a chat with them. No message is sent — the
// inbox is opened so the user types the first line in the reply dock. Best-effort
// caches the target's actor avatar first so the header renders nicely.
export async function openApConversation(target: string): Promise<void> {
  const cfg = (window as any).__BISET_CONFIG__
  const apUrl: string = cfg?.ap_url || (cfg?.hostname ? `https://ap.${cfg.hostname}` : '')
  if (apUrl) {
    try {
      const r = await fetch(`${apUrl}/resolve?acct=${encodeURIComponent(target)}`)
      const j = await r.json()
      if (j?.icon && !avatarDataUrl(target)) saveAvatar(target, j.icon)
    } catch { /* best-effort */ }
  }
  await loadLeftInboxes()
  const existing = lastLeftInboxes.find(i => i.contact === target)
  if (existing) { switchInbox(existing); return }
  // Prefer an AP-relay session so replies route over ActivityPub; fall back to
  // any session (its relay tag drives delivery downstream).
  const apSess = sessions.find(s => isApRelay(s.account.serverUrl)) ?? sessions[0]
  if (!apSess) return
  switchInbox({ user: apSess.account.email, mailbox: '', contact: target, relay: apUrl })
}

export function markRead(item: InboxSummary) {
  const sess = activeSession()
  if (!sess) return
  ;(async () => {
    // Mark all emails from this contact/mailbox as seen
    try {
      const { getInboxEmails } = await import('../app.ts')
      const selfAddr = sess.jmapAccountId || sess.account.email
      const emails = getInboxEmails(item.mailbox, item.contact, selfAddr, identityKey(sess))
      const unread = emails.filter(e => !(e.keywords as any)?.['$seen'])
      if (unread.length) {
        // A merged inbox can hold messages from more than one relay (mail + AP for
        // the same identity) — markSeen must go to each message's own relay/session,
        // not just the active one, or the untouched relay's server-side state
        // reverts the mark on the next sync.
        const byRelay = new Map<string, Email[]>()
        for (const e of unread) {
          const relay = (e as any)._relay as string ?? sess.account.serverUrl
          if (!byRelay.has(relay)) byRelay.set(relay, [])
          byRelay.get(relay)!.push(e)
        }
        for (const [relay, group] of byRelay) {
          const relaySess = sessionForRelay(item.user, relay) ?? sess
          const ids = group.map(e => e.id as string).filter(Boolean)
          if (!ids.length) continue
          try { await jmapEmail.markSeen(relaySess.jmapClient, relaySess.jmapAccountId, ids) }
          catch (e) { console.log('[markRead] markSeen failed for', relay, e) }
        }
        // Persist $seen to the local store too — loadInboxSummaries recomputes
        // has_unread from store keywords, so without this the mark reappears
        // on the next sync (server-change propagation lags).
        for (const e of unread) {
          const kw = ((e as any).keywords ?? {}) as Record<string, boolean>
          kw['$seen'] = true
          ;(e as any).keywords = kw
          messages.put(e)
          await flushMessage(e)
        }
      }
    } catch {}
    const listIdx = lastLeftInboxes.findIndex(i => isk(i) === isk(item))
    if (listIdx >= 0) {
      lastLeftInboxes[listIdx].has_unread = false
      lastLeftInboxes[listIdx].unread_count = 0
      renderLeftInboxes(lastLeftInboxes)
    }
  })()
}

export function isUnread(item: InboxSummary) {
  const found = lastLeftInboxes.find(i => isk(i) === isk(item))
  return !!found?.has_unread
}

// The notif toggle is stored per-account (jmap_notif_<email>), keyed off
// activeSession(). On the menu-hash boot path (main.ts: #config/#account)
// setupLeftPane runs before sessions are loaded, so the first read here sees
// no session and lands on the wrong (empty-email) key — call this again once
// sessions exist to pick up the real saved value and fix the toggle's DOM.
export function syncNotifToggle(): void {
  const notifKey = `jmap_notif_${activeSession()?.account.email ?? ''}`
  setNotifEnabled(localStorage.getItem(notifKey) === '1')
  document.getElementById('config-notif-toggle')?.classList.toggle('on', notifEnabled)
  document.getElementById('lp-notify-toggle')?.classList.toggle('on', notifEnabled)
  // Self-healing: re-arms the push subscription on every boot where the
  // toggle is already on, not just right after the user flips it (idempotent).
  if (notifEnabled) enablePush().catch(() => {})
}

// Archive / un-archive a whole conversation by toggling the $archived keyword on
// every message it currently holds (server-synced) and mirroring it into the
// local store. Archived state is derived from the *latest* message, so a new
// incoming message auto-unarchives (see loadInboxSummaries).
export async function archiveInbox(item: InboxSummary, archived: boolean) {
  const sess = sessionFor(item.user) ?? activeSession()
  if (!sess) return
  const { getInboxEmails } = await import('../app.ts')
  const selfAddr = sess.jmapAccountId || sess.account.email
  const emails = getInboxEmails(item.mailbox, item.contact, selfAddr, identityKey(sess))
  const ids = emails.map(e => e.id as string).filter(Boolean)
  try {
    if (ids.length) await jmapEmail.markArchived(sess.jmapClient, sess.jmapAccountId, ids, archived)
    for (const e of emails) {
      const kw = ((e as any).keywords ?? {}) as Record<string, boolean>
      if (archived) kw['$archived'] = true; else delete kw['$archived']
      ;(e as any).keywords = kw
      messages.put(e)
      await flushMessage(e)
    }
  } catch { showSysMsg(archived ? 'Archive failed' : 'Unarchive failed'); return }
  const idx = lastLeftInboxes.findIndex(i => isk(i) === isk(item))
  if (idx >= 0) lastLeftInboxes[idx].archived = archived
  showSysMsg(archived ? 'Archived' : 'Unarchived')
  await loadLeftInboxes()
}

export async function doDeleteInbox(target: InboxSummary) {
  // Operate on the session that owns this inbox, not necessarily the active one.
  const sess = sessions.find(s => s.account.email === target.user) ?? activeSession()
  let anyAttempted = false
  let anyFailed = false
  if (sess) {
    try {
      const { getInboxEmails } = await import('../app.ts')
      const selfAddr = sess.jmapAccountId || sess.account.email
      const emails = getInboxEmails(target.mailbox, target.contact, selfAddr, identityKey(sess))
      // A merged inbox can hold messages from more than one relay (mail + AP
      // for the same identity) — destroy must go to each message's own
      // relay/session, or ids belonging to the untouched relay fail server-
      // side (silently, since Email/destroy just reports them as
      // notDestroyed rather than throwing) and never actually get deleted.
      const byRelay = new Map<string, Email[]>()
      for (const e of emails) {
        const relay = (e as any)._relay as string ?? sess.account.serverUrl
        if (!byRelay.has(relay)) byRelay.set(relay, [])
        byRelay.get(relay)!.push(e)
      }
      for (const [relay, group] of byRelay) {
        const relaySess = sessionForRelay(target.user, relay) ?? sess
        const ids = group.map(e => e.id as string).filter(Boolean)
        if (!ids.length) continue
        anyAttempted = true
        try {
          await jmapEmail.destroy(relaySess.jmapClient, relaySess.jmapAccountId, ids)
          // Server-side destroy succeeded, but the local store (and its
          // IndexedDB cache) still has these messages — loadLeftInboxes
          // below rebuilds its summary from that local store, so without
          // this the "deleted" inbox reappears until the next full resync.
          for (const e of group) {
            const acct = messages.accountOf(e)
            messages.remove(acct, e.id as string)
            await removeMessage(acct, e.id as string)
          }
        } catch (e) { anyFailed = true; console.warn('[doDeleteInbox] destroy failed for', relay, e) }
      }
    } catch (e) { anyFailed = true; console.warn('[doDeleteInbox] failed', e) }
  }

  const ci = currentInbox
  if (ci && isk(ci) === isk(target)) {
    processedMessages.splice(0)
    renderedKeys.clear()
    setLastTs(0)
    setFocusedThreadKey(null)
  }
  const idxBefore = lastLeftInboxes.findIndex(i => isk(i) === isk(target))
  await loadLeftInboxes()
  const remaining = lastLeftInboxes.filter(i => isk(i) !== isk(target))
  if (ci && isk(ci) === isk(target)) {
    if (remaining.length > 0) switchInbox(remaining[Math.max(0, idxBefore - 1)])
    else render()
  }
  showSysMsg(anyFailed ? 'Delete failed for some messages' : (anyAttempted ? 'Deleted' : 'Nothing to delete'))
}

export async function deleteInbox(item: InboxSummary) {
  if (!confirm(`Delete all messages from "${item.contact || item.mailbox}"?`)) return
  await doDeleteInbox(item)
}

// ── Time formatting ───────────────────────────────────────────────────────────

export function formatLpTime(ts: number | undefined): string {
  if (!ts) return ''
  const d = new Date(ts), now = new Date(), diff = now.getTime() - d.getTime()
  if (diff < 86400000 && d.getDate() === now.getDate())
    return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })
  if (diff < 604800000) return d.toLocaleDateString('en-US', { weekday: 'short' })
  return d.toLocaleDateString('en-US', { month: 'numeric', day: 'numeric' })
}

// ── LP keyboard navigation ────────────────────────────────────────────────────

// Flat ordered list. Expanded accordions contribute thread rows (header visually
// grouped with thread1 via CSS :has); collapsed / empty contribute the header row.
function lpNavItems(): HTMLElement[] {
  const result: HTMLElement[] = []
  for (const inbox of document.querySelectorAll<HTMLElement>('#left-list .lp-item')) {
    if (inbox.style.display === 'none') continue
    const tl = inbox.querySelector<HTMLElement>('.lp-thread-list')
    const rows = tl && tl.style.display !== 'none'
      ? [...tl.querySelectorAll<HTMLElement>('.lp-thread-row')]
      : []
    if (rows.length) for (const row of rows) result.push(row)
    else result.push(inbox)
  }
  return result
}

// Resolve _lpFocusedKey to the current DOM element (recomputed fresh each call).
// If the inbox is expanded and _lpFocusedKey is an inbox key, resolve to thread1
// (the header is visually co-highlighted via CSS :has).
function focusedNavEl(items: HTMLElement[]): HTMLElement | undefined {
  if (_lpFocusedKey?.startsWith('thread:')) {
    const tk = _lpFocusedKey.slice(7)
    return items.find(el => el.dataset.threadKey === tk)
  }
  const key = _lpFocusedKey ?? (currentInbox ? isk(currentInbox) : null)
  if (!key) return undefined
  return items.find(el => el.dataset.inboxKey === key)
    ?? items.find(el =>
      el.closest<HTMLElement>('.lp-item')?.dataset.inboxKey === key &&
      el === el.closest<HTMLElement>('.lp-item')?.querySelector('.lp-thread-list .lp-thread-row'),
    )
}

// Pure CSS: apply focused class to exactly one item. No side effects on data.
// .focused doubles as the keyboard-nav cursor, applied from many render paths
// (renderThreadAccordion, renderLeftInboxes, applyLpSearch, ...) — there's no
// keyboard to navigate with on a touchscreen, and re-applying it on every one
// of those re-renders was flashing an unrelated row/inbox background after
// taps (toggle, thread click, ...). Guarding every call site was whack-a-mole;
// guard the class application here instead so it's fixed everywhere at once.
function navFocusEnabled(): boolean {
  return window.innerWidth > 520
}

export function syncNavFocus() {
  document.querySelectorAll<HTMLElement>('#left-list .lp-item, #left-list .lp-thread-row')
    .forEach(el => el.classList.remove('focused'))
  const items = lpNavItems()
  const target = focusedNavEl(items)
  if (target) {
    if (navFocusEnabled()) target.classList.add('focused')
    lpNavIdx = items.indexOf(target)
  } else {
    lpNavIdx = -1
  }
}

// Set focus on el: update key, apply CSS, trigger data action.
//
// This is the single entry point for "user hover/click intent to view a
// thread" — it must ALWAYS leave menu mode before any render() call reaches
// thread.ts, or that render() silently no-ops (thread.ts's render() bails
// while inMenuMode() is true, by design, so a passive background refresh
// doesn't yank the user off a settings page they're reading). Previously only
// switchInbox() cleared the flag, so the "already on this inbox" fast path
// below (calling render(true) directly, without going through switchInbox)
// left a stale _inMenuMode=true in place — hovering back onto the inbox you
// were on before opening a menu page silently did nothing, while hovering to
// a DIFFERENT (never-visited) inbox worked, because that path always goes
// through switchInbox(). Clearing it here, once, for every path through this
// function, closes that whole bug class rather than patching one call site.
function lpFocusEl(el: HTMLElement) {
  _inMenuMode = false
  document.querySelectorAll<HTMLElement>('#left-list .lp-item, #left-list .lp-thread-row')
    .forEach(item => item.classList.remove('focused'))
  if (navFocusEnabled()) el.classList.add('focused')
  el.scrollIntoView({ block: 'nearest' })
  if (el.classList.contains('lp-thread-row')) {
    const threadKey = el.dataset.threadKey!
    _lpFocusedKey = 'thread:' + threadKey
    const inboxEl = el.closest<HTMLElement>('.lp-item')
    const inboxKey = inboxEl?.dataset.inboxKey
    if (inboxKey && (!currentInbox || isk(currentInbox) !== inboxKey)) {
      const found = lastLeftInboxes.find(i => isk(i) === inboxKey)
      if (found) {
        switchInbox(found).then(() => {
          setFocusedThreadKey(threadKey)
          render(true)
        })
        return
      }
    }
    setFocusedThreadKey(threadKey)
    render(true)
  } else {
    const key = el.dataset.inboxKey!
    _lpFocusedKey = key
    const found = lastLeftInboxes.find(i => isk(i) === key)
    if (found) switchInbox(found)
  }
}

function lpNavClear() {
  lpNavItems().forEach(el => el.classList.remove('focused'))
  _lpFocusedKey = null
  lpNavIdx = -1
}

// ── LP item rendering ─────────────────────────────────────────────────────────

function toggleAccordionForItem(inboxEl: HTMLElement, focusThread = true) {
  const key = inboxEl.dataset.inboxKey!
  const threadList = inboxEl.querySelector<HTMLElement>('.lp-thread-list')
  const toggleBtn = inboxEl.querySelector<HTMLButtonElement>('.lp-thread-toggle')
  if (!threadList) return
  if (_expandedInboxKeys.has(key)) {
    _expandedInboxKeys.delete(key)
    if (toggleBtn) toggleBtn.textContent = '◂'
    threadList.style.display = 'none'
    _lpFocusedKey = key
    syncNavFocus()
  } else {
    _expandedInboxKeys.add(key)
    if (toggleBtn) toggleBtn.textContent = '▾'
    if (currentInbox && isk(currentInbox) === key) {
      renderThreadAccordion()
      threadList.style.display = 'block'
      if (focusThread) {
        const firstRow = threadList.querySelector<HTMLElement>('.lp-thread-row')
        if (firstRow) lpFocusEl(firstRow)
        else syncNavFocus()
      } else {
        syncNavFocus()
      }
    } else {
      const found = lastLeftInboxes.find(i => isk(i) === key)
      if (found) {
        const appEl = document.getElementById('app')
        // Only preserve show-left on narrow/mobile widths, where it's the
        // single-column pane toggle it was meant for — re-adding it
        // unconditionally left it stuck from an earlier (e.g. resized-from-
        // mobile) session and, on desktop, `body:has(#app.show-left)
        // #reply-dock{display:none}` (style.css) then hid the reply box
        // outright with no flicker, a SEPARATE bug from the scroll-race one
        // fixed the same day (2026-07-14, user-reported: dock sometimes
        // never appeared at all, not just flickered and vanished).
        const wasShowLeft = window.innerWidth <= 520 && appEl?.classList.contains('show-left')
        switchInbox(found).then(() => {
          if (wasShowLeft) appEl?.classList.add('show-left')
          threadList.style.display = 'block'
          if (focusThread) {
            const firstRow = threadList.querySelector<HTMLElement>('.lp-thread-row')
            if (firstRow) lpFocusEl(firstRow)
            else syncNavFocus()
          } else {
            syncNavFocus()
          }
        })
      }
    }
  }
}

export function makeLpItem(item: InboxSummary) {
  // The other party only — which of our own mailboxes/relays a conversation
  // lives under is a self-referential detail with no business in the label
  // (mirrors the permalink hash, see utils.ts's inboxToHash). Fallback chain
  // (did/contacts.ts's displayLabelFor): (1) their self-asserted name, (2) a
  // shortened DID if one is known but no name is, (3) the literal address.
  // mailbox is a last-resort fallback for the (should-never-happen)
  // empty-contact case only.
  const contactLabel = item.inbox_type === 'group' ? (item.group_name || item.contact) : (item.contact && displayLabelFor(item.contact))
  const rawName = contactLabel || item.mailbox
  const isCurrent = !!(currentInbox && isk(currentInbox) === isk(item))
  // Suppress the unread badge only for the conversation actually SHOWN in the
  // reading pane — i.e. current AND not sitting behind a menu page (/debug,
  // /config, …). Otherwise a conversation you opened, then left for a menu,
  // keeps its stale "current" flag and silently hides its unread count even
  // though you're not looking at it (exactly the "count won't show" report).
  const viewing = isCurrent && !inMenuMode()
  const unread = !viewing && isUnread(item)
  const a = document.createElement('a')
  a.className = 'lp-item'
  a.href = '#'
  a.dataset.inboxKey = isk(item)
  const p = previewFor(item.latest_body || '')
  // The avatar represents the OTHER party, not us: for a 1:1 that's the contact,
  // for a group its name. rawName carries our own mailbox as a prefix (for the
  // label line), so deriving the initial/colour from it would show self.
  const avatarSubject = (item.inbox_type === 'group' ? (item.group_name || item.contact) : item.contact) || rawName
  const avatarInner = item.avatar_url
    ? `<img src="${item.avatar_url}" style="width:100%;height:100%;object-fit:cover;border-radius:50%;">`
    : avatarSubject.charAt(0).toUpperCase()
  const avatarBg = item.avatar_url ? 'background:transparent' : avatarStyle(avatarSubject)
  const unreadBadge = unread
    ? (item.unread_count ? `<div class="unread-badge">${item.unread_count > 99 ? '99+' : item.unread_count}</div>` : '<div class="unread-dot"></div>')
    : ''
  const avatarHTML = `<div class="lp-avatar" style="${avatarBg}">${avatarInner}${unreadBadge}</div>`
  a.innerHTML = `
    <div class="lp-inner">
      ${avatarHTML}
      <div class="lp-info">
        <div class="lp-name">${esc(rawName)}</div>
        <div class="lp-preview">${p.text}</div>
      </div>
      <button class="lp-thread-toggle" tabindex="-1">◂</button>
    </div>
    <div class="lp-thread-list" style="display:none"></div>
  `
  if (_expandedInboxKeys.has(isk(item))) {
    a.querySelector<HTMLElement>('.lp-thread-list')!.style.display = 'block'
    a.querySelector<HTMLButtonElement>('.lp-thread-toggle')!.textContent = '▾'
  }
  // Mobile toggle button
  a.querySelector<HTMLButtonElement>('.lp-thread-toggle')?.addEventListener('click', (e) => {
    e.preventDefault(); e.stopPropagation()
    toggleAccordionForItem(a, false)
  })
  // Header hover → focus thread1. Rightmost 20% is excluded (toggle area).
  // Uses mousemove so crossing from right→left zone also triggers.
  const innerEl = a.querySelector<HTMLElement>('.lp-inner')
  if (innerEl) {
    let _hoverFired = false
    const triggerHeaderFocus = () => {
      const firstRow = a.querySelector<HTMLElement>('.lp-thread-list .lp-thread-row')
      if (firstRow) {
        lpFocusEl(firstRow)
      } else {
        const found = lastLeftInboxes.find(i => isk(i) === isk(item))
        if (found) switchInbox(found).then(() => {
          const fr = a.querySelector<HTMLElement>('.lp-thread-list .lp-thread-row')
          if (fr) lpFocusEl(fr)
        })
      }
    }
    innerEl.addEventListener('mouseenter', () => { _hoverFired = false })
    innerEl.addEventListener('mouseleave', () => { _hoverFired = false })
    innerEl.addEventListener('mousemove', (e) => {
      if (_hoverFired || window.innerWidth <= 520) return
      const rect = innerEl.getBoundingClientRect()
      if (e.clientX > rect.right - rect.width * 0.1) return
      _hoverFired = true
      triggerHeaderFocus()
    })
  }
  // Avatar → inbox context menu
  const avatarEl = a.querySelector<HTMLElement>('.lp-avatar')
  if (avatarEl) {
    avatarEl.style.cursor = 'pointer'
    avatarEl.addEventListener('click', (e) => {
      e.preventDefault(); e.stopPropagation()
      openInboxMenuFor(item, avatarEl)
    })
  }
  if (p.needsDecrypt) {
    const $pv = a.querySelector('.lp-preview')
    if ($pv) decryptPreviewInto(item.latest_body!, $pv, item.user)
  }
  a.addEventListener('click', (e) => {
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return
    if ((e.target as HTMLElement).closest('.lp-thread-toggle')) return
    e.preventDefault()
    if (a.classList.contains('swiped')) { a.classList.remove('swiped'); return }
    if (window.innerWidth <= 520) {
      // Mobile: navigate to thread1 regardless of accordion state
      const firstRow = a.querySelector<HTMLElement>('.lp-thread-list .lp-thread-row')
      if (firstRow) {
        lpFocusEl(firstRow)
        document.getElementById('app')?.classList.remove('show-left')
      } else {
        const found = lastLeftInboxes.find(i => isk(i) === isk(item))
        if (found) switchInbox(found).then(() => {
          const fr = a.querySelector<HTMLElement>('.lp-thread-list .lp-thread-row')
          if (fr) lpFocusEl(fr)
          // switchInbox already removes show-left
        })
      }
    } else {
      toggleAccordionForItem(a)
      document.getElementById('lp-search')?.focus()
    }
  })
  const delBtn = document.createElement('button')
  delBtn.className = 'lp-delete-btn'
  delBtn.textContent = 'Delete'
  delBtn.addEventListener('click', async e => {
    e.stopPropagation()
    await deleteInbox(item)
  })
  a.appendChild(delBtn)
  // Live-follow swipe: the delete button reveals in step with the finger
  // instead of only snapping in once a threshold is crossed at touchend.
  // Direction is decided after a small movement (like the right-swipe-to-
  // open-list gesture in main.ts) so a mostly-vertical touch still scrolls
  // the list normally.
  const SWIPE_MAX = 72
  let touchStartX = 0
  let touchStartY = 0
  let swipeDragging = false
  let swipeLocked: 'x' | 'y' | null = null
  let dragDx = 0
  a.addEventListener('touchstart', e => {
    touchStartX = e.touches[0].clientX
    touchStartY = e.touches[0].clientY
    swipeLocked = null
    swipeDragging = false
    if (innerEl) innerEl.style.transition = 'none'
  }, { passive: true })
  a.addEventListener('touchmove', e => {
    const dx = e.touches[0].clientX - touchStartX
    const dy = e.touches[0].clientY - touchStartY
    if (!swipeLocked) {
      if (Math.abs(dx) < 8 && Math.abs(dy) < 8) return
      swipeLocked = Math.abs(dx) > Math.abs(dy) * 1.5 ? 'x' : 'y'
      swipeDragging = swipeLocked === 'x'
    }
    if (!swipeDragging) return
    e.preventDefault()
    const base = a.classList.contains('swiped') ? -SWIPE_MAX : 0
    dragDx = Math.max(-SWIPE_MAX, Math.min(0, base + dx))
    if (innerEl) innerEl.style.transform = `translateX(${dragDx}px)`
    const revealFrac = Math.abs(dragDx) / SWIPE_MAX
    delBtn.style.opacity = String(revealFrac)
    delBtn.style.pointerEvents = revealFrac > 0.5 ? 'auto' : 'none'
  }, { passive: false })
  a.addEventListener('touchend', () => {
    if (innerEl) innerEl.style.transition = ''
    delBtn.style.opacity = ''
    delBtn.style.pointerEvents = ''
    if (innerEl) innerEl.style.transform = ''
    if (swipeDragging) {
      if (dragDx < -SWIPE_MAX / 2) lpRevealDelete(a)
      else a.classList.remove('swiped')
    }
    swipeDragging = false
  }, { passive: true })
  return a
}

let archivedExpanded = false

export function renderLeftInboxes(inboxes: InboxSummary[]) {
  setLastLeftInboxes(inboxes)
  // Badge = total unread MESSAGES (not conversations) — matches what a user
  // counting "2 messages arrived" expects, and mirrors iOS Mail/Messages. Safe
  // now that reactions/edits are excluded everywhere (they never carry an
  // unread_count into a surfaced inbox). Falls back to has_unread as 1 for any
  // inbox that somehow lacks a computed count.
  syncAppBadge(inboxes
    .filter(i => !i.archived && i.has_unread)
    .reduce((sum, i) => sum + (i.unread_count ?? 1), 0))
  const $list = document.getElementById('left-list')
  if (!$list) return
  // Drop any prior archived section so the active-list diff below sees a clean
  // DOM (it's rebuilt from scratch at the end of each render).
  $list.querySelectorAll('.lp-archive-section').forEach(el => el.remove())

  if (!inboxes.length) {
    $list.innerHTML = ''
    const $empty = document.getElementById('lp-empty')
    if ($empty) $empty.style.display = 'block'
    return
  }
  const $empty = document.getElementById('lp-empty')
  if ($empty) $empty.style.display = 'none'

  const active = inboxes.filter(i => !i.archived)
  const archived = inboxes.filter(i => i.archived)

  const existingMap = new Map([...$list.querySelectorAll('.lp-item')].map(el => [(el as HTMLElement).dataset.inboxKey, el]))
  const activeKeys = new Set(active.map(i => isk(i)))

  existingMap.forEach((el, key) => { if (!activeKeys.has(key!)) el.remove() })

  for (let i = 0; i < active.length; i++) {
    const item = active[i]
    const key = isk(item)
    const isCurrent = !!(currentInbox && isk(currentInbox) === key)
    const unread = !(isCurrent && !inMenuMode()) && isUnread(item)
    const p = previewFor(item.latest_body || '')

    let a = existingMap.get(key) as HTMLElement | undefined
    if (!a) {
      const newA = makeLpItem(item)
      const refEl = $list.children[i] ?? null; $list.insertBefore(newA, refEl)
      a = newA
    } else {
      // (selected class removed — focus tracked via _lpFocusedKey / syncNavFocus)
      // Contact name can resolve AFTER this row was first drawn (DIDComm's
      // doc.name arrives async, patched into contactsStore well after the
      // message itself renders — see channel.ts's pollDidCommOnce) — recompute
      // it every pass rather than only at creation, so the raw DID a row was
      // first drawn with doesn't survive until a full reload rebuilds it.
      const contactLabel = item.inbox_type === 'group' ? (item.group_name || item.contact) : (item.contact && displayLabelFor(item.contact))
      const $name = a.querySelector('.lp-name')
      const rawName = contactLabel || item.mailbox
      if ($name && $name.textContent !== rawName) $name.textContent = rawName
      const badge = a.querySelector('.unread-dot, .unread-badge')
      const badgeText = unread && item.unread_count ? (item.unread_count > 99 ? '99+' : String(item.unread_count)) : null
      if (!unread) {
        badge?.remove()
      } else if (badgeText) {
        if (badge?.classList.contains('unread-badge')) {
          if (badge.textContent !== badgeText) badge.textContent = badgeText
        } else {
          badge?.remove()
          const av = a.querySelector('.lp-avatar')
          if (av) av.insertAdjacentHTML('beforeend', `<div class="unread-badge">${badgeText}</div>`)
        }
      } else if (!badge) {
        const av = a.querySelector('.lp-avatar')
        if (av) av.insertAdjacentHTML('beforeend', '<div class="unread-dot"></div>')
      } else if (badge.classList.contains('unread-badge')) {
        badge.remove()
        const av = a.querySelector('.lp-avatar')
        if (av) av.insertAdjacentHTML('beforeend', '<div class="unread-dot"></div>')
      }
      const $preview = a.querySelector('.lp-preview')
      if ($preview && $preview.innerHTML !== p.text) $preview.innerHTML = p.text
      if (p.needsDecrypt && $preview) decryptPreviewInto(item.latest_body!, $preview, item.user)

      const refEl = $list.children[i] ?? null
      if (refEl !== a) $list.insertBefore(a, refEl)
    }
  }

  // Archived conversations live in a collapsible section pinned to the bottom.
  if (archived.length) {
    const sec = document.createElement('div')
    sec.className = 'lp-archive-section'
    const toggle = document.createElement('div')
    toggle.className = 'lp-archive-toggle'
    toggle.innerHTML = `<span class="lp-archive-caret">${archivedExpanded ? '▾' : '▸'}</span><span>Archived (${archived.length})</span>`
    toggle.addEventListener('click', () => { archivedExpanded = !archivedExpanded; renderLeftInboxes(lastLeftInboxes) })
    sec.appendChild(toggle)
    if (archivedExpanded) {
      for (const item of archived) {
        const el = makeLpItem(item)
        el.classList.add('lp-archived-item')
        sec.appendChild(el)
      }
    }
    $list.appendChild(sec)
  }

  applyLpSearch()
  restoreAccordionStates()
  renderThreadAccordion()  // pre-populate thread rows for CSS highlight
  syncNavFocus()
}

function restoreAccordionStates() {
  for (const key of _expandedInboxKeys) {
    const itemEl = [...document.querySelectorAll<HTMLElement>('#left-list .lp-item')]
      .find(el => el.dataset.inboxKey === key)
    if (!itemEl) continue
    const tl = itemEl.querySelector<HTMLElement>('.lp-thread-list')
    if (tl) tl.style.display = 'block'
  }
}

export function applyLpSearch() {
  const q = ((document.getElementById('lp-search') as HTMLInputElement)?.value ?? '').toLowerCase().trim()
  const allItems = [...document.querySelectorAll('#left-list .lp-item')]
  let visible = 0
  allItems.forEach(el => {
    const name = el.querySelector('.lp-name')?.textContent?.toLowerCase() ?? ''
    const show = !q || name.includes(q)
    ;(el as HTMLElement).style.display = show ? '' : 'none'
    if (show) visible++
  })
  syncNavFocus()
  const noMatch = allItems.length && !visible
  const $empty = document.getElementById('lp-empty')
  if ($empty) $empty.style.display = (!q && noMatch) ? 'block' : 'none'
}

export function lpRevealDelete(el: HTMLElement) {
  document.querySelectorAll('#left-list .lp-item.swiped').forEach(x => { if (x !== el) x.classList.remove('swiped') })
  el.classList.add('swiped')
}

// ── Setup ─────────────────────────────────────────────────────────────────────

export async function setupLeftPane() {
  const $app = document.getElementById('app')
  $app?.classList.add('lp-enabled')
  // Left column defaults to OFF (collapsed) and its on/off state is remembered
  // across sessions (localStorage 'lp-open'). Desktop only — on mobile the pane is
  // an overlay governed by 'show-left'.
  if (window.innerWidth > 520) {
    if (localStorage.getItem('lp-open') === '1') $app?.classList.remove('single-col')
    else $app?.classList.add('single-col')
  }
  const savedLpWidth = localStorage.getItem('lp-width')
  if (savedLpWidth) document.documentElement.style.setProperty('--lp-width', savedLpWidth + 'px')

  const resizeHandle = document.getElementById('lp-resize-handle')
  if (resizeHandle) {
    let startX = 0, startWidth = 0
    const onMouseMove = (e: MouseEvent) => {
      const w = Math.max(200, Math.min(600, startWidth + e.clientX - startX))
      document.documentElement.style.setProperty('--lp-width', w + 'px')
      localStorage.setItem('lp-width', String(w))
    }
    const onMouseUp = () => {
      document.removeEventListener('mousemove', onMouseMove)
      document.removeEventListener('mouseup', onMouseUp)
      document.body.style.cursor = ''
      document.body.style.userSelect = ''
    }
    resizeHandle.addEventListener('mousedown', (e) => {
      startX = e.clientX
      startWidth = parseInt(getComputedStyle(document.documentElement).getPropertyValue('--lp-width')) || 300
      document.addEventListener('mousemove', onMouseMove)
      document.addEventListener('mouseup', onMouseUp)
      document.body.style.cursor = 'col-resize'
      document.body.style.userSelect = 'none'
      e.preventDefault()
    })
  }

  syncNotifToggle()

  function toggleCmdPalette(e: Event) {
    e.stopPropagation()
    if (($lpSearch as HTMLInputElement).value.startsWith('/')) {
      ($lpSearch as HTMLInputElement).value = ''
      hideCmdPalette()
      applyLpSearch()
    } else {
      ($lpSearch as HTMLInputElement).value = '/'
      showCommands('/')
      $lpSearch.focus()
    }
  }

  const $lpSearch = document.getElementById('lp-search')!
  const $lpCmds = document.getElementById('lp-commands')!
  const $cmdPage = document.getElementById('cmd-page')!
  const $outer = document.getElementById('outer')!

  // ── cmd pages ──

  function renderAccountPage() {
    return `<div class="cmd-page-content wide-page">
      <div class="cmd-page-section" id="cmd-acc-identity-section" style="display:none">
        <div id="cmd-acc-identity-fields">
          <div id="cmd-acc-identity-avatar" class="lp-avatar"></div>
          <div id="cmd-acc-identity-text">
            <div id="cmd-acc-identity-name" title="Click to change display name"></div>
            <div id="cmd-acc-identity-did-row">
              <span id="cmd-acc-identity-did" title="Click to view DID document"></span>
              <button id="cmd-acc-identity-copy" type="button" aria-label="Copy DID" title="Copy DID"><svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg></button>
            </div>
          </div>
          <button id="cmd-acc-identity-menu-btn" type="button" aria-label="Menu"><svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><circle cx="12" cy="5" r="1.5"/><circle cx="12" cy="12" r="1.5"/><circle cx="12" cy="19" r="1.5"/></svg></button>
        </div>
        <div id="cmd-acc-identity-expanded">
          <button id="cmd-acc-identity-republish" type="button" aria-label="Republish to DHT" title="Republish to DHT"><svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 1 1-2.64-6.36"/><path d="M21 3v6h-6"/></svg></button>
          <pre id="cmd-acc-identity-doc"></pre>
        </div>
      </div>
      <div class="cmd-page-section" id="cmd-acc-list"></div>
      <div class="cmd-page-section" id="cmd-acc-panel" style="display:none">
        <div class="cmd-acc-relay-row">
          <input id="cmd-acc-relay" class="cmd-input" type="text" placeholder="Relay URL (ex. biset.md)" required>
          <span id="cmd-acc-relay-badge"></span>
        </div>
        <div id="cmd-acc-relay-error" class="cmd-acc-error" style="display:none"></div>
        <div id="cmd-acc-choice">
          <button type="button" class="cmd-acc-choice-btn" data-mode="add">Sign up</button>
          <button type="button" class="cmd-acc-choice-btn" data-mode="login">Log in</button>
        </div>
        <div id="cmd-acc-signup-body" style="display:none"></div>
        <form id="cmd-acc-form" class="cmd-form" style="display:none" autocomplete="on">
          <div class="cmd-acc-email-row">
            <input id="cmd-acc-email" class="cmd-input" type="text" placeholder="Email" autocomplete="username" required>
          </div>
          <div class="cmd-acc-login-row">
            <input id="cmd-acc-password" class="cmd-input" type="password" placeholder="Password" autocomplete="current-password" required>
            <button id="cmd-acc-add" type="submit" class="cmd-page-btn primary">Add</button>
          </div>
          <div id="cmd-acc-error" class="cmd-acc-error" style="display:none"></div>
        </form>
      </div>
    </div>`
  }

  // Resets the "+ New JMAP account" panel back to its opening screen (the
  // Sign up / Log in choice) and clears whatever was typed into either form.
  // Called both when the trigger card opens the panel and after Add
  // succeeds/fails, so there's no separate Cancel button to do this instead.
  function resetAddAccountPanel(): void {
    const choice = document.getElementById('cmd-acc-choice') as HTMLElement | null
    const addForm = document.getElementById('cmd-acc-form') as HTMLFormElement | null
    const signupBody = document.getElementById('cmd-acc-signup-body') as HTMLElement | null
    if (choice) choice.style.display = 'flex'
    // Restore Sign up / Log in and drop any mediator "Register" swap from a
    // previous open (the blur handler re-applies it if the URL is a mediator).
    choice?.querySelectorAll<HTMLButtonElement>('.cmd-acc-choice-btn').forEach(b => { b.style.display = '' })
    document.getElementById('cmd-acc-mediator-register')?.remove()
    if (addForm) addForm.style.display = 'none'
    if (signupBody) { signupBody.style.display = 'none'; signupBody.textContent = '' }
    for (const id of ['cmd-acc-relay', 'cmd-acc-email', 'cmd-acc-password']) {
      const el = document.getElementById(id) as HTMLInputElement | null
      if (el) el.value = ''
    }
    const relayInput = document.getElementById('cmd-acc-relay') as HTMLInputElement | null
    if (relayInput) relayInput.disabled = false
    const relayRow = relayInput?.closest('.cmd-acc-relay-row') as HTMLElement | null
    relayRow?.classList.remove('locked')
    if (relayRow) relayRow.style.display = ''
    const relayBadge = document.getElementById('cmd-acc-relay-badge')
    if (relayBadge) relayBadge.textContent = ''
    const relayErr = document.getElementById('cmd-acc-relay-error')
    if (relayErr) relayErr.style.display = 'none'
    const formErr = document.getElementById('cmd-acc-error')
    if (formErr) formErr.style.display = 'none'
  }

  function onShowAccount() {
    onShowAccounts()

    const relayInput = document.getElementById('cmd-acc-relay') as HTMLInputElement | null
    const relayErr = document.getElementById('cmd-acc-relay-error')
    const addForm = document.getElementById('cmd-acc-form') as HTMLFormElement | null

    // Protocol pill(s) for whatever relay is typed — queries that relay's own
    // /relay-info directly (accurate for ANY relay, not a heuristic tied to
    // biset's own AP relay the way the old email-domain check was). A bare
    // apex (expandDualRelay) resolves to two relays, so both get their own
    // pill instead of only the one that happened to answer last.
    relayInput?.addEventListener('blur', async () => {
      const badge = document.getElementById('cmd-acc-relay-badge')
      if (!badge) return
      badge.innerHTML = ''
      const raw = relayInput.value.trim().replace(/\/$/, '')
      if (!raw) return

      // A DIDComm mediator has no account — it needs registering, not signing up
      // or logging in. Detect it and swap the Sign up / Log in choice for a
      // single credential-less "Register".
      const { isMediatorUrl } = await import('../did/create-standalone.ts')
      const isMed = await isMediatorUrl(raw)
      if (relayInput.value.trim().replace(/\/$/, '') !== raw) return // stale by the time it resolved
      const choiceEl = document.getElementById('cmd-acc-choice') as HTMLElement | null
      const modeBtns = choiceEl?.querySelectorAll<HTMLButtonElement>('.cmd-acc-choice-btn')
      let regBtn = document.getElementById('cmd-acc-mediator-register') as HTMLButtonElement | null
      if (isMed) {
        modeBtns?.forEach(b => { b.style.display = 'none' })
        if (!regBtn && choiceEl) {
          regBtn = document.createElement('button')
          regBtn.id = 'cmd-acc-mediator-register'
          regBtn.type = 'button'
          // Same look as Sign up / Log in (.cmd-acc-choice-btn). The setup loop
          // that attaches the relay handler to that class skips this id, and it
          // ran before this button existed anyway.
          regBtn.className = 'cmd-acc-choice-btn'
          regBtn.style.cssText = 'flex:1;font-family:inherit'
          regBtn.textContent = 'Register with mediator'
          choiceEl.appendChild(regBtn)
          regBtn.addEventListener('click', async () => {
            regBtn!.disabled = true; regBtn!.textContent = 'Registering…'
            try {
              const { registerWithMediator } = await import('../did/create-standalone.ts')
              const reg = await registerWithMediator(relayInput.value.trim())
              showSysMsg('Registered with mediator')
              const panel = document.getElementById('cmd-acc-panel'); if (panel) panel.style.display = 'none'
              resetAddAccountPanel()
              renderAccountsList()
              // Wire the new channel into the same left/right column UI every
              // other conversation uses (did/didcomm/channel.ts) — without
              // this the mediator card would appear but no inbox would ever
              // show DIDComm messages until the next full reload.
              const { setupDidCommChannel } = await import('../did/didcomm/channel.ts')
              await setupDidCommChannel(reg.own.did, () => { import('./shell.ts').then(s => s.fetchMessages()); loadLeftInboxes() })
            } catch (e) {
              regBtn!.disabled = false; regBtn!.textContent = 'Register with mediator'
              showSysMsg('Register failed: ' + (e instanceof Error ? e.message : String(e)), 8000)
            }
          })
        }
        if (regBtn) regBtn.style.display = ''
        return // a mediator has no relay-type pills
      }
      modeBtns?.forEach(b => { b.style.display = '' })
      if (regBtn) regBtn.style.display = 'none'

      const dual = expandDualRelay(raw)
      const urls = dual ?? [/^https?:\/\//i.test(raw) ? raw : 'https://' + raw]
      const { fetchRelayInfo, relayInfoFor } = await import('../context.ts')
      await Promise.all(urls.map(u => fetchRelayInfo(u)))
      if (relayInput.value.trim().replace(/\/$/, '') !== raw) return // stale by the time it resolved
      const pills = urls
        .map(u => relayInfoFor(u)?.type)
        .filter((t): t is 'mail' | 'activitypub' => !!t)
        .map(t => `<span style="font-size:10px;font-weight:700;color:#fff;border-radius:4px;padding:1px 5px;flex-shrink:0;background:${t === 'activitypub' ? '#8b5cf6' : '#64748b'}">${t === 'activitypub' ? 'AP' : 'Mail'}</span>`)
      if (!pills.length) return
      badge.style.cssText = 'display:flex;gap:4px;flex-shrink:0'
      badge.innerHTML = pills.join('')
    })

    // Relay URL is required up front for either path — Sign up (provision a
    // new address under the current identity there) or Log in (an account
    // that already exists there). See ARC.md 2026-07-14 "Add account"
    // unification; opened via the "+ New JMAP account" trigger card at the
    // end of the account list (renderAccountsList) — kept as a static panel
    // outside the dynamically-rebuilt list so in-progress input survives a
    // re-render.
    for (const btn of document.querySelectorAll<HTMLButtonElement>('.cmd-acc-choice-btn')) {
      btn.addEventListener('click', async () => {
        if (relayErr) relayErr.style.display = 'none'
        const raw = relayInput?.value.trim()
        if (!raw) {
          if (relayErr) { relayErr.textContent = 'Relay URL required'; relayErr.style.display = 'block' }
          relayInput?.focus()
          return
        }
        // The relay is committed for the rest of this flow (Sign up's steps,
        // or the Log in form below) — lock it instead of leaving an editable
        // field sitting above steps that already depend on its value.
        if (relayInput) relayInput.disabled = true
        relayInput?.closest('.cmd-acc-relay-row')?.classList.add('locked')
        const choice = document.getElementById('cmd-acc-choice') as HTMLElement | null
        if (btn.dataset.mode === 'add') {
          // Passed exactly as typed (not URL-prefixed): openAddRelayOrDomainFlow
          // itself distinguishes a relay URL from a bare domain by whether a
          // scheme is present — force-prefixing here would misroute a bare BYO
          // domain into the arbitrary-relay branch instead of the domain-
          // ownership one. Renders inline in this same panel (signupBody)
          // instead of a separate overlay — matches Log in's own inline reveal
          // rather than popping a different UI out from under it.
          const signupBody = document.getElementById('cmd-acc-signup-body') as HTMLElement | null
          if (!signupBody) return
          if (choice) choice.style.display = 'none'
          signupBody.style.display = 'block'
          const { openAddRelayOrDomainFlow } = await import('./custom-domain.ts')
          openAddRelayOrDomainFlow(raw, signupBody, resetAddAccountPanel)
          return
        }
        if (choice) choice.style.display = 'none'
        // 'contents', not 'flex' — the form itself generates no box (style.css
        // #cmd-acc-form), so its rows join the panel's own flex gap directly.
        if (addForm) addForm.style.display = 'contents'
        ;(document.getElementById('cmd-acc-email') as HTMLInputElement)?.focus()
      })
    }
  }

  // ── /debug: unread reconciliation diagnostic ─────────────────────────────────
  // Temporary. Shows the unread messages the SERVER reports vs how the LOCAL
  // store attributes each one, so a stuck "Unread: N" that won't clear can be
  // traced to the exact messages + inboxes responsible (are they even in the
  // local store? what inbox key? group or 1:1? which relay?).
  function renderDebugPage() {
    return `<div class="cmd-page-content wide-page">
      <div class="cmd-page-section">
        <h3>Unread diagnostic <span id="debug-copy-hint" style="font-size:11px;font-weight:400;color:var(--text-dim)">— tap to copy</span></h3>
        <pre id="debug-out" style="white-space:pre-wrap;word-break:break-all;font-size:11px;font-family:ui-monospace,monospace;line-height:1.5;margin:0;cursor:pointer">Loading…</pre>
      </div>
    </div>`
  }

  async function onShowDebug() {
    const out = document.getElementById('debug-out')
    if (!out) return
    // Tap anywhere on the output to copy it — saves fiddly text selection on
    // mobile when relaying this back for debugging.
    out.addEventListener('click', async () => {
      const hint = document.getElementById('debug-copy-hint')
      try {
        await navigator.clipboard.writeText(out.textContent ?? '')
        if (hint) { hint.textContent = '— copied!'; setTimeout(() => { hint.textContent = '— tap to copy' }, 1500) }
      } catch {
        // clipboard API can be unavailable (insecure context / denied) — fall
        // back to selecting the text so a manual copy is one gesture.
        const range = document.createRange()
        range.selectNodeContents(out)
        const sel = window.getSelection()
        sel?.removeAllRanges()
        sel?.addRange(range)
        if (hint) { hint.textContent = '— selected, ⌘C / long-press copy'; setTimeout(() => { hint.textContent = '— tap to copy' }, 2500) }
      }
    })
    const lines: string[] = []
    try {
      for (const s of sessions) {
        const email = s.account.email
        // Server truth: one Email/query+get per session, count non-seen non-own.
        const [qr] = await s.jmapClient.api.Email.query({ accountId: s.jmapAccountId, limit: 5000 } as any)
        const ids: string[] = (qr as any).ids ?? []
        let serverUnread: any[] = []
        if (ids.length) {
          const [gr] = await s.jmapClient.api.Email.get({
            accountId: s.jmapAccountId, ids: ids as any,
            properties: ['id', 'keywords', 'from', 'subject', 'headers', 'mailboxIds'],
          })
          serverUnread = ((gr as any).list ?? []).filter((e: any) => {
            const from = e.from?.[0]?.email ?? ''
            return from !== email && !e.keywords?.['$seen'] && !isSecurejoinEmail(e) && !isReaction(e)
          })
        }
        lines.push(`=== ${email} @ ${s.account.serverUrl} ===`)
        lines.push(`SERVER unread (non-seen, non-own, non-noise): ${serverUnread.length}`)
        // Local store view — is each server-unread message present locally, and how attributed?
        const local = messages.forIdentity(identityKeyForEmail(email))
        const localById = new Map(local.map(m => [m.id as string, m]))
        for (const e of serverUnread) {
          const from = e.from?.[0]?.email ?? '?'
          const inStore = localById.get(e.id)
          const mbx = Object.keys(e.mailboxIds ?? {}).map(mailboxNameFromId).find(Boolean) ?? '?'
          let attribution = 'NOT IN LOCAL STORE'
          if (inStore) {
            const gid = readGroupHeaders(inStore).id
            const seenLocal = !!(inStore.keywords as any)?.['$seen']
            const flags = [isEdit(inStore) ? 'EDIT' : '', isReaction(inStore) ? 'REACT' : '', isSecurejoinEmail(inStore) ? 'SJOIN' : ''].filter(Boolean).join(',')
            attribution = gid ? `group:${gid.slice(0, 12)}` : `1:1 ${from}`
            attribution += ` | localSeen=${seenLocal}${flags ? ' | ' + flags : ''}`
          }
          lines.push(`  • ${from} | ${attribution}`)
        }
      }
      // What the left pane actually surfaces as unread — the real source of the
      // list. If a store-unread message's inbox isn't here (or shows a smaller
      // count), that inbox is being dropped/undercounted before it can render.
      lines.push('')
      lines.push('=== loadInboxSummaries unread inboxes ===')
      const summaries = await loadInboxSummaries()
      const unreadInboxes = summaries.filter(s => s.has_unread)
      lines.push(`inboxes with has_unread: ${unreadInboxes.length}`)
      for (const s of unreadInboxes) {
        lines.push(`  • ${s.contact} | count=${s.unread_count ?? '?'} | archived=${!!s.archived}`)
      }
      // What the SERVICE WORKER actually did on its last push (written by
      // sw.ts). Confirms which sw.js version is active on this device and
      // whether decrypt/reaction-classification worked in the SW context.
      lines.push('')
      lines.push('=== service worker (last push) ===')
      const reg = ('serviceWorker' in navigator) ? await navigator.serviceWorker.getRegistration() : null
      lines.push(`active SW: ${reg?.active ? 'yes' : 'NO'} | waiting: ${reg?.waiting ? 'yes (update pending!)' : 'no'}`)
      const activeVer = await idb.get(idb.STORES.accounts, 'sw_active_version').catch(() => null)
      lines.push(`active SW version: ${activeVer ?? '?'}`)
      const swdbg = await idb.get(idb.STORES.accounts, 'sw_last_push_debug').catch(() => null) as any
      if (swdbg) {
        lines.push(`version: ${swdbg.version} | ${swdbg.at ? Math.round((Date.now() - swdbg.at) / 1000) + 's ago' : '?'}`)
        lines.push(`candidates=${swdbg.candidates} pgp=${swdbg.pgp} decryptOk=${swdbg.decryptOk} decryptFail=${swdbg.decryptFail}`)
        lines.push(`classify: reaction=${swdbg.reaction} edit=${swdbg.edit} real=${swdbg.real}`)
        lines.push(`badge=${swdbg.badge} willNotify=${swdbg.willNotify} (realCount=${swdbg.realCount} freshCount=${swdbg.freshCount})`)
        lines.push(`lastDisposition: ${swdbg.lastDisp ?? '?'}`)
        lines.push(`lastHeaderKeys: ${swdbg.lastHdrKeys ?? '?'}`)
      } else {
        lines.push('no push processed yet by this SW')
      }
    } catch (err) {
      lines.push('ERROR: ' + (err as any)?.message)
    }
    out.textContent = lines.join('\n')
  }

  function renderConfigPage() {
    // File System Access API — unsupported on any iOS browser (all engines are
    // WebKit there, per Apple policy) and on Firefox. Hide rather than show a
    // button that will just throw.
    const vaultSection = 'showDirectoryPicker' in window
      ? `<div class="cmd-page-section">
        <h3>Vault (Markdown)</h3>
        <button id="vault-enable-btn">Select folder to enable</button>
      </div>`
      : ''
    return `<div class="cmd-page-content wide-page">
      <div class="cmd-page-section">
        <h3>Notifications</h3>
        <div class="cmd-page-row">
          <span>Push notifications</span>
          <div class="toggle-switch${notifEnabled ? ' on' : ''}" id="config-notif-toggle" style="cursor:pointer"></div>
        </div>
      </div>
      ${vaultSection}
    </div>`
  }

  async function onShowConfig() {
    const $tog = document.getElementById('config-notif-toggle')
    if ($tog) {
      $tog.addEventListener('click', async () => {
        if (!notifEnabled) {
          if (Notification.permission === 'denied') { alert('Notifications are blocked in this browser.'); return }
          if (Notification.permission !== 'granted') {
            const r = await Notification.requestPermission()
            if (r !== 'granted') return
          }
        }
        setNotifEnabled(!notifEnabled)
        localStorage.setItem(`jmap_notif_${activeSession()?.account.email ?? ''}`, notifEnabled ? '1' : '0')
        $tog.classList.toggle('on', notifEnabled)
        document.getElementById('lp-notify-toggle')?.classList.toggle('on', notifEnabled)
        if (notifEnabled) enablePush().catch(() => {})
        else disablePush().catch(() => {})
      })
    }

    // Vault opt-in
    const $vaultBtn = document.getElementById('vault-enable-btn') as HTMLButtonElement | null
    console.log('[vault] onShowConfig, btn:', !!$vaultBtn)
    if ($vaultBtn) {
      $vaultBtn.addEventListener('click', async () => {
        console.log('[vault] click', typeof (window as any).showDirectoryPicker)
        try {
          const handle = await (window as any).showDirectoryPicker({ mode: 'readwrite' })
          console.log('[vault] handle:', handle)
          // Verify write permission
          if ((handle as any).queryPermission) {
            const perm = await (handle as any).queryPermission({ mode: 'readwrite' })
            console.log('[vault] queryPermission:', perm)
            if (perm !== 'granted' && (handle as any).requestPermission) {
              const req = await (handle as any).requestPermission({ mode: 'readwrite' })
              console.log('[vault] requestPermission:', req)
            }
          }
          setVaultHandle(handle)
          console.log('[vault] handle set')
          await querystate.loadFromVault()
          console.log('[vault] querystate loaded')
          await loadFromVault()
          console.log('[vault] loadFromVault done')
          await flushAll()
          console.log('[vault] flushAll returned')
          await startWatch()
          console.log('[vault] startWatch done')
          showSysMsg('Vault enabled')
        } catch (e) {
          if ((e as any)?.name !== 'AbortError') showSysMsg('Vault selection failed')
        }
      })
    }
  }

  function renderComposePage() {
    return `<div class="cmd-page-content compose-page">
      <div class="new-compose-card">
        <div class="new-compose-field">
          <div id="new-recipients" class="new-recipients-list">
            <div class="new-recipient-row" data-kind="to">
              <span class="new-field-label">To</span>
              <span class="new-recip-protos"></span>
              <input class="new-field-input" type="email" placeholder="recipient@example.com" autocomplete="off">
              <button id="new-add-btn" class="new-compose-add-btn" tabindex="-1" style="font-size:18px;padding:0 4px;line-height:1">+</button>
            </div>
          </div>
        </div>
        <div id="new-from-field" class="new-compose-field" style="align-items:center">
          <span class="new-field-label">From</span>
          <button type="button" id="new-from" class="new-field-input new-from-btn"></button>
        </div>
        <div id="new-title-field" class="new-compose-field">
          <span id="new-title-label" class="new-field-label">Subject</span>
          <input id="new-title" class="new-field-input" placeholder="(no subject)" autocomplete="off">
        </div>
        <div class="new-compose-body-field">
          <span class="new-field-label">Body</span>
          <textarea id="new-body" placeholder="Write a message…"></textarea>
        </div>
        <div class="reply-attachments" id="new-attachments" style="display:none"></div>
        <div class="new-compose-actions" style="justify-content:flex-end">
          <button id="new-attach-btn" class="reply-attach-btn" type="button" title="Attach file">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/></svg>
          </button>
          <input id="new-attach-input" type="file" multiple style="display:none">
          <div class="t-send-wrap">
            <div class="t-send-avatar" id="new-send-avatar"></div>
            <button id="new-send-btn" class="t-send-btn" title="Send">
              <svg viewBox="0 0 24 24"><path d="M2 12L22 2L12 22L10 14L2 12Z"/></svg>
            </button>
          </div>
        </div>
      </div>
    </div>`
  }

  async function onShowNew() {
    const recipientsDiv = document.getElementById('new-recipients')!
    const addBtn = document.getElementById('new-add-btn')

    // A DIDComm-registered identity's synthetic session (did/didcomm/channel.ts)
    // may not exist in sessions[] yet — main.ts registers it fire-and-forget
    // (best-effort, non-blocking) for a relay-backed identity that ALSO has
    // DIDComm, so a compose opened moments after boot can race it. Actively
    // check+register here instead of passively trusting sessions[]'s current
    // contents, so the From selector never silently omits (or, worse, ends up
    // entirely empty for) the one identity a relay-less user actually has.
    let ownChannelDid: string | null = null
    {
      const did = currentIdentityDid()
      if (did) {
        const { hasDidCommChannel, ensureDidCommSession } = await import('../did/didcomm/channel.ts')
        if (await hasDidCommChannel(did)) { ensureDidCommSession(did); ownChannelDid = did } // idempotent — no-op if already registered
      }
    }

    // ── Per-recipient protocol options ──────────────────────────────────────
    // A recipient row can have MULTIPLE viable delivery protocols — an email
    // address might also be a discoverable ActivityPub actor and/or have a DID
    // anchor; a did: address might advertise mail/AP endpoints in its own
    // document. Each option carries the EFFECTIVE address to send to for that
    // protocol (an AP/mail address discovered off a DID's document, or the DID
    // itself when an email turns out to have one) — never resolved
    // automatically into the compose, only offered as a click-to-pick pill
    // (see request history: auto-redirecting a typed DID to a resolved email
    // was explicitly the wrong behavior).
    type Proto = 'mail' | 'ap' | 'did'
    interface ProtoOption { protocol: Proto; address: string }
    const PROTO_COLOR: Record<Proto, string> = { mail: '#64748b', ap: '#8b5cf6', did: '#0ea5e9' }
    const PROTO_TEXT: Record<Proto, string> = { mail: 'Mail', ap: 'AP', did: 'DID' }
    const rowProtoOptions = new WeakMap<HTMLElement, ProtoOption[]>()
    const rowProtoSelected = new WeakMap<HTMLElement, Proto>()
    const rowProtoManual = new WeakSet<HTMLElement>() // user explicitly clicked a pill — stop auto-switching it
    const rowEffective = (row: HTMLElement): ProtoOption | undefined => {
      const opts = rowProtoOptions.get(row) ?? []
      const sel = rowProtoSelected.get(row)
      return opts.find(o => o.protocol === sel) ?? opts[0]
    }
    const rowProtosEl = (row: HTMLElement): HTMLElement => {
      let el = row.querySelector<HTMLElement>('.new-recip-protos')
      if (!el) {
        el = document.createElement('span')
        el.className = 'new-recip-protos'
        row.querySelector('.new-field-label')?.after(el)
      }
      return el
    }
    const renderRowProtos = (row: HTMLElement) => {
      const el = rowProtosEl(row)
      el.innerHTML = ''
      const opts = rowProtoOptions.get(row) ?? []
      const sel = rowProtoSelected.get(row)
      for (const o of opts) {
        const b = document.createElement('span')
        b.textContent = PROTO_TEXT[o.protocol]
        const isSel = o.protocol === sel
        b.style.cssText = `font-size:10px;font-weight:700;color:#fff;border-radius:4px;padding:1px 5px;margin-right:6px;flex-shrink:0;cursor:pointer;user-select:none;background:${isSel ? PROTO_COLOR[o.protocol] : 'rgba(128,128,128,0.4)'}`
        b.title = isSel ? `Sending via ${PROTO_TEXT[o.protocol]}` : `Click to send via ${PROTO_TEXT[o.protocol]} instead`
        b.addEventListener('click', e => {
          e.stopPropagation()
          rowProtoManual.add(row)
          rowProtoSelected.set(row, o.protocol)
          renderRowProtos(row)
          // Show what's actually being sent to, not just what was typed — a
          // DID row that toggled to [Mail]/[AP] displays the mail/AP address
          // its own document claimed for that protocol, not the raw DID.
          const inp = row.querySelector<HTMLInputElement>('.new-field-input')
          if (inp) inp.value = o.address
          syncFromRequirement()
        })
        el.append(b)
      }
    }
    // `forcedDefault`, when its protocol is present in `opts`, wins UNLESS the
    // user already manually picked something for this row (rowProtoManual) —
    // this is what lets "AP just got confirmed" flip the default from mail to
    // AP (matching the old auto-on AP badge) while never overriding an
    // explicit click, and never hijacking a DID row's default away from `did`
    // just because its document also advertises a mail/AP fallback.
    const setRowProtoOptions = (row: HTMLElement, opts: ProtoOption[], forcedDefault?: Proto) => {
      rowProtoOptions.set(row, opts)
      const current = rowProtoSelected.get(row)
      const manual = rowProtoManual.has(row) && current && opts.some(o => o.protocol === current)
      let next: Proto | undefined
      if (manual) next = current
      else if (forcedDefault && opts.some(o => o.protocol === forcedDefault)) next = forcedDefault
      else if (current && opts.some(o => o.protocol === current)) next = current
      else next = opts[0]?.protocol
      if (next) rowProtoSelected.set(row, next); else rowProtoSelected.delete(row)
      renderRowProtos(row)
      syncFromRequirement()
    }
    const clearRowProtos = (row: HTMLElement) => {
      rowProtoOptions.delete(row)
      rowProtoSelected.delete(row)
      rowProtoManual.delete(row)
      renderRowProtos(row)
      syncFromRequirement()
    }

    // Unified compose: no Message/Group toggle. Each recipient row is tagged
    // To/Cc/Bcc; the "+" button chooses which to add. 2+ visible recipients
    // (To+Cc — Bcc is hidden and never turns a chat into a group) => group, so
    // DeltaChat Chat-Group-* headers get attached; a single visible recipient
    // stays a 1:1 chat. Non-DeltaChat peers just fall back (plaintext / no group
    // semantics) — handled downstream by encryptText.
    type Kind = 'to' | 'cc' | 'bcc'
    const collect = () => {
      const out = { to: [] as string[], cc: [] as string[], bcc: [] as string[] }
      for (const row of recipientsDiv.querySelectorAll<HTMLElement>('.new-recipient-row')) {
        const v = row.querySelector<HTMLInputElement>('.new-field-input')?.value.trim()
        if (!v) continue
        out[(row.dataset.kind as Kind) ?? 'to'].push(rowEffective(row)?.address ?? v)
      }
      return out
    }
    const isGroup = () => { const r = collect(); return r.to.length + r.cc.length >= 2 }
    const updateTitleLabel = () => {
      const g = isGroup()
      const lbl = document.getElementById('new-title-label')
      const inp = document.getElementById('new-title') as HTMLInputElement | null
      if (lbl) lbl.textContent = g ? 'Group name' : 'Subject'
      if (inp) inp.placeholder = g ? 'Group name' : '(no subject)'
    }

    // "From" is a CUSTOM dropdown, not a native <select>: each option needs
    // the exact protocol pill (colored [Mail]/[AP]/[DID] badge) the To field
    // and conversation header use — and a native <option> can't host a styled
    // child element, only plain text. The trigger button shows the selected
    // "<pill> address", and clicking it opens a menu of the same rows.
    //
    // One row per SESSION, not per unique email — a relay-backed identity's
    // mail and ActivityPub accounts share the same address but are genuinely
    // different endpoints (different server, different credentials), so both
    // are pickable; the DIDComm endpoint's "address" is the DID itself.
    const fromBtn = document.getElementById('new-from') as HTMLButtonElement | null
    type FromOption = { email: string; serverUrl: string }
    let fromOptions: FromOption[] = []
    let fromSelectedIdx = 0
    // Middle-ellipsis by ACTUAL rendered layout, not canvas font guessing:
    // shrink `span`'s text until `container` (the pill + this span in a flex
    // row, `overflow:hidden`) stops overflowing — measured via the browser's
    // own scrollWidth/clientWidth, so it's exact regardless of font load
    // timing or how wide the field ends up. Produces exactly one `…`.
    // Cheap (a handful of iterations, only when the text overflows) and safe
    // to re-run on resize. The container must already be laid out; callers
    // append it (or it's on-screen) before calling.
    const fitMiddleEllipsis = (container: HTMLElement, span: HTMLElement, full: string) => {
      span.textContent = full
      if (container.scrollWidth <= container.clientWidth) return
      let lo = 1, hi = full.length - 1
      const at = (n: number) => {
        const head = Math.ceil(n / 2)
        span.textContent = full.slice(0, head) + '…' + full.slice(full.length - (n - head))
      }
      while (lo < hi) {
        const mid = Math.ceil((lo + hi) / 2)
        at(mid)
        if (container.scrollWidth <= container.clientWidth) lo = mid; else hi = mid - 1
      }
      at(lo)
    }
    // The shared protocol pill (same style as thread.ts's #conv-via and the
    // recipient AP badge): colored background, white text, to the LEFT of the
    // address. relayProtocolLabel (context.ts) is the single source of the
    // transport's text + color.
    const protoPill = (serverUrl: string): HTMLElement | null => {
      const lbl = relayProtocolLabel(serverUrl)
      if (!lbl) return null
      const s = document.createElement('span')
      s.textContent = lbl.text
      s.style.cssText = `font-size:10px;font-weight:700;color:#fff;background:${lbl.color};border-radius:4px;padding:1px 5px;margin-right:6px;flex-shrink:0`
      return s
    }

    // ── DID display: name + fixed short form ────────────────────────────────
    // A DID is far too long to show whole, and (unlike an email) middle-
    // ellipsizing it to the field width gives a shape that jumps around with
    // layout. shortDid (did/contacts.ts — shared with the inbox list and
    // thread header, not reimplemented here) keeps the did:method: prefix
    // plus just the first/last 3 chars: did:dht:6oi…b7x. When the DID
    // document advertises a name, prepend it: "y / did:dht:6oi…b7x".
    const didNames = new Map<string, string>() // did -> resolved self-asserted name
    const didNameTried = new Set<string>()
    const didDisplayText = (did: string): string => {
      const n = didNames.get(did)
      return n ? `${n} / ${shortDid(did)}` : shortDid(did)
    }
    // Fill in a DID's display name (local Card first — no network — then a
    // document resolve), re-rendering the From button once it lands.
    const ensureDidName = (did: string) => {
      if (didNameTried.has(did)) return
      didNameTried.add(did)
      const local = nameForContact(did)
      if (local) { didNames.set(did, local); renderFromButton(); return }
      resolveDidDocFull(did).then(doc => {
        const nm = (doc as any)?.name as string | undefined
        if (nm) { didNames.set(did, nm); renderFromButton() }
      }).catch(() => {})
    }

    const renderFromButton = () => {
      if (!fromBtn) return
      fromBtn.innerHTML = ''
      const o = fromOptions[fromSelectedIdx]
      if (!o) return
      const pill = protoPill(o.serverUrl)
      if (pill) fromBtn.append(pill)
      const addr = document.createElement('span')
      addr.className = 'from-addr'
      addr.style.cssText = 'white-space:nowrap;min-width:0;overflow:hidden;text-overflow:ellipsis'
      fromBtn.append(addr)
      if (o.serverUrl === DIDCOMM_SERVER_URL || o.email.startsWith('did:')) {
        addr.textContent = didDisplayText(o.email) // fixed short form, no width-fit
        ensureDidName(o.email)
      } else {
        fitMiddleEllipsis(fromBtn, addr, o.email)
      }
      // Dim if the SELECTED option doesn't match what the To field requires —
      // syncFromRequirement already tries to hop off a disallowed selection
      // first; this only shows when no alternative exists to hop to.
      const allowed = fromOptionAllowed(o, requiredFromProto())
      addr.style.opacity = allowed ? '1' : DISABLED_OPACITY
      if (pill) pill.style.opacity = allowed ? '1' : DISABLED_OPACITY
    }

    // ── From⇄To protocol match ──────────────────────────────────────────────
    // A message goes out over exactly ONE transport, decided by the From
    // endpoint: [Mail]→SMTP, [AP]→ActivityPub, [DID]→DIDComm. The FIRST filled
    // recipient's currently-selected protocol pill (see the To-field protocol
    // pills below) narrows which From endpoints are even choosable — a
    // non-matching From option is dimmed AND actually disabled, not just
    // visually muted, so there's no way to end up with a From/To mismatch at
    // send time.
    const DISABLED_OPACITY = '0.25'
    const fromProtoOf = (serverUrl: string): Proto =>
      serverUrl === DIDCOMM_SERVER_URL ? 'did' : isApRelay(serverUrl) ? 'ap' : 'mail'
    const requiredFromProto = (): Proto | null => {
      for (const row of recipientsDiv.querySelectorAll<HTMLElement>('.new-recipient-row')) {
        if (!row.querySelector<HTMLInputElement>('.new-field-input')?.value.trim()) continue
        return rowEffective(row)?.protocol ?? null // filled but not yet resolved — nothing choosable yet either
      }
      return null
    }
    // No required protocol (nothing typed in To yet, or it hasn't resolved)
    // means NOTHING is choosable — every From option is disabled until To
    // actually settles on a transport, rather than defaulting to "anything
    // goes" and risking a From picked before To narrows what's even valid.
    const fromOptionAllowed = (o: FromOption, required: Proto | null): boolean =>
      required !== null && fromProtoOf(o.serverUrl) === required
    // Recomputes which From options are choosable whenever a recipient's
    // protocol selection changes. If the currently-selected From no longer
    // qualifies, hop to the first one that does — "can't be selected" has to
    // mean the actual selection moves, not just that it LOOKS disabled.
    const syncFromRequirement = () => {
      const required = requiredFromProto()
      const current = fromOptions[fromSelectedIdx]
      if (required && current && !fromOptionAllowed(current, required)) {
        const alt = fromOptions.findIndex(o => fromOptionAllowed(o, required))
        if (alt >= 0) { fromSelectedIdx = alt; updateSendAvatar() }
      }
      renderFromButton()
    }
    let fromMenu: HTMLElement | null = null
    const closeFromMenu = () => { fromMenu?.remove(); fromMenu = null }
    const openFromMenu = () => {
      if (!fromBtn) return
      if (fromMenu) { closeFromMenu(); return }
      const menu = document.createElement('div')
      menu.className = 'new-from-menu'
      const r = fromBtn.getBoundingClientRect()
      menu.style.top = r.bottom + 4 + 'px'
      menu.style.left = r.left + 'px'
      menu.style.minWidth = r.width + 'px'
      menu.style.maxWidth = Math.max(r.width, Math.min(window.innerWidth - r.left - 12, 480)) + 'px'
      const required = requiredFromProto()
      const pending: Array<{ row: HTMLElement; addr: HTMLElement; email: string }> = []
      fromOptions.forEach((o, i) => {
        const allowed = fromOptionAllowed(o, required)
        const row = document.createElement('button')
        row.type = 'button'
        row.disabled = !allowed
        row.className = 'new-from-menu-item' + (i === fromSelectedIdx ? ' selected' : '')
        row.style.cssText = allowed ? '' : `opacity:${DISABLED_OPACITY};cursor:not-allowed`
        const pill = protoPill(o.serverUrl)
        if (pill) row.append(pill)
        const addr = document.createElement('span')
        addr.style.cssText = 'white-space:nowrap;min-width:0;overflow:hidden;text-overflow:ellipsis'
        row.append(addr)
        if (allowed) {
          row.addEventListener('click', () => {
            fromSelectedIdx = i
            renderFromButton()
            updateSendAvatar()
            closeFromMenu()
          })
        }
        menu.append(row)
        // A DID row uses the fixed short form + name (same as the button); only
        // email rows get width-fitted (they rarely need it, but a very long one
        // still gets a clean middle-ellipsis).
        if (o.serverUrl === DIDCOMM_SERVER_URL || o.email.startsWith('did:')) {
          addr.textContent = didDisplayText(o.email)
          ensureDidName(o.email)
        } else {
          pending.push({ row, addr, email: o.email })
        }
      })
      document.body.append(menu)
      // Now that the menu is laid out at its real width, fit each email row.
      for (const p of pending) fitMiddleEllipsis(p.row, p.addr, p.email)
      fromMenu = menu
      setTimeout(() => document.addEventListener('click', closeFromMenu, { once: true }), 0)
    }
    fromBtn?.addEventListener('click', e => { e.stopPropagation(); openFromMenu() })
    if (fromBtn) {
      // `sessions` can still be empty on a fresh #new load (init race), so fall
      // back to the stored account list — never leave the selector blank.
      fromOptions = sessions.length
        ? sessions.map(s => ({ email: s.account.email, serverUrl: s.account.serverUrl }))
        : loadStoredAccounts().map(a => ({ email: a.email, serverUrl: a.serverUrl }))
      // Guarantee the identity's DIDComm endpoint is offered whenever it has a
      // channel — covers both the synthetic-session-not-yet-in-sessions[] race
      // and the fallback-to-stored-accounts branch (stored accounts never
      // include the DIDComm pseudo-account).
      if (ownChannelDid && !fromOptions.some(o => o.serverUrl === DIDCOMM_SERVER_URL)) {
        fromOptions.push({ email: ownChannelDid, serverUrl: DIDCOMM_SERVER_URL })
      }
      const activeEmail = activeSession()?.account.email
      fromSelectedIdx = Math.max(0, fromOptions.findIndex(o => o.email === activeEmail))
      renderFromButton()
      if (typeof ResizeObserver !== 'undefined') new ResizeObserver(() => renderFromButton()).observe(fromBtn)
    }
    const selectedFromOption = (): FromOption | undefined => fromOptions[fromSelectedIdx]
    const selectedFrom = () => selectedFromOption()?.email || activeSession()?.account.email || ''

    // Send button mirrors the reply dock: shows the From avatar, revealing the
    // send icon on hover (t-send-wrap CSS). Keep it in sync with the From select.
    const updateSendAvatar = () => {
      const el = document.getElementById('new-send-avatar') as HTMLElement | null
      if (!el) return
      const email = selectedFrom()
      const url = avatarDataUrl(email)
      if (url) {
        el.style.background = 'transparent'
        el.innerHTML = `<img src="${url}">`
      } else {
        el.style.background = (avatarStyle(email).match(/background:([^;]+)/) ?? [])[1] || 'var(--accent)'
        el.textContent = (email[0] || '?').toUpperCase()
      }
    }
    updateSendAvatar()

    // Relay base URLs for this home domain (see account-create.getMailUrl/getApUrl).
    const cfg = (window as any).__BISET_CONFIG__
    const mailUrl = cfg?.mail_url || (cfg?.hostname ? `https://mail.${cfg.hostname}` : '')
    const apUrl = cfg?.ap_url || (cfg?.hostname ? `https://ap.${cfg.hostname}` : '')

    // Resolves ALL viable protocol options for whatever's currently in `inp`
    // and feeds them into the row's protocol pills (rowProto* above) — this is
    // the one place that decides what To offers:
    //   - did: address → always [DID]; if its document also advertises a mail
    //     or ActivityPub service (DidService.protocol/address), those become
    //     additional pills, but DID stays the DEFAULT selection (never
    //     silently redirected to a resolved address — same reasoning as
    //     before: a typed DID sends over DIDComm unless the user explicitly
    //     clicks a different pill).
    //   - email address → [Mail] baseline while probes are in flight. AP
    //     webfinger and a DID DNS anchor are probed IN PARALLEL, but the
    //     final option list is synthesized once BOTH settle (not applied
    //     piecemeal as each resolves) specifically so the AP/mail decision
    //     below can see the DID result no matter which probe happens to
    //     finish first:
    //       - AP hit, no DID record  → [AP] only, mail dropped. Nothing here
    //         can positively confirm OR rule out plain SMTP deliverability
    //         (no MX/mailbox probe exists — an MX record would only prove
    //         the DOMAIN accepts mail for SOME address, not this local
    //         part), so this is a judgment call: an address that
    //         webfinger-resolves to a real actor with no DID anchor behind
    //         it is almost always a fediverse-only handle (mastodon.social
    //         and friends), not a real mailbox.
    //       - AP hit AND a DID record → [Mail] + [AP] together. A DID anchor
    //         is exactly the signal that this is a portable, dual-protocol
    //         biset-native identity (one identity, many endpoints — mail and
    //         ActivityPub genuinely both live at the same address), not a
    //         fediverse-only handle, so mail stays offered.
    //       - no AP hit → [Mail] (+ [DID] if a DID record was found).
    //     AP becomes the DEFAULT selection whenever it's offered (matching
    //     the old auto-on AP badge); a DID hit never forces a default.
    // Loading spinner at the recipient field's right edge, shown only while
    // resolveRecipientProtocols has a resolve in flight (DID doc lookup, or
    // the AP/DID probes for an email address) — the gap between typing a
    // did:dht: address and its [Mail]/[AP] pills actually appearing is a
    // real wait (a DHT/pkarr resolve, not instant), and with nothing here it
    // just looked stalled.
    const recipLoadingEl = (row: HTMLElement): HTMLElement => {
      let el = row.querySelector<HTMLElement>('.recip-loading')
      if (!el) {
        el = document.createElement('span')
        el.className = 'recip-loading'
        row.querySelector('.new-field-input')?.after(el)
      }
      return el
    }
    const setRecipLoading = (row: HTMLElement, loading: boolean) => {
      recipLoadingEl(row).dataset.active = loading ? 'true' : 'false'
    }

    const resolveRecipientProtocols = async (inp: HTMLInputElement) => {
      const row = inp.closest<HTMLElement>('.new-recipient-row')
      if (!row) return
      const addr = inp.value.trim()
      if (!addr) { clearRowProtos(row); setRecipLoading(row, false); return }

      // A pill toggle (renderRowProtos) rewrites the input's displayed text to
      // the effective address for whatever protocol got picked — e.g. a DID
      // row toggled to [Mail] now shows that DID document's claimed mail
      // address. Clicking the pill blurs the input, which would otherwise
      // land right back here and re-probe THAT address from scratch (and,
      // for a mail address that happens to itself resolve as AP, silently
      // flip the selection again). If the row already knows this exact
      // address as one of its own already-resolved options and the user
      // picked it explicitly, there's nothing new to resolve — leave it.
      if (rowProtoManual.has(row) && (rowProtoOptions.get(row) ?? []).some(o => o.address === addr)) return

      if (addr.startsWith('did:')) {
        setRowProtoOptions(row, [{ protocol: 'did', address: addr }], 'did')
        setRecipLoading(row, true)
        try {
          // resolveDidDocFull uses this browser's own relay /pkarr gateways
          // (CORS-open) — did:dht won't resolve through the public gateways
          // from a file:// page.
          const doc = await resolveDidDocFull(addr)
          if (inp.value.trim() !== addr) return // stale
          const opts: ProtoOption[] = [{ protocol: 'did', address: addr }]
          for (const s of doc?.service ?? []) {
            if (s.protocol === 'mail' && s.address) opts.push({ protocol: 'mail', address: s.address })
            if (s.protocol === 'activitypub' && s.address) opts.push({ protocol: 'ap', address: s.address })
          }
          setRowProtoOptions(row, opts, 'did')
        } catch { /* best-effort */ } finally { setRecipLoading(row, false) }
        return
      }

      if (!addr.includes('@')) { clearRowProtos(row); setRecipLoading(row, false); return }

      setRowProtoOptions(row, [{ protocol: 'mail', address: addr }], 'mail')
      setRecipLoading(row, true)

      const sess = sessionFor(selectedFrom()) ?? activeSession()
      if (sess && !isApRelay(sess.account.serverUrl)) {
        prefetchRecipientKey(addr, sess.account.email, sess.account.serverUrl, sess.account.password)
      }

      const apProbe = (async (): Promise<boolean> => {
        if (!apUrl) return false
        try {
          const r = await fetch(`${apUrl}/resolve?acct=${encodeURIComponent(addr)}`)
          const j = await r.json()
          // Cache the recipient's actor avatar so the conversation shows it once opened.
          if (j?.icon && !avatarDataUrl(addr)) saveAvatar(addr, j.icon)
          return !!j?.ap
        } catch { return false }
      })()

      const didProbe = (async (): Promise<string | null> => {
        try {
          const { discoverDidForAddress } = await import('../did/discovery.ts')
          return await discoverDidForAddress(addr)
        } catch { return null }
      })()

      // Background contact-cache warm (relays/name durability) — unrelated to
      // the probes above, same TTL-guarded call as always.
      import('../did/discovery.ts').then(m => m.refreshContact(addr)).catch(() => {})

      const [apHit, didHit] = await Promise.all([apProbe, didProbe])
      setRecipLoading(row, false)
      if (inp.value.trim() !== addr) return // stale

      const opts: ProtoOption[] = []
      if (!apHit || didHit) opts.push({ protocol: 'mail', address: addr })
      if (apHit) opts.push({ protocol: 'ap', address: addr })
      if (didHit) opts.push({ protocol: 'did', address: didHit })
      setRowProtoOptions(row, opts, apHit ? 'ap' : 'mail')
    }

    const attachPrefetch = (inp: HTMLInputElement) => {
      inp.addEventListener('input', updateTitleLabel)
      inp.addEventListener('blur', () => { resolveRecipientProtocols(inp) })
    }

    const addRow = (kind: Kind, focus = false) => {
      const row = document.createElement('div')
      row.className = 'new-recipient-row'
      row.dataset.kind = kind
      const tag = document.createElement('span')
      tag.className = 'new-field-label new-field-label-toggle'
      tag.textContent = kind === 'cc' ? 'Cc' : 'Bcc'
      tag.title = 'Click to toggle Cc / Bcc'
      // Cc and Bcc rows are otherwise identical — no separate chooser to add
      // one or the other, just add a Cc row and let its own label toggle it.
      tag.addEventListener('click', () => {
        const next: Kind = row.dataset.kind === 'cc' ? 'bcc' : 'cc'
        row.dataset.kind = next
        tag.textContent = next === 'cc' ? 'Cc' : 'Bcc'
        updateTitleLabel() // Bcc doesn't count toward the group/1:1 decision — a toggle can change it
      })
      const inp = document.createElement('input')
      inp.className = 'new-field-input'
      inp.type = 'email'
      inp.placeholder = 'recipient@example.com'
      inp.autocomplete = 'off'
      attachPrefetch(inp)
      const rm = document.createElement('button')
      rm.className = 'group-remove-btn'
      rm.tabIndex = -1
      rm.textContent = '×'
      rm.addEventListener('click', () => { row.remove(); updateTitleLabel(); syncFromRequirement() })
      row.append(tag, inp, rm)
      recipientsDiv.appendChild(row)
      updateTitleLabel()
      if (focus) inp.focus()
    }

    // "+" adds a Cc row directly — no Cc/Bcc chooser menu; toggle between
    // them by clicking the row's own label (see addRow above).
    addBtn?.addEventListener('click', (e) => {
      e.stopPropagation()
      addRow('cc', true)
    })

    // Mark the initial static row as the To recipient and wire prefetch.
    const firstRow = recipientsDiv.querySelector<HTMLElement>('.new-recipient-row')
    if (firstRow) firstRow.dataset.kind = 'to'
    const firstInp = recipientsDiv.querySelector<HTMLInputElement>('.new-field-input')
    if (firstInp) attachPrefetch(firstInp)
    updateTitleLabel()

    // Pre-fill the To field when compose was opened via openComposeTo (e.g. the
    // /<user>/ page). Resolve straight away so the protocol pills show.
    if (composePrefillTo && firstInp) {
      firstInp.value = composePrefillTo
      composePrefillTo = null
      resolveRecipientProtocols(firstInp)
      updateTitleLabel()
      // Body focus is driven by openComposeTo's retry loop (more reliable across
      // the #new→app transition than a focus() here).
    }

    // Attachments (mail relay only, mirrors thread.ts's reply-box — see
    // pgp/crypto.ts buildMultipartBody for the wire format).
    let pendingAttachments: OutgoingAttachment[] = []
    const newAttachBtn = document.getElementById('new-attach-btn') as HTMLButtonElement | null
    const newAttachInput = document.getElementById('new-attach-input') as HTMLInputElement | null
    const newAttachmentsRow = document.getElementById('new-attachments') as HTMLElement | null
    const renderNewAttachments = () => {
      if (!newAttachmentsRow) return
      newAttachmentsRow.style.display = pendingAttachments.length ? 'flex' : 'none'
      newAttachmentsRow.innerHTML = pendingAttachments.map((a, i) => `
        <span class="reply-attachment-chip" data-idx="${i}">
          <span class="reply-attachment-name">${esc(a.filename)}</span>
          <button type="button" class="reply-attachment-remove" data-idx="${i}" aria-label="Remove">×</button>
        </span>
      `).join('')
    }
    newAttachmentsRow?.addEventListener('click', e => {
      const btn = (e.target as HTMLElement).closest('.reply-attachment-remove') as HTMLElement | null
      if (!btn) return
      pendingAttachments.splice(Number(btn.dataset.idx), 1)
      renderNewAttachments()
    })
    newAttachBtn?.addEventListener('click', () => newAttachInput?.click())
    newAttachInput?.addEventListener('change', async () => {
      const files = Array.from(newAttachInput.files ?? [])
      newAttachInput.value = ''
      for (const f of files) {
        const bytes = new Uint8Array(await f.arrayBuffer())
        pendingAttachments.push({ filename: f.name, contentType: f.type, bytes })
      }
      renderNewAttachments()
    })

    // Cmd/Ctrl+Enter sends, mirroring the reply field (thread.ts). Reuse the send
    // button's click handler so there's a single send path.
    document.getElementById('new-body')?.addEventListener('keydown', e => {
      if (e.key === 'Enter' && !e.isComposing && (e.metaKey || e.ctrlKey)) {
        e.preventDefault()
        ;(document.getElementById('new-send-btn') as HTMLButtonElement)?.click()
      }
    })

    document.getElementById('new-send-btn')?.addEventListener('click', async () => {
      // A row blurred by clicking Send directly (never lost focus, so
      // resolveRecipientProtocols never ran) gets a synchronous baseline here
      // — real resolution also kicked off, but best-effort/non-blocking so a
      // slow network never delays sending.
      for (const inp of recipientsDiv.querySelectorAll<HTMLInputElement>('.new-field-input')) {
        const row = inp.closest<HTMLElement>('.new-recipient-row')
        const v = inp.value.trim()
        if (!row || !v || rowProtoOptions.get(row)) continue
        if (v.startsWith('did:')) setRowProtoOptions(row, [{ protocol: 'did', address: v }], 'did')
        else if (v.includes('@')) setRowProtoOptions(row, [{ protocol: 'mail', address: v }], 'mail')
        resolveRecipientProtocols(inp)
      }
      const { to, cc, bcc } = collect()
      const visible = [...to, ...cc]
      if (!visible.length) { (recipientsDiv.querySelector('.new-field-input') as HTMLElement)?.focus(); return }
      const body = (document.getElementById('new-body') as HTMLTextAreaElement)?.value.trim() || ''
      const fromEmail = selectedFrom()
      const title = (document.getElementById('new-title') as HTMLInputElement)?.value.trim() || ''

      // Protocol from each row's selected pill. A single compose is one
      // protocol — mixing mail, ActivityPub and DIDComm recipients in one
      // message isn't allowed (each is a different transport, DIDComm doesn't
      // even have a "cc").
      const filledRows = [...recipientsDiv.querySelectorAll<HTMLElement>('.new-recipient-row')]
        .filter(r => r.querySelector<HTMLInputElement>('.new-field-input')?.value.trim())
      const apCount = filledRows.filter(r => rowEffective(r)?.protocol === 'ap').length
      const didCount = filledRows.filter(r => rowEffective(r)?.protocol === 'did').length
      if (apCount > 0 && apCount < filledRows.length - didCount) {
        showSysMsg('Mixed mail + ActivityPub recipients not allowed'); return
      }
      if (didCount > 0 && (didCount < filledRows.length || visible.length > 1)) {
        showSysMsg('DIDComm only supports one direct recipient — no mixing with mail/AP or group sends'); return
      }
      if (apCount > 0 && pendingAttachments.length) {
        showSysMsg('Attachments are not supported over ActivityPub'); return
      }
      if (didCount > 0 && pendingAttachments.length) {
        showSysMsg('Attachments are not supported over DIDComm'); return
      }
      // A DID recipient has no relay to route through — jmapCreateEmail
      // resolves the sender purely by fromEmail in that case (app.ts).
      const relayUrl = didCount > 0 ? undefined : (apCount > 0 ? apUrl : mailUrl)
      const attachmentsToSend = pendingAttachments
      pendingAttachments = []
      renderNewAttachments()

      // 2+ visible recipients (To+Cc) => group; a single one => 1:1. Bcc rides
      // along in both cases without affecting the group decision.
      if (visible.length >= 2) {
        const groupName = title || 'Group'
        const groupId = newGroupId()
        const result = await jmapCreateEmail({ to, cc, bcc }, body, groupName, '', { id: groupId, name: groupName }, [], fromEmail, relayUrl, attachmentsToSend)
        if (!result.ok) { showSysMsg(result.error || 'Send failed'); return }
        ;($lpSearch as HTMLInputElement).value = ''
        hideCmdPalette()
        const sess = sessionForRelay(fromEmail, relayUrl) ?? sessionFor(fromEmail) ?? activeSession()
        // Pull the just-sent copy into the local store so the conversation shows
        // up without a manual reload (the store only fills on sync, which the
        // send path used to skip — Safari/Brave especially never caught up).
        if (sess) { try { const { sync } = await import('../sync/session.ts'); await sync(sess) } catch {} }
        await loadLeftInboxes()
        if (sess) {
          switchInbox({
            user: sess.account.email,
            mailbox: '',
            contact: `group:${groupId}`,
            inbox_type: 'group',
            group_id: groupId,
            group_name: groupName,
            participants: visible,
            relay: relayUrl,
          })
        }
      } else {
        const subject = title
        const result = await jmapCreateEmail({ to, cc, bcc }, body, subject, '', undefined, [], fromEmail, relayUrl, attachmentsToSend)
        if (!result.ok) { showSysMsg(result.error || 'Send failed'); return }
        ;($lpSearch as HTMLInputElement).value = ''
        hideCmdPalette()
        const sess = sessionForRelay(fromEmail, relayUrl) ?? sessionFor(fromEmail) ?? activeSession()
        // Pull the just-sent copy into the store first (see group branch above);
        // then prefer the authoritative summary sync produced over a hand-built
        // one, and no longer gate on currentInbox (null on a fresh #new load).
        if (sess) { try { const { sync } = await import('../sync/session.ts'); await sync(sess) } catch {} }
        await loadLeftInboxes()
        if (to[0] && sess) {
          const match = lastLeftInboxes.find(i => i.user === sess.account.email && i.contact === to[0])
          switchInbox(match ?? {
            user: sess.account.email,
            mailbox: currentInbox?.mailbox ?? '',
            contact: to[0],
            latest_ts: Date.now(),
            latest_body: body,
            latest_subject: subject,
            relay: relayUrl,
          })
        }
      }
    })
  }

  function fmtRelTime(ts?: number): string {
    if (!ts) return 'Never'
    const s = Math.floor((Date.now() - ts) / 1000)
    if (s < 60) return `${s}s ago`
    if (s < 3600) return `${Math.floor(s / 60)}m ago`
    if (s < 86400) return `${Math.floor(s / 3600)}h ago`
    return `${Math.floor(s / 86400)}d ago`
  }

  function fmtBytes(n: number): string {
    if (n < 1024) return `${n} B`
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
    return `${(n / (1024 * 1024)).toFixed(1)} MB`
  }

  const _accInfoCache = new Map<string, { name?: string; unread?: number; total?: number; pgp?: boolean; lastSyncAt?: number }>()

  // Per-RELAY stats (identity-by-DID: each relay endpoint is its own card). Keyed
  // by accountKey (email+serverUrl) and queries that specific relay's session.
  async function fetchAccountInfo(session: import('../types.ts').AccountSession) {
    if (!session) return null
    const email = session.account.email
    const cacheKey = accountKey(session.account)
    const info: { name?: string; unread?: number; total?: number; pgp?: boolean; lastSyncAt?: number } = _accInfoCache.get(cacheKey) ?? {}

    try {
      const [r] = await (session.jmapClient.api as any).Identity.get({ accountId: session.jmapAccountId, ids: null })
      const id = (r.list as any[]).find(i => i.email === email) ?? r.list[0]
      info.name = (id as any)?.name || undefined
    } catch (e) { console.error('[fetchAccountInfo Identity.get]', e) }

    try {
      const [qr] = await session.jmapClient.api.Email.query({ accountId: session.jmapAccountId, limit: 5000 } as any)
      const ids: string[] = (qr as any).ids ?? []
      if (ids.length) {
        const [gr] = await session.jmapClient.api.Email.get({
          accountId: session.jmapAccountId,
          ids: ids as any,
          properties: ['id', 'keywords', 'from', 'subject', 'headers'],
        })
        const emails: any[] = (gr as any).list ?? []
        // Own sent mail never carries $seen (mirrors app.ts's loadInboxSummaries
        // and sw.ts) — without this exclusion every account looked permanently
        // more "unread" than it really was, inflated by its own sent history.
        // Secure-Join handshake noise and reactions are excluded from every
        // inbox the user can actually open (see loadInboxSummaries/getInboxEmails),
        // so they never get a chance to be marked $seen — left uncounted here
        // too, or "Unread" gets permanently stuck above 0 no matter how much
        // the user actually reads. Same exclusions apply to "Total" — it's meant
        // to read as "how many conversation messages", not a raw mailbox count
        // padded by your own sent copies.
        const realEmails = emails.filter(e => {
          if (isSecurejoinEmail(e) || isReaction(e)) return false
          const fromEmail = e.from?.[0]?.email ?? ''
          return fromEmail !== email
        })
        info.total = realEmails.length
        info.unread = realEmails.filter(e => !e.keywords?.['$seen']).length
        info.lastSyncAt = Date.now()
      } else {
        info.total = 0
        info.unread = 0
        info.lastSyncAt = Date.now()
      }
    } catch (e) { console.error('[fetchAccountInfo Email.query]', e) }

    // AP relays have no PGP key store (initPGPForSession no-ops there) — skip
    // the fetch entirely rather than hitting a route that doesn't exist there
    // (was surfacing as a noisy cross-origin CORS failure, not a clean 404).
    if (isApRelay(session.account.serverUrl)) {
      info.pgp = undefined
    } else {
      try {
        const resp = await fetch(session.account.serverUrl.replace(/\/$/, '') + '/pgp/privkey', {
          headers: { Authorization: 'Basic ' + btoa(session.account.email + ':' + session.account.password) },
        })
        info.pgp = resp.ok
      } catch (e) { console.error('[fetchAccountInfo pgp]', e); info.pgp = false }
    }

    _accInfoCache.set(cacheKey, info)
    return info
  }

  // ── dropdown menus (per-account + identity) ─────────────────────────────────

  let _openMenuCleanup: (() => void) | null = null

  function closeAccountMenu() {
    _openMenuCleanup?.()
    _openMenuCleanup = null
  }

  interface MenuItem { label: string; danger?: boolean; onClick: () => void }

  // Shared small dropdown builder — anchored below-right of `anchor`, closes on
  // outside click/Escape. Used by both the per-account card menu and the
  // identity-level menu (renderAccountsList's hamburger button).
  function openDropdownMenu(anchor: HTMLElement, items: MenuItem[]): void {
    closeAccountMenu()
    const rect = anchor.getBoundingClientRect()
    const menu = document.createElement('div')
    menu.style.cssText = `position:fixed;top:${rect.bottom + 4}px;left:${Math.max(8, rect.right - 180)}px;width:180px;background:var(--bg);border:1px solid var(--border, rgba(128,128,128,0.25));border-radius:8px;box-shadow:0 4px 16px rgba(0,0,0,0.18);z-index:10000;padding:4px;font-size:14px`
    for (const item of items) {
      const b = document.createElement('button')
      b.type = 'button'
      b.style.cssText = `display:block;width:100%;text-align:left;padding:8px 12px;background:none;border:none;border-radius:6px;cursor:pointer;color:${item.danger ? '#ff3b30' : 'var(--text)'};font-size:14px`
      b.textContent = item.label
      b.addEventListener('mouseover', () => { b.style.background = 'rgba(128,128,128,0.12)' })
      b.addEventListener('mouseout', () => { b.style.background = 'none' })
      b.addEventListener('click', () => { closeAccountMenu(); item.onClick() })
      menu.appendChild(b)
    }
    document.body.appendChild(menu)
    const onDocClick = (ev: MouseEvent) => {
      if (!menu.contains(ev.target as Node)) closeAccountMenu()
    }
    const onKey = (ev: KeyboardEvent) => { if (ev.key === 'Escape') closeAccountMenu() }
    setTimeout(() => document.addEventListener('click', onDocClick), 0)
    document.addEventListener('keydown', onKey)
    _openMenuCleanup = () => {
      document.removeEventListener('click', onDocClick)
      document.removeEventListener('keydown', onKey)
      menu.remove()
    }
  }

  // Identity-level menu (hamburger button in the account-page heading). Change
  // password + recovery phrase both operate on the envelope, which lives on
  // whichever of the identity's relays isn't an AP relay (the "home" relay —
  // same criterion the old standalone recovery-phrase section used) — an AP
  // relay never holds an envelope. Folds that former standalone section in
  // here instead of keeping two places to reach the same thing.
  function openIdentityMenu(anchor: HTMLElement): void {
    const homeIdentity = sessions.find(s => !isApRelay(s.account.serverUrl))
    if (!homeIdentity) { showSysMsg('No password-protected relay in this identity'); return }
    const idKey = identityKey(homeIdentity)
    openDropdownMenu(anchor, [
      { label: 'Change password', onClick: () => openPasswordModal(homeIdentity.account.email) },
      {
        label: 'Show recovery phrase', onClick: async () => {
          const { showMnemonicWithPassword } = await import('./mnemonic.ts')
          showMnemonicWithPassword(homeIdentity.account.email, homeIdentity.account.serverUrl)
        },
      },
      {
        label: 'Download all data', onClick: async () => {
          // The per-card "Download" only ever exports ONE relay's data (by
          // design — see storage.go). This is the whole-identity counterpart:
          // every relay/address sharing the DID, bundled into one archive —
          // real directory structure (raw/) plus the same markdown rendering
          // vault sync uses (markdown/), each under its own relay folder so a
          // cross-relay thread's independent per-store halves stay separate
          // (no cross-relay merging here, same as the server's own storage).
          const endpoints = loadStoredAccounts().filter(a => (a.did || a.email) === idKey)
          showSysMsg('Preparing download…', 30000)
          const { exportAccountStorage } = await import('../cryptenv.ts')
          const { buildAccountArchiveEntries } = await import('../vault/export.ts')
          const { buildZip } = await import('../vault/zip.ts')
          const allEntries: { path: string; data: Uint8Array }[] = []
          let failures = 0
          for (const ep of endpoints) {
            const data = await exportAccountStorage(ep.serverUrl, ep.email, ep.password)
            if (!data) { failures++; continue }
            const entries = await buildAccountArchiveEntries(ep.email, data.files)
            for (const e of entries) allEntries.push({ path: `${ep.email}/${e.path}`, data: e.data })
          }
          const zipBytes = buildZip(allEntries)
          const blob = new Blob([zipBytes.buffer as ArrayBuffer], { type: 'application/zip' })
          const url = URL.createObjectURL(blob)
          const link = document.createElement('a')
          link.href = url
          link.download = `${homeIdentity.account.email}-all-data.zip`
          link.click()
          URL.revokeObjectURL(url)
          showSysMsg(failures ? `Downloaded with ${failures} relay(s) failed` : 'Download ready')
        },
      },
      {
        label: 'Delete account', onClick: async () => {
          // Whole-identity delete: every relay/address sharing this DID, not
          // just the "home" one — per-card "Delete account" already covers a
          // single relay; this is the counterpart for the whole identity.
          const endpoints = loadStoredAccounts().filter(a => (a.did || a.email) === idKey)
          const list = endpoints.map(e => e.email).join(', ')
          if (!confirm(`Permanently delete this identity across all ${endpoints.length} relay(s) (${list})? This deletes all messages and account data everywhere — it cannot be undone.`)) return
          const { deleteAccountOnRelay } = await import('../cryptenv.ts')
          let failures = 0
          for (const ep of endpoints) {
            const ok = await deleteAccountOnRelay(ep.serverUrl, ep.email, ep.password, ep.did)
            if (!ok) failures++
          }
          saveStoredAccounts(loadStoredAccounts().filter(a => (a.did || a.email) !== idKey))
          for (let i = sessions.length - 1; i >= 0; i--) {
            if (identityKey(sessions[i]) === idKey) sessions.splice(i, 1)
          }
          for (const ep of endpoints) {
            _accInfoCache.delete(accountKey(ep))
            await deleteKey(ep.email)
            if (localStorage.getItem(`jmap_notif_${ep.email}`) != null) localStorage.removeItem(`jmap_notif_${ep.email}`)
            if (localStorage.getItem(`sjoin_invites_${ep.email}`) != null) localStorage.removeItem(`sjoin_invites_${ep.email}`)
          }
          await clearIdentityCache(idKey)
          renderAccountsList(); loadLeftInboxes()
          showSysMsg(failures ? `Deleted with ${failures} failure(s) — some relay data may remain` : 'Identity deleted')
        },
      },
    ])
  }

  // Drops just THIS one relay/address from local storage — session, stored
  // credentials, cached info. Used by both "Log out" (local-only) and
  // "Delete account" (after the server-side delete already succeeded). If
  // this was the identity's only remaining relay, this IS a full identity
  // sign-out, so it also clears identity-scoped local state (PGP keys,
  // notif prefs, cache) instead of leaving them orphaned.
  async function removeRelayLocally(email: string, serverUrl: string): Promise<void> {
    const idKey = identityKeyForEmail(email)
    const remaining = loadStoredAccounts().filter(a =>
      (a.did || a.email) === idKey && !(a.email === email && a.serverUrl === serverUrl))
    const wasLastRelay = remaining.length === 0
    saveStoredAccounts(loadStoredAccounts().filter(x => !(x.email === email && x.serverUrl === serverUrl)))
    for (let i = sessions.length - 1; i >= 0; i--) {
      if (sessions[i].account.email === email && sessions[i].account.serverUrl === serverUrl) sessions.splice(i, 1)
    }
    _accInfoCache.delete(accountKey({ email, serverUrl }))
    if (wasLastRelay) {
      if (localStorage.getItem(`jmap_notif_${email}`) != null) localStorage.removeItem(`jmap_notif_${email}`)
      if (localStorage.getItem(`sjoin_invites_${email}`) != null) localStorage.removeItem(`sjoin_invites_${email}`)
      await deleteKey(email)
      await clearIdentityCache(idKey)
    } else {
      import('../did/publish.ts').then(m => m.publishOwnDids()).catch(() => {})
    }
    // This device's own DIDComm mediator registration is per-DEVICE state
    // (create-standalone.ts's DidKeyAgreement note — a random key this one
    // browser minted), not scoped to "is this identity's LAST relay going
    // away" — found live: gating it on wasLastRelay left a stale, still-
    // published key behind every time a device logged out of just ONE of
    // several relay accounts, because the identity was still considered
    // active via whichever relay remained. Any explicit Log out — this
    // relay card's, or the mediator card's own — means THIS DEVICE is done;
    // unregisterFromMediator is a harmless no-op (throws, caught) for the
    // common case of a device that never registered a DIDComm channel at
    // all, and by the time this runs the identity's session may already be
    // gone from sessions[], so the identity key must be passed explicitly.
    import('../did/create-standalone.ts').then(m => m.unregisterFromMediator(email))
      .catch(e => console.warn('[logout] unregisterFromMediator failed — this device\'s DIDComm key may still be published:', e instanceof Error ? e.message : e))
    renderAccountsList(); loadLeftInboxes()
  }

  function openAccountMenu(anchor: HTMLElement, email: string, serverUrl?: string) {
    const items: MenuItem[] = [
      { label: 'Change password', onClick: () => openPasswordModal(email) },
      // DeltaChat SecureJoin invite link (setup-contact) — moved here from the
      // compose "From" row, which is the wrong place for a per-ACCOUNT action
      // (the link is scoped to whichever address it's generated for, not to
      // whatever's currently being composed).
      {
        label: 'DeltaChat link', onClick: async () => {
          const url = await newInviteUrl(email, email)
          if (!url) { showSysMsg('Invite link failed (no key set)'); return }
          try { await navigator.clipboard.writeText(url); showSysMsg('DeltaChat invite link copied') }
          catch { prompt('Copy this invite link:', url) } // clipboard denied — still surface it
        },
      },
    ]
    if (serverUrl) {
      // Actually deletes the account's data on THIS relay (messages, mailbox,
      // envelope — see go-jmapsmtp/go-jmapap's /account/delete) — distinct
      // from "Log out" below, which only forgets local credentials and
      // leaves the server-side account untouched.
      items.push({
        label: 'Delete account', onClick: async () => {
          if (!confirm(`Permanently delete ${email}? This deletes all messages and account data on the server — it cannot be undone.`)) return
          const session = sessions.find(s => s.account.email === email && s.account.serverUrl === serverUrl)
          if (!session) { showSysMsg('Not connected — log in before deleting'); return }
          const { deleteAccountOnRelay } = await import('../cryptenv.ts')
          const ok = await deleteAccountOnRelay(serverUrl, email, session.account.password, session.account.did)
          if (!ok) { showSysMsg('Delete failed'); return }
          await removeRelayLocally(email, serverUrl)
          showSysMsg('Account deleted')
        },
      })
      // No separate "wipe the whole identity" action — it used to be a
      // hidden effect of this same item (clicking it from ONE relay's card
      // silently logged out AP and mail together, since both shared a DID).
      // This is always scoped to just this one card; logging out of an
      // identity's last remaining relay naturally covers full sign-out,
      // arrived at explicitly one relay at a time.
      items.push({
        label: 'Log out', onClick: () => removeRelayLocally(email, serverUrl),
      })
    }
    openDropdownMenu(anchor, items)
  }

  // ── modal helpers ───────────────────────────────────────────────────────────

  function openModal(title: string, bodyEl: HTMLElement): () => void {
    const overlay = document.createElement('div')
    overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.4);z-index:10001;display:flex;align-items:center;justify-content:center;padding:16px'
    const box = document.createElement('div')
    box.style.cssText = 'background:var(--bg);color:var(--text);border-radius:12px;padding:20px;max-width:420px;width:100%;box-shadow:0 8px 32px rgba(0,0,0,0.3);max-height:90vh;overflow:auto'
    const header = document.createElement('div')
    header.style.cssText = 'display:flex;justify-content:space-between;align-items:center;margin-bottom:16px'
    const h = document.createElement('h3')
    h.textContent = title
    h.style.cssText = 'margin:0;font-size:16px'
    const close = document.createElement('button')
    close.type = 'button'
    close.textContent = '✕'
    close.style.cssText = 'background:none;border:none;color:var(--text-dim);font-size:20px;cursor:pointer;padding:0 4px'
    const dismiss = () => {
      document.removeEventListener('keydown', onKey)
      overlay.remove()
    }
    const onKey = (ev: KeyboardEvent) => { if (ev.key === 'Escape') dismiss() }
    document.addEventListener('keydown', onKey)
    close.addEventListener('click', dismiss)
    overlay.addEventListener('click', (ev) => { if (ev.target === overlay) dismiss() })
    header.append(h, close)
    box.append(header, bodyEl)
    overlay.appendChild(box)
    document.body.appendChild(overlay)
    return dismiss
  }

  function openPasswordModal(email: string) {
    const session = sessions.find(s => s.account.email === email)
    const body = document.createElement('form')
    body.style.cssText = 'display:flex;flex-direction:column;gap:10px'
    body.autocomplete = 'off'
    body.innerHTML = `
      <div style="font-size:12px;color:var(--text-dim)">${esc(email)}</div>
      <input class="cmd-input" type="password" name="old" placeholder="Current password" autocomplete="current-password" required>
      <input class="cmd-input" type="password" name="new" placeholder="New password (min 8 chars)" autocomplete="new-password" required>
      <input class="cmd-input" type="password" name="new2" placeholder="Confirm new password" autocomplete="new-password" required>
      <div data-role="error" style="color:#ff3b30;font-size:12px;display:none"></div>
      <div data-role="ok" style="color:#34c759;font-size:12px;display:none"></div>
      <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:4px">
        <button type="button" data-role="cancel" class="cmd-page-btn" style="width:auto;padding:6px 14px">Cancel</button>
        <button type="submit" data-role="submit" class="cmd-page-btn primary" style="width:auto;padding:6px 14px">Change</button>
      </div>`
    const dismiss = openModal('Change password', body)
    body.querySelector<HTMLButtonElement>('[data-role=cancel]')!.addEventListener('click', dismiss)
    body.addEventListener('submit', async (ev) => {
      ev.preventDefault()
      if (!session) return
      const oldPw = (body.elements.namedItem('old') as HTMLInputElement).value
      const newPw = (body.elements.namedItem('new') as HTMLInputElement).value
      const newPw2 = (body.elements.namedItem('new2') as HTMLInputElement).value
      const errEl = body.querySelector<HTMLElement>('[data-role=error]')!
      const okEl = body.querySelector<HTMLElement>('[data-role=ok]')!
      const submit = body.querySelector<HTMLButtonElement>('[data-role=submit]')!
      errEl.style.display = 'none'; okEl.style.display = 'none'
      if (newPw !== newPw2) { errEl.textContent = 'New passwords do not match'; errEl.style.display = 'block'; return }
      if (newPw.length < 8) { errEl.textContent = 'New password must be at least 8 characters'; errEl.style.display = 'block'; return }
      submit.disabled = true; submit.textContent = 'Changing…'
      try {
        const { rewrapEnvelope, putEnvelope } = await import('../cryptenv.ts')
        const env = await fetchEnvelope(session.account.serverUrl, session.account.email)
        if (!env) { errEl.textContent = 'Failed to fetch envelope'; errEl.style.display = 'block'; return }
        let newEnv
        try { newEnv = await rewrapEnvelope(env, oldPw, newPw) }
        catch { errEl.textContent = 'Current password is incorrect'; errEl.style.display = 'block'; return }
        const ok = await putEnvelope(session.account.serverUrl, session.account.email, session.account.password, newEnv)
        if (!ok) { errEl.textContent = 'Server update failed'; errEl.style.display = 'block'; return }
        okEl.textContent = 'Changed successfully'; okEl.style.display = 'block'
        setTimeout(dismiss, 800)
      } finally {
        submit.disabled = false; submit.textContent = 'Change'
      }
    })
  }

  function openDisplayNameModal(email: string) {
    const session = sessions.find(s => s.account.email === email)
    const cached = _accInfoCache.get(email)
    const currentName = cached?.name || email.split('@')[0]
    const body = document.createElement('form')
    body.style.cssText = 'display:flex;flex-direction:column;gap:10px'
    body.innerHTML = `
      <div style="font-size:12px;color:var(--text-dim)">${esc(email)}</div>
      <input class="cmd-input" type="text" name="name" value="${esc(currentName)}" placeholder="Display name" required autofocus>
      <div data-role="error" style="color:#ff3b30;font-size:12px;display:none"></div>
      <div data-role="ok" style="color:#34c759;font-size:12px;display:none"></div>
      <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:4px">
        <button type="button" data-role="cancel" class="cmd-page-btn" style="width:auto;padding:6px 14px">Cancel</button>
        <button type="submit" data-role="submit" class="cmd-page-btn primary" style="width:auto;padding:6px 14px">Save</button>
      </div>`
    const dismiss = openModal('Change display name', body)
    body.querySelector<HTMLButtonElement>('[data-role=cancel]')!.addEventListener('click', dismiss)
    body.addEventListener('submit', async (ev) => {
      ev.preventDefault()
      if (!session) return
      const newName = (body.elements.namedItem('name') as HTMLInputElement).value.trim()
      const errEl = body.querySelector<HTMLElement>('[data-role=error]')!
      const okEl = body.querySelector<HTMLElement>('[data-role=ok]')!
      const submit = body.querySelector<HTMLButtonElement>('[data-role=submit]')!
      errEl.style.display = 'none'; okEl.style.display = 'none'
      if (!newName) { errEl.textContent = 'Display name required'; errEl.style.display = 'block'; return }
      submit.disabled = true; submit.textContent = 'Saving…'
      try {
        const [r] = await (session.jmapClient.api as any).Identity.get({ accountId: session.jmapAccountId, ids: null })
        const id = (r.list as any[]).find(i => i.email === email) ?? r.list[0]
        if (!id?.id) { errEl.textContent = 'Failed to fetch identity'; errEl.style.display = 'block'; return }
        await session.jmapClient.api.Identity.set({
          accountId: session.jmapAccountId,
          update: { [id.id]: { name: newName } as any },
        })
        // Mirror into the local identities store — jmapCreateEmail reads
        // Identity.name from there when it builds the From header, and only
        // refetches from the server when the store is empty. Without this,
        // the new name wouldn't take effect on a send until the next full
        // resync happened to run.
        identities.set(identities.all().map(i => (i.id === id.id ? { ...i, name: newName } : i)))
        const cache = _accInfoCache.get(email) ?? {}
        cache.name = newName
        _accInfoCache.set(email, cache)
        renderAccountsList()
        // Also publish it into the DID document (biset extension, see
        // document.ts) — same name, one more place it shows up: anyone who
        // resolves this DID (e.g. via the [DID] badge) sees it instead of the
        // raw did:dht string. Genuinely best-effort — the name is already
        // saved server-side either way, so this must not fail the save — but
        // logged rather than dropped, so a document that can NEVER publish
        // leaves a trace instead of nothing at all.
        import('../did/publish.ts').then(m => m.publishOneVisible(email))
          .catch(e => console.error(`[did/publish] ${email}: republish after name change failed —`, e))
        okEl.textContent = 'Saved'; okEl.style.display = 'block'
        setTimeout(dismiss, 600)
      } catch {
        errEl.textContent = 'Save failed'; errEl.style.display = 'block'
      } finally {
        submit.disabled = false; submit.textContent = 'Save'
      }
    })
  }

  // Expand/collapse the identity heading's raw DID document — same pattern as
  // #conv-meta's click-to-expand (thread.ts). Resolves live from the DHT via
  // this identity's own relay gateways (not a local reconstruction) so what's
  // shown matches what a contact resolving this DID actually sees.
  async function toggleIdentityDidDoc(section: HTMLElement, docEl: HTMLElement, did: string): Promise<void> {
    const wasExpanded = section.classList.contains('expanded')
    section.classList.toggle('expanded')
    if (wasExpanded) return
    docEl.textContent = 'Resolving…'
    try {
      // Was its own relay-sessions-only gateway list (relaysForId(did),
      // filtered) — empty for a relay-less (DID⊥relay) identity, which has no
      // relay session to draw a /pkarr gateway from at all. resolveDidDocFull
      // (above) already solves this the right way via channel.ts's
      // ownGateways (relay gateways + this identity's own mediator's
      // token-gated pkarr, plus the public fallbacks) — reuse it instead of
      // a second gateway-list implementation that only worked for a
      // relay-backed identity. This is what made a standalone identity's own
      // #account page permanently report "No document found" even though the
      // record was resolvable everywhere else (own anchor, public gateways).
      const doc = await resolveDidDocFull(did)
      // The document's keys are raw Uint8Arrays — JSON.stringify serializes
      // typed arrays as {"0":244,"1":42,...} (no special-casing, unlike a
      // plain array). Format every one as hex instead of dumping 32 numbered
      // object keys each. Keep this in step with DidDocument's key fields:
      // keyAgreementKeys (one per registered device, document.ts's
      // DidKeyAgreement) was added later and initially missed here, which
      // showed up as one key rendering as hex next to another rendering as
      // an object.
      const hex = (b: Uint8Array) => [...b].map(x => x.toString(16).padStart(2, '0')).join('')
      const forDisplay = doc && {
        ...doc,
        identityKey: hex(doc.identityKey),
        ...(doc.keyAgreementKeys?.length ? { keyAgreementKeys: doc.keyAgreementKeys.map(k => ({ kid: `#k${k.n}`, publicKey: hex(k.publicKey) })) } : {}),
      }
      docEl.textContent = forDisplay ? JSON.stringify(forDisplay, null, 2) : 'No document found (not yet published, or no gateway reachable)'
    } catch {
      docEl.textContent = 'Failed to resolve DID document'
    }
  }

  function renderAccountsList() {
    const $list = document.getElementById('cmd-acc-list')
    if (!$list) return
    $list.textContent = ''
    const accounts = loadStoredAccounts()
    // One session = one identity (ARC.md 2026-07-14): every loaded account
    // shares the same DID (if any), so the identity is a property of the
    // PAGE, not of any one card — shown once in the heading, avatar + [display
    // name / shortened DID], instead of repeated per card.
    const identitySection = document.getElementById('cmd-acc-identity-section')
    const identityAvatar = document.getElementById('cmd-acc-identity-avatar')
    const identityName = document.getElementById('cmd-acc-identity-name')
    const identityDid = document.getElementById('cmd-acc-identity-did')
    const identityCopy = document.getElementById('cmd-acc-identity-copy')
    const identityRepublish = document.getElementById('cmd-acc-identity-republish') as HTMLButtonElement | null
    const identityMenuBtn = document.getElementById('cmd-acc-identity-menu-btn') as HTMLButtonElement | null
    const identityDoc = document.getElementById('cmd-acc-identity-doc')
    const repAccount = accounts.find(a => a.did)
    if (identitySection && identityAvatar && identityName && identityDid && identityDoc) {
      if (repAccount?.did) {
        const repEmail = repAccount.email
        const did = repAccount.did
        identityAvatar.textContent = ''
        identityAvatar.style.cssText = 'cursor:pointer;position:relative;overflow:hidden'
        identityAvatar.title = 'Click to set avatar'
        const ownAvatar = avatarDataUrl(repEmail)
        if (ownAvatar) {
          identityAvatar.style.cssText += ';background:transparent'
          const img = document.createElement('img')
          img.src = ownAvatar
          img.style.cssText = 'width:100%;height:100%;object-fit:cover;border-radius:50%'
          identityAvatar.appendChild(img)
        } else {
          identityAvatar.style.cssText += ';' + avatarStyle(repEmail)
          identityAvatar.textContent = repEmail.charAt(0).toUpperCase()
        }
        identityAvatar.onclick = () => pickAndSetIdentityAvatar(did)
        // Default is the localpart until changed — the server synthesizes
        // exactly this as Identity.name until a real Identity/set happens
        // (go-jmapserver's defaultIdentity()), so this needs no separate
        // "auto-derive at creation" step of its own.
        const name = identities.all().find(i => i.email === repEmail)?.name || repEmail.split('@')[0]
        identityName.textContent = name
        identityName.onclick = () => openDisplayNameModal(repEmail)
        const suffix = did.replace(/^did:dht:/, '')
        identityDid.textContent = `did:dht:${suffix.slice(0, 8)}…${suffix.slice(-6)}`
        identityDid.onclick = () => toggleIdentityDidDoc(identitySection, identityDoc, did)
        if (identityMenuBtn) identityMenuBtn.onclick = (ev) => { ev.stopPropagation(); openIdentityMenu(identityMenuBtn) }
        if (identityCopy) {
          identityCopy.onclick = (ev) => {
            ev.stopPropagation() // don't also trigger identityDid's expand-doc click
            navigator.clipboard?.writeText(did).then(() => showSysMsg('DID copied')).catch(() => {})
          }
        }
        // Republishing publishes the WHOLE identity's document (every relay,
        // every address — see publish.ts's publishOne) regardless of which
        // account triggered it, so it belongs here once, not duplicated in
        // every per-card menu (it used to be, and always did the same thing
        // no matter which card's menu you opened it from).
        if (identityRepublish) {
          identityRepublish.onclick = async () => {
            showSysMsg('Publishing to the network…', 30000)
            try {
              const ok = await (await import('../did/publish.ts')).publishOneVisible(repEmail)
              showSysMsg(ok ? 'Published to DHT' : 'No gateway reachable (record not published)')
            } catch (e) {
              // Show the actual reason: publishOneVisible only throws when the
              // document itself can't be published (too big to sign, chain
              // link unplaceable, ...). Reporting those as "no gateway
              // reachable" — as this used to — sends you debugging the network
              // for a problem that has nothing to do with it.
              showSysMsg(`Publish failed: ${e instanceof Error ? e.message : String(e)}`, 15000)
            }
          }
        }
        identitySection.style.display = ''
      } else if (standaloneDid()) {
        // Relay-less identity (DID⊥relay): no StoredAccount to hang the heading
        // on, so drive it from the DID alone — DID + doc view + republish. No
        // avatar/name/menu tied to an address it doesn't have yet; adding a
        // relay below fills those in the normal way.
        const sDid = standaloneDid()!
        identityAvatar.textContent = '◇'
        identityAvatar.style.cssText = 'display:flex;align-items:center;justify-content:center;background:var(--header-border);color:var(--text-dim)'
        identityAvatar.onclick = null
        identityName.textContent = 'Your identity'
        identityName.onclick = null
        const suffix = sDid.replace(/^did:dht:/, '')
        identityDid.textContent = `did:dht:${suffix.slice(0, 8)}…${suffix.slice(-6)}`
        identityDid.onclick = () => toggleIdentityDidDoc(identitySection, identityDoc, sDid)
        if (identityMenuBtn) identityMenuBtn.style.display = 'none'
        if (identityCopy) {
          identityCopy.onclick = (ev) => {
            ev.stopPropagation()
            navigator.clipboard?.writeText(sDid).then(() => showSysMsg('DID copied')).catch(() => {})
          }
        }
        if (identityRepublish) {
          identityRepublish.onclick = async () => {
            showSysMsg('Publishing to the network…', 30000)
            const did = await (await import('../did/create-standalone.ts')).refreshStandalone()
            showSysMsg(did ? 'Published to DHT' : 'Publish failed', 8000)
          }
        }
        // Adding a relay uses the normal "+ New JMAP account" panel below,
        // which provisions under THIS identity's DID (see the standalone branch
        // in the add-account flow) — no separate button.
        identitySection.style.display = ''
      } else {
        identitySection.style.display = 'none'
        identitySection.classList.remove('expanded')
      }
    }
    if (!accounts.length && !standaloneDid()) {
      const msg = document.createElement('div')
      msg.className = 'lp-search-status'
      msg.textContent = 'No accounts'
      $list.appendChild(msg)
    }
    // (a standalone identity shows its DID heading above instead of "No accounts")
    const relayLabel = (url: string): string => {
      try { return new URL(url).hostname.split('.')[0] } catch { return '?' }
    }
    const protoLabel = (url: string): string => isApRelay(url) ? 'AP' : 'SMTP'
    // One card per RELAY endpoint. Identity-by-DID: the DID is the identity; each
    // relay is a concrete endpoint you see and manage (SMTP, ActivityPub, …).
    // Sorting by did keeps an identity's relays adjacent (the DID itself is
    // shown once, in the page heading above — see identitySection).
    const idKeyOf = (x: { did?: string; email: string }) => x.did || x.email
    const relayCards = [...accounts].sort((x, y) =>
      idKeyOf(x).localeCompare(idKeyOf(y)) || x.serverUrl.localeCompare(y.serverUrl))
    for (const a of relayCards) {
      const session = sessions.find(s => s.account.email === a.email && s.account.serverUrl === a.serverUrl)
      const connected = !!session
      const cached = _accInfoCache.get(a.email + '\0' + a.serverUrl) ?? {}

      const row = document.createElement('div')
      row.className = 'cmd-page-row'
      row.style.cssText = 'gap:12px;align-items:center;padding:10px 12px'

      // Avatar lives at the identity heading now, not per card — it applies to
      // every address of this identity (see pickAndSetIdentityAvatar).
      const left = document.createElement('div')
      left.style.cssText = 'flex:1;min-width:0;display:flex;flex-direction:column;gap:4px'

      const headRow = document.createElement('div')
      headRow.style.cssText = 'display:flex;align-items:center;gap:8px;min-width:0'
      const dot = document.createElement('span')
      dot.style.cssText = `width:8px;height:8px;border-radius:50%;flex-shrink:0;background:${connected ? '#34c759' : '#ff3b30'}`
      const protoEl = document.createElement('span')
      protoEl.style.cssText = 'font-size:11px;font-weight:700;letter-spacing:0.04em;color:var(--accent2, #888);flex-shrink:0'
      protoEl.textContent = protoLabel(a.serverUrl)
      const sep = document.createElement('span')
      sep.style.cssText = 'color:var(--text-dim);flex-shrink:0'
      sep.textContent = ':'
      const addrEl = document.createElement('span')
      addrEl.style.cssText = 'font-size:13px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis'
      addrEl.textContent = a.email
      headRow.append(dot, protoEl, sep, addrEl)

      const statsRow = document.createElement('div')
      statsRow.style.cssText = 'display:flex;flex-wrap:wrap;gap:12px;font-size:11px;color:var(--text-dim)'
      const fmtUnread = (c: { unread?: number; total?: number }) => `Unread: ${c.unread ?? '…'}/${c.total ?? '…'}`
      const statUnread = document.createElement('span')
      statUnread.dataset.kind = 'unread'
      statUnread.textContent = fmtUnread(cached)
      const statPgp = document.createElement('span')
      statPgp.dataset.kind = 'pgp'
      statPgp.textContent = cached.pgp == null ? '' : cached.pgp ? 'PGP ✓' : 'PGP ✗'
      const statSync = document.createElement('span')
      statSync.dataset.kind = 'sync'
      statSync.textContent = `Sync: ${fmtRelTime(cached.lastSyncAt)}`
      statsRow.append(statUnread, statSync, statPgp)

      // DID is shown once in the page heading (identitySection above), not
      // per card — every card here shares it (one session = one identity).
      left.append(headRow, statsRow)

      const menuBtn = document.createElement('button')
      menuBtn.type = 'button'
      menuBtn.style.cssText = 'background:none;border:none;color:var(--text-dim);cursor:pointer;padding:6px;line-height:0;border-radius:6px;flex-shrink:0;display:flex;align-items:center;justify-content:center'
      menuBtn.innerHTML = `<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><circle cx="12" cy="5" r="1.5"/><circle cx="12" cy="12" r="1.5"/><circle cx="12" cy="19" r="1.5"/></svg>`
      menuBtn.setAttribute('aria-label', 'Menu')
      menuBtn.addEventListener('mouseover', () => { menuBtn.style.background = 'rgba(128,128,128,0.12)' })
      menuBtn.addEventListener('mouseout', () => { menuBtn.style.background = 'none' })
      menuBtn.addEventListener('click', (ev) => {
        ev.stopPropagation()
        openAccountMenu(menuBtn, a.email, a.serverUrl)
      })

      row.append(left, menuBtn)

      // "How your data is stored" (issue #7): the whole card is the click
      // target — the border between cards opens into a filled panel instead
      // of staying a line (same idea as #cmd-acc-identity-expanded). One
      // fetch per expand, not cached, so it stays current with a purge/delete
      // done moments earlier.
      const cardWrap = document.createElement('div')
      cardWrap.className = 'acc-card-wrap'
      const panel = document.createElement('div')
      panel.className = 'acc-storage-panel'
      const panelHeader = document.createElement('div')
      panelHeader.className = 'acc-storage-header'
      const panelTitle = document.createElement('span')
      panelTitle.className = 'acc-storage-title'
      panelTitle.textContent = 'Storage'
      const panelActions = document.createElement('div')
      panelActions.className = 'acc-storage-actions'
      const downloadBtn = document.createElement('button')
      downloadBtn.type = 'button'
      downloadBtn.className = 'acc-storage-icon-btn'
      downloadBtn.setAttribute('aria-label', 'Download')
      downloadBtn.title = 'Download this relay’s data'
      downloadBtn.innerHTML = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3v12"/><path d="M6 11l6 6 6-6"/><path d="M4 21h16"/></svg>'
      const purgeBtn = document.createElement('button')
      purgeBtn.type = 'button'
      purgeBtn.className = 'acc-storage-icon-btn'
      purgeBtn.setAttribute('aria-label', 'Purge messages')
      purgeBtn.title = 'Purge messages'
      purgeBtn.innerHTML = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 7h16"/><path d="M9 7V4h6v3"/><path d="M6 7l1 13h10l1-13"/><path d="M10 11v6"/><path d="M14 11v6"/></svg>'
      panelActions.append(downloadBtn, purgeBtn)
      panelHeader.append(panelTitle, panelActions)
      const tree = document.createElement('div')
      tree.className = 'acc-storage-tree'
      tree.textContent = 'Loading…'
      panel.append(panelHeader, tree)
      cardWrap.append(row, panel)
      $list.appendChild(cardWrap)

      const loadStorageTree = async () => {
        tree.textContent = 'Loading…'
        const { fetchAccountStorage } = await import('../cryptenv.ts')
        const info = await fetchAccountStorage(a.serverUrl, a.email, a.password)
        if (!info) { tree.textContent = 'Failed to load — check the relay is reachable.'; return }
        panelTitle.textContent = `STORAGE : ${fmtBytes(info.totalSizeBytes)}`
        tree.textContent = ''
        info.entries.forEach((entry, i) => {
          const isLastEntry = i === info.entries.length - 1
          const line = document.createElement('div')
          line.className = 'tree-entry'
          const prefix = document.createElement('span')
          prefix.textContent = isLastEntry ? '└─' : '├─'
          const name = document.createElement('span')
          name.className = 'tree-name'
          name.textContent = entry.type === 'dir' ? `${entry.name}/` : entry.name
          const meta = document.createElement('span')
          meta.className = 'tree-meta'
          meta.textContent = entry.type === 'dir'
            ? `(${entry.count ?? 0} file${entry.count === 1 ? '' : 's'}, ${fmtBytes(entry.sizeBytes)})`
            : `(${fmtBytes(entry.sizeBytes)})`
          line.append(prefix, name, meta)
          tree.appendChild(line)

          // Drill-down: "messages" is the one entry summarized rather than
          // listed (could be thousands of files) — click it to fetch and
          // show the individual files nested underneath.
          if (entry.type === 'dir' && entry.name === 'messages' && entry.count) {
            line.classList.add('tree-expandable')
            const subList = document.createElement('div')
            subList.className = 'tree-sublist'
            tree.appendChild(subList)
            line.addEventListener('click', async () => {
              const expandingSub = subList.style.display !== 'block'
              subList.style.display = expandingSub ? 'block' : 'none'
              line.classList.toggle('tree-expanded', expandingSub)
              if (!expandingSub || subList.dataset.loaded) return
              subList.dataset.loaded = '1'
              subList.textContent = 'Loading…'
              const { fetchMessageFiles } = await import('../cryptenv.ts')
              const files = await fetchMessageFiles(a.serverUrl, a.email, a.password)
              subList.textContent = ''
              if (!files) { subList.textContent = 'Failed to load'; return }
              files.forEach((f, fi) => {
                const subLine = document.createElement('div')
                subLine.className = 'tree-entry'
                const subPrefix = document.createElement('span')
                subPrefix.textContent = fi === files.length - 1 ? '└─' : '├─'
                const subName = document.createElement('span')
                subName.className = 'tree-name'
                subName.textContent = f.name
                const subMeta = document.createElement('span')
                subMeta.className = 'tree-meta'
                subMeta.textContent = `(${fmtBytes(f.sizeBytes)})`
                subLine.append(subPrefix, subName, subMeta)
                subList.appendChild(subLine)
              })
            })
          }
        })
        if (!info.entries.length) tree.textContent = 'Empty.'
      }

      row.addEventListener('click', () => {
        const expanding = !cardWrap.classList.contains('expanded')
        cardWrap.classList.toggle('expanded')
        if (expanding) loadStorageTree()
      })

      downloadBtn.addEventListener('click', async (ev) => {
        ev.stopPropagation()
        if (downloadBtn.disabled) return
        downloadBtn.disabled = true
        try {
          const { exportAccountStorage } = await import('../cryptenv.ts')
          const bundle = await exportAccountStorage(a.serverUrl, a.email, a.password)
          if (!bundle) { showSysMsg('Download failed'); return }
          // Real directory structure (raw/) + the same markdown rendering
          // vault sync uses (markdown/), zipped — not a flattened JSON blob.
          const { buildAccountArchiveEntries } = await import('../vault/export.ts')
          const { buildZip } = await import('../vault/zip.ts')
          const entries = await buildAccountArchiveEntries(a.email, bundle.files)
          const zipBytes = buildZip(entries)
          const blob = new Blob([zipBytes.buffer as ArrayBuffer], { type: 'application/zip' })
          const url = URL.createObjectURL(blob)
          const link = document.createElement('a')
          link.href = url
          link.download = `${a.email}-data.zip`
          link.click()
          URL.revokeObjectURL(url)
        } finally {
          downloadBtn.disabled = false
        }
      })

      purgeBtn.addEventListener('click', async (ev) => {
        ev.stopPropagation()
        if (purgeBtn.disabled) return
        if (!confirm(`Delete every stored message for ${a.email} on this relay? Mailboxes, contacts, and the account itself are kept — only the messages are removed. This cannot be undone.`)) return
        purgeBtn.disabled = true
        try {
          const { purgeAccountMessages } = await import('../cryptenv.ts')
          const n = await purgeAccountMessages(a.serverUrl, a.email, a.password)
          if (n == null) { showSysMsg('Purge failed'); return }
          showSysMsg(`Purged ${n} message${n === 1 ? '' : 's'}`)
          loadStorageTree()
          loadLeftInboxes()
        } finally {
          purgeBtn.disabled = false
        }
      })

      if (session) {
        fetchAccountInfo(session).then(info => {
          if (!info) return
          statUnread.textContent = fmtUnread(info)
          statPgp.textContent = info.pgp == null ? '' : info.pgp ? 'PGP ✓' : 'PGP ✗'
          statSync.textContent = `Sync: ${fmtRelTime(info.lastSyncAt)}`
        }).catch(() => {})
      }
    }

    // Trailing "card" (n+1th) that opens the same add-relay/login panel the
    // old top-of-page "+" toggle used to — kept as its own last row so
    // `.acc-card-wrap:last-child` styling (no border under the very last
    // item) lands here instead of on the last real account.
    const newCardWrap = document.createElement('div')
    newCardWrap.className = 'acc-card-wrap'
    const newCardRow = document.createElement('div')
    newCardRow.className = 'cmd-page-row acc-new-account-row'
    const newCardText = document.createElement('h3')
    newCardText.style.margin = '0'
    const newCardPlus = document.createElement('span')
    newCardPlus.className = 'acc-new-account-plus'
    newCardPlus.textContent = '+'
    newCardText.append(newCardPlus, 'New Relay')
    newCardRow.appendChild(newCardText)
    newCardRow.addEventListener('click', () => {
      const panel = document.getElementById('cmd-acc-panel')
      if (!panel) return
      const opening = panel.style.display === 'none'
      // 'flex', not 'block' — #cmd-acc-panel's own CSS is display:flex (its
      // gap is the one spacing mechanism for all rows inside it); an inline
      // 'block' here overrides that stylesheet rule outright, silently
      // disabling gap entirely (2026-07-14, user-reported: gap changes had
      // zero visible effect no matter the value, because of exactly this).
      panel.style.display = opening ? 'flex' : 'none'
      if (opening) {
        resetAddAccountPanel()
        ;(document.getElementById('cmd-acc-relay') as HTMLInputElement | null)?.focus()
      }
    })
    newCardWrap.appendChild(newCardRow)
    $list.appendChild(newCardWrap)

    // Mediator card — the DIDComm mediator this identity is registered with, in
    // the same card format as a relay (a mediator IS a relay for DIDComm). Its
    // URL lives in the DID record, so this fills in asynchronously; a stale
    // render's callback bails (its newCardWrap is already detached).
    const mediatorRecKey = repAccount?.email ?? standaloneDid()
    if (mediatorRecKey) {
      getDidRecord(mediatorRecKey).then(rec => {
        if (!rec?.didCommMediatorUrl) return
        if (newCardWrap.parentNode !== $list) return
        if (document.getElementById('cmd-acc-mediator-card')) return
        $list.insertBefore(buildMediatorCard(rec.didCommMediatorUrl, mediatorRecKey), newCardWrap)
      }).catch(() => {})
    }
  }

  function buildMediatorCard(mediatorUrl: string, identityKey: string): HTMLElement {
    let host = mediatorUrl
    try { host = new URL(mediatorUrl).hostname } catch { /* keep raw */ }
    const wrap = document.createElement('div')
    wrap.className = 'acc-card-wrap'
    wrap.id = 'cmd-acc-mediator-card'
    const row = document.createElement('div')
    row.className = 'cmd-page-row'
    row.style.cssText = 'gap:12px;align-items:center;padding:10px 12px'
    const left = document.createElement('div')
    left.style.cssText = 'flex:1;min-width:0;display:flex;flex-direction:column;gap:4px'
    const headRow = document.createElement('div')
    headRow.style.cssText = 'display:flex;align-items:center;gap:8px;min-width:0'
    const dot = document.createElement('span')
    dot.style.cssText = 'width:8px;height:8px;border-radius:50%;flex-shrink:0;background:#34c759'
    const protoEl = document.createElement('span')
    protoEl.style.cssText = 'font-size:11px;font-weight:700;letter-spacing:0.04em;color:var(--accent2, #888);flex-shrink:0'
    protoEl.textContent = 'DIDComm'
    const sep = document.createElement('span')
    sep.style.cssText = 'color:var(--text-dim);flex-shrink:0'
    sep.textContent = ':'
    const addrEl = document.createElement('span')
    addrEl.style.cssText = 'font-size:13px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis'
    addrEl.textContent = host
    headRow.append(dot, protoEl, sep, addrEl)
    const statsRow = document.createElement('div')
    statsRow.style.cssText = 'display:flex;flex-wrap:wrap;gap:12px;font-size:11px;color:var(--text-dim)'
    const stat = document.createElement('span')
    stat.textContent = 'Mediator · DIDComm inbox'
    statsRow.append(stat)
    left.append(headRow, statsRow)

    // Unlike a relay card, only "Log out" applies here — a mediator has no
    // password and no server-side account to delete, only the keylist
    // registration to withdraw (see unregisterFromMediator).
    const menuBtn = document.createElement('button')
    menuBtn.type = 'button'
    menuBtn.style.cssText = 'background:none;border:none;color:var(--text-dim);cursor:pointer;padding:6px;line-height:0;border-radius:6px;flex-shrink:0;display:flex;align-items:center;justify-content:center'
    menuBtn.innerHTML = `<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><circle cx="12" cy="5" r="1.5"/><circle cx="12" cy="12" r="1.5"/><circle cx="12" cy="19" r="1.5"/></svg>`
    menuBtn.setAttribute('aria-label', 'Menu')
    menuBtn.addEventListener('mouseover', () => { menuBtn.style.background = 'rgba(128,128,128,0.12)' })
    menuBtn.addEventListener('mouseout', () => { menuBtn.style.background = 'none' })
    menuBtn.addEventListener('click', (ev) => {
      ev.stopPropagation()
      openDropdownMenu(menuBtn, [{
        label: 'Log out', danger: true, onClick: async () => {
          try {
            const { unregisterFromMediator } = await import('../did/create-standalone.ts')
            await unregisterFromMediator()
            showSysMsg('Logged out of mediator')
          } catch (e) {
            showSysMsg('Log out failed: ' + (e instanceof Error ? e.message : String(e)), 8000)
          }
          wrap.remove()
        },
      }])
    })

    row.append(left, menuBtn)

    // Device list panel — same accordion shape as a relay card's storage
    // panel (.acc-storage-panel, driven by .acc-card-wrap.expanded in CSS),
    // one row per keyAgreementKeys entry currently cached locally (this
    // device's own + every known sibling — the same set buildOwnDocument
    // publishes, so it matches what's actually live). Trash icon per row
    // removes just that entry (create-standalone.ts's removeDeviceKey) —
    // the human-confirmed manual prune, not an automatic one.
    const panel = document.createElement('div')
    panel.className = 'acc-storage-panel'
    const panelHeader = document.createElement('div')
    panelHeader.className = 'acc-storage-header'
    const panelTitle = document.createElement('span')
    panelTitle.className = 'acc-storage-title'
    panelTitle.textContent = 'Devices'
    panelHeader.append(panelTitle)
    const deviceList = document.createElement('div')
    deviceList.className = 'acc-device-list'
    panel.append(panelHeader, deviceList)

    const loadDevices = async () => {
      deviceList.textContent = 'Loading…'
      const rec = await getDidRecord(identityKey).catch(() => null)
      if (!rec) { deviceList.textContent = 'Failed to load.'; return }
      const entries: Array<{ kid: string; publicKey: string; isSelf: boolean }> = []
      if (rec.didCommOwnKid && rec.didCommPublicKey) entries.push({ kid: rec.didCommOwnKid, publicKey: rec.didCommPublicKey, isSelf: true })
      for (const s of rec.didCommSiblingKeys ?? []) entries.push({ kid: s.kid, publicKey: s.publicKey, isSelf: false })
      deviceList.textContent = ''
      if (!entries.length) { deviceList.textContent = 'No devices.'; return }
      for (const entry of entries) {
        const devRow = document.createElement('div')
        devRow.className = 'acc-device-row'
        const label = document.createElement('span')
        label.className = 'acc-device-label'
        const shortKey = entry.publicKey.slice(0, 8) + '…' + entry.publicKey.slice(-4)
        label.textContent = `${entry.kid} · ${shortKey}${entry.isSelf ? ' · This device' : ''}`
        const trashBtn = document.createElement('button')
        trashBtn.type = 'button'
        trashBtn.className = 'acc-storage-icon-btn'
        trashBtn.setAttribute('aria-label', 'Remove device')
        trashBtn.title = entry.isSelf ? 'Log out this device' : 'Remove this device'
        trashBtn.innerHTML = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 7h16"/><path d="M9 7V4h6v3"/><path d="M6 7l1 13h10l1-13"/><path d="M10 11v6"/><path d="M14 11v6"/></svg>'
        trashBtn.addEventListener('click', async (ev) => {
          ev.stopPropagation()
          if (trashBtn.disabled) return
          if (!confirm(entry.isSelf
            ? 'Log this device out of the mediator? It will stop receiving DIDComm messages until it registers again.'
            : `Remove device ${entry.kid} from the published key list? This cannot be undone from here.`)) return
          trashBtn.disabled = true
          try {
            const { removeDeviceKey } = await import('../did/create-standalone.ts')
            await removeDeviceKey(identityKey, entry.kid)
            showSysMsg(entry.isSelf ? 'Logged out of mediator' : 'Device removed')
            if (entry.isSelf) { wrap.remove(); return }
            loadDevices()
          } catch (e) {
            showSysMsg('Remove failed: ' + (e instanceof Error ? e.message : String(e)), 8000)
            trashBtn.disabled = false
          }
        })
        devRow.append(label, trashBtn)
        deviceList.appendChild(devRow)
      }
    }

    row.addEventListener('click', () => {
      const expanding = !wrap.classList.contains('expanded')
      wrap.classList.toggle('expanded')
      if (expanding) loadDevices()
    })

    wrap.append(row, panel)
    return wrap
  }

  function onShowAccounts() {
    renderAccountsList()
    const form = document.getElementById('cmd-acc-form') as HTMLFormElement | null
    form?.addEventListener('submit', async (ev) => {
      ev.preventDefault()
      const relayInput = document.getElementById('cmd-acc-relay') as HTMLInputElement
      const emailInput = document.getElementById('cmd-acc-email') as HTMLInputElement
      const pwInput = document.getElementById('cmd-acc-password') as HTMLInputElement
      const errEl = document.getElementById('cmd-acc-error')!
      const addBtn = document.getElementById('cmd-acc-add') as HTMLButtonElement

      const email = emailInput.value.trim()
      const pw = pwInput.value
      const raw = relayInput.value.trim().replace(/\/$/, '')
      // The relay picker at the top of the panel is required for either path
      // (Sign up or Log in) — no more domain-guessing fallback ladder here.
      // A bare apex ("biset.md") still expands to BOTH mail+ap siblings
      // (expandDualRelay) — the same home-identity pairing #new provisions,
      // now available on Log in too (best-effort: whichever comes up is
      // kept, same as the old auto-discovery this replaced).
      const dual = expandDualRelay(raw)
      const servers = dual ?? (raw ? [/^https?:\/\//i.test(raw) ? raw : 'https://' + raw] : [])
      if (!servers.length) { errEl.textContent = 'Relay URL required'; errEl.style.display = 'block'; return }
      if (!email || !pw) { errEl.textContent = 'Email and Password required'; errEl.style.display = 'block'; return }

      addBtn.disabled = true; addBtn.textContent = 'Connecting…'; errEl.style.display = 'none'

      // Own relays ideally carry a cryptenv envelope (the identity's wrapped
      // master secret); a third-party/DID-less relay has none, so the raw
      // password is used as-is.
      let kek: Uint8Array | undefined
      let masterSecret: Uint8Array | undefined
      let badPw = false
      const resolveAuth = async (server: string): Promise<string | null> => {
        const env = await fetchEnvelope(server, email)
        if (!env) return pw
        try {
          const u = await unsealEnvelope(env, pw)
          kek = u.kek
          masterSecret = u.masterSecret
          const { password } = await relayAuth(u.masterSecret, server)
          return password
        } catch { badPw = true; return null }
      }

      const connected: Array<{ session: any; server: string; token: string }> = []
      for (const server of servers) {
        const token = await resolveAuth(server)
        if (badPw) break
        if (!token) continue
        const session = await initSession({ serverUrl: server, email, password: token }).catch(() => null)
        if (session) {
          if (kek) (session as any).kek = kek
          connected.push({ session, server, token })
        }
      }

      if (badPw) {
        errEl.textContent = 'Incorrect password'
        errEl.style.display = 'block'
        addBtn.disabled = false; addBtn.textContent = 'Add'
        return
      }
      if (!connected.length) {
        errEl.textContent = 'Failed to establish JMAP session'
        errEl.style.display = 'block'
        addBtn.disabled = false; addBtn.textContent = 'Add'
        return
      }

      const isFirst = sessions.length === 0
      // Lazy DID migration (DID.md "Existing account" flow): a password entry
      // is exactly the moment masterSecret is available. Deterministic
      // derivation means this is idempotent for accounts that already have a
      // local DID record — initDid() just returns the existing one.
      const { initDid } = await import('../did/index.ts')
      const didRecord = masterSecret ? await initDid(email, masterSecret) : null

      // One session = one identity (ARC.md 2026-07-14): this account's own
      // DID/masterSecret is DERIVED independently of whatever is currently
      // active (initDid(email, masterSecret) computes the DID purely from
      // THIS account's own seed) — so logging into an account belonging to a
      // genuinely different identity must never silently merge into the
      // active one's sessions. Switching identity is logout-then-login only.
      if (!isFirst) {
        const activeIdKey = identityIds()[0]
        const newIdKey = didRecord?.did || email
        if (activeIdKey && newIdKey !== activeIdKey) {
          errEl.textContent = 'This account belongs to a different identity — log out first to switch.'
          errEl.style.display = 'block'
          addBtn.disabled = false; addBtn.textContent = 'Add'
          return
        }
      }

      // Self-resolution (DID.md): don't just connect the relay(s) explicitly
      // requested — also pick up any relay this identity's OWN DID document
      // currently lists (e.g. added from another device, or after a move) that
      // isn't among `connected` yet. Mirrors contact discovery, applied to the
      // account holder's own identity. Best-effort; never blocks login.
      if (didRecord && masterSecret) {
        const { syncRelaysFromDid } = await import('../did/sync.ts')
        const extra = await syncRelaysFromDid(didRecord.did, email, masterSecret, connected.map(c => c.server))
        for (const e of extra) {
          if (kek) (e.session as any).kek = kek
          connected.push(e)
        }
      }

      // Persist + register each connected relay, deduped by (email, serverUrl) so
      // mail and AP for the same identity coexist as separate sessions.
      const stored = loadStoredAccounts()
      for (const c of connected) {
        // Tag the endpoint with its DID so it groups by identity (see context.ts).
        if (didRecord) c.session.account.did = didRecord.did
        // Each relay's own address — usually == the login email, but a
        // self-synced relay (see syncRelaysFromDid above) may carry a
        // different address (svc.address) after a move.
        const relayEmail: string = c.session.account.email || email
        const existingStored = stored.find(a => a.email === relayEmail && a.serverUrl === c.server)
        if (existingStored) { if (didRecord) existingStored.did = didRecord.did }
        else stored.push({ serverUrl: c.server, email: relayEmail, password: c.token, did: didRecord?.did })
        if (!sessions.some(s => s.account.email === relayEmail && s.account.serverUrl === c.server)) {
          sessions.push(c.session)
        }
        if (kek) initPGPForSession(c.session, kek)
        if (didRecord) {
          const { registerDid } = await import('../did/provision.ts')
          const { hexToBytes } = await import('../utils.ts')
          registerDid(c.server, relayEmail, c.token, didRecord.did, hexToBytes(didRecord.rootPrivateKey))
        }
      }
      saveStoredAccounts(stored)
      addBtn.disabled = false; addBtn.textContent = 'Add'
      resetAddAccountPanel()
      const panel = document.getElementById('cmd-acc-panel') as HTMLElement | null
      if (panel) panel.style.display = 'none'
      renderAccountsList()
      loadLeftInboxes()
      if (isFirst) startPolling()
    })
  }

  const LP_COMMANDS: Array<{ name: string; page?: () => string; action: () => void; onShow?: () => void | Promise<void> }> = [
    { name: '/account', page: renderAccountPage, action: () => {}, onShow: onShowAccount },
    { name: '/config',  page: renderConfigPage,  action: () => {}, onShow: onShowConfig },
    { name: '/compose',     page: renderComposePage,     action: () => {}, onShow: onShowNew },
    { name: '/debug',       page: renderDebugPage,       action: () => {}, onShow: onShowDebug },
  ]
  let cmdSelectedIdx = -1
  let _filteredCmds: typeof LP_COMMANDS = []

  _showMenuPageFn = renderMenuInboxImpl
  _renderAccountsListFn = renderAccountsList
  _openInboxMenuFn = (item, anchor) => {
    menuTargetInbox = item
    const m = document.getElementById('lp-inbox-menu')
    const ab = document.getElementById('lp-archive-inbox-btn')
    if (ab) ab.textContent = item.archived ? 'Unarchive' : 'Archive'
    const r = anchor.getBoundingClientRect()
    if (m) { m.style.display = 'block'; m.style.top = (r.bottom + 4) + 'px'; m.style.left = r.left + 'px' }
  }

  // Auto-navigate to menu page if URL hash points to one.
  {
    const rawHash = decodeURIComponent(location.hash.slice(1))
    if (rawHash && !rawHash.includes('@')) {
      const relayName = (document.title || '').toLowerCase()
      const legacyToAccount = ['accounts', 'profile', relayName].includes(rawHash.toLowerCase())
      if (legacyToAccount) {
        renderMenuInboxImpl('/account')
      } else {
        const cmd = LP_COMMANDS.find(c => c.name === rawHash || c.name === '/' + rawHash)
        if (cmd) renderMenuInboxImpl(cmd.name)
      }
    }
  }

  function makeCmdPastRow(cmd: typeof LP_COMMANDS[number], onSelect: (name: string) => void) {
    const row = document.createElement('div')
    row.className = 'past-row'
    const hdr = document.createElement('div')
    hdr.className = 'past-row-header'
    const title = document.createElement('span')
    title.className = 'past-row-title'
    title.textContent = cmd.name.replace('/', '')
    hdr.appendChild(title)
    hdr.addEventListener('click', () => onSelect(cmd.name))
    row.appendChild(hdr)
    return row
  }

  function renderMenuInboxImpl(focusedName: string) {
    const cmd = LP_COMMANDS.find(c => c.name === focusedName)
    if (!cmd?.page) return
    _inMenuMode = true

    const hashName = focusedName.startsWith('/') ? focusedName.slice(1) : focusedName
    try { history.replaceState(null, '', '#' + hashName) } catch {}

    const $past = document.getElementById('past-threads')
    const $active = document.getElementById('active-thread')
    const dock = document.getElementById('reply-dock')
    const $convMeta = document.getElementById('conv-meta')

    $cmdPage.style.display = 'none'
    // Empty it, don't just hide it — #reply-dock:empty{display:none}
    // (style.css) is what actually keeps the dock invisible on every menu
    // page from here on; a menu page never calls render() (thread.ts) to
    // re-clear it the way opening a real thread does, so if this only set
    // display:none, whatever content was in the dock from before opening
    // this menu page would just sit there ready to reappear the moment
    // anything else touched .style.display (2026-07-14, user-reported: the
    // reply box showed up ON a menu page, exactly this).
    if (dock) dock.innerHTML = ''
    if ($convMeta) $convMeta.style.display = 'none'
    $outer.style.display = ''
    syncDockPosition()

    if ($past) {
      $past.innerHTML = ''
      for (const c of LP_COMMANDS) {
        if (c.name === focusedName) continue
        $past.appendChild(makeCmdPastRow(c, renderMenuInboxImpl))
      }
    }

    if ($active) {
      $active.innerHTML = ''
      const card = document.createElement('div')
      card.className = 'cmd-thread-card'
      card.id = 'focused-thread-card'
      card.innerHTML = cmd.page()
      $active.appendChild(card)
    }

    const $headerTitle = document.getElementById('header-thread-title')
    const $groupIcon = document.getElementById('header-group-icon')
    if ($headerTitle) { $headerTitle.textContent = cmd.name.replace('/', ''); $headerTitle.className = '' }
    if ($groupIcon) $groupIcon.style.display = 'none'

    const $lpHam = document.getElementById('lp-hamburger')
    if ($lpHam) $lpHam.style.display = ''

    cmd.onShow?.()
    requestAnimationFrame(() => scrollToFocused())

    _menuResizeObserver?.disconnect()
    if (typeof ResizeObserver !== 'undefined') {
      const $activeEl = document.getElementById('active-thread')
      if ($activeEl) {
        _menuResizeObserver = new ResizeObserver(() => { if (_inMenuMode) updateScrollSpacer() })
        _menuResizeObserver.observe($activeEl)
      }
    }
  }

  function showCmdPage(cmd: typeof LP_COMMANDS[number] | undefined) {
    if (!cmd?.page) { hideCmdPage(); return }
    renderMenuInboxImpl(cmd.name)
  }

  function hideCmdPage() {
    _inMenuMode = false
    _menuResizeObserver?.disconnect()
    $cmdPage.style.display = 'none'
    const $convMeta = document.getElementById('conv-meta')
    if ($convMeta) $convMeta.style.display = ''
    // No dock.style.display touch — render() just below (thread.ts)
    // populates or clears #reply-dock's content, and #reply-dock:empty
    // (style.css) is what actually governs its visibility now.
    $outer.style.display = ''
    render()
  }

  function showCommands(q: string) {
    const filtered = LP_COMMANDS.filter(c => c.name.startsWith(q))
    _filteredCmds = filtered
    cmdSelectedIdx = filtered.length ? 0 : -1
    $lpCmds.innerHTML = ''
    filtered.forEach((cmd, i) => {
      const el = document.createElement('div')
      el.className = 'lp-cmd-item' + (i === 0 ? ' selected' : '')
      el.textContent = cmd.name
      el.addEventListener('mousedown', e => {
        e.preventDefault()
        cmdSelectedIdx = i
        updateCmdSelection([...$lpCmds.querySelectorAll('.lp-cmd-item')], i)
        showCmdPage(cmd)
        cmd.action()
      })
      $lpCmds.appendChild(el)
    })
    const visible = filtered.length > 0
    $lpCmds.style.display = visible ? '' : 'none'
    const $leftList = document.getElementById('left-list')
    if ($leftList) $leftList.style.display = visible ? 'none' : ''
    const $lpEmpty = document.getElementById('lp-empty')
    if ($lpEmpty) $lpEmpty.style.display = 'none'
    if (filtered.length > 0) showCmdPage(filtered[0])
    return filtered
  }

  function hideCmdPalette() {
    $lpCmds.style.display = 'none'
    const $leftList = document.getElementById('left-list')
    if ($leftList) $leftList.style.display = ''
    cmdSelectedIdx = -1
    _filteredCmds = []
    hideCmdPage()
  }

  function updateCmdSelection(items: Element[], idx: number) {
    items.forEach((el, i) => el.classList.toggle('selected', i === idx))
    if (idx >= 0 && idx < _filteredCmds.length) showCmdPage(_filteredCmds[idx])
  }

  // ── Full-text search via SearchSnippet/get ──────────────────────────────
  const $searchResults = document.getElementById('lp-search-results')!
  let _searchTimer: ReturnType<typeof setTimeout> | null = null

  function clearSearchResults() {
    if ($searchResults) {
      $searchResults.innerHTML = ''
      $searchResults.style.display = 'none'
    }
    const $leftList = document.getElementById('left-list')
    if ($leftList) $leftList.style.display = ''
  }

  async function doEmailSearch(q: string) {
    if (!$searchResults) return
    $searchResults.innerHTML = `<div class="lp-search-status">Searching…</div>`
    $searchResults.style.display = ''
    const $leftList = document.getElementById('left-list')
    if ($leftList) $leftList.style.display = 'none'

    const sess = activeSession()
    if (!sess) {
      $searchResults.innerHTML = `<div class="lp-search-status">No session</div>`
      return
    }

    try {
      const api = sess.jmapClient.api as any
      const accountId = sess.jmapAccountId
      const selfAddr = accountId || sess.account.email

      const [queryRes] = await api.Email.query({
        accountId,
        filter: { text: q },
        limit: 20,
        sort: [{ property: 'receivedAt', isAscending: false }],
      })
      const ids: string[] = queryRes.ids ?? []
      if (!ids.length) {
        $searchResults.innerHTML = `<div class="lp-search-status">No results</div>`
        return
      }

      const [[emailRes], [snippetRes]] = await Promise.all([
        api.Email.get({
          accountId,
          ids,
          properties: ['id', 'from', 'to', 'subject', 'receivedAt', 'threadId'],
        }),
        api.SearchSnippet.get({
          accountId,
          filter: { text: q },
          emailIds: ids,
        }),
      ])

      const emails: any[] = emailRes.list ?? []
      const snippetMap = new Map<string, any>()
      for (const s of (snippetRes.list ?? [])) snippetMap.set(s.emailId, s)

      if (!emails.length) {
        $searchResults.innerHTML = `<div class="lp-search-status">No results</div>`
        return
      }

      const html = emails.map(e => {
        const from = e.from?.[0]
        const fromAddr = from?.email ?? ''
        const fromName = from?.name || fromAddr
        const contact = fromAddr === selfAddr ? (e.to?.[0]?.email ?? '') : fromAddr
        const snippet = snippetMap.get(e.id)
        const subjectSnip = snippet?.subject ? `<span class="lp-search-subject">${snippet.subject}</span>` : `<span class="lp-search-subject">${esc(e.subject ?? '')}</span>`
        const bodySnip = snippet?.preview ? `<span class="lp-search-preview">${snippet.preview}</span>` : ''
        const ts = e.receivedAt ? formatTime(new Date(e.receivedAt).getTime() / 1000) : ''
        return `<div class="lp-search-result" data-contact="${esc(contact)}">
          <span class="lp-search-contact">${esc(fromName)}</span>
          <span class="lp-search-ts">${esc(ts)}</span>
          ${subjectSnip}${bodySnip}
        </div>`
      }).join('')

      $searchResults.innerHTML = `<div class="lp-search-header">Results: ${emails.length}</div>` + html

      $searchResults.querySelectorAll<HTMLElement>('.lp-search-result').forEach(el => {
        el.addEventListener('click', () => {
          const contact = el.dataset.contact!
          // Find matching inbox from lastLeftInboxes or build a minimal one
          const found = lastLeftInboxes.find(i => i.contact === contact && i.user === sess.account.email)
          if (found) {
            switchInbox(found)
          } else if (currentInbox) {
            switchInbox({ ...currentInbox, contact })
          }
          ;($lpSearch as HTMLInputElement).value = ''
          clearSearchResults()
        })
      })
    } catch (err) {
      if ($searchResults) $searchResults.innerHTML = `<div class="lp-search-status">Error: ${esc(String(err))}</div>`
    }
  }

  $lpSearch.addEventListener('input', () => {
    const v = ($lpSearch as HTMLInputElement).value
    lpNavIdx = -1
    if (v.startsWith('/')) {
      clearSearchResults()
      showCommands(v)
    } else {
      hideCmdPalette()
      if (v.length >= 2) {
        if (_searchTimer) clearTimeout(_searchTimer)
        _searchTimer = setTimeout(() => doEmailSearch(v), 400)
      } else {
        if (_searchTimer) { clearTimeout(_searchTimer); _searchTimer = null }
        clearSearchResults()
        applyLpSearch()
      }
    }
  })

  // Search box: handles only / command palette and Escape
  $lpSearch.addEventListener('keydown', e => {
    const v = ($lpSearch as HTMLInputElement).value
    if (v.startsWith('/')) {
      const cmdItems = [...$lpCmds.querySelectorAll('.lp-cmd-item')]
      if (e.key === 'ArrowDown') {
        e.preventDefault()
        cmdSelectedIdx = Math.min(cmdSelectedIdx + 1, cmdItems.length - 1)
        updateCmdSelection(cmdItems, cmdSelectedIdx)
      } else if (e.key === 'ArrowUp') {
        e.preventDefault()
        cmdSelectedIdx = Math.max(cmdSelectedIdx - 1, 0)
        updateCmdSelection(cmdItems, cmdSelectedIdx)
      } else if (e.key === 'Enter') {
        e.preventDefault()
        const exact = LP_COMMANDS.find(c => c.name === v.trim())
        if (exact) { exact.action(); return }
        if (cmdSelectedIdx >= 0 && cmdSelectedIdx < cmdItems.length) {
          const cmd = LP_COMMANDS.find(c => c.name === cmdItems[cmdSelectedIdx].textContent)
          if (cmd) cmd.action()
        }
      } else if (e.key === 'Escape') {
        ;($lpSearch as HTMLInputElement).value = ''
        hideCmdPalette()
      }
      return
    }
    if (e.key === 'Escape') {
      lpNavClear()
      ;($lpSearch as HTMLInputElement).value = ''
      clearSearchResults()
      applyLpSearch()
    }
  })

  // Document-level nav: Arrow / Space work regardless of search focus
  document.addEventListener('keydown', e => {
    // Ignore when typing in a real input (but allow when lp-search is focused and empty)
    const active = document.activeElement
    const isTextInput = active instanceof HTMLTextAreaElement ||
      (active instanceof HTMLInputElement && active !== $lpSearch)
    if (isTextInput) return

    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault()
      const items = lpNavItems()
      if (!items.length) return
      const focused = focusedNavEl(items)
      const cur = focused ? items.indexOf(focused) : -1
      const next = e.key === 'ArrowDown'
        ? (cur < items.length - 1 ? cur + 1 : cur)
        : Math.max(cur - 1, 0)
      const target = items[next]
      if (target && target !== focused) {
        ;($lpSearch as HTMLInputElement).blur()
        lpFocusEl(target)
      }
    } else if (e.key === ' ') {
      const items = lpNavItems()
      const el = focusedNavEl(items)
      if (el?.classList.contains('lp-item')) {
        e.preventDefault()
        toggleAccordionForItem(el)
      } else if (el?.classList.contains('lp-thread-row')) {
        // thread1 (first row) acts as "thread0+1" unit — Space closes accordion
        const inboxEl = el.closest<HTMLElement>('.lp-item')
        if (inboxEl && el === inboxEl.querySelector('.lp-thread-list .lp-thread-row')) {
          e.preventDefault()
          toggleAccordionForItem(inboxEl)
        }
      }
    } else if (e.key === 'ArrowRight') {
      e.preventDefault()
      const ta = document.querySelector('#focused-thread-card textarea') ?? document.querySelector('.reply-box textarea')
      if (ta) { (ta as HTMLElement).focus(); (ta as HTMLInputElement).setSelectionRange((ta as HTMLInputElement).value.length, (ta as HTMLInputElement).value.length) }
    }
  })

  setTimeout(() => $lpSearch.focus(), 100)

  await loadLeftInboxes()
  // Periodic backstop: pull each relay and refresh the list, so new conversations
  // still surface if an SSE push was missed (e.g. a dropped EventSource).
  setInterval(async () => {
    try {
      const { sync } = await import('../sync/session.ts')
      // sync() speaks JMAP — the synthetic DIDComm session (context.ts's
      // isDidCommRelay) has no jmapClient (null) behind it, and calling
      // sync() on it threw every 30s (sync/index.ts's own start() already
      // filters this same way; this periodic backstop just hadn't).
      await Promise.allSettled(sessions.filter(s => !isDidCommRelay(s.account.serverUrl)).map(sync))
    } catch { /* best-effort */ }
    loadLeftInboxes()
  }, 30000)

  // .eml drag-drop → Email/import
  const $lp = document.getElementById('left-pane')!
  if ($lp) {
    $lp.addEventListener('dragover', e => { e.preventDefault(); $lp.classList.add('drag-over') })
    $lp.addEventListener('dragleave', e => { if (!$lp.contains(e.relatedTarget as Node)) $lp.classList.remove('drag-over') })
    $lp.addEventListener('drop', async e => {
      e.preventDefault()
      $lp.classList.remove('drag-over')
      const file = e.dataTransfer?.files[0]
      if (!file || !file.name.toLowerCase().endsWith('.eml')) { showSysMsg('Drop an .eml file'); return }
      showSysMsg('Importing…')
      const sess = activeSession()
      if (!sess) { showSysMsg('No session'); return }
      try {
        const emlText = await file.text()
        await (sess.jmapClient.api as any).Email.import({
          accountId: sess.jmapAccountId,
          emails: {
            import1: {
              blobId: emlText, // servers may support raw import
              mailboxIds: {},
            },
          },
        })
        showSysMsg('Import complete')
        await loadLeftInboxes()
      } catch { showSysMsg('Import failed') }
    })
  }
}
