import { currentInbox, setCurrentInbox, activeSession, sessionFor, sessionForRelay, relaysFor, accountKey, identityKey, identityKeyForEmail, sessions, loadStoredAccounts, saveStoredAccounts, setVaultHandle, isApRelay } from '../context.ts'
import {
  lastLeftInboxes, setLastLeftInboxes,
  processedMessages, renderedKeys,
  setLastTs, setIsFirstFetch,
  focusedThreadKey, setFocusedThreadKey,
  notifEnabled, setNotifEnabled,
  lastTs, groupMessages,
} from '../state.ts'
import { esc, formatTime, avatarStyle, inboxToHash, markProgrammaticScroll, syncAppBadge, mailboxNameFromId } from '../utils.ts'
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
import { setupAccountCreateOverlay } from './account-create.ts'
import { newGroupId, isSecurejoinEmail, readGroupHeaders, isEdit } from '../deltachat/protocol.ts'
import { isReaction } from '../mail/reactions.ts'
import { newInviteUrl } from '../deltachat/securejoin.ts'
import { enablePush, disablePush } from '../push/client.ts'

// ── InboxSummary key ──────────────────────────────────────────────────────────
function isk(i: InboxSummary): string { return i.user + '\0' + i.mailbox + '\0' + i.contact }

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
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

// Opens a file picker and sets the given account's own avatar (stored + gossiped
// on outgoing DeltaChat messages via buildProtectedHeaders).
function pickAndSetAvatar(email: string): void {
  const input = document.createElement('input')
  input.type = 'file'
  input.accept = 'image/*'
  input.addEventListener('change', async () => {
    const file = input.files?.[0]
    if (!file) return
    try {
      const dataUrl = await imageFileToAvatarDataUrl(file)
      await saveAvatar(email, dataUrl)
      // Push the new picture to this identity's AP relay(s) so the fediverse
      // actor document advertises it.
      advertiseOwnAvatarForEmail(email)
      refreshAccountsList()
      loadLeftInboxes()
    } catch (e) { console.log('[avatar] set own failed', e) }
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
  const $dock = document.getElementById('reply-dock')
  if ($dock) { $dock.style.display = ''; $dock.classList.remove('dock-hidden') }

  const prev = currentInbox
  if (prev && prev.user === item.user && prev.mailbox === item.mailbox && prev.contact === item.contact) {
    document.getElementById('app')?.classList.remove('show-left')
    if (wasInMenuMode) render()
    return
  }
  saveCurrentInbox()
  setCurrentInbox(item)
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
  markProgrammaticScroll()
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
        const wasShowLeft = appEl?.classList.contains('show-left')
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
  const rawName = item.mailbox && item.contact ? `${item.mailbox} / ${item.contact}` : (item.contact || item.mailbox)
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
      <div class="cmd-page-section">
        <div style="display:flex;justify-content:space-between;align-items:center">
          <h3 style="margin:0">Add JMAP account</h3>
          <button id="cmd-acc-toggle" type="button" class="cmd-page-btn" style="width:auto;padding:4px 12px;font-size:13px">+</button>
        </div>
        <div style="margin-top:8px">
          <button id="cmd-acc-customdomain" type="button" style="background:none;border:none;color:var(--text-dim);font-size:12px;text-decoration:underline;text-underline-offset:2px;cursor:pointer;padding:0">Add my own domain…</button>
        </div>
        <form id="cmd-acc-form" style="display:none;flex-direction:column;gap:8px;margin-top:12px" autocomplete="on">
          <input id="cmd-acc-server" class="cmd-input" type="url" placeholder="Server URL (https://...)" autocomplete="url" style="display:none">
          <input id="cmd-acc-email" class="cmd-input" type="text" placeholder="Email (or gateway username)" autocomplete="username" required>
          <input id="cmd-acc-password" class="cmd-input" type="password" placeholder="Password" autocomplete="current-password" required>
          <div id="cmd-acc-error" style="color:#ff3b30;font-size:12px;display:none"></div>
          <div style="display:flex;justify-content:flex-end;gap:8px">
            <button id="cmd-acc-cancel" type="button" class="cmd-page-btn" style="width:auto;padding:6px 18px">Cancel</button>
            <button id="cmd-acc-add" type="submit" class="cmd-page-btn primary" style="width:auto;padding:6px 18px">Add</button>
          </div>
        </form>
      </div>
      <div class="cmd-page-section" id="cmd-acc-list"></div>
      <div class="cmd-page-section" id="cmd-acc-recovery" style="display:none">
        <div style="display:flex;justify-content:space-between;align-items:center;gap:12px">
          <div style="min-width:0">
            <h3 style="margin:0">Recovery phrase</h3>
            <div style="font-size:12px;color:var(--text-dim);margin-top:2px">24 words that restore your identity on any device.</div>
          </div>
          <button id="cmd-acc-recovery-btn" type="button" class="cmd-page-btn" style="width:auto;padding:6px 14px;flex-shrink:0">Show</button>
        </div>
      </div>
    </div>`
  }

  function onShowAccount() {
    onShowAccounts()

    // Recovery phrase is only meaningful for a home (cryptenv-envelope) identity.
    // Reveal the section for the first such identity and wire its button to the
    // password-gated display (masterSecret isn't persisted — see mnemonic.ts).
    const recoverySection = document.getElementById('cmd-acc-recovery')
    const recoveryBtn = document.getElementById('cmd-acc-recovery-btn') as HTMLButtonElement | null
    const homeIdentity = sessions.find(s => !isApRelay(s.account.serverUrl))
    if (recoverySection && recoveryBtn && homeIdentity) {
      recoverySection.style.display = ''
      recoveryBtn.addEventListener('click', async () => {
        const { showMnemonicWithPassword } = await import('./mnemonic.ts')
        showMnemonicWithPassword(homeIdentity.account.email, homeIdentity.account.serverUrl)
      })
    }

    const addToggle = document.getElementById('cmd-acc-toggle') as HTMLButtonElement | null
    const addForm = document.getElementById('cmd-acc-form') as HTMLFormElement | null
    const addCancel = document.getElementById('cmd-acc-cancel')
    const setOpen = (open: boolean) => {
      if (!addForm || !addToggle) return
      addForm.style.display = open ? 'flex' : 'none'
      addToggle.textContent = open ? '−' : '+'
      if (open) (document.getElementById('cmd-acc-email') as HTMLInputElement)?.focus()
    }
    addToggle?.addEventListener('click', () => setOpen(addForm?.style.display === 'none'))
    document.getElementById('cmd-acc-customdomain')?.addEventListener('click', async () => {
      const { openCustomDomainFlow } = await import('./custom-domain.ts')
      openCustomDomainFlow()
    })
    addCancel?.addEventListener('click', () => {
      ;(document.getElementById('cmd-acc-email') as HTMLInputElement).value = ''
      ;(document.getElementById('cmd-acc-password') as HTMLInputElement).value = ''
      ;(document.getElementById('cmd-acc-server') as HTMLInputElement).value = ''
      ;(document.getElementById('cmd-acc-server') as HTMLInputElement).style.display = 'none'
      const errEl = document.getElementById('cmd-acc-error')
      if (errEl) errEl.style.display = 'none'
      setOpen(false)
    })
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
        <div id="new-from-field" class="new-compose-field" style="align-items:center">
          <span class="new-field-label">From</span>
          <select id="new-from" class="new-field-input"></select>
          <button id="new-invite-btn" class="cmd-page-btn" style="flex-shrink:0;padding:4px;background:none;border:none;box-shadow:none" title="Copy Invitation"><img src="data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9Im5vIj8+CjwhLS0gQ3JlYXRlZCB3aXRoIElua3NjYXBlIChodHRwOi8vd3d3Lmlua3NjYXBlLm9yZy8pIC0tPgoKPHN2ZwogICB4bWxuczpkYz0iaHR0cDovL3B1cmwub3JnL2RjL2VsZW1lbnRzLzEuMS8iCiAgIHhtbG5zOmNjPSJodHRwOi8vY3JlYXRpdmVjb21tb25zLm9yZy9ucyMiCiAgIHhtbG5zOnJkZj0iaHR0cDovL3d3dy53My5vcmcvMTk5OS8wMi8yMi1yZGYtc3ludGF4LW5zIyIKICAgeG1sbnM6c3ZnPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIKICAgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIgogICB4bWxuczp4bGluaz0iaHR0cDovL3d3dy53My5vcmcvMTk5OS94bGluayIKICAgeG1sbnM6c29kaXBvZGk9Imh0dHA6Ly9zb2RpcG9kaS5zb3VyY2Vmb3JnZS5uZXQvRFREL3NvZGlwb2RpLTAuZHRkIgogICB4bWxuczppbmtzY2FwZT0iaHR0cDovL3d3dy5pbmtzY2FwZS5vcmcvbmFtZXNwYWNlcy9pbmtzY2FwZSIKICAgd2lkdGg9IjQ4cHgiCiAgIGhlaWdodD0iNDhweCIKICAgaWQ9InN2ZzI5ODUiCiAgIHZlcnNpb249IjEuMSIKICAgaW5rc2NhcGU6dmVyc2lvbj0iMC45MSByMTM3MjUiCiAgIHNvZGlwb2RpOmRvY25hbWU9ImRlbHRhLXY3LXBhdGhlZC5zdmciCiAgIGlua3NjYXBlOmV4cG9ydC1maWxlbmFtZT0iL2hvbWUvYnBldGVyc2VuL3Byb2plY3RzL21lc3Nlbmdlci1hbmRyb2lkL01lc3NlbmdlclByb2ovc3JjL21haW4vcmVzL2RyYXdhYmxlLXhoZHBpL2ljX2xhdW5jaGVyLnBuZyIKICAgaW5rc2NhcGU6ZXhwb3J0LXhkcGk9IjE4My44MyIKICAgaW5rc2NhcGU6ZXhwb3J0LXlkcGk9IjE4My44MyI+CiAgPGRlZnMKICAgICBpZD0iZGVmczI5ODciPgogICAgPGxpbmVhckdyYWRpZW50CiAgICAgICBpZD0ibGluZWFyR3JhZGllbnQ0NDA5Ij4KICAgICAgPHN0b3AKICAgICAgICAgc3R5bGU9InN0b3AtY29sb3I6I2Y5ZjlmOTtzdG9wLW9wYWNpdHk6MSIKICAgICAgICAgb2Zmc2V0PSIwIgogICAgICAgICBpZD0ic3RvcDQ0MTEiIC8+CiAgICAgIDxzdG9wCiAgICAgICAgIHN0eWxlPSJzdG9wLWNvbG9yOiNjY2NjY2M7c3RvcC1vcGFjaXR5OjA7IgogICAgICAgICBvZmZzZXQ9IjEiCiAgICAgICAgIGlkPSJzdG9wNDQxMyIgLz4KICAgIDwvbGluZWFyR3JhZGllbnQ+CiAgICA8bGluZWFyR3JhZGllbnQKICAgICAgIGlkPSJsaW5lYXJHcmFkaWVudDQzOTkiPgogICAgICA8c3RvcAogICAgICAgICBzdHlsZT0ic3RvcC1jb2xvcjojZjlmOWY5O3N0b3Atb3BhY2l0eToxOyIKICAgICAgICAgb2Zmc2V0PSIwIgogICAgICAgICBpZD0ic3RvcDQ0MDEiIC8+CiAgICAgIDxzdG9wCiAgICAgICAgIHN0eWxlPSJzdG9wLWNvbG9yOiNmOWY5Zjk7c3RvcC1vcGFjaXR5OjA7IgogICAgICAgICBvZmZzZXQ9IjEiCiAgICAgICAgIGlkPSJzdG9wNDQwMyIgLz4KICAgIDwvbGluZWFyR3JhZGllbnQ+CiAgICA8bGluZWFyR3JhZGllbnQKICAgICAgIGlkPSJsaW5lYXJHcmFkaWVudDQzNzUiPgogICAgICA8c3RvcAogICAgICAgICBzdHlsZT0ic3RvcC1jb2xvcjojMzY0ZTU5O3N0b3Atb3BhY2l0eToxOyIKICAgICAgICAgb2Zmc2V0PSIwIgogICAgICAgICBpZD0ic3RvcDQzNzciIC8+CiAgICAgIDxzdG9wCiAgICAgICAgIHN0eWxlPSJzdG9wLWNvbG9yOiMzNjRlNTk7c3RvcC1vcGFjaXR5OjA7IgogICAgICAgICBvZmZzZXQ9IjEiCiAgICAgICAgIGlkPSJzdG9wNDM3OSIgLz4KICAgIDwvbGluZWFyR3JhZGllbnQ+CiAgICA8bGluZWFyR3JhZGllbnQKICAgICAgIGlkPSJsaW5lYXJHcmFkaWVudDQzNjciPgogICAgICA8c3RvcAogICAgICAgICBzdHlsZT0ic3RvcC1jb2xvcjojZGMwMDBmO3N0b3Atb3BhY2l0eToxOyIKICAgICAgICAgb2Zmc2V0PSIwIgogICAgICAgICBpZD0ic3RvcDQzNjkiIC8+CiAgICAgIDxzdG9wCiAgICAgICAgIHN0eWxlPSJzdG9wLWNvbG9yOiMwMGZmMDA7c3RvcC1vcGFjaXR5OjA7IgogICAgICAgICBvZmZzZXQ9IjEiCiAgICAgICAgIGlkPSJzdG9wNDM3MSIgLz4KICAgIDwvbGluZWFyR3JhZGllbnQ+CiAgICA8bGluZWFyR3JhZGllbnQKICAgICAgIGlkPSJsaW5lYXJHcmFkaWVudDQzNTkiPgogICAgICA8c3RvcAogICAgICAgICBzdHlsZT0ic3RvcC1jb2xvcjojZGMwMDBmO3N0b3Atb3BhY2l0eToxOyIKICAgICAgICAgb2Zmc2V0PSIwIgogICAgICAgICBpZD0ic3RvcDQzNjEiIC8+CiAgICAgIDxzdG9wCiAgICAgICAgIHN0eWxlPSJzdG9wLWNvbG9yOiMwMDAwMDA7c3RvcC1vcGFjaXR5OjA7IgogICAgICAgICBvZmZzZXQ9IjEiCiAgICAgICAgIGlkPSJzdG9wNDM2MyIgLz4KICAgIDwvbGluZWFyR3JhZGllbnQ+CiAgICA8bGluZWFyR3JhZGllbnQKICAgICAgIGlua3NjYXBlOmNvbGxlY3Q9ImFsd2F5cyIKICAgICAgIHhsaW5rOmhyZWY9IiNsaW5lYXJHcmFkaWVudDQzNzUiCiAgICAgICBpZD0ibGluZWFyR3JhZGllbnQ0MzgxIgogICAgICAgeDE9IjMxLjk1NzI2OCIKICAgICAgIHkxPSIyOS43NTE0OTMiCiAgICAgICB4Mj0iLTQ1LjA0MTQwNSIKICAgICAgIHkyPSItMTguNTkxNjE2IgogICAgICAgZ3JhZGllbnRVbml0cz0idXNlclNwYWNlT25Vc2UiCiAgICAgICBncmFkaWVudFRyYW5zZm9ybT0ibWF0cml4KDAuOTM3NjYzOTMsMCwwLDAuOTM3NjYzOTMsMS41NDI1NjYsMS43MTk5NjkzKSIgLz4KICAgIDxsaW5lYXJHcmFkaWVudAogICAgICAgaW5rc2NhcGU6Y29sbGVjdD0iYWx3YXlzIgogICAgICAgeGxpbms6aHJlZj0iI2xpbmVhckdyYWRpZW50NDQwOSIKICAgICAgIGlkPSJsaW5lYXJHcmFkaWVudDQ0MTUiCiAgICAgICB4MT0iMTYuMzQ1MTI1IgogICAgICAgeTE9IjMuODM4ODk0OCIKICAgICAgIHgyPSIzNi4wMDE1NjEiCiAgICAgICB5Mj0iMjQuMzU5MTY0IgogICAgICAgZ3JhZGllbnRVbml0cz0idXNlclNwYWNlT25Vc2UiIC8+CiAgPC9kZWZzPgogIDxzb2RpcG9kaTpuYW1lZHZpZXcKICAgICBpZD0iYmFzZSIKICAgICBwYWdlY29sb3I9IiNmZmZmZmYiCiAgICAgYm9yZGVyY29sb3I9IiM2NjY2NjYiCiAgICAgYm9yZGVyb3BhY2l0eT0iMS4wIgogICAgIGlua3NjYXBlOnBhZ2VvcGFjaXR5PSIwLjAiCiAgICAgaW5rc2NhcGU6cGFnZXNoYWRvdz0iMiIKICAgICBpbmtzY2FwZTp6b29tPSI5Ljg5OTQ5NDkiCiAgICAgaW5rc2NhcGU6Y3g9IjEuOTU0Nzk3OCIKICAgICBpbmtzY2FwZTpjeT0iMjguMDAwMjMyIgogICAgIGlua3NjYXBlOmN1cnJlbnQtbGF5ZXI9ImxheWVyMSIKICAgICBzaG93Z3JpZD0idHJ1ZSIKICAgICBpbmtzY2FwZTpncmlkLWJib3g9InRydWUiCiAgICAgaW5rc2NhcGU6ZG9jdW1lbnQtdW5pdHM9InB4IgogICAgIGlua3NjYXBlOnNuYXAtZ2xvYmFsPSJmYWxzZSIKICAgICBpbmtzY2FwZTpzbmFwLWJib3g9InRydWUiCiAgICAgaW5rc2NhcGU6YmJveC1ub2Rlcz0idHJ1ZSIKICAgICBpbmtzY2FwZTpiYm94LXBhdGhzPSJ0cnVlIgogICAgIGlua3NjYXBlOnNuYXAtYmJveC1lZGdlLW1pZHBvaW50cz0idHJ1ZSIKICAgICBpbmtzY2FwZTp3aW5kb3ctd2lkdGg9IjE1NDMiCiAgICAgaW5rc2NhcGU6d2luZG93LWhlaWdodD0iODc2IgogICAgIGlua3NjYXBlOndpbmRvdy14PSI1NyIKICAgICBpbmtzY2FwZTp3aW5kb3cteT0iMjQiCiAgICAgaW5rc2NhcGU6d2luZG93LW1heGltaXplZD0iMSIgLz4KICA8bWV0YWRhdGEKICAgICBpZD0ibWV0YWRhdGEyOTkwIj4KICAgIDxyZGY6UkRGPgogICAgICA8Y2M6V29yawogICAgICAgICByZGY6YWJvdXQ9IiI+CiAgICAgICAgPGRjOmZvcm1hdD5pbWFnZS9zdmcreG1sPC9kYzpmb3JtYXQ+CiAgICAgICAgPGRjOnR5cGUKICAgICAgICAgICByZGY6cmVzb3VyY2U9Imh0dHA6Ly9wdXJsLm9yZy9kYy9kY21pdHlwZS9TdGlsbEltYWdlIiAvPgogICAgICAgIDxkYzp0aXRsZT48L2RjOnRpdGxlPgogICAgICA8L2NjOldvcms+CiAgICA8L3JkZjpSREY+CiAgPC9tZXRhZGF0YT4KICA8ZwogICAgIGlkPSJsYXllcjEiCiAgICAgaW5rc2NhcGU6bGFiZWw9IkxheWVyIDEiCiAgICAgaW5rc2NhcGU6Z3JvdXBtb2RlPSJsYXllciI+CiAgICA8cGF0aAogICAgICAgc3R5bGU9ImZpbGw6I2ZmZmZmZjtmaWxsLW9wYWNpdHk6MTtzdHJva2U6IzAwMDAwMDtzdHJva2Utd2lkdGg6MC41NzQwNTA3ODtzdHJva2UtbGluZWpvaW46cm91bmQ7c3Ryb2tlLW1pdGVybGltaXQ6NDtzdHJva2UtZGFzaGFycmF5Om5vbmU7c3Ryb2tlLW9wYWNpdHk6MC40MzkyMTU2OSIKICAgICAgIGQ9Im0gMjQuMDE1NDE5LDEuMjg3MDI0OSBjIC0xMi41NDk0MjEsMCAtMjIuNzI4MzkzNiwxMC4xNzg5NzExIC0yMi43MjgzOTM2LDIyLjcyODM5MzEgMCwxMi41NDk0MjIgMTAuMTc4OTcyNiwyMi43MjgzOTUgMjIuNzI4MzkzNiwyMi43MjgzOTUgMTQuMzM3NzQyLC0wLjM0Mjg3NyA5LjYxNDM1MiwtNC43MDI3MDUgMjMuNjk3NTU2LDAuOTY5MTYxIC03LjU0NTQ1MywtMTMuMDAxNTU1IC0xLjA4Mjk3MywtMTMuMzI5NjQgLTAuOTY5MTYxLC0yMy42OTc1NTYgMCwtMTIuNTQ5NDIyIC0xMC4xNzg5NzMsLTIyLjcyODM5MzEgLTIyLjcyODM5NSwtMjIuNzI4MzkzMSB6IgogICAgICAgaWQ9InBhdGgzNzY5IgogICAgICAgaW5rc2NhcGU6Y29ubmVjdG9yLWN1cnZhdHVyZT0iMCIKICAgICAgIHNvZGlwb2RpOm5vZGV0eXBlcz0ic3NjY2NzIiAvPgogICAgPHBhdGgKICAgICAgIGlua3NjYXBlOmNvbm5lY3Rvci1jdXJ2YXR1cmU9IjAiCiAgICAgICBpZD0icGF0aDM3OTkiCiAgICAgICBkPSJNIDIzLjk4MjI0OSw1LjMxMDYxNjMgQyAxMy42NDU4MjIsNS40MzY0MDA1IDUuMjYxODM1NSwxMy45Mjk5OSA1LjI2MTgzNTUsMjQuMjc1NzUzIGMgMCwxMC4zNDU3NjQgOC4zODM5ODY1LDE4LjYzNTMwMSAxOC43MjA0MTM1LDE4LjUwOTUxNiA5LjgyNzcyNCwtMC4wMzk1MSA3LjUxNjc2OSwtNS40ODk2OTUgMTguMzgwMDgyLC0wLjQ0MzE4NyAtNS45NTA4NDksLTkuMjk2MTE1IDAuMjAxNzUzLC0xMC41MzM2NjcgMC4zNDAzMzYsLTE4LjUyMTk0NyAwLC0xMC4zNDU3NjYgLTguMzgzOTg5LC0xOC42MzUzMDMxIC0xOC43MjA0MTgsLTE4LjUwOTUxODcgeiIKICAgICAgIHN0eWxlPSJmaWxsOnVybCgjbGluZWFyR3JhZGllbnQ0MzgxKTtmaWxsLW9wYWNpdHk6MTtzdHJva2U6bm9uZSIKICAgICAgIHNvZGlwb2RpOm5vZGV0eXBlcz0ic3NjY2NzIiAvPgogICAgPGcKICAgICAgIHN0eWxlPSJmb250LXN0eWxlOm5vcm1hbDtmb250LXdlaWdodDpub3JtYWw7Zm9udC1zaXplOjQwcHg7bGluZS1oZWlnaHQ6MTI1JTtmb250LWZhbWlseTpTYW5zO2xldHRlci1zcGFjaW5nOjBweDt3b3JkLXNwYWNpbmc6MHB4O2ZpbGw6IzAwMDAwMDtmaWxsLW9wYWNpdHk6MTtzdHJva2U6bm9uZSIKICAgICAgIGlkPSJ0ZXh0NDM4MyIgLz4KICAgIDxnCiAgICAgICBzdHlsZT0iZm9udC1zdHlsZTpub3JtYWw7Zm9udC13ZWlnaHQ6bm9ybWFsO2ZvbnQtc2l6ZTo0MHB4O2xpbmUtaGVpZ2h0OjEyNSU7Zm9udC1mYW1pbHk6U2FucztsZXR0ZXItc3BhY2luZzowcHg7d29yZC1zcGFjaW5nOjBweDtmaWxsOiMwMDAwMDA7ZmlsbC1vcGFjaXR5OjE7c3Ryb2tlOm5vbmUiCiAgICAgICBpZD0idGV4dDQ0MjEiIC8+CiAgICA8ZwogICAgICAgdHJhbnNmb3JtPSJzY2FsZSgxLjExMjIzNzMsMC44OTkwODg3NCkiCiAgICAgICBzdHlsZT0iZm9udC1zdHlsZTpub3JtYWw7Zm9udC13ZWlnaHQ6bm9ybWFsO2ZvbnQtc2l6ZTo0Mi4xMDU4NzMxMXB4O2xpbmUtaGVpZ2h0OjEyNSU7Zm9udC1mYW1pbHk6U2FucztsZXR0ZXItc3BhY2luZzowcHg7d29yZC1zcGFjaW5nOjBweDtmaWxsOiNmZmZmZmY7ZmlsbC1vcGFjaXR5OjE7c3Ryb2tlOm5vbmUiCiAgICAgICBpZD0idGV4dDM3OTciPgogICAgICA8cGF0aAogICAgICAgICBkPSJtIDIxLjY4ODg1NCwyMy42MzYyNTEgcSAtMS4wMjc5NzUsLTEuMTUxMzMzIC0yLjg1Nzc3MSwtMi43NTQ5NzQgLTIuMDE0ODMyLC0xLjc2ODExOCAtMi43MTM4NTUsLTIuNzc1NTM0IC0wLjY5OTAyNCwtMS4wMjc5NzUgLTAuNjk5MDI0LC0yLjI0MDk4NiAwLC0xLjgwOTIzNyAxLjY4NTg4LC0yLjgzNzIxMiAxLjY4NTg4LC0xLjA0ODUzNSA0LjM5OTczNSwtMS4wNDg1MzUgMi43MTM4NTUsMCA0LjcyODY4NywwLjkyNTE3OCAyLjAzNTM5MSwwLjkyNTE3NyAyLjAzNTM5MSwyLjU0OTM3OSAwLDAuNzgxMjYxIC0wLjQ5MzQyOCwxLjI5NTI0OSAtMC40OTM0MjgsMC41MTM5ODcgLTEuMTUxMzMzLDAuNTEzOTg3IC0wLjk0NTczNywwIC0yLjIyMDQyNiwtMS40MTg2MDYgLTEuMjk1MjQ5LC0xLjQzOTE2NSAtMi4xOTk4NjgsLTIuMDE0ODMyIC0wLjg4NDA1OSwtMC41OTYyMjUgLTIuMDc2NTEsLTAuNTk2MjI1IC0xLjUyMTQwNCwwIC0yLjUwODI2LDAuNjc4NDYzIC0wLjk2NjI5NywwLjY3ODQ2NCAtMC45NjYyOTcsMS43MjY5OTkgMCwwLjk4Njg1NyAwLjgwMTgyMSwxLjg1MDM1NiAwLjgwMTgyMSwwLjg2MzQ5OSA0LjEzMjQ2MSwzLjE0NTYwNSAzLjU1Njc5NSwyLjQ0NjU4MSA1LjAxNjUyLDMuODI0MDY4IDEuNDgwMjg1LDEuMzc3NDg3IDIuNDA1NDYyLDMuMzUxMiAwLjkyNTE3OCwxLjk3MzcxMyAwLjkyNTE3OCw0LjE3MzU4IDAsMy44NjUxODggLTIuNzM0NDE0LDYuODI1NzU3IC0yLjcxMzg1NSwyLjk0MDAxIC02LjM1Mjg4OCwyLjk0MDAxIC0zLjMxMDA4MSwwIC01LjU5MjE4NywtMi4zNjQzNDQgLTIuMjgyMTA1LC0yLjM2NDM0MyAtMi4yODIxMDUsLTYuMzExNzY5IDAsLTMuODAzNTA5IDIuNTA4MjYsLTYuMzUyODg4IDIuNTI4ODE5LC0yLjU0OTM3OSA2LjIwODk3MSwtMy4wODM5MjYgeiBtIDAuOTA0NjE5LDAuOTQ1NzM3IHEgLTUuOTAwNTc5LDAuOTY2Mjk3IC01LjkwMDU3OSw4LjEwMDQ0NyAwLDMuNjgwMTUyIDEuNDU5NzI1LDUuNzE1NTQzIDEuNDgwMjg1LDIuMDM1MzkxIDMuNDMzNDM4LDIuMDM1MzkxIDIuMDM1MzkxLDAgMy4zNTEyLC0xLjk1MzE1MyAxLjMxNTgwOCwtMS45NzM3MTMgMS4zMTU4MDgsLTUuMzI0OTEzIDAsLTQuODUyMDQ0IC0zLjY1OTU5MiwtOC41NzMzMTUgeiIKICAgICAgICAgc3R5bGU9ImZvbnQtZmFtaWx5OidUaW1lcyBOZXcgUm9tYW4nOy1pbmtzY2FwZS1mb250LXNwZWNpZmljYXRpb246J1RpbWVzIE5ldyBSb21hbic7ZmlsbDojZmZmZmZmO2ZpbGwtb3BhY2l0eToxIgogICAgICAgICBpZD0icGF0aDQxNjEiIC8+CiAgICA8L2c+CiAgPC9nPgo8L3N2Zz4K" width="20" height="20" alt="DeltaChat" style="display:block"></button>
        </div>
        <div class="new-compose-field">
          <div id="new-recipients" class="new-recipients-list">
            <div class="new-recipient-row" data-kind="to">
              <span class="new-field-label">To</span>
              <input class="new-field-input" type="email" placeholder="recipient@example.com" autocomplete="off">
              <button id="new-add-btn" class="new-compose-add-btn" tabindex="-1" style="font-size:18px;padding:0 4px;line-height:1">+</button>
            </div>
          </div>
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
        <div id="new-invite-out" class="new-compose-field" style="display:none">
          <input id="new-invite-url" class="new-field-input" readonly onclick="this.select()">
        </div>
      </div>
    </div>`
  }

  function onShowNew() {
    const recipientsDiv = document.getElementById('new-recipients')!
    const addBtn = document.getElementById('new-add-btn')

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
        out[(row.dataset.kind as Kind) ?? 'to'].push(v)
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

    // Populate the "From" account selector; hide the row when there's nothing
    // to choose (0–1 accounts) so it doesn't add noise to the common case.
    const fromSel = document.getElementById('new-from') as HTMLSelectElement | null
    if (fromSel) {
      // `sessions` can still be empty on a fresh #new load (init race), so fall
      // back to the stored account list — never leave the selector blank.
      const emails = (sessions.length ? sessions.map(s => s.account.email) : loadStoredAccounts().map(a => a.email))
      const uniq = [...new Set(emails)]
      const def = activeSession()?.account.email ?? uniq[0]
      fromSel.innerHTML = uniq.map(e =>
        `<option value="${esc(e)}"${e === def ? ' selected' : ''}>${esc(e)}</option>`,
      ).join('')
    }
    const selectedFrom = () => (document.getElementById('new-from') as HTMLSelectElement | null)?.value
      || activeSession()?.account.email || ''

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
    fromSel?.addEventListener('change', updateSendAvatar)

    // Relay base URLs for this home domain (see account-create.getMailUrl/getApUrl).
    const cfg = (window as any).__BISET_CONFIG__
    const mailUrl = cfg?.mail_url || (cfg?.hostname ? `https://mail.${cfg.hostname}` : '')
    const apUrl = cfg?.ap_url || (cfg?.hostname ? `https://ap.${cfg.hostname}` : '')

    // Background recipient discovery: ask our own AP relay (server-side webfinger,
    // no browser CORS) whether the address is an ActivityPub actor. If so, badge
    // the row — the message will route via AP, made explicit in the UI.
    const resolveAp = async (inp: HTMLInputElement) => {
      const row = inp.closest<HTMLElement>('.new-recipient-row')
      if (!row) return
      row.querySelector('.ap-badge')?.remove()
      delete row.dataset.ap
      const addr = inp.value.trim()
      if (!addr || !addr.includes('@') || !apUrl) return
      try {
        const r = await fetch(`${apUrl}/resolve?acct=${encodeURIComponent(addr)}`)
        const j = await r.json()
        // Cache the recipient's actor avatar so the conversation shows it once opened.
        if (j?.icon && !avatarDataUrl(addr)) saveAvatar(addr, j.icon)
        if (j?.ap && inp.value.trim() === addr) {
          const b = document.createElement('span')
          b.className = 'ap-badge'
          b.textContent = 'AP'
          b.style.cssText = 'font-size:10px;font-weight:700;color:#fff;background:#8b5cf6;border-radius:4px;padding:1px 5px;margin-left:4px;flex-shrink:0;align-self:center;cursor:pointer;user-select:none;transition:opacity .12s,filter .12s'
          // The badge is a toggle: on = deliver via ActivityPub, off (dim +
          // grayscale) = fall back to mail for this recipient.
          const setOn = (on: boolean) => {
            if (on) { row.dataset.ap = 'true'; b.style.opacity = ''; b.style.filter = ''; b.title = 'ActivityPub — click to send via mail instead' }
            else { delete row.dataset.ap; b.style.opacity = '0.4'; b.style.filter = 'grayscale(1)'; b.title = 'Mail — click to send via ActivityPub' }
          }
          b.addEventListener('click', () => setOn(row.dataset.ap !== 'true'))
          setOn(true)
          inp.after(b)
        }
      } catch { /* discovery is best-effort */ }
    }

    const attachPrefetch = (inp: HTMLInputElement) => {
      inp.addEventListener('input', updateTitleLabel)
      inp.addEventListener('blur', async () => {
        const addr = inp.value.trim()
        const sess = sessionFor(selectedFrom()) ?? activeSession()
        if (!addr || !addr.includes('@') || !sess) return
        // Only warm the PGP peer-key cache on a mail relay; the AP relay has no
        // peer-key store (and PGP is meaningless for fediverse recipients).
        if (!isApRelay(sess.account.serverUrl)) {
          prefetchRecipientKey(addr, sess.account.email, sess.account.serverUrl, sess.account.password)
        }
        resolveAp(inp)
      })
    }

    const addRow = (kind: Kind, focus = false) => {
      const row = document.createElement('div')
      row.className = 'new-recipient-row'
      row.dataset.kind = kind
      const tag = document.createElement('span')
      tag.className = 'new-field-label'
      tag.textContent = kind === 'cc' ? 'Cc' : 'Bcc'
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
      rm.addEventListener('click', () => { row.remove(); updateTitleLabel() })
      row.append(tag, inp, rm)
      recipientsDiv.appendChild(row)
      updateTitleLabel()
      if (focus) inp.focus()
    }

    // "+" opens a tiny chooser: add a Cc or a Bcc row.
    let addMenu: HTMLElement | null = null
    const closeAddMenu = () => { addMenu?.remove(); addMenu = null }
    addBtn?.addEventListener('click', (e) => {
      e.stopPropagation()
      if (addMenu) { closeAddMenu(); return }
      const menu = document.createElement('div')
      menu.className = 'new-recip-menu'
      for (const kind of ['cc', 'bcc'] as Kind[]) {
        const b = document.createElement('button')
        b.className = 'new-recip-menu-item'
        b.textContent = kind === 'cc' ? 'Cc' : 'Bcc'
        b.addEventListener('click', () => { addRow(kind, true); closeAddMenu() })
        menu.append(b)
      }
      const r = (addBtn as HTMLElement).getBoundingClientRect()
      menu.style.top = r.bottom + 4 + 'px'
      menu.style.left = r.left + 'px'
      document.body.append(menu)
      addMenu = menu
      setTimeout(() => document.addEventListener('click', closeAddMenu, { once: true }), 0)
    })

    // Mark the initial static row as the To recipient and wire prefetch.
    const firstRow = recipientsDiv.querySelector<HTMLElement>('.new-recipient-row')
    if (firstRow) firstRow.dataset.kind = 'to'
    const firstInp = recipientsDiv.querySelector<HTMLInputElement>('.new-field-input')
    if (firstInp) attachPrefetch(firstInp)
    updateTitleLabel()

    // Pre-fill the To field when compose was opened via openComposeTo (e.g. the
    // /<user>/ page). Resolve straight away so the AP badge shows.
    if (composePrefillTo && firstInp) {
      firstInp.value = composePrefillTo
      composePrefillTo = null
      resolveAp(firstInp)
      updateTitleLabel()
      // Body focus is driven by openComposeTo's retry loop (more reliable across
      // the #new→app transition than a focus() here).
    }

    // DeltaChat SecureJoin invite link (setup-contact). A DeltaChat/chatmail
    // contact opens this to exchange keys with biset automatically.
    document.getElementById('new-invite-btn')?.addEventListener('click', async () => {
      const fromEmail = selectedFrom()
      if (!fromEmail) { showSysMsg('No session'); return }
      const url = await newInviteUrl(fromEmail, fromEmail)
      if (!url) { showSysMsg('Invite link failed (no key set)'); return }
      const out = document.getElementById('new-invite-out')!
      const inp = document.getElementById('new-invite-url') as HTMLInputElement
      out.style.display = ''
      inp.value = url
      inp.focus(); inp.select()
      try { await navigator.clipboard.writeText(url); showSysMsg('Invite link copied') } catch { /* manual copy */ }
    })

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
      const { to, cc, bcc } = collect()
      const visible = [...to, ...cc]
      if (!visible.length) { (recipientsDiv.querySelector('.new-field-input') as HTMLElement)?.focus(); return }
      const body = (document.getElementById('new-body') as HTMLTextAreaElement)?.value.trim() || ''
      const fromEmail = selectedFrom()
      const title = (document.getElementById('new-title') as HTMLInputElement)?.value.trim() || ''

      // Protocol from the AP badges. A single compose is one protocol — mixing
      // mail + ActivityPub recipients in one message is not allowed.
      const filledRows = [...recipientsDiv.querySelectorAll<HTMLElement>('.new-recipient-row')]
        .filter(r => r.querySelector<HTMLInputElement>('.new-field-input')?.value.trim())
      const apCount = filledRows.filter(r => r.dataset.ap === 'true').length
      if (apCount > 0 && apCount < filledRows.length) {
        showSysMsg('Mixed mail + ActivityPub recipients not allowed'); return
      }
      if (apCount > 0 && pendingAttachments.length) {
        showSysMsg('Attachments are not supported over ActivityPub'); return
      }
      const relayUrl = apCount > 0 ? apUrl : mailUrl
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

  // ── per-account context menu ────────────────────────────────────────────────

  let _openMenuCleanup: (() => void) | null = null

  function closeAccountMenu() {
    _openMenuCleanup?.()
    _openMenuCleanup = null
  }

  function openAccountMenu(anchor: HTMLElement, email: string, serverUrl?: string) {
    closeAccountMenu()
    const rect = anchor.getBoundingClientRect()
    const menu = document.createElement('div')
    menu.style.cssText = `position:fixed;top:${rect.bottom + 4}px;left:${Math.max(8, rect.right - 180)}px;width:180px;background:var(--bg);border:1px solid var(--border, rgba(128,128,128,0.25));border-radius:8px;box-shadow:0 4px 16px rgba(0,0,0,0.18);z-index:10000;padding:4px;font-size:14px`
    const mkItem = (label: string, danger: boolean, onClick: () => void) => {
      const b = document.createElement('button')
      b.type = 'button'
      b.style.cssText = `display:block;width:100%;text-align:left;padding:8px 12px;background:none;border:none;border-radius:6px;cursor:pointer;color:${danger ? '#ff3b30' : 'var(--text)'};font-size:14px`
      b.textContent = label
      b.addEventListener('mouseover', () => { b.style.background = 'rgba(128,128,128,0.12)' })
      b.addEventListener('mouseout', () => { b.style.background = 'none' })
      b.addEventListener('click', () => { closeAccountMenu(); onClick() })
      menu.appendChild(b)
    }
    mkItem('Change password', false, () => openPasswordModal(email))
    mkItem('Change display name', false, () => openDisplayNameModal(email))
    // Re-publish this identity's DID document (relay list + address) to the DHT.
    // Normally automatic (on boot and on relay change); this is a manual nudge,
    // e.g. after adding a relay elsewhere or if a record expired.
    mkItem('Republish to DHT', false, async () => {
      // DHT puts take several seconds each (mainline DHT traversal latency,
      // now run in parallel across gateways but still not instant) — a long
      // duration here keeps the toast up as a "working" indicator instead of
      // vanishing after 1.8s while the request is still in flight.
      showSysMsg('Publishing to the network…', 30000)
      try {
        const ok = await (await import('../did/publish.ts')).publishOneVisible(email)
        showSysMsg(ok ? 'Published to DHT' : 'No gateway reachable (record not published)')
      } catch { showSysMsg('Publish failed') }
    })
    // Move / spread this identity to a relay on another domain (same DID). Keeps
    // one identity across both addresses; contacts follow via the DID (S2).
    mkItem('Move to another relay…', false, () => {
      const target = prompt('Provision this identity on another relay (base URL, e.g. https://mail.example.com):')?.trim()
      if (!target) return
      // Needs the password to unseal the master secret (scoped token + binding
      // signature) — the seed is never persisted.
      const password = prompt('Enter your password to authorize the move:')
      if (password) moveIdentityToRelay(email, target, password)
    })
    // Per-relay: drop just THIS endpoint from the identity (the card's own relay),
    // as long as it isn't the identity's last one. Republishes so the DID document
    // no longer lists it.
    if (serverUrl && relaysFor(email).length > 1) {
      mkItem('Remove this relay', true, async () => {
        saveStoredAccounts(loadStoredAccounts().filter(x => !(x.email === email && x.serverUrl === serverUrl)))
        for (let i = sessions.length - 1; i >= 0; i--) {
          if (sessions[i].account.email === email && sessions[i].account.serverUrl === serverUrl) sessions.splice(i, 1)
        }
        import('../did/publish.ts').then(m => m.publishOwnDids()).catch(() => {})
        renderAccountsList(); loadLeftInboxes()
      })
    }
    mkItem('Log out', true, async () => {
      // Remove the whole IDENTITY across ALL its relays/addresses (per-relay
      // removal is "Remove this relay"). Compute the identity key BEFORE tearing
      // sessions down, then drop every endpoint that shares it.
      const idKey = identityKeyForEmail(email)
      const endpoints = loadStoredAccounts().filter(a => (a.did || a.email) === idKey)
      const emails = new Set(endpoints.map(e => e.email))
      saveStoredAccounts(loadStoredAccounts().filter(a => (a.did || a.email) !== idKey))
      for (let i = sessions.length - 1; i >= 0; i--) {
        if (identityKey(sessions[i]) === idKey) sessions.splice(i, 1)
      }
      // Clear localStorage keys + PGP keys scoped to each of the identity's addresses.
      for (const k of Object.keys(localStorage)) {
        for (const em of emails) if (k === `jmap_notif_${em}` || k === `sjoin_invites_${em}`) localStorage.removeItem(k)
      }
      for (const em of emails) await deleteKey(em)
      for (const ep of endpoints) _accInfoCache.delete(accountKey(ep))
      await clearIdentityCache(idKey)
      renderAccountsList()
    })
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
        okEl.textContent = 'Saved'; okEl.style.display = 'block'
        setTimeout(dismiss, 600)
      } catch {
        errEl.textContent = 'Save failed'; errEl.style.display = 'block'
      } finally {
        submit.disabled = false; submit.textContent = 'Save'
      }
    })
  }

  // Move / spread an identity to a relay on a DIFFERENT domain (S2). Provisions
  // the SAME envelope (→ same seed → same DID) at the target; the target's apex
  // assigns a new address (localpart@newdomain), which the response returns. The
  // new endpoint is tagged with the identity's DID so it merges under one
  // identity (A1) and its messages unify (A2). Re-publishing lists the new
  // address in alsoKnownAs so contacts following the DID can reach the move —
  // the core of domain-death portability (a).
  async function moveIdentityToRelay(email: string, targetUrl: string, password: string): Promise<void> {
    const tgt = targetUrl.replace(/\/$/, '')
    const existing = relaysFor(email)[0]
    if (!existing) { showSysMsg('No connected session for this identity'); return }
    const username = email.split('@')[0]
    try {
      const { getDidRecord, storeDidRecord } = await import('../did/store.ts')
      const rec = await getDidRecord(email)
      if (!rec) { showSysMsg('No DID for this identity'); return }
      // The scoped token + binding signature need the master secret, which only
      // the password unseals (the seed is never persisted). Get it from any of the
      // identity's existing cryptenv relays.
      const env = await fetchEnvelope(existing.account.serverUrl, existing.account.email)
      if (!env) { showSysMsg('Could not read the account envelope'); return }
      let masterSecret: Uint8Array
      try { masterSecret = (await unsealEnvelope(env, password)).masterSecret }
      catch { showSysMsg('Incorrect password'); return }
      // Bind to the target with a signature (no secret leaves); a move to a
      // third-party relay does NOT get the envelope (recovery stays seed-only).
      const { provisionAccount } = await import('../did/provision.ts')
      const res = await provisionAccount({
        serverUrl: tgt, username, did: rec.did,
        rootPrivateKey: hexToBytes(rec.rootPrivateKey), masterSecret,
      })
      if (res.conflict) { showSysMsg('That address is owned by a different key'); return }
      if (!res.ok) { showSysMsg(`Move failed (${res.status})`); return }
      const newEmail = res.email || `${username}@${new URL(tgt).hostname}`
      const session = await initSession({ serverUrl: tgt, email: newEmail, password: res.password!, did: rec.did }).catch(() => null)
      if (!session) { showSysMsg('Provisioned but failed to connect'); return }
      session.account.did = rec.did
      // initSession already fires fetchRelayInfo(tgt) fire-and-forget, but the
      // card renders synchronously right after — awaiting it explicitly here
      // (idempotent no-op once cached) ensures the FIRST paint already knows
      // whether tgt is mail or activitypub, instead of falling back to the
      // home-ap_url guess (wrong for any foreign AP relay) with nothing to
      // ever correct the label afterward — protoEl.textContent is set once at
      // card-creation time and never revisited.
      const { fetchRelayInfo } = await import('../context.ts')
      await fetchRelayInfo(tgt)
      const { deriveKek } = await import('../cryptenv.ts')
      const kek = await deriveKek(masterSecret)
      ;(session as any).kek = kek
      if (!sessions.some(s => s.account.email === newEmail && s.account.serverUrl === tgt)) sessions.push(session)
      const stored = loadStoredAccounts()
      if (!stored.some(a => a.email === newEmail && a.serverUrl === tgt)) {
        saveStoredAccounts([...stored, { serverUrl: tgt, email: newEmail, password: res.password!, did: rec.did }])
      }
      initPGPForSession(session, kek)
      // Mirror the DID record under the new address so it stays resolvable if the
      // new endpoint later becomes the representative (e.g. the old one is dropped).
      await storeDidRecord({ ...rec, email: newEmail })
      if (isApRelay(tgt)) advertiseOwnAvatarForEmail(newEmail)
      startPolling()
      renderAccountsList()
      loadLeftInboxes()
      // The move itself (provision + connect, above) is fast; publishing the
      // updated relay list to the DHT is the slow part (several seconds per
      // gateway). Report them as two distinct steps so a contact-discovery
      // wait isn't mistaken for the move having failed or hung.
      showSysMsg(`Moved — also reachable at ${newEmail}. Publishing to the network…`, 30000)
      import('../did/publish.ts').then(m => m.publishOneVisible(email)).then(ok => {
        showSysMsg(ok ? `Published — ${newEmail} is now discoverable` : 'Moved, but no gateway accepted the publish (will retry automatically)')
      }).catch(() => { showSysMsg('Moved, but publishing to the network failed (will retry automatically)') })
    } catch (e) { console.warn('[move] failed', e); showSysMsg('Could not move identity') }
  }

  function renderAccountsList() {
    const $list = document.getElementById('cmd-acc-list')
    if (!$list) return
    $list.textContent = ''
    const accounts = loadStoredAccounts()
    if (!accounts.length) {
      const msg = document.createElement('div')
      msg.className = 'lp-search-status'
      msg.textContent = 'No accounts'
      $list.appendChild(msg)
      return
    }
    const relayLabel = (url: string): string => {
      try { return new URL(url).hostname.split('.')[0] } catch { return '?' }
    }
    const protoLabel = (url: string): string => isApRelay(url) ? 'AP' : 'SMTP'
    // One card per RELAY endpoint. Identity-by-DID: the DID is the identity; each
    // relay is a concrete endpoint you see and manage (SMTP, ActivityPub, …).
    // Cards of the same identity share a DID (shown small on each); sorting by
    // did keeps an identity's relays adjacent.
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

      const avatarName = a.email
      const avatar = document.createElement('div')
      avatar.className = 'lp-avatar'
      avatar.style.cssText = 'flex-shrink:0;cursor:pointer;position:relative;overflow:hidden'
      avatar.title = 'Click to set avatar'
      const ownAvatar = avatarDataUrl(a.email)
      if (ownAvatar) {
        avatar.style.cssText += ';background:transparent'
        const img = document.createElement('img')
        img.src = ownAvatar
        img.style.cssText = 'width:100%;height:100%;object-fit:cover;border-radius:50%'
        avatar.appendChild(img)
      } else {
        avatar.style.cssText += ';' + avatarStyle(avatarName)
        avatar.textContent = avatarName.charAt(0).toUpperCase()
      }
      avatar.addEventListener('click', (ev) => { ev.stopPropagation(); pickAndSetAvatar(a.email) })

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
      statsRow.append(statUnread, statPgp, statSync)

      // The identity IS the DID (identity-by-DID) — surface it. The address in
      // the header is just its current primary handle; this line is the stable
      // root that binds all the endpoints above. Click to copy.
      const didLine = document.createElement('div')
      if (a.did) {
        const suffix = a.did.replace(/^did:dht:/, '')
        didLine.style.cssText = 'font-size:11px;color:var(--text-dim);font-family:ui-monospace,monospace;cursor:pointer;white-space:nowrap;overflow:hidden;text-overflow:ellipsis'
        didLine.textContent = `did:dht:${suffix.slice(0, 8)}…${suffix.slice(-6)}`
        didLine.title = `${a.did}\n(click to copy)`
        didLine.addEventListener('click', (ev) => { ev.stopPropagation(); navigator.clipboard?.writeText(a.did!).then(() => showSysMsg('DID copied')).catch(() => {}) })
        left.append(headRow, didLine, statsRow)
      } else {
        left.append(headRow, statsRow)
      }

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

      row.append(avatar, left, menuBtn)
      $list.appendChild(row)

      if (session) {
        fetchAccountInfo(session).then(info => {
          if (!info) return
          statUnread.textContent = fmtUnread(info)
          statPgp.textContent = info.pgp == null ? '' : info.pgp ? 'PGP ✓' : 'PGP ✗'
          statSync.textContent = `Sync: ${fmtRelTime(info.lastSyncAt)}`
        }).catch(() => {})
      }
    }
  }

  function onShowAccounts() {
    renderAccountsList()
    const form = document.getElementById('cmd-acc-form') as HTMLFormElement | null
    form?.addEventListener('submit', async (ev) => {
      ev.preventDefault()
      const serverInput = document.getElementById('cmd-acc-server') as HTMLInputElement
      const emailInput = document.getElementById('cmd-acc-email') as HTMLInputElement
      const pwInput = document.getElementById('cmd-acc-password') as HTMLInputElement
      const errEl = document.getElementById('cmd-acc-error')!
      const addBtn = document.getElementById('cmd-acc-add') as HTMLButtonElement

      const email = emailInput.value.trim()
      const pw = pwInput.value
      if (!email || !pw) { errEl.textContent = 'Email and Password required'; errEl.style.display = 'block'; return }

      const raw = serverInput.value.trim().replace(/\/$/, '')
      const explicit = raw && !/^https?:\/\//i.test(raw) ? 'https://' + raw : raw
      const domain = email.split('@')[1] ?? ''
      // An identity can span multiple relays. For the home domain, connect BOTH
      // the mail (mail.<host>) and ActivityPub (ap.<host>) relays best-effort —
      // whichever comes up is kept, so an AP-only account (no mailbox) is fine.
      // An explicit server overrides to that single relay; other domains fall
      // back to bare-domain JMAP autodiscovery.
      const cfg = (window as any).__BISET_CONFIG__
      const homeHost = cfg?.hostname
      const mailUrl = cfg?.mail_url || (homeHost ? `https://mail.${homeHost}` : '')
      const apUrl = cfg?.ap_url || (homeHost ? `https://ap.${homeHost}` : '')
      const apexOf = (u: string) => { try { return new URL(u).hostname.split('.').slice(1).join('.') } catch { return '' } }
      const isHomeDomain = (d: string) => d === homeHost || (!!mailUrl && d === apexOf(mailUrl)) || (!!apUrl && d === apexOf(apUrl))
      let candidates: string[]
      if (explicit) candidates = [explicit]
      else if (domain && isHomeDomain(domain)) candidates = [mailUrl, apUrl].filter(Boolean)
      else if (domain) candidates = ['https://' + domain]
      else candidates = []
      if (!candidates.length) {
        serverInput.style.display = ''
        ;(serverInput as HTMLInputElement).focus()
        errEl.textContent = 'Server URL required'
        errEl.style.display = 'block'
        addBtn.disabled = false; addBtn.textContent = 'Add'
        return
      }

      addBtn.disabled = true; addBtn.textContent = 'Connecting…'; errEl.style.display = 'none'

      // Relays of one identity ideally share a cryptenv envelope (same authToken).
      // Legacy accounts may have independent envelopes per relay, so we fetch each
      // relay's envelope separately and only fall back to a cached token when the
      // relay has no envelope of its own. kek is kept from the first successful
      // unseal (mail relay) since that's where the PGP key lives.
      let kek: Uint8Array | undefined
      let masterSecret: Uint8Array | undefined
      let badPw = false
      const resolveAuth = async (server: string): Promise<string | null> => {
        const env = await fetchEnvelope(server, email)
        if (!env) return pw // non-cryptenv / DID-less relay: use the raw password
        try {
          const u = await unsealEnvelope(env, pw)
          if (!kek) kek = u.kek
          if (!masterSecret) masterSecret = u.masterSecret
          // Relay-scoped token for THIS server (not a shared master token).
          const { password } = await relayAuth(u.masterSecret, server)
          return password
        } catch { badPw = true; return null }
      }

      const connected: Array<{ session: any; server: string; token: string }> = []
      for (const server of candidates) {
        const token = await resolveAuth(server)
        if (badPw) break
        if (!token) continue
        const session = await initSession({ serverUrl: server, email, password: token }).catch(() => null)
        if (!session) { console.warn('[add] connect failed', server); continue }
        if (kek) (session as any).kek = kek
        connected.push({ session, server, token })
      }

      if (badPw) {
        errEl.textContent = 'Incorrect password'
        errEl.style.display = 'block'
        addBtn.disabled = false; addBtn.textContent = 'Add'
        return
      }
      if (!connected.length) {
        serverInput.style.display = ''
        if (!serverInput.value) serverInput.value = candidates[0]
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
        if (didRecord) { const { putDid } = await import('../cryptenv.ts'); putDid(c.server, relayEmail, c.token, didRecord.did) }
      }
      saveStoredAccounts(stored)
      addBtn.disabled = false; addBtn.textContent = 'Add'
      serverInput.value = ''; serverInput.style.display = 'none'
      emailInput.value = ''
      pwInput.value = ''
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
    if (dock) dock.style.display = 'none'
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
    const dock = document.getElementById('reply-dock')
    if (dock) dock.style.display = ''
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
      await Promise.allSettled(sessions.map(sync))
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

  setupAccountCreateOverlay()
}
