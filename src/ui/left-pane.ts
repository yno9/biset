import { currentInbox, setCurrentInbox, activeSession, sessionFor, sessionForRelay, relaysFor, relaysForId, accountKey, identityKey, identityKeyForEmail, identityIds, sessions, loadStoredAccounts, saveStoredAccounts, setVaultHandle, vaultHandle, clearVaultHandle, isApRelay, isDidCommRelay, relayProtocolLabel, fetchRelayInfo, DIDCOMM_SERVER_URL, mailRelayUrl } from '../context.ts'
import { ownDid, mediatorDeviceActivity, type MediatorDeviceActivity } from '../did/didcomm-devices.ts'
import { bisetWebvhUsername, parseWebvhDid } from '../did/webvh/identifier.ts'
import { currentIdentityDid } from '../did/didcomm/channel.ts'
import { resolveAny as resolveDidAny } from '../did/resolver.ts'
import { getDidRecord, identityProtectionEnabled } from '../did/store.ts'
import {
  lastLeftInboxes, setLastLeftInboxes,
  processedMessages, renderedKeys,
  setLastTs, setIsFirstFetch,
  focusedThreadKey, setFocusedThreadKey,
  notifEnabled, setNotifEnabled,
  lastTs, groupMessages,
} from '../state.ts'
import { esc, formatTime, avatarStyle, inboxToHash, syncAppBadge, hexToBytes, expandDualRelay, previewText } from '../utils.ts'
import { hashSeg } from '../route.ts'
import { displayLabelFor, nameForContact, shortDid, ownDidParts, shortOwnDid, labelForDid, contactIdentityKey } from '../did/contacts.ts'
import type { InboxSummary, StoredAccount, AccountSession } from '../types.ts'
import type { Email } from 'jmap-rfc-types'
// Circular (safe — used only in function bodies):
import { render, syncDockPosition, scrollToFocused, updateScrollSpacer } from './thread.ts'
import { fetchMessages, showSysMsg, startPolling } from './shell.ts'
import { setupNewUserPage, mountNewUserPageInline, unmountNewUserPageInline, getMailUrl, getHostname, randomHex4 } from './account-create.ts'
// From app.ts (safe — called only inside async functions):
import { loadInboxSummaries, initSession, jmapCreateEmail, persistSession } from '../app.ts'
import { decryptAndParse, prefetchRecipientKey } from '../pgp/index.ts'
import { deleteKey } from '../pgp/keys.ts'
import type { OutgoingAttachment } from '../pgp/crypto.ts'
import { clearIdentity as clearIdentityCache } from '../store/cache.ts'
import { avatarDataUrl, saveAvatar } from '../deltachat/avatar.ts'
import { advertiseOwnAvatarForEmail } from '../ap/avatar.ts'
import { apOutboundUrl } from '../ap/config.ts'
import * as jmapEmail from '../jmap/email.ts'
import * as messages from '../store/messages.ts'
import * as identities from '../store/identities.ts'
import { loadFromVault, flushAll, flushMessage, removeMessage } from '../vault/persist.ts'
import * as querystate from '../jmap/querystate.ts'
import { startWatch, stopWatch } from '../vault/watch.ts'
import { newGroupId, isSecurejoinEmail } from '../deltachat/protocol.ts'
import { isReaction } from '../mail/reactions.ts'
import { newInviteUrl } from '../deltachat/securejoin.ts'
import { enablePush, disablePush, setActiveConversation, publishUnreadCounts } from '../push/client.ts'

// ── InboxSummary key ──────────────────────────────────────────────────────────
function isk(i: InboxSummary): string { return i.user + '\0' + i.mailbox + '\0' + i.contact }

// Resolves a DID's full document. Shared by the compose To-field's DID pill
// lookup and the #account page's own-document viewer — the latter used to
// reimplement this a second way (relay-sessions-only, silently empty for a
// relay-less identity), which is why a standalone identity's own #account
// page permanently reported "No document found" despite the record
// resolving fine everywhere else.
async function resolveDidDocFull(did: string) {
  return await resolveDidAny(did)
}


// ── Preview cache / decrypt ───────────────────────────────────────────────────

const _previewCache = new Map<string, string>()

function fmtPreview(body: string): string {
  return esc(previewText(body))
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
// Keeps the account page's floating "+ New Relay" button and its panel
// centred on the right column (positionAccFloating). Module-scoped so
// re-entering the account page replaces it rather than stacking observers.
let accFloatingObserver: ResizeObserver | null = null
let _showMenuPageFn: ((name: string) => void) | null = null
export function showMenuPage(name: string) { _showMenuPageFn?.(name) }

// Open the compose page with the To field pre-filled. Consumed once by the
// compose page's onShow (composePrefillTo). Backs the /<user>/ entry point: start
// a message to that user. URL becomes the SAME shape as a conversation
// permalink (#<contact>, route.ts's hashSeg/utils.ts's inboxToHash) — a
// shareable link to someone with no conversation yet, resolved by main.ts's
// route() the same way an existing one is (2026-08-16, folded the old
// separate `#compose/<addr>` shape into this one).
let composePrefillTo: string | null = null
export function openComposeTo(addr: string) {
  composePrefillTo = addr
  showMenuPage('/compose')
  // On mobile, showApp defaults a fresh (message-less) account to the left pane;
  // opening compose is an explicit intent to see the form, so reveal the right
  // column instead.
  document.getElementById('app')?.classList.remove('show-left')
  try { history.replaceState(null, '', '/#' + hashSeg(addr)) } catch { /* file:// */ }
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
      // Also keyed by the bare DID: a DIDComm send has no "address" of its
      // own to look avatarDataUrl up by (didcomm/channel.ts's sendViaDidComm
      // reads avatarDataUrl(selfDid) directly), and the synthetic DIDComm
      // account's own `email` isn't always the repAccount this panel reads
      // from when the identity also has a real relay.
      await saveAvatar(did, dataUrl)
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

/** The device-list row suffix describing how alive a device slot is, per the
 * mediator (didcomm-devices.ts's mediatorDeviceActivity). Empty string
 * whenever there is nothing trustworthy to say — no answer from the mediator,
 * or this device itself (which is answering right now by definition) — since
 * an absent label reads as "no information", while a wrong one ("never seen")
 * would invite deleting a live device. */
function deviceActivityLabel(activity: MediatorDeviceActivity | null, kid: string, isSelf: boolean): string {
  if (!activity || isSelf) return ''
  const entry = activity.byKid.get(kid)
  // Registration is a fact this mediator answers for regardless of version, so
  // this line is always safe to draw.
  if (!entry) return ' · not registered with the mediator'
  // Everything below depends on the mediator actually reporting pickup times.
  // A mediator that doesn't (an anchor older than the field) says nothing about
  // any device — and silence must render as silence, never as "never picked up".
  if (!activity.reportsLastSeen) return ''
  if (entry.lastSeen === undefined) return ' · never picked up'
  const days = Math.floor((Date.now() - entry.lastSeen) / 86_400_000)
  if (days >= 1) return ` · last seen ${days}d ago`
  return ' · active today'
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
      if (window.innerWidth <= 574) {
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
    row.addEventListener('mouseenter', () => { if (window.innerWidth > 574) lpFocusEl(row) })
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
  // Tell the Service Worker which conversation is on screen, so a push for
  // this one doesn't raise a banner over the thread the user is reading.
  setActiveConversation(inboxToHash(item))
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
  const apUrl: string = apOutboundUrl(cfg)
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
  // Self-healing: re-arms the push subscription on every boot where the
  // toggle is already on, not just right after the user flips it (idempotent).
  // Also the only recovery path on iOS, which never fires
  // pushsubscriptionchange when the OS drops a subscription.
  if (notifEnabled) {
    enablePush()
      .then(ok => { if (!ok) console.warn('[push] re-arm on boot registered with no relay') })
      .catch(() => {})
  }
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
  return window.innerWidth > 574
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
  document.querySelectorAll<HTMLElement>('#left-list .lp-item, #left-list .lp-thread-row')
    .forEach(item => item.classList.remove('focused'))
  if (navFocusEnabled()) el.classList.add('focused')
  el.scrollIntoView({ block: 'nearest' })
  if (el.classList.contains('lp-thread-row')) {
    // Cleared on the thread-row path only, where this function calls render()
    // ITSELF — NOT unconditionally at the top. switchInbox (the inbox-row path
    // below) reads the flag to decide whether its "already on this inbox" fast
    // path still owes a render(); clearing it here first made that read always
    // false, so focusing the inbox you were already on before opening a menu
    // page left the menu page on screen with no render() at all — the very bug
    // class this clear was added to close, just moved to the other branch
    // (2026-07-28). switchInbox clears it on its own path, so both paths still
    // leave menu mode before any render() reaches thread.ts.
    _inMenuMode = false
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
        const wasShowLeft = window.innerWidth <= 574 && appEl?.classList.contains('show-left')
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
  // reading pane — i.e. current AND not sitting behind a menu page (/config,
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
      if (_hoverFired || window.innerWidth <= 574) return
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
    if (window.innerWidth <= 574) {
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
  const unreadInboxes = inboxes.filter(i => !i.archived && i.has_unread)
  const unreadIn = (list: InboxSummary[]) => list.reduce((sum, i) => sum + (i.unread_count ?? 1), 0)
  syncAppBadge(unreadIn(unreadInboxes))
  // The Service Worker rebuilds this same badge on every push, from what a
  // JMAP relay knows plus what the mediator still has queued. Neither of those
  // covers a DIDComm message that has already been picked up — it lives in the
  // local store and nowhere else — and neither survives a relay it can't
  // reach. Publish both halves so a background push adds to the count instead
  // of replacing it (which dropped the badge to just the new arrival, then
  // jumped back up the moment the app was opened).
  const didcommUnread = unreadIn(unreadInboxes.filter(i => isDidCommRelay(i.relay)))
  publishUnreadCounts(unreadIn(unreadInboxes) - didcommUnread, didcommUnread)
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
      // Same async-arrival problem as the name above, but for avatars: a
      // DeltaChat group/contact avatar (Chat-Group-Avatar / Chat-User-Avatar)
      // is only learned once its message is decrypted during sync, which can
      // land well after this row was first drawn without one. Patch the <img>
      // in place instead of waiting for a full reload to pick it up.
      const $avatar = a.querySelector('.lp-avatar')
      if ($avatar && item.avatar_url && !$avatar.querySelector('img')) {
        const img = document.createElement('img')
        img.src = item.avatar_url
        img.style.cssText = 'width:100%;height:100%;object-fit:cover;border-radius:50%;'
        $avatar.insertBefore(img, $avatar.firstChild)
        ;($avatar as HTMLElement).style.background = 'transparent'
      }
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
  if (window.innerWidth > 574) {
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

  // Search field only makes sense at the very top of the list — hide it (with
  // the CSS transition on .lp-search-hidden) as soon as the list scrolls, so
  // scrolled content isn't fighting a floating input for attention.
  {
    const $leftPane = document.getElementById('left-pane')
    const $lpSearchWrap = document.getElementById('lp-search-wrap')
    const $mainToggle = document.getElementById('main-toggle')
    const $lpHamburgerLeft = document.getElementById('lp-hamburger-left')
    let lastScrollTop = 0
    $leftPane?.addEventListener('scroll', () => {
      const st = $leftPane.scrollTop
      // Hidden only while actively scrolling down — scrolling back up (or
      // being back at the top) brings it back, same as the thread column's
      // title (main.ts).
      const hidden = st > 0 && st > lastScrollTop
      lastScrollTop = st
      $lpSearchWrap?.classList.toggle('lp-search-hidden', hidden)
      $mainToggle?.classList.toggle('lp-search-hidden', hidden)
      $lpHamburgerLeft?.classList.toggle('lp-search-hidden', hidden)
    }, { passive: true })
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
        <div id="cmd-acc-identity-fields" title="Click to view devices and DID document">
          <div id="cmd-acc-identity-avatar" class="lp-avatar"></div>
          <div id="cmd-acc-identity-text">
            <div id="cmd-acc-identity-name-row">
              <span id="cmd-acc-identity-name"></span>
              <span id="cmd-acc-identity-name-edit" aria-hidden="true"><svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg></span>
            </div>
            <div id="cmd-acc-identity-did-row">
              <span id="cmd-acc-identity-did"></span>
              <button id="cmd-acc-identity-copy" type="button" aria-label="Copy DID" title="Copy DID"><svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg></button>
            </div>
          </div>
          <button id="cmd-acc-identity-menu-btn" type="button" aria-label="Menu"><svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><circle cx="12" cy="5" r="1.5"/><circle cx="12" cy="12" r="1.5"/><circle cx="12" cy="19" r="1.5"/></svg></button>
        </div>
        <div id="cmd-acc-sync-stalled" style="display:none"></div>
        <div id="cmd-acc-identity-expanded">
          <div class="acc-storage-header">
            <span class="acc-storage-title">Devices</span>
          </div>
          <div id="cmd-acc-identity-devices" class="acc-device-list"></div>
          <div class="acc-storage-header" style="margin-top:12px">
            <span class="acc-storage-title">DID:Webvh</span>
            <div class="acc-storage-actions">
              <button id="cmd-acc-identity-sync-btn" class="acc-storage-icon-btn" type="button" aria-label="Sync" title="Sync"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M23 4v6h-6"/><path d="M1 20v-6h6"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg></button>
            </div>
          </div>
          <pre id="cmd-acc-identity-doc"></pre>
        </div>
        <input id="cmd-acc-identity-devices-import-input" type="file" accept=".zip" style="display:none">
      </div>
      <div class="cmd-page-section" id="cmd-acc-list"></div>
      <button id="cmd-acc-fab" type="button"><span class="acc-new-account-plus">+</span>New Relay</button>
      <div id="cmd-acc-panel-backdrop"></div>
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
    for (const id of ['cmd-acc-relay', 'cmd-acc-email']) {
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

  // ── Add-relay panel open/close ──────────────────────────────────────────
  // The panel used to be toggled inline from a trailing "+ New Relay" card,
  // with `panel.style.display` written directly at three separate call
  // sites. It's a floating bottom button opening an overlay now (2026-08-12,
  // user-requested), which needs a class toggled for the expand transition
  // and a backdrop shown alongside — too much to keep duplicating, hence
  // this pair being the only place either is touched.
  //
  // 'flex', not 'block' — #cmd-acc-panel's own CSS is display:flex (its gap
  // is the one spacing mechanism for all rows inside it); an inline 'block'
  // overrides that stylesheet rule outright, silently disabling gap entirely
  // (2026-07-14, user-reported: gap changes had zero visible effect no
  // matter the value, because of exactly this).
  // Both floaters are `position: fixed` (they must not scroll with the card
  // list, and the panel has to land on the button's own coordinates), but
  // they belong to the RIGHT COLUMN, not the viewport (2026-08-12,
  // user-requested) — and `fixed` resolves left/bottom against the viewport.
  // So the horizontal placement is measured rather than declared. A
  // ResizeObserver on #right-col keeps it honest through both window resizes
  // and left-pane toggles (the pane collapsing changes the column's width
  // without any window event at all).
  function positionAccFloating(): void {
    const col = document.getElementById('right-col')
    if (!col) return
    const r = col.getBoundingClientRect()
    if (!r.width) return // hidden (app not shown yet) — nothing meaningful to measure
    const centre = r.left + r.width / 2
    const fab = document.getElementById('cmd-acc-fab') as HTMLElement | null
    const panel = document.getElementById('cmd-acc-panel') as HTMLElement | null
    if (fab) fab.style.left = `${centre}px`
    if (panel) {
      panel.style.left = `${centre}px`
      // Never wider than the column it belongs to, whatever the stylesheet's
      // own min() says about the viewport.
      panel.style.maxWidth = `${Math.max(240, r.width - 32)}px`
    }
  }

  function openAddRelayPanel(): void {
    const panel = document.getElementById('cmd-acc-panel') as HTMLElement | null
    const backdrop = document.getElementById('cmd-acc-panel-backdrop') as HTMLElement | null
    if (!panel) return
    resetAddAccountPanel()
    panel.style.display = 'flex'
    positionAccFloating()
    if (backdrop) backdrop.classList.add('open')
    document.getElementById('cmd-acc-fab')?.classList.add('hidden')
    // One frame between `display` becoming non-none and the class that
    // animates it — a transition can't run on an element that was
    // display:none in the same frame, so without this the panel just
    // appears at its final size with no expand at all.
    requestAnimationFrame(() => {
      panel.classList.add('open')
      ;(document.getElementById('cmd-acc-relay') as HTMLInputElement | null)?.focus()
    })
  }

  function closeAddRelayPanel(): void {
    const panel = document.getElementById('cmd-acc-panel') as HTMLElement | null
    const backdrop = document.getElementById('cmd-acc-panel-backdrop') as HTMLElement | null
    if (!panel) return
    panel.classList.remove('open')
    if (backdrop) backdrop.classList.remove('open')
    document.getElementById('cmd-acc-fab')?.classList.remove('hidden')
    // Hidden only after the collapse transition, so it actually plays.
    // Guarded on still being closed: a reopen inside the timeout window
    // would otherwise hide the panel it just opened.
    setTimeout(() => {
      if (!panel.classList.contains('open')) panel.style.display = 'none'
    }, 180)
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
      const { isMediatorUrl } = await import('../did/didcomm-devices.ts')
      const probe = await isMediatorUrl(raw)
      if (relayInput.value.trim().replace(/\/$/, '') !== raw) return // stale by the time it resolved
      // A failed probe (network error, CORS, 5xx) is not a confirmed
      // "not a mediator" — don't fall through to relay-apex expansion on
      // a hostname we couldn't actually reach.
      if (probe === 'unknown') return
      const choiceEl = document.getElementById('cmd-acc-choice') as HTMLElement | null
      const modeBtns = choiceEl?.querySelectorAll<HTMLButtonElement>('.cmd-acc-choice-btn')
      let regBtn = document.getElementById('cmd-acc-mediator-register') as HTMLButtonElement | null
      if (probe === 'mediator') {
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
              const { registerWithMediator } = await import('../did/didcomm-devices.ts')
              const reg = await registerWithMediator(relayInput.value.trim())
              showSysMsg('Registered with mediator')
              closeAddRelayPanel()
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

  function renderConfigPage() {
    // File System Access API — unsupported on any iOS browser (all engines are
    // WebKit there, per Apple policy) and on Firefox. Hide rather than show a
    // button that will just throw.
    const vaultSection = 'showDirectoryPicker' in window
      ? `<div class="cmd-page-section">
        <h3>Vault (Markdown)</h3>
        <div class="cmd-page-row">
          <span>Vault</span>
          <div class="toggle-switch${vaultHandle ? ' on' : ''}" id="config-vault-toggle" style="cursor:pointer"></div>
        </div>
      </div>`
      : ''
    // Pre-rotation status (did/webvh/prerotation.ts) is only known async
    // (it lives in the log's parameters, not anything resolved sync-side) —
    // rendered off here, corrected by onShowConfig right after paint. The
    // section itself only needs an identity to exist at all, checked sync.
    const preRotationSection = currentIdentityDid()
      ? `<div class="cmd-page-section">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px">
          <h3 style="margin:0">Key rotation</h3>
          <div class="toggle-switch" id="config-prerotation-toggle" style="cursor:pointer"></div>
        </div>
        <div style="display:flex;align-items:center;gap:10px;padding:6px 0">
          <button id="prerotation-rotate-btn" class="cmd-page-btn primary" style="display:none;padding:4px 12px;font-size:11px;font-weight:900;text-transform:uppercase;border-radius:20px;flex-shrink:0">Rotate</button>
          <span style="font-size:13px;color:var(--text-dim);flex-shrink:0">Sign Key:</span>
          <span id="config-prerotation-key" style="font-family:ui-monospace,monospace;font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex:1;min-width:0"></span>
        </div>
        <div style="display:flex;align-items:center;gap:10px;padding:6px 0">
          <button id="prerotation-revoke-btn" class="cmd-page-btn primary" style="display:none;padding:4px 12px;font-size:11px;font-weight:900;text-transform:uppercase;border-radius:20px;flex-shrink:0">Revoke</button>
          <span style="font-size:13px;color:var(--text-dim);flex-shrink:0">Root Key:</span>
          <span id="config-rootkey" style="font-family:ui-monospace,monospace;font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex:1;min-width:0"></span>
        </div>
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
      ${preRotationSection}
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
        if (!notifEnabled) { disablePush().catch(() => {}); return }
        // Turning it on silently left the toggle "on" with no relay actually
        // holding the subscription if every registration POST failed — the
        // user then waited forever for a push that was never going to be sent.
        const ok = await enablePush().catch(() => false)
        if (!ok) {
          setNotifEnabled(false)
          localStorage.setItem(`jmap_notif_${activeSession()?.account.email ?? ''}`, '0')
          $tog.classList.remove('on')
          alert('Could not enable notifications — no relay or mediator accepted the subscription.')
        }
      })
    }

    // Key rotation (did:webvh pre-rotation — src/did/webvh/prerotation.ts).
    // Status is async-only (it lives in the log's parameters), so the
    // toggle paints off and gets corrected here rather than in the
    // sync renderConfigPage.
    const $preRotTog = document.getElementById('config-prerotation-toggle')
    const $rotateBtn = document.getElementById('prerotation-rotate-btn') as HTMLButtonElement | null
    const $preRotKey = document.getElementById('config-prerotation-key')
    const $rootKey = document.getElementById('config-rootkey')
    const $revokeBtn = document.getElementById('prerotation-revoke-btn') as HTMLButtonElement | null
    if ($preRotTog && $rotateBtn) {
      const did = currentIdentityDid()
      if (did) {
        // Sign key / Root key stay visible regardless of toggle state — only
        // the [Rotate]/[Revoke] buttons (the OPERATIONS) are gated on it,
        // since pre-rotation being off doesn't make either key stop existing
        // (2026-08-17, user-requested).
        const reflect = (active: boolean) => {
          $preRotTog.classList.toggle('on', active)
          $rotateBtn.style.display = active ? '' : 'none'
          if ($revokeBtn) $revokeBtn.style.display = active ? '' : 'none'
        }
        // Shows both keys currently in play, not just on/off — "Rotate"
        // changes the sign key every time and "Revoke" moves the root key
        // too, and before/after both just read "on" without this, so there
        // was no way to tell either operation actually landed from a no-op
        // (2026-08-17, user: 本当にrotateしたかわからない). Full strings in
        // the DOM; single-line clamp + native text-overflow:ellipsis (each
        // span's own style, above) is what elides the tail rather than
        // wrapping to a second line — user: 二行になる場合は…末尾から省略.
        // Both public keys are already in the resolved document anyone can
        // fetch — showing them here reveals nothing that isn't already
        // public (user asked before adding the root key row).
        const refreshKeyLabel = async () => {
          try {
            const { fetchCurrentLog } = await import('../did/webvh/log-io.ts')
            const { last } = await fetchCurrentLog(did)
            if ($preRotKey) $preRotKey.textContent = last.parameters.updateKeys?.[0] ?? ''
            const state = last.state as { verificationMethod?: Array<{ publicKeyMultibase?: string }> }
            if ($rootKey) $rootKey.textContent = state.verificationMethod?.[0]?.publicKeyMultibase ?? ''
          } catch {
            if ($preRotKey) $preRotKey.textContent = ''
            if ($rootKey) $rootKey.textContent = ''
          }
        }
        const { isPreRotationActive } = await import('../did/webvh/prerotation.ts')
        isPreRotationActive(did).then(reflect).catch(() => {})
        refreshKeyLabel()

        $preRotTog.addEventListener('click', async () => {
          const active = $preRotTog.classList.contains('on')
          const { runActivatePreRotation, runDeactivatePreRotation } = await import('./prerotation.ts')
          const ok = active ? await runDeactivatePreRotation(did) : await runActivatePreRotation(did)
          if (ok) { reflect(!active); refreshKeyLabel() }
        })
        $rotateBtn.addEventListener('click', async () => {
          const { runRotateNow } = await import('./prerotation.ts')
          const wasDisabled = $rotateBtn.disabled
          $rotateBtn.disabled = true
          try {
            const ok = await runRotateNow(did)
            // Still active either way (rotating always re-commits — see
            // prerotation.ts's own header) — nothing to reflect but the
            // button's own disabled state and the key label, which is the
            // one thing that actually moves on a successful rotate.
            if (ok) refreshKeyLabel()
          } finally {
            $rotateBtn.disabled = wasDisabled
          }
        })
        if ($revokeBtn) {
          $revokeBtn.addEventListener('click', async () => {
            if (!confirm('Revoke the Root Key? Your current recovery phrase stops working permanently — it will no longer restore this identity, log into mail, or sign as you on any device.\n\nYou will be asked for your Spare Key phrase, then shown TWO new phrases to save: a new Root Key and a new Spare Key.\n\nUse this only if you believe your current phrase is compromised.')) return
            const { runRevokeRootKey } = await import('./prerotation.ts')
            const wasDisabled = $revokeBtn.disabled
            $revokeBtn.disabled = true
            try {
              const ok = await runRevokeRootKey(did)
              if (ok) refreshKeyLabel()
            } finally {
              $revokeBtn.disabled = wasDisabled
            }
          })
        }
      }
    }

    // Vault opt-in — a toggle like the others (2026-08-17, was a bare
    // "Select folder to enable" button that looked nothing like the rest of
    // this page). Turning it off just tears down the local watch; turning it
    // on re-runs the same directory-picker flow as before, and reverts to off
    // if the picker is cancelled or permission is refused.
    const $vaultTog = document.getElementById('config-vault-toggle')
    if ($vaultTog) {
      $vaultTog.addEventListener('click', async () => {
        const active = $vaultTog.classList.contains('on')
        if (active) {
          stopWatch()
          clearVaultHandle()
          $vaultTog.classList.remove('on')
          showSysMsg('Vault disabled')
          return
        }
        try {
          const handle = await (window as any).showDirectoryPicker({ mode: 'readwrite' })
          if ((handle as any).queryPermission) {
            const perm = await (handle as any).queryPermission({ mode: 'readwrite' })
            if (perm !== 'granted' && (handle as any).requestPermission) {
              await (handle as any).requestPermission({ mode: 'readwrite' })
            }
          }
          setVaultHandle(handle)
          await querystate.loadFromVault()
          await loadFromVault()
          await flushAll()
          await startWatch()
          $vaultTog.classList.add('on')
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
          <button id="new-send-btn" class="t-send-btn always-send" title="Send">
            <svg viewBox="0 0 24 24"><path d="M2 12L22 2L12 22L10 14L2 12Z"/></svg>
          </button>
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

    // A did:webvh's SCID is 46 chars of base58 nobody reads — same rule the
    // account page's own DID line uses (contacts.ts's ownDidParts), reused
    // here for a To-field recipient's DID rather than the signed-in user's
    // own. `inp.value` shows the elided form; the ACTUAL address (needed for
    // resolveDidDocFull/send, which require the real SCID) is kept in
    // `dataset.fullDid` — inpAddr is the one place that reads it back.
    // Cleared the moment the user types into the field by hand (attachPrefetch's
    // 'input' listener) so a manual edit is never silently overridden by a
    // stale full DID from before.
    const setRecipientInputValue = (inp: HTMLInputElement, address: string) => {
      if (address.startsWith('did:webvh:') && bisetWebvhUsername(address)) {
        inp.value = shortOwnDid(address)
        inp.dataset.fullDid = address
      } else {
        inp.value = address
        delete inp.dataset.fullDid
      }
    }
    const inpAddr = (inp: HTMLInputElement): string => (inp.dataset.fullDid || inp.value).trim()
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
          if (inp) setRecipientInputValue(inp, o.address)
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
      // Keep the field's displayed text in sync with whichever protocol just
      // became selected, auto or not — a [DID] pill next to an unrelated
      // mail-shaped string is misleading (found live: y@biset.md shown with
      // [DID] highlighted, when the actual DIDComm target is a different
      // identifier entirely). The explicit pill-click handler below already
      // does this for a manual pick; this covers the auto-selected case
      // (e.g. resolveRecipientProtocols defaulting a plain address to DID).
      const inp = row.querySelector<HTMLInputElement>('.new-field-input')
      const opt = next ? opts.find(o => o.protocol === next) : undefined
      if (inp && opt) setRecipientInputValue(inp, opt.address)
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
        const inp = row.querySelector<HTMLInputElement>('.new-field-input')
        if (!inp || !inp.value.trim()) continue
        out[(row.dataset.kind as Kind) ?? 'to'].push(rowEffective(row)?.address ?? inpAddr(inp))
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
      if (n) return `${n} / ${shortDid(did)}`
      // Unlike contacts.ts's labelForDid (bare username — fine for an inbox
      // list where every row already reads as "a person"), the From button
      // stands alone with no other context, so a bisetWebvhUsername gets the
      // full elided-SCID form (did:webvh:{domain}:{username}) rather than
      // just the username — otherwise a fresh identity's random name (e.g.
      // "89b3") reads as some opaque label, not recognizably a DID at all.
      return bisetWebvhUsername(did) ? shortOwnDid(did) : shortDid(did)
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

    // No identity at all yet (a first-time visitor who landed straight in
    // compose — main.ts's handleUserLanding/route, 2026-08-16): the From
    // field itself doubles as the account-creation affordance instead of
    // sending the visitor through a separate #new page first. Clicking it
    // creates a DIDComm-only identity (src/did/create.ts) and drops the
    // result straight into fromOptions/fromSelectedIdx — no page navigation.
    let creatingAccount = false
    const renderCreateAccountAffordance = () => {
      if (!fromBtn) return
      fromBtn.innerHTML = '' // idempotent even when called directly (handleCreateAccount), not just via renderFromButton
      fromBtn.disabled = creatingAccount
      const label = document.createElement('span')
      label.className = 'new-from-create-btn'
      label.style.cssText = 'white-space:nowrap;flex-shrink:0'
      label.textContent = creatingAccount ? 'Creating account…' : 'create account'
      fromBtn.append(label)
    }
    const handleCreateAccount = async () => {
      if (creatingAccount) return
      creatingAccount = true
      renderCreateAccountAffordance()
      try {
        const hostname = getHostname()
        if (!hostname) throw new Error('hostname not set in config.json')
        const username = randomHex4()
        const masterSecret = crypto.getRandomValues(new Uint8Array(32))
        const { createIdentity, registerIdentityChannel } = await import('../did/create.ts')
        const { didRecord } = await createIdentity(masterSecret, username, hostname)
        await registerIdentityChannel(didRecord.did, () => { fetchMessages(); loadLeftInboxes() })
        ownChannelDid = didRecord.did
        fromOptions = [{ email: didRecord.did, serverUrl: DIDCOMM_SERVER_URL }]
        fromSelectedIdx = 0
        syncFromRequirement()
        refreshAccountsList()
        const { showMnemonic } = await import('./mnemonic.ts')
        showMnemonic(masterSecret, {
          firstTime: true,
          onClose: () => {
            import('../did/store.ts')
              .then(async m => {
                const ok = await m.enableIdentityProtection(`${username}@${hostname}`)
                if (!ok) console.warn('[identity] passkey protection not enabled — secrets stay plaintext at rest')
              })
              .catch(e => console.warn('[identity] passkey protection failed:', e instanceof Error ? e.message : e))
          },
        })
      } catch (e) {
        showSysMsg(e instanceof Error ? e.message : String(e))
      } finally {
        creatingAccount = false
        renderFromButton()
      }
    }
    const renderFromButton = () => {
      if (!fromBtn) return
      fromBtn.innerHTML = ''
      const o = fromOptions[fromSelectedIdx]
      if (!o) { renderCreateAccountAffordance(); return }
      fromBtn.disabled = false
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
        if (alt >= 0) fromSelectedIdx = alt
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
    fromBtn?.addEventListener('click', e => {
      e.stopPropagation()
      if (!fromOptions.length) { handleCreateAccount(); return }
      openFromMenu()
    })
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

    // Relay base URLs for this home domain (see account-create.getMailUrl/getApUrl).
    const cfg = (window as any).__BISET_CONFIG__
    const mailUrl = cfg?.mail_url || (cfg?.hostname ? mailRelayUrl(cfg.hostname) : '')
    const apUrl = apOutboundUrl(cfg)

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
      const addr = inpAddr(inp)
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
          if (inpAddr(inp) !== addr) return // stale
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
      if (inpAddr(inp) !== addr) return // stale

      const opts: ProtoOption[] = []
      if (!apHit || didHit) opts.push({ protocol: 'mail', address: addr })
      if (apHit) opts.push({ protocol: 'ap', address: addr })
      if (didHit) opts.push({ protocol: 'did', address: didHit })
      // AP still wins when both are on offer (matches the old auto-on AP
      // badge); otherwise DID beats Mail — a published DID anchor is the
      // stronger, more capable transport (e2ee by default, portable
      // identity) whenever this address turns out to have one.
      setRowProtoOptions(row, opts, apHit ? 'ap' : didHit ? 'did' : 'mail')
    }

    const attachPrefetch = (inp: HTMLInputElement) => {
      // A manual edit invalidates whatever full DID was stashed for the
      // elided display (setRecipientInputValue) — from here on inp.value
      // IS the address, same as any other row.
      inp.addEventListener('input', () => { delete inp.dataset.fullDid; updateTitleLabel() })
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
      setRecipientInputValue(firstInp, composePrefillTo)
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
        const v = inpAddr(inp)
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
      if (!fromEmail) { showSysMsg('Create an account first (From field)'); fromBtn?.focus(); return }
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
      if (didCount > 0 && didCount < filledRows.length) {
        showSysMsg('DIDComm recipients cannot be mixed with mail or ActivityPub ones'); return
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
      if (visible.length >= 2 && didCount > 0) {
        // Several DIDComm recipients: an MLS group conversation. Not the same
        // object as the email group below at all — this one has a ratchet
        // tree, so membership is cryptographic (a removed member cannot read
        // what follows) rather than a recipient list anyone can edit.
        const groupName = title || 'Group'
        const { createGroupConversation } = await import('../did/didcomm/channel.ts')
        const sess = sessionFor(fromEmail) ?? activeSession()
        const selfDid = sess?.account.did
        if (!selfDid) { showSysMsg('This identity has no DID to start a group with'); return }
        const created = await createGroupConversation(selfDid, groupName, visible)
        if (!created.ok) { showSysMsg(created.error); return }
        // Whoever could not be reached is named rather than silently dropped:
        // "the group exists but Bob is not in it" is a fact the user has to
        // have, and the remedy (invite them again later) is theirs to choose.
        if (created.skipped.length) {
          showSysMsg(`Could not invite ${created.skipped.map(d => displayLabelFor(d)).join(', ')} — no key packages published`)
        }
        if (body) {
          const { sendToGroup } = await import('../did/didcomm/channel.ts')
          const sent = await sendToGroup(selfDid, created.groupId, body, '')
          if (!sent.ok) { showSysMsg(sent.error || 'Send failed'); return }
        }
        ;($lpSearch as HTMLInputElement).value = ''
        hideCmdPalette()
        await loadLeftInboxes()
        switchInbox({
          user: sess.account.email,
          mailbox: '',
          contact: `group:${created.groupId}`,
          inbox_type: 'group',
          group_id: created.groupId,
          group_name: groupName,
          participants: visible,
        })
      } else if (visible.length >= 2) {
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
        // A DIDComm send has nothing to pull: sendViaDidComm already wrote the
        // only local copy that will ever exist (no server-side Sent to sync
        // back), and the synthetic session behind it has a null jmapClient.
        const isDidSend = didCount > 0 || isDidCommRelay(sess?.account.serverUrl)
        if (sess && !isDidSend) { try { const { sync } = await import('../sync/session.ts'); await sync(sess) } catch {} }
        await loadLeftInboxes()
        if (to[0] && sess) {
          // Match on IDENTITY, not on the sending session's own address: a
          // summary's `user` is whichever endpoint came first for that identity
          // (app.ts's loadInboxSummaries), which for a relay-backed identity
          // sending over DIDComm is its relay address — while `sess` here is
          // the synthetic DIDComm session, whose "email" is the DID itself. The
          // literal comparison never matched in that case, so a just-created
          // DIDComm conversation always fell through to the hand-built summary
          // below (wrong mailbox → empty thread, row left unselected). Contact
          // side goes through contactIdentityKey for the same reason the
          // summaries themselves do: one row per contact DID, not per address.
          const idKey = identityKey(sess)
          const contactKey = contactIdentityKey(to[0])
          const match = lastLeftInboxes.find(i => identityKeyForEmail(i.user) === idKey && contactIdentityKey(i.contact) === contactKey)
          switchInbox(match ?? {
            user: sess.account.email,
            // A DIDComm conversation's mailbox name IS the sending DID —
            // didcomm/channel.ts files every message under `mbx-<own did>`.
            // currentInbox's mailbox belongs to whatever was open before this
            // compose and would make getInboxEmails match nothing.
            mailbox: isDidSend ? (sess.account.did ?? '') : (currentInbox?.mailbox ?? ''),
            contact: to[0],
            latest_ts: Date.now(),
            latest_body: body,
            latest_subject: subject,
            relay: isDidSend ? DIDCOMM_SERVER_URL : relayUrl,
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

  // Identity-level "Download all data" / "Delete account" menu disabled
  // (commented out for easy revival, 2026-07-27, user-requested) — the
  // per-relay card versions of both actions (storage.go's export/purge,
  // and each card's own "Delete account") remain the way to reach either
  // one, now scoped to a single relay at a time instead of the whole
  // identity in one shot. The identityMenuBtn hamburger itself is now
  // unconditionally hidden in both renderAccountsList branches above/below
  // (nothing left for it to open).
  //
  // function openIdentityMenu(anchor: HTMLElement): void {
  //   const homeIdentity = sessions.find(s => !isApRelay(s.account.serverUrl))
  //   if (!homeIdentity) { showSysMsg('No password-protected relay in this identity'); return }
  //   const idKey = identityKey(homeIdentity)
  //   openDropdownMenu(anchor, [
  //     // password/envelope concept disabled (commented out for easy revival —
  //     // account-create.ts's submit handler has the fuller note; mnemonic.ts's
  //     // showMnemonicWithPassword explains why this one is also structurally
  //     // gone, not just hidden). The phrase is now shown exactly once, right
  //     // after creation (showMnemonic, called from account-create.ts).
  //     // {
  //     //   label: 'Show recovery phrase', onClick: async () => {
  //     //     const { showMnemonicWithPassword } = await import('./mnemonic.ts')
  //     //     showMnemonicWithPassword(homeIdentity.account.email, homeIdentity.account.serverUrl)
  //     //   },
  //     // },
  //     {
  //       label: 'Download all data', onClick: async () => {
  //         // The per-card "Download" only ever exports ONE relay's data (by
  //         // design — see storage.go). This is the whole-identity counterpart:
  //         // every relay/address sharing the DID, bundled into one archive —
  //         // real directory structure (raw/) plus the same markdown rendering
  //         // vault sync uses (markdown/), each under its own relay folder so a
  //         // cross-relay thread's independent per-store halves stay separate
  //         // (no cross-relay merging here, same as the server's own storage).
  //         const endpoints = loadStoredAccounts().filter(a => (a.did || a.email) === idKey)
  //         showSysMsg('Preparing download…', 30000)
  //         const { exportAccountStorage } = await import('../cryptenv.ts')
  //         const { buildAccountArchiveEntries } = await import('../vault/export.ts')
  //         const { buildZip } = await import('../vault/zip.ts')
  //         const allEntries: { path: string; data: Uint8Array }[] = []
  //         let failures = 0
  //         for (const ep of endpoints) {
  //           const data = await exportAccountStorage(ep.serverUrl, ep.email, ep.password)
  //           if (!data) { failures++; continue }
  //           const entries = await buildAccountArchiveEntries(ep.email, data.files)
  //           for (const e of entries) allEntries.push({ path: `${ep.email}/${e.path}`, data: e.data })
  //         }
  //         const zipBytes = buildZip(allEntries)
  //         const blob = new Blob([zipBytes.buffer as ArrayBuffer], { type: 'application/zip' })
  //         const url = URL.createObjectURL(blob)
  //         const link = document.createElement('a')
  //         link.href = url
  //         link.download = `${homeIdentity.account.email}-all-data.zip`
  //         link.click()
  //         URL.revokeObjectURL(url)
  //         showSysMsg(failures ? `Downloaded with ${failures} relay(s) failed` : 'Download ready')
  //       },
  //     },
  //     {
  //       label: 'Delete account', onClick: async () => {
  //         // Whole-identity delete: every relay/address sharing this DID, not
  //         // just the "home" one — per-card "Delete account" already covers a
  //         // single relay; this is the counterpart for the whole identity.
  //         const endpoints = loadStoredAccounts().filter(a => (a.did || a.email) === idKey)
  //         const list = endpoints.map(e => e.email).join(', ')
  //         if (!confirm(`Permanently delete this identity across all ${endpoints.length} relay(s) (${list})? This deletes all messages and account data everywhere — it cannot be undone.`)) return
  //         const { deleteAccountOnRelay } = await import('../cryptenv.ts')
  //         let failures = 0
  //         for (const ep of endpoints) {
  //           const ok = await deleteAccountOnRelay(ep.serverUrl, ep.email, ep.password, ep.did)
  //           if (!ok) failures++
  //         }
  //         saveStoredAccounts(loadStoredAccounts().filter(a => (a.did || a.email) !== idKey))
  //         for (let i = sessions.length - 1; i >= 0; i--) {
  //           if (identityKey(sessions[i]) === idKey) sessions.splice(i, 1)
  //         }
  //         for (const ep of endpoints) {
  //           _accInfoCache.delete(accountKey(ep))
  //           await deleteKey(ep.email)
  //           if (localStorage.getItem(`jmap_notif_${ep.email}`) != null) localStorage.removeItem(`jmap_notif_${ep.email}`)
  //           if (localStorage.getItem(`sjoin_invites_${ep.email}`) != null) localStorage.removeItem(`sjoin_invites_${ep.email}`)
  //         }
  //         await clearIdentityCache(idKey)
  //         renderAccountsList(); loadLeftInboxes()
  //         showSysMsg(failures ? `Deleted with ${failures} failure(s) — some relay data may remain` : 'Identity deleted')
  //       },
  //     },
  //   ])
  // }

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
    }
    // Republish without the relay that just went away — for the LAST one too,
    // not only when others remain. Removing the last relay leaves a
    // relay-less identity that still has its DIDComm channel, which is a
    // first-class shape here (main.ts's bootSessions handles zero
    // StoredAccounts; didcomm-devices.ts publishes with `gatewayUrls([], mUrl)`),
    // so its document has to stop advertising a relay it no longer uses.
    if (!isDidCommRelay(serverUrl)) {
      // Only republish automatically when this identity actually has a
      // registered mediator — an unpublished/mediator-less identity's
      // document is nobody's business to keep current for free (published/
      // unpublished design, [[project_biset_did_relay_orthogonality]]).
      // Removing a relay still changes what the document WOULD say, but
      // that's exactly what the explicit "Republish" button is for when
      // there's no mediator keeping it live automatically.
      import('../did/didcomm/channel.ts').then(async m => {
        if (await m.hasDidCommChannel(idKey)) {
          // Method-agnostic (did:dht/did:webvh) — publishOneVisible
          // (dht/publish.ts) used to be called here directly, which is
          // did:dht-only and silently built the wrong document for a
          // did:webvh identity (same bug class as republishIdentity's note
          // above, found in the same pass).
          const rec = await getDidRecord(idKey)
          if (rec) {
            const { publishBareOrCurrent } = await import('../did/didcomm-devices.ts')
            await publishBareOrCurrent(rec)
          }
        }
      }).catch(() => {})
    }
    // Deregister from the mediator ONLY when the card being logged out is the
    // DIDComm card itself. A relay card's Log out must not touch it.
    //
    // This used to run for every card, on the reasoning that any explicit Log
    // out means THIS DEVICE is done. It does not: `removeRelayLocally` "only
    // drops the StoredAccount/session, never the DidRecord" (this file's own
    // note at the re-login handler), and the identity plainly survives — the
    // wasLastRelay branch above clears per-address leftovers and a cache,
    // nothing more. So the old rule destroyed this device's DIDComm key while
    // deliberately keeping the identity that key belongs to.
    //
    // It also made a supported state unreachable by the obvious route:
    // an identity that never had a relay keeps working over DIDComm, while
    // the same identity arrived at by removing its last relay went dead. Two
    // histories, one state, different outcomes — from the pair the codebase
    // calls orthogonal ([[project_biset_did_relay_orthogonality]]).
    //
    // And it is the bug the "Delete account"/"Log out" split above already
    // fixed once, in the same shape: an identity-wide effect fired from a
    // card-scoped action ("This is always scoped to just this one card").
    //
    // What the old rule was protecting against — a still-published key left
    // behind — is the full sign-out's job, and app.ts's logout() still
    // deregisters every identity there. That is the one place that means this
    // device is leaving.
    //
    // unregisterFromMediator is a harmless no-op (throws, caught) for a device
    // that never registered a DIDComm channel, and by the time this runs the
    // identity's session may already be gone from sessions[], so the identity
    // key must be passed explicitly.
    //
    // AWAITED, not fire-and-forget — found live: logging out of two relays
    // back to back (this identity's mail + ap pair) let the SECOND card's
    // click fire before the first's revoke had actually finished its network
    // round-trip, and a subsequent reload/navigation (landing on the
    // now-empty-identity #new page) can abort an in-flight, un-awaited
    // fetch outright — the revoke never completes, and the only credentials
    // that could ever prove ownership of that slot are gone the moment this
    // function returns and the caller moves on. Awaiting here can't fix a
    // navigation that happens from OUTSIDE this call, but it stops this
    // function itself from racing its own async work.
    if (isDidCommRelay(serverUrl)) {
      await import('../did/didcomm-devices.ts').then(m => m.unregisterFromMediator(idKey))
        .catch(e => console.warn('[logout] unregisterFromMediator failed — this device\'s DIDComm key may still be published:', e instanceof Error ? e.message : e))
    }
    renderAccountsList(); loadLeftInboxes()
  }

  function openAccountMenu(anchor: HTMLElement, email: string, serverUrl?: string, did?: string) {
    const items: MenuItem[] = [
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
    if (serverUrl && did) {
      // Root-key-signed re-vouch for a modern (password-less) DID-bound
      // account whose LOCAL device key is gone but the account itself still
      // exists server-side — distinct from "Enable this device" above
      // (password-based, needs an active session to unseal against) and
      // from claiming (would 409 UsernameTaken, the account already
      // exists). Mirrors exactly what restoreFromMnemonic does per relay,
      // just triggered manually for one already-known card instead of
      // during a full identity restore (2026-08-17: found live after a
      // device-key-clobbering race — since fixed in didcomm-devices.ts's
      // publishCurrentState — left a claimed relay's local device key gone
      // with no UI path back in short of recreating the identity).
      items.push({
        label: 'Reconnect device', onClick: async () => {
          const { unlockIdentitySecrets, getDidRecord } = await import('../did/store.ts')
          if (!(await unlockIdentitySecrets())) return
          const rec = await getDidRecord(did)
          if (!rec) { showSysMsg('No local record for this identity'); return }
          const at = email.lastIndexOf('@')
          if (at <= 0) { showSysMsg('Malformed address'); return }
          const username = email.slice(0, at)
          const domain = email.slice(at + 1)
          showSysMsg('Reconnecting…', 15000)
          const { vouchThisDevice, deviceLabel } = await import('../did/provision.ts')
          const vouch = await vouchThisDevice({
            serverUrl, username, domain, did, rootPrivateKey: hexToBytes(rec.rootPrivateKey), label: deviceLabel(),
          }).catch(() => ({ ok: false, status: 0 }))
          if (!vouch.ok) { showSysMsg(`Reconnect failed (HTTP ${vouch.status})`, 8000); return }
          const { deriveKek } = await import('../cryptenv.ts')
          const kek = rec.masterSeed ? await deriveKek(hexToBytes(rec.masterSeed)) : undefined
          const { connectAndPersist } = await import('../app.ts')
          const session = await connectAndPersist({ serverUrl, email, password: '', did }, kek)
          if (!session) { showSysMsg('Vouched, but failed to connect'); return }
          refreshAccountsList()
          showSysMsg('Reconnected')
        },
      })
    }
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
      // Per-device JMAP credential (account-model redesign,
      // src/did/devicebind.ts): scoped to THIS relay/account specifically,
      // like Delete account/Log out above — devices.go's list/revoke are
      // per (serverUrl, email), not per-identity, since each relay keeps its
      // own independent authorized-device list.
      items.push({
        label: 'Devices', onClick: () => openDevicesModal(email, serverUrl),
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


  // Per-device JMAP credential management (src/did/devicebind.ts, this
  // session's account-model redesign): list/revoke the devices THIS
  // (serverUrl, email) account currently authorizes, and — if this browser's
  // own device isn't among them yet (a legacy account, or a device that
  // never vouched here) — offer to enable it.
  function openDevicesModal(email: string, serverUrl: string) {
    const session = sessions.find(s => s.account.email === email && s.account.serverUrl === serverUrl)
    const body = document.createElement('div')
    body.style.cssText = 'display:flex;flex-direction:column;gap:4px;min-width:280px'
    const list = document.createElement('div')
    list.textContent = 'Loading…'
    list.style.cssText = 'font-size:13px;color:var(--text-dim)'
    body.appendChild(list)
    const enableRow = document.createElement('div')
    body.appendChild(enableRow)

    async function refresh() {
      if (!session) { list.textContent = 'Not connected'; return }
      let ownDeviceId: string | undefined
      if (session.account.did) {
        const { getDidRecord } = await import('../did/store.ts')
        ownDeviceId = (await getDidRecord(session.account.did))?.jmapDevicePublicKey
      }
      let devices: { id: string; label: string; created_at: number }[]
      try {
        const resp = await fetch(`${serverUrl.replace(/\/$/, '')}/account/devices`, {
          headers: { Authorization: 'Basic ' + btoa(session.account.email + ':' + session.account.password) },
        })
        if (!resp.ok) { list.textContent = 'Failed to load devices'; return }
        // ?? [] : a relay predating the ListDeviceKeys nil-slice fix (or any
        // future server bug of the same shape) could still send JSON `null`
        // for "no devices yet" — defend at this response boundary rather
        // than trust the server never regresses it.
        devices = (await resp.json()) ?? []
      } catch {
        list.textContent = 'Failed to load devices'
        return
      }
      list.innerHTML = ''
      if (!devices.length) {
        const p = document.createElement('div')
        p.textContent = 'No devices registered — this account is only reachable with its password.'
        p.style.cssText = 'font-size:12px;color:var(--text-dim);padding:4px 0'
        list.appendChild(p)
      }
      for (const d of devices) {
        const isThis = d.id === ownDeviceId
        const row = document.createElement('div')
        row.style.cssText = 'display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px solid var(--border)'
        const info = document.createElement('div')
        info.style.cssText = 'font-size:13px'
        info.textContent = d.label + (isThis ? ' (this device)' : '')
        row.appendChild(info)
        const del = document.createElement('button')
        del.type = 'button'
        del.textContent = 'Revoke'
        del.className = 'cmd-page-btn'
        del.style.cssText = 'width:auto;padding:4px 10px;font-size:12px'
        del.addEventListener('click', async () => {
          const warn = isThis ? ' This is THIS device — revoking it will log it out of this account immediately (the password will still work).' : ''
          if (!confirm(`Revoke "${d.label}"?${warn}`)) return
          try {
            const r = await fetch(`${serverUrl.replace(/\/$/, '')}/account/devices?id=${encodeURIComponent(d.id)}`, {
              method: 'DELETE',
              headers: { Authorization: 'Basic ' + btoa(session.account.email + ':' + session.account.password) },
            })
            if (r.ok) { showSysMsg('Device revoked'); refresh() } else { showSysMsg('Revoke failed') }
          } catch { showSysMsg('Revoke failed') }
        })
        row.appendChild(del)
        list.appendChild(row)
      }
      enableRow.innerHTML = ''
      if (session.account.did && !devices.some(d => d.id === ownDeviceId)) {
        const btn = document.createElement('button')
        btn.type = 'button'
        btn.textContent = 'Enable per-device login on this device…'
        btn.className = 'cmd-page-btn primary'
        btn.style.cssText = 'width:100%;margin-top:8px'
        btn.addEventListener('click', () => enableThisDevice(session, refresh))
        enableRow.appendChild(btn)
      }
    }
    openModal('Devices', body)
    refresh()
  }

  // Proves ownership of the account (password → envelope → rootPrivateKey,
  // same unseal step "Change password" already does) and, on success, vouches
  // THIS browser's device key for it (src/did/provision.ts's vouchThisDevice)
  // — after which this device can log in with its own key, independent of
  // the password and unaffected by any later identity-key rotation.
  function enableThisDevice(session: import('../types.ts').AccountSession, onDone: () => void) {
    const body = document.createElement('form')
    body.style.cssText = 'display:flex;flex-direction:column;gap:10px'
    body.autocomplete = 'off'
    body.innerHTML = `
      <div style="font-size:12px;color:var(--text-dim)">Enter your password once to prove you own this account. This device will then hold its own key and won't need the password again.</div>
      <input class="cmd-input" type="password" name="pw" placeholder="Password" autocomplete="current-password" required>
      <div data-role="error" style="color:#ff3b30;font-size:12px;display:none"></div>
      <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:4px">
        <button type="button" data-role="cancel" class="cmd-page-btn" style="width:auto;padding:6px 14px">Cancel</button>
        <button type="submit" data-role="submit" class="cmd-page-btn primary" style="width:auto;padding:6px 14px">Enable</button>
      </div>`
    const dismiss = openModal('Enable this device', body)
    body.querySelector<HTMLButtonElement>('[data-role=cancel]')!.addEventListener('click', dismiss)
    body.addEventListener('submit', async (ev) => {
      ev.preventDefault()
      const pw = (body.elements.namedItem('pw') as HTMLInputElement).value
      const errEl = body.querySelector<HTMLElement>('[data-role=error]')!
      const submit = body.querySelector<HTMLButtonElement>('[data-role=submit]')!
      errEl.style.display = 'none'
      submit.disabled = true; submit.textContent = 'Enabling…'
      try {
        if (!session.account.did) throw new Error('This account has no DID')
        const { unsealCurrentIdentity, vouchThisDevice } = await import('../did/provision.ts')
        const unsealed = await unsealCurrentIdentity(session.account.did, pw)
        if (!unsealed.ok) { errEl.textContent = unsealed.error; errEl.style.display = 'block'; return }
        const at = session.account.email.lastIndexOf('@')
        const username = session.account.email.slice(0, at)
        const domain = session.account.email.slice(at + 1)
        const deviceLabel = (navigator as any).userAgentData?.platform || navigator.platform || 'Browser'
        const r = await vouchThisDevice({
          serverUrl: session.account.serverUrl, username, domain, did: session.account.did,
          rootPrivateKey: unsealed.identity.rootPrivateKey, label: deviceLabel,
        })
        if (!r.ok) { errEl.textContent = `Server error (${r.status})`; errEl.style.display = 'block'; return }
        dismiss()
        showSysMsg('Device enabled')
        onDone()
      } catch (e) {
        errEl.textContent = e instanceof Error ? e.message : String(e)
        errEl.style.display = 'block'
      } finally {
        submit.disabled = false; submit.textContent = 'Enable'
      }
    })
  }

  // A display name for identities that have no relay yet (and therefore no
  // JMAP Identity object to hold one). Same key shape as didcomm-devices.ts's
  // OWN_DID_KEY — a small localStorage entry, not synced across devices or
  // published anywhere on its own. Once a relay is claimed, the JMAP
  // Identity.name becomes the real source of truth (openDisplayNameModal
  // below writes both, so the two never disagree while a relay exists) —
  // this cache is only ever a fallback for "no session to ask".
  const LOCAL_DISPLAY_NAME_PREFIX = 'biset_display_name_'
  function localDisplayName(did: string): string | null {
    try { return localStorage.getItem(LOCAL_DISPLAY_NAME_PREFIX + did) } catch { return null }
  }
  function setLocalDisplayName(did: string, name: string): void {
    try { localStorage.setItem(LOCAL_DISPLAY_NAME_PREFIX + did, name) } catch { /* ignore */ }
  }
  // The name actually shown for an identity, in priority order: the JMAP
  // Identity's own name (server-side, only meaningful once repEmail exists),
  // the local cache above (set before any relay existed, or if the JMAP
  // fetch/set failed), the DID's own path-segment username (always present,
  // never wrong — see buildBisetWebvhDid), and finally the email localpart
  // as a last resort for a repEmail whose DID somehow has no readable
  // username (a non-biset-shaped webvh identifier).
  function currentDisplayName(did: string, repEmail?: string): string {
    if (repEmail) {
      const jmapName = identities.all().find(i => i.email === repEmail)?.name
      if (jmapName) return jmapName
    }
    return localDisplayName(did) || bisetWebvhUsername(did) || repEmail?.split('@')[0] || 'Your identity'
  }

  // Writes `name` to this session's JMAP Identity and mirrors it into every
  // local cache that reads Identity.name (identities store, _accInfoCache,
  // the heading's own DOM text) — the part of openDisplayNameModal's submit
  // handler that talks to the relay, split out so claimMailAccount can run
  // the identical sequence right after provisioning (2026-08-16: a display
  // name set BEFORE claiming, while there was no relay to hold it, used to
  // sit in localStorage forever — the JMAP Identity a freshly claimed
  // account gets defaults to the localpart, same as go-jmapserver's
  // defaultIdentity(), and nothing ever pushed the local name into it).
  // Returns false on any failure; the caller decides how loud to be about
  // that (claimMailAccount treats it as best-effort, this modal surfaces it).
  async function applyDisplayNameToRelay(session: AccountSession, email: string, name: string): Promise<boolean> {
    try {
      const [r] = await (session.jmapClient.api as any).Identity.get({ accountId: session.jmapAccountId, ids: null })
      const id = (r.list as any[]).find(i => i.email === email) ?? r.list[0]
      if (!id?.id) return false
      await session.jmapClient.api.Identity.set({
        accountId: session.jmapAccountId,
        update: { [id.id]: { name } as any },
      })
      identities.set(identities.all().map(i => (i.id === id.id ? { ...i, name } : i)))
      const cache = _accInfoCache.get(email) ?? {}
      cache.name = name
      _accInfoCache.set(email, cache)
      return true
    } catch {
      return false
    }
  }

  function openDisplayNameModal(did: string, email?: string) {
    const session = email ? sessions.find(s => s.account.email === email) : undefined
    const currentName = currentDisplayName(did, email)
    const body = document.createElement('form')
    body.style.cssText = 'display:flex;flex-direction:column;gap:10px'
    body.innerHTML = `
      <div style="font-size:12px;color:var(--text-dim)">${esc(email ?? did)}</div>
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
      const newName = (body.elements.namedItem('name') as HTMLInputElement).value.trim()
      const errEl = body.querySelector<HTMLElement>('[data-role=error]')!
      const okEl = body.querySelector<HTMLElement>('[data-role=ok]')!
      const submit = body.querySelector<HTMLButtonElement>('[data-role=submit]')!
      errEl.style.display = 'none'; okEl.style.display = 'none'
      if (!newName) { errEl.textContent = 'Display name required'; errEl.style.display = 'block'; return }
      submit.disabled = true; submit.textContent = 'Saving…'
      // Always written locally, relay or not — the one thing every identity
      // can hold regardless of whether a JMAP Identity exists yet.
      setLocalDisplayName(did, newName)
      if (!session || !email) {
        const identityNameEl = document.getElementById('cmd-acc-identity-name')
        if (identityNameEl) identityNameEl.textContent = newName
        dismiss()
        renderAccountsList()
        return
      }
      try {
        const ok = await applyDisplayNameToRelay(session, email, newName)
        if (!ok) { errEl.textContent = 'Failed to fetch identity'; errEl.style.display = 'block'; return }
        // Direct DOM update, not relying on renderAccountsList() below alone
        // (user-reported, 2026-08-12: the DID document picked up the new
        // name on republish but the identity heading's own text never did) —
        // renderAccountsList re-derives the heading's name from
        // identities.all() via repAccount's email, which should already
        // reflect the .set() above, but setting the visible text directly
        // here removes any dependency on that indirection being exactly
        // right for the account that was actually just renamed.
        const identityNameEl = document.getElementById('cmd-acc-identity-name')
        if (identityNameEl) identityNameEl.textContent = newName
        renderAccountsList()
        // Also publish it into the DID document (biset extension, see
        // document.ts) — same name, one more place it shows up: anyone who
        // resolves this DID (e.g. via the [DID] badge) sees it instead of the
        // raw did:dht string. Only when a mediator is already registered —
        // an unpublished identity's document isn't kept current for free
        // (published/unpublished design); the explicit "Republish" button
        // covers a mediator-less identity that wants this out now anyway.
        // Genuinely best-effort otherwise — the name is already saved
        // server-side either way, so this must not fail the save — but
        // logged rather than dropped, so a document that can NEVER publish
        // leaves a trace instead of nothing at all.
        import('../did/didcomm/channel.ts').then(async m => {
          if (!(await m.hasDidCommChannel(did))) return
          // Method-agnostic — see removeRelayLocally's identical note above.
          const rec = await getDidRecord(did)
          if (!rec) return
          const { publishBareOrCurrent } = await import('../did/didcomm-devices.ts')
          await publishBareOrCurrent(rec)
        }).catch(e => console.error(`[did/publish] ${email}: republish after name change failed —`, e))
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

  // The "Republish" button's one implementation, method-agnostic (did:dht /
  // did:webvh) via publishBareOrCurrent's own methodOpsFor dispatch — shared
  // by both the relay-backed and zero-relay identity-heading branches below.
  // User-reported bug (2026-07-27): the relay-backed branch used to call
  // dht/publish.ts's publishOneVisible directly, which is did:dht-only (no
  // method dispatch at all) — for a did:webvh identity WITH a relay (the
  // common case, since #new's did:webvh always implies a username/relay),
  // clicking Republish silently built and PUT a phantom did:dht-shaped
  // record instead (same root key, different DID string) while reporting
  // success — the real did:webvh document was never touched. The zero-relay
  // branch already called publishBareOrCurrent correctly; this just extends
  // that same call to the relay-backed case too, rather than a second,
  // divergent implementation.
  // Re-shows the 24 words (mnemonic.ts's showStoredMnemonic), behind a fresh
  // passkey gesture on a protected device. Only "nothing to show" gets a
  // message: a refused prompt is the user's own answer, and the seed being
  // absent means this identity predates seed storage and has never been
  // logged into with its phrase since.
  async function showRecoveryPhrase(did: string): Promise<void> {
    const { showStoredMnemonic } = await import('./mnemonic.ts')
    const shown = await showStoredMnemonic(did)
    if (!shown) showSysMsg('No recovery phrase stored for this identity on this device', 8000)
  }

  // Offered only while this device has no passkey guarding the identity —
  // enrolment needs a real click (WebAuthn transient activation), which is
  // exactly why signup hangs it off the phrase dialog's own button and login
  // doesn't attempt it at all (did/restore.ts's note).
  async function protectWithPasskey(userName: string): Promise<void> {
    const { enableIdentityProtection } = await import('../did/store.ts')
    showSysMsg('Waiting for passkey…', 30000)
    const ok = await enableIdentityProtection(userName).catch(() => false)
    showSysMsg(ok ? 'Identity protected on this device' : 'Not protected — passkey unavailable or declined', 8000)
    refreshAccountsList()
  }

  // Whether this device can still publish this identity's document at all.
  // Silent failure is the default everywhere else: publishFull catches its
  // own error and returns 0, so a boot-time avatar publish or a mediator
  // re-registration that can no longer sign just... doesn't, with nothing on
  // screen and only a console line (PLANROTATION.md §2 C3). Those paths
  // cannot prompt for a phrase — no human is present — so the only fix is to
  // make the state visible somewhere a human looks, which is this page.
  //
  // Stalled means: pre-rotation has moved updateKeys off the Root Key at some
  // point, and this device holds no Sign Key that the log still authorises
  // (never entered here, or entered before a further rotate superseded it).
  // Everything else — including "activated but never rotated", where the Root
  // Key is still the Sign Key — is fine and shows nothing.
  const _syncStalled = new Map<string, { stalled: boolean; at: number }>()
  const SYNC_STALLED_TTL_MS = 60_000
  async function isPublishStalled(did: string): Promise<boolean> {
    if (!did.startsWith('did:webvh:')) return false
    const cached = _syncStalled.get(did)
    if (cached && Date.now() - cached.at < SYNC_STALLED_TTL_MS) return cached.stalled
    try {
      const [{ fetchCurrentLog }, { encodeMultikey }, { getDidRecord }] = await Promise.all([
        import('../did/webvh/log-io.ts'), import('../did/webvh/multikey.ts'), import('../did/store.ts'),
      ])
      const [log, rec] = await Promise.all([fetchCurrentLog(did), getDidRecord(did)])
      if (!rec) return false
      const authorised = log.last.parameters.updateKeys ?? []
      const holds = (hex?: string) => !!hex && authorised.includes(encodeMultikey(hexToBytes(hex)))
      const stalled = !holds(rec.rootPublicKey) && !holds(rec.signingPublicKey)
      _syncStalled.set(did, { stalled, at: Date.now() })
      return stalled
    } catch {
      // Couldn't ask (offline, anchor down) is not "stalled" — same
      // fail-closed-on-uncertainty stance as resolveConfirmedAbsent.
      return false
    }
  }

  async function refreshSyncStalledBanner(did: string): Promise<void> {
    const el = document.getElementById('cmd-acc-sync-stalled')
    if (!el) return
    if (!(await isPublishStalled(did))) { el.style.display = 'none'; return }
    el.textContent = ''
    el.style.cssText = 'display:flex;align-items:center;gap:10px;margin-top:10px;padding:9px 12px;border-radius:8px;background:rgba(255,149,0,0.12);font-size:12.5px;line-height:1.45;color:var(--text)'
    const txt = document.createElement('span')
    txt.style.flex = '1'
    txt.textContent = 'This device can no longer publish your DID document — key rotation moved control to a Sign Key it does not hold. Mail routing and device changes will not reach the network until you enter that phrase.'
    const btn = document.createElement('button')
    btn.type = 'button'
    btn.className = 'cmd-page-btn primary'
    btn.style.cssText = 'padding:4px 12px;font-size:11px;font-weight:900;text-transform:uppercase;border-radius:20px;flex-shrink:0'
    btn.textContent = 'Fix'
    btn.onclick = async (ev) => {
      ev.stopPropagation()
      _syncStalled.delete(did)
      await republishIdentity(did)
      refreshSyncStalledBanner(did)
    }
    el.append(txt, btn)
  }

  async function republishIdentity(did: string): Promise<void> {
    // Method-neutral wording throughout ("Sync", not "Publish to DHT") —
    // did:webvh has no DHT/gateway concept at all (a single HTTP PUT to the
    // anchor, see webvh/method-ops.ts's noGateways), so did:dht-specific
    // language here was actively wrong for it, not just imprecise.
    showSysMsg('Syncing…', 30000)
    try {
      // Publishing signs with the root key, which is sealed at rest on a
      // passkey-protected device (did/store.ts). No-op when this device never
      // enabled protection.
      const { unlockIdentitySecrets } = await import('../did/store.ts')
      if (!(await unlockIdentitySecrets())) { showSysMsg('Unlock cancelled — not synced'); return }
      let rec = await getDidRecord(did)
      if (!rec) throw new Error('no local DID record')
      const { publishBareOrCurrent } = await import('../did/didcomm-devices.ts')

      // The root key may no longer hold updateKeys authority — pre-rotation
      // activated then rotated/deactivated/revoked at any point in this
      // identity's history moves updateKeys away from root and never moves
      // it back (this session's whole pre-rotation design). publishFull
      // would otherwise silently fail with the stale key (caught, logged,
      // returns 0) and just report "Nothing reachable" — checked here
      // instead so Sync can prompt for the CURRENT phrase, the same
      // recovery path rotate/deactivate/revoke already use (2026-08-17,
      // user: a plain activate→deactivate cycle broke Sync with no way back
      // in from the UI).
      let signingKeyOverride: { privateKey: Uint8Array; publicKey: Uint8Array } | undefined
      if (did.startsWith('did:webvh:')) {
        const [{ fetchCurrentLog }, { encodeMultikey }] = await Promise.all([
          import('../did/webvh/log-io.ts'), import('../did/webvh/multikey.ts'),
        ])
        const currentLog = await fetchCurrentLog(did).catch(() => null)
        const rootKey = encodeMultikey(hexToBytes(rec.rootPublicKey))
        if (currentLog && !(currentLog.last.parameters.updateKeys ?? []).includes(rootKey)) {
          const { revealCurrentSigner } = await import('./prerotation.ts')
          const revealed = await revealCurrentSigner(did)
          if (!revealed) { showSysMsg('Sync needs your Sign Key phrase — cancelled'); return }
          signingKeyOverride = revealed
          // revealCurrentSigner may just have written signingPrivateKey/
          // signingPublicKey to this SAME record (cacheSigningKey) — re-read
          // it so the `rec` handed to publishBareOrCurrent below reflects
          // that. Without this, publishFull's own internal read-modify-write
          // (syncDevicePosition, called from inside publishCurrentState)
          // would put back the STALE snapshot captured above, silently
          // erasing the cache this exact Sync call just wrote — the reason
          // Sync kept re-prompting on every single click even right after
          // "fixing" that (found live, 2026-08-17).
          rec = (await getDidRecord(did)) ?? rec
        }
      }

      // publishCurrentState refuses outright — before it ever reaches
      // publishFull, so before the override above can help — when this
      // identity has device keys but no mediator recorded to route them to.
      // That state is reachable precisely BECAUSE of a stale signing key:
      // registerWithMediator publishes as its first step, so it fails and
      // never records didCommMediatorUrl/didCommRoutingKey, and every later
      // Sync then hits the refusal instead of the publish. Breaking that
      // loop is exactly what a human-driven Sync can do that no automatic
      // path can: it has a freshly entered Sign Key in hand. Found live on
      // y@biset.md (2026-08-17): "Nothing reachable" on every Sync, with the
      // correct phrase entered each time.
      if (signingKeyOverride && !(rec.didCommMediatorUrl && rec.didCommRoutingKey) && rec.didCommPublicKey) {
        const { mediatorUrl, registerWithMediator } = await import('../did/didcomm-devices.ts')
        const mUrl = rec.didCommMediatorUrl || mediatorUrl()
        if (mUrl) {
          try {
            await registerWithMediator(mUrl, signingKeyOverride)
            rec = (await getDidRecord(did)) ?? rec
          } catch (e) {
            console.warn('[sync] mediator re-registration failed:', e instanceof Error ? e.message : e)
          }
        }
      }

      const accepted = await publishBareOrCurrent(rec, signingKeyOverride)
      // Whatever the banner last concluded is now out of date either way —
      // a success means it should disappear, a failure that its 60s TTL
      // shouldn't hide a state the user just tried to fix.
      _syncStalled.delete(did)
      showSysMsg(accepted > 0 ? 'Synced' : 'Nothing reachable — not synced')
    } catch (e) {
      showSysMsg(`Sync failed: ${e instanceof Error ? e.message : String(e)}`, 15000)
    }
  }

  // Full sign-out, from the identity card's own menu (2026-08-12 — it used
  // to sit on the top-right page-navigation menu, which is the wrong place
  // for the one action there that isn't navigation). The confirm text is the
  // promise app.ts's logout() actually keeps: local only, nothing
  // server-side. logout() itself re-renders this page in its zero-account
  // state when it's done — no reload, no navigation.
  async function confirmAndLogout(): Promise<void> {
    if (!confirm('Log out and erase ALL local data (accounts, messages, keys)? This cannot be undone.')) return
    const { logout } = await import('../app.ts')
    await logout()
  }

  // The account page's own DID line: shown with the SCID elided
  // (`did:webvh:t.biset.md:bfc5`) — 46 characters of base58 mean nothing to
  // the account holder. The DID text + copy button area is one target: hover
  // it for the full identifier in a bubble, click it to copy that full DID
  // (never the elided form). The area shrinks to its own content (style.css's
  // align-self on the row), so the rest of the card still expands on click.
  function wireIdentityDid(didEl: HTMLElement, did: string) {
    const row = didEl.parentElement ?? didEl
    const { prefix, suffix } = ownDidParts(did)
    didEl.textContent = prefix + suffix
    // A CSS bubble rather than `title`: the native tooltip takes a second to
    // appear and breaks the DID across the screen's edge on its own terms.
    row.dataset.fullDid = did
    row.onclick = (ev) => {
      ev.stopPropagation() // copy only; don't also expand the card
      navigator.clipboard?.writeText(did).then(() => showSysMsg('DID copied')).catch(() => {})
    }
  }

  // Provisions the home mail relay for the CURRENT identity, on demand —
  // the counterpart to account-create.ts no longer doing this eagerly at
  // signup. Mirrors custom-domain.ts's showRelayCreateStep (same
  // unlockIdentitySecrets → getDidRecord → provisionAccount →
  // connectAndPersist shape), simplified: no relay-URL/username input,
  // since both are fixed (home mail relay, the DID's own path-segment
  // username) rather than user-chosen.
  async function claimMailAccount(did: string): Promise<void> {
    const username = bisetWebvhUsername(did)
    // The DID's OWN domain segment, not the deployment's fixed getHostname()
    // — a relay's `authorized_did_domain` gate (jmapsmtp's ARC.md §2a) admits
    // an identity by matching its did:webvh domain exactly, so an identity
    // rooted at biset.md can only ever claim `*@biset.md`, never
    // `*@t.biset.md`, however this deployment's own config.json hostname
    // happens to be set. Using the fixed hostname here used to build an
    // address for the WRONG domain whenever they differ (found live,
    // 2026-08-16: a biset.md identity was shown a doomed "claim t.biset.md"
    // card that the relay would have rejected outright).
    let didDomain: string | null = null
    try { didDomain = parseWebvhDid(did).domain } catch { /* not a biset-shaped webvh DID */ }
    // Same bug the comment above already describes, just one line further
    // than it was fixed: didDomain was corrected, but the actual request
    // target here still used getMailUrl() — this deployment's OWN
    // mail.<hostname>, not the identity's. That sent every claim to
    // whichever domain happened to be serving the page, which happily
    // provisioned `<username>@<ITS OWN domain>` and handed back an address
    // that was never the one the card showed (found live, 2026-08-17:
    // claiming the `y@biset.md` card from a t.biset.md-served page silently
    // created `y@t.biset.md` instead).
    //
    // mailUrl itself is NOT `mail.<didDomain>` though — see context.ts's
    // mailRelayUrl for why (one relay serves every domain in this deployment
    // behind ONE apex URL; mail.t.biset.md has no DNS record at all).
    const mailUrl = didDomain ? mailRelayUrl(didDomain) : null
    if (!username || !didDomain || !mailUrl) { showSysMsg('Mail relay not configured for this deployment'); return }

    const { getDidRecord, unlockIdentitySecrets } = await import('../did/store.ts')
    if (!(await unlockIdentitySecrets())) return
    const rec = await getDidRecord(did)
    if (!rec) { showSysMsg('No local record for this identity'); return }
    const rootPrivateKey = hexToBytes(rec.rootPrivateKey)

    const { provisionAccount } = await import('../did/provision.ts')
    // domain MUST be explicit — provision.ts's own note on this field spells
    // out why: a relay can host several domains behind one serverUrl,
    // distinguished only by this field, and omitting it falls back to
    // "the relay's open domain" — never necessarily didDomain. That default
    // is exactly what silently provisioned `y@t.biset.md` for a
    // `did:webvh:...:biset.md:y` claim: mail.biset.md hosts BOTH biset.md
    // and t.biset.md, and only t.biset.md is configured open — biset.md
    // requires a provision_secret this UI has no field for yet (found live,
    // 2026-08-17, alongside the mailUrl bug this same claim card carried).
    let res = await provisionAccount({ serverUrl: mailUrl, username, did, rootPrivateKey, envelope: rec.envelope, domain: didDomain })
    // 403 here (jmapsmtp's Refusal::DomainNotOpen etc. — provision.rs's own
    // may_provision) means the domain isn't self-service: no
    // authorized_did_domain match, allow_provision off, and no secret sent
    // yet. It gates EVERY provision attempt unconditionally, including
    // reclaiming an address this exact DID already legitimately owns per
    // the claim registry (server.rs checks it before ever looking at
    // whether the name is already taken) — so there is no path around this
    // for a privileged domain except supplying the secret its own operator
    // configured. One retry, not a loop: a wrong secret should fail
    // visibly, not prompt forever.
    if (!res.ok && res.status === 403) {
      const secret = prompt(`${didDomain} requires a provisioning secret to claim ${username}@${didDomain}. Enter it:`)
      if (secret) {
        res = await provisionAccount({ serverUrl: mailUrl, username, did, rootPrivateKey, envelope: rec.envelope, domain: didDomain, provisionSecret: secret })
      }
    }
    if (!res.ok) {
      // The relay's own text (provision.ts's ProvisionResult.error) now
      // surfaces directly rather than a hardcoded "owned by a different
      // key" for every 409 — jmapsmtp maps BOTH UsernameTaken ("this
      // account already exists — you want to log in, not claim") and
      // IdentityOwnedByAnother (a genuine conflict) to the same status
      // code, and only the server's own message text tells them apart.
      showSysMsg(res.error || `Server error (${res.status})`)
      return
    }
    const email = res.email || `${username}@${didDomain}`

    // A kek, when this record has the seed to derive one from (did/index.ts's
    // localDidRecord/initDidWebvh — absent only for an identity created
    // before 2026-08-17, or restored on a device that hasn't kept it), so
    // connectAndPersist's PGP setup actually runs. Without it a freshly
    // claimed relay silently got no PGP key at all (found live, 2026-08-17)
    // — restoreFromMnemonic already derives one the same way, this just
    // brings claim in line with it.
    const { deriveKek } = await import('../cryptenv.ts')
    const kek = rec.masterSeed ? await deriveKek(hexToBytes(rec.masterSeed)) : undefined

    const { connectAndPersist } = await import('../app.ts')
    const session = await connectAndPersist({ serverUrl: mailUrl, email, password: '', did }, kek)
    if (!session) { showSysMsg('Claimed, but failed to connect'); return }

    // Carry over a display name set BEFORE this relay existed (the
    // localStorage cache openDisplayNameModal writes even with no relay to
    // hold it) — the freshly claimed Identity otherwise defaults to the
    // localpart (go-jmapserver's defaultIdentity()), silently discarding
    // whatever name was already showing on this exact card a moment ago.
    // Best-effort: claiming has already succeeded either way.
    const localName = localDisplayName(did)
    if (localName && localName !== username) {
      await applyDisplayNameToRelay(session, email, localName).catch(() => false)
    }

    // Publish the new relay to the DID document (routing.json's `service`
    // array) — without this, claiming only ever produced a LOCAL session:
    // restoreFromMnemonic (did/restore.ts) discovers relays exclusively from
    // `doc.service.filter(s => !!s.address)` on the resolved document, never
    // from this device's own StoredAccounts, so an identity that claimed
    // mail here could connect on THIS device but a sign-out + restore (or
    // any other device) found nothing to reconnect to, forever — the same
    // shape as every other device having zero relays (found live,
    // 2026-08-17). liveRelayInputs (didcomm-devices.ts) reads live sessions,
    // and `session` was just added to sessions[] by connectAndPersist above,
    // so this republish picks it up. Best-effort: the claim itself already
    // succeeded either way, and the existing "Sync" action (identity menu)
    // covers a publish that fails here.
    try {
      const { publishBareOrCurrent } = await import('../did/didcomm-devices.ts')
      await publishBareOrCurrent(rec)
    } catch (e) {
      console.warn('[claimMailAccount] publish after claim failed (non-fatal, Sync will retry):', e instanceof Error ? e.message : e)
    }

    const { fetchRelayInfo } = await import('../context.ts')
    await fetchRelayInfo(mailUrl)
    renderAccountsList()
    showSysMsg(`Claimed ${email}`)
  }

  // The home mail relay's card when this identity has NOT claimed it yet —
  // same row shape as a real relay card (relayCards below), styled dim/gray
  // and reduced to a single "Claim account" action, so the surface a
  // brand-new identity sees is discoverable rather than an empty list. Never
  // shown for an identity with no DID at all (nothingSetUp's signup form
  // covers that case instead).
  function renderUnclaimedMailCard($list: HTMLElement, accounts: StoredAccount[]): void {
    const did = ownDid()
    if (!did) return
    const username = bisetWebvhUsername(did)
    // The DID's own domain segment — see claimMailAccount's identical note.
    // A card built from the deployment's fixed hostname instead would offer
    // to claim an address this identity's DID can never actually be
    // authorized for (authorized_did_domain matches the DID's domain
    // exactly), for any identity rooted at a different domain than this
    // deployment's own config.json happens to name.
    let didDomain: string | null = null
    try { didDomain = parseWebvhDid(did).domain } catch { /* not a biset-shaped webvh DID */ }
    if (!username || !didDomain) return
    // Not gated on getMailUrl() (this deployment's own mail.<hostname>) any
    // more: whether to OFFER claiming `<username>@<didDomain>` is a property
    // of the identity, not of which domain happens to be serving this page
    // right now. A deployment with no mail relay of its OWN can still show
    // (and successfully act on, via claimMailAccount's own didDomain-derived
    // URL) a claim card for an identity rooted at some OTHER domain that
    // does have one — the previous `!mailUrl` gate hid it in exactly that
    // case (found alongside claimMailAccount's own bug, 2026-08-17).
    const email = `${username}@${didDomain}`
    // Already claimed (a real StoredAccount exists for this address) — the
    // real card in relayCards below covers it, don't show a second one.
    if (accounts.some(a => a.email === email && a.did === did)) return

    const row = document.createElement('div')
    row.className = 'cmd-page-row'
    row.style.cssText = 'gap:12px;align-items:center;padding:10px 12px;opacity:0.55'

    const left = document.createElement('div')
    left.style.cssText = 'flex:1;min-width:0;display:flex;flex-direction:column;gap:4px'
    const headRow = document.createElement('div')
    headRow.style.cssText = 'display:flex;align-items:center;gap:8px;min-width:0'
    const dot = document.createElement('span')
    dot.style.cssText = 'width:8px;height:8px;border-radius:50%;flex-shrink:0;background:var(--text-dim)'
    const protoEl = document.createElement('span')
    protoEl.style.cssText = 'font-size:11px;font-weight:700;letter-spacing:0.04em;color:var(--text-dim);flex-shrink:0'
    protoEl.textContent = 'MAIL'
    const sep = document.createElement('span')
    sep.style.cssText = 'color:var(--text-dim);flex-shrink:0'
    sep.textContent = ':'
    const addrEl = document.createElement('span')
    addrEl.style.cssText = 'font-size:13px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis'
    addrEl.textContent = email
    headRow.append(dot, protoEl, sep, addrEl)
    const statusRow = document.createElement('div')
    statusRow.style.cssText = 'font-size:11px;color:var(--text-dim)'
    statusRow.textContent = 'Not claimed'
    left.append(headRow, statusRow)

    const menuBtn = document.createElement('button')
    menuBtn.type = 'button'
    menuBtn.style.cssText = 'background:none;border:none;color:var(--text-dim);cursor:pointer;padding:6px;line-height:0;border-radius:6px;flex-shrink:0;display:flex;align-items:center;justify-content:center'
    menuBtn.innerHTML = `<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><circle cx="12" cy="5" r="1.5"/><circle cx="12" cy="12" r="1.5"/><circle cx="12" cy="19" r="1.5"/></svg>`
    menuBtn.setAttribute('aria-label', 'Menu')
    menuBtn.addEventListener('mouseover', () => { menuBtn.style.background = 'rgba(128,128,128,0.12)' })
    menuBtn.addEventListener('mouseout', () => { menuBtn.style.background = 'none' })
    menuBtn.addEventListener('click', (ev) => {
      ev.stopPropagation()
      openDropdownMenu(menuBtn, [
        { label: 'Claim account', onClick: () => claimMailAccount(did) },
      ])
    })

    row.append(left, menuBtn)
    $list.appendChild(row)
  }

  function renderAccountsList() {
    const $list = document.getElementById('cmd-acc-list')
    if (!$list) return
    // BEFORE the clear, always: the zero-account branch below parks the live
    // #new-user-page node in this very container, and `textContent = ''`
    // would destroy it outright — taking #new's only DOM (and every listener
    // bound to it) with it for the rest of the session.
    unmountNewUserPageInline()
    $list.textContent = ''
    const accounts = loadStoredAccounts()
    // One session = one identity (ARC.md 2026-07-14): every loaded account
    // shares the same DID (if any), so the identity is a property of the
    // PAGE, not of any one card — shown once in the heading, avatar + [display
    // name / shortened DID], instead of repeated per card.
    const identitySection = document.getElementById('cmd-acc-identity-section')
    const identityFields = document.getElementById('cmd-acc-identity-fields')
    const identityAvatar = document.getElementById('cmd-acc-identity-avatar')
    const identityName = document.getElementById('cmd-acc-identity-name')
    const identityDid = document.getElementById('cmd-acc-identity-did')
    const identityMenuBtn = document.getElementById('cmd-acc-identity-menu-btn') as HTMLButtonElement | null
    const identityDoc = document.getElementById('cmd-acc-identity-doc')
    const identityDevices = document.getElementById('cmd-acc-identity-devices')
    const identitySyncBtn = document.getElementById('cmd-acc-identity-sync-btn')
    const repAccount = accounts.find(a => a.did)
    // Whether this device already has a passkey guarding the seed + root key
    // (did/store.ts) — decides whether the menu offers to set one up.
    const identityProtected = identityProtectionEnabled()
    if (identitySection && identityFields && identityAvatar && identityName && identityDid && identityDoc && identityDevices) {
      // The whole card is the click target now (not just the DID text) —
      // same "click anywhere to expand" pattern the relay/storage cards
      // already use (.acc-card-wrap's cmd-page-row). Sub-controls inside it
      // (avatar, name, copy button, menu button) stop propagation so they
      // keep their own single-purpose click behavior instead of also
      // toggling the expand panel.
      const wireIdentityHeading = (did: string) => {
        identityFields.onclick = () => toggleIdentityExpanded(identitySection, identityDevices, identityDoc, did)
      }
      // One identity, one heading, regardless of whether it has a relay yet
      // (2026-08-16 — used to be two near-duplicate branches, "has a
      // StoredAccount" vs "DID only", that quietly disagreed on the name
      // ('Your identity' vs the real one), the avatar (fixed glyph vs the
      // saved picture — pickAndSetIdentityAvatar already keys by the bare
      // DID too, so relay-less rendering never actually needed the fixed
      // glyph), and the menu (Change display name only appeared once a
      // relay existed, even though currentDisplayName/setLocalDisplayName
      // above work with no relay at all). `repEmail` is the only thing that
      // still varies — some of what it feeds (Identity.get/.set,
      // "Delete account" elsewhere) is genuinely relay-specific — so it
      // stays optional rather than being faked.
      const did = repAccount?.did ?? ownDid()
      const repEmail = repAccount?.email
      if (did) {
        identityAvatar.textContent = ''
        identityAvatar.style.cssText = 'cursor:pointer;position:relative;overflow:hidden'
        identityAvatar.title = 'Click to set avatar'
        // pickAndSetIdentityAvatar saves under every known address AND the
        // bare DID (its own note) — read the DID first as the identity-wide
        // picture, falling back to the address only for a picture saved
        // before that dual-write existed.
        const ownAvatar = avatarDataUrl(did) ?? (repEmail ? avatarDataUrl(repEmail) : undefined)
        const initialsSource = repEmail ?? currentDisplayName(did)
        if (ownAvatar) {
          identityAvatar.style.cssText += ';background:transparent'
          const img = document.createElement('img')
          img.src = ownAvatar
          img.style.cssText = 'width:100%;height:100%;object-fit:cover;border-radius:50%'
          identityAvatar.appendChild(img)
        } else {
          identityAvatar.style.cssText += ';' + avatarStyle(initialsSource)
          identityAvatar.textContent = initialsSource.charAt(0).toUpperCase()
        }
        identityAvatar.onclick = (ev) => { ev.stopPropagation(); pickAndSetIdentityAvatar(did) }
        identityName.textContent = currentDisplayName(did, repEmail)
        identityName.onclick = (ev) => { ev.stopPropagation(); openDisplayNameModal(did, repEmail) }
        wireIdentityDid(identityDid, did)
        wireIdentityHeading(did)
        // Change display name moved onto the name text's own click (hover
        // reveals the pencil icon as the affordance, 2026-08-16), Sync/
        // Export/Import moved off the Devices panel's own icon row
        // (2026-08-11), and Log out moved off the top-right page menu
        // (2026-08-12) — that menu is page navigation, and logging out was
        // the one item on it that wasn't. Sync (republishIdentity) publishes
        // the WHOLE identity's document (every relay, every address)
        // regardless of which account triggered it. It moved back out to
        // its own icon button on the DID:Webvh row (2026-08-16,
        // user-requested revert) — it's the one action people reach for
        // often enough that burying it in the dropdown was the wrong call.
        if (identityMenuBtn) {
          identityMenuBtn.style.display = ''
          identityMenuBtn.onclick = (ev) => {
            ev.stopPropagation()
            openDropdownMenu(identityMenuBtn, [
              ...(identityProtected ? [] : [{ label: 'Protect with passkey', onClick: () => protectWithPasskey(repEmail ?? did) }]),
              { label: 'Show recovery phrase', onClick: () => showRecoveryPhrase(did) },
              { label: 'Export Messages', onClick: () => exportIdentityMessages(did) },
              { label: 'Import Messages', onClick: () => importIdentityMessages() },
              // did:webvh only — did:dht has no location to move (its DID is
              // a pure function of the key, PLAN.md §2.1) and no other method
              // this identity might have has a portability mechanism at all.
              ...(did.startsWith('did:webvh:')
                ? [{
                  label: 'Edit identity', onClick: async () => {
                    const { openEditIdentityModal } = await import('./edit-identity.ts')
                    openEditIdentityModal(did, openModal, () => renderAccountsList(), () => { fetchMessages(); loadLeftInboxes() })
                  },
                }]
                : []),
              { label: 'Log out', danger: true, onClick: () => confirmAndLogout() },
            ])
          }
        }
        if (identitySyncBtn) {
          identitySyncBtn.onclick = (ev) => {
            ev.stopPropagation()
            republishIdentity(did)
          }
        }
        refreshSyncStalledBanner(did)
        // Adding a relay uses the normal "+ New JMAP account" panel below
        // (or, for the home mail relay specifically, the unclaimed card's
        // own "Claim account" — renderUnclaimedMailCard), which provisions
        // under THIS identity's DID — no separate button here.
        identitySection.style.display = ''
      } else {
        identitySection.style.display = 'none'
        identitySection.classList.remove('expanded')
      }
    }
    // Nothing set up on this device: show the #new signup form right here
    // rather than a bare "No accounts" line (2026-08-12, user-requested) —
    // it's the only thing there is to do from this page in that state, and
    // the floating "+ New Relay" button stays available alongside it for
    // joining an existing relay instead. setup* are idempotent, so calling
    // them on every render is free.
    const nothingSetUp = !accounts.length && !ownDid()
    if (nothingSetUp) {
      setupNewUserPage()
      mountNewUserPageInline($list)
    }
    // With the signup form standing in for the whole page, "account" names
    // something that doesn't exist yet — the app's own name is what this
    // screen is actually introducing. Safe to write unconditionally here:
    // reaching this line means the account page's own markup is on screen
    // (the $list lookup above returns otherwise), so there's no conversation
    // title to clobber. renderMenuInboxImpl sets the plain page name first
    // and only then calls onShow → here, so this always wins.
    const $headerTitle = document.getElementById('header-thread-title')
    if ($headerTitle) $headerTitle.textContent = nothingSetUp ? 'biset' : 'account'
    // (a standalone identity shows its DID heading above instead)
    const relayLabel = (url: string): string => {
      try { return new URL(url).hostname.split('.')[0] } catch { return '?' }
    }
    // The home mail relay's own card, ALWAYS shown once this identity has a
    // DID — claimed (a real StoredAccount exists) or not (2026-08-16,
    // "claim account" redesign: #new no longer provisions mail itself, see
    // account-create.ts's submit handler). Unclaimed is the default state
    // for a brand new identity; claiming happens explicitly from this
    // card's own hamburger menu (claimMailAccount below), never implicitly.
    renderUnclaimedMailCard($list, accounts)

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
      // Relay-advertised label (GET /relay-info, context.ts's relayProtocolLabel) —
      // no hardcoded AP/mail guess here. Cache-first render, refreshed once
      // fetchRelayInfo resolves (mirrors fetchAccountInfo's pattern below).
      protoEl.textContent = relayProtocolLabel(a.serverUrl)?.text ?? '…'
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
      menuBtn.style.cssText = 'position:relative;background:none;border:none;color:var(--text-dim);cursor:pointer;padding:6px;line-height:0;border-radius:6px;flex-shrink:0;display:flex;align-items:center;justify-content:center'
      menuBtn.innerHTML = `<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><circle cx="12" cy="5" r="1.5"/><circle cx="12" cy="12" r="1.5"/><circle cx="12" cy="19" r="1.5"/></svg>`
      menuBtn.setAttribute('aria-label', 'Menu')
      menuBtn.addEventListener('mouseover', () => { menuBtn.style.background = 'rgba(128,128,128,0.12)' })
      menuBtn.addEventListener('mouseout', () => { menuBtn.style.background = 'none' })
      menuBtn.addEventListener('click', (ev) => {
        ev.stopPropagation()
        openAccountMenu(menuBtn, a.email, a.serverUrl, a.did)
      })
      // Overlaid on this card's own hamburger (not the top-level one) while
      // fetchAccountInfo — the actual JMAP Identity.get/Email.query round trip
      // that fills in Unread/PGP/Sync below — is in flight, so a still-blank
      // "Unread: …/…" doesn't read as "nothing to show" (2026-08-17, user:
      // 自分がいっているハンバーガーボタンはjmap relayカードのハンバーカード).
      const menuSpinner = document.createElement('span')
      menuSpinner.style.cssText = 'display:none;position:absolute;inset:0;border-radius:6px;background:var(--bg);pointer-events:none'
      const menuSpinnerRing = document.createElement('span')
      menuSpinnerRing.style.cssText = 'position:absolute;inset:6px;border-radius:50%;border:1.5px solid var(--accent);border-top-color:transparent;border-right-color:transparent;animation:recip-loading-spin 0.7s linear infinite'
      menuSpinner.appendChild(menuSpinnerRing)
      menuBtn.appendChild(menuSpinner)

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
        // session?.account.password, not a.password — for a DID-bound account
        // the StoredAccount's own password field is always '' (initSession's
        // per-device branch is the only real credential); the live session
        // carries the actual device-session bearer token that was used to
        // connect (jmap/client.ts's initSession returns a shallow copy with
        // it). Using a.password directly always 401'd for any DID-bound
        // account — "Failed to load" regardless of the relay actually being
        // fine (found live, did:webvh test account, 2026-07-27). Same fix
        // applies to every other storage-panel action below (message list,
        // download, purge).
        const info = await fetchAccountStorage(a.serverUrl, a.email, session?.account.password ?? a.password)
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
              const files = await fetchMessageFiles(a.serverUrl, a.email, session?.account.password ?? a.password)
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
          const bundle = await exportAccountStorage(a.serverUrl, a.email, session?.account.password ?? a.password)
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
          const n = await purgeAccountMessages(a.serverUrl, a.email, session?.account.password ?? a.password)
          if (n == null) { showSysMsg('Purge failed'); return }
          showSysMsg(`Purged ${n} message${n === 1 ? '' : 's'}`)
          loadStorageTree()
          loadLeftInboxes()
        } finally {
          purgeBtn.disabled = false
        }
      })

      if (session) {
        menuSpinner.style.display = 'block'
        fetchAccountInfo(session).then(info => {
          if (!info) return
          statUnread.textContent = fmtUnread(info)
          statPgp.textContent = info.pgp == null ? '' : info.pgp ? 'PGP ✓' : 'PGP ✗'
          statSync.textContent = `Sync: ${fmtRelTime(info.lastSyncAt)}`
        }).catch(() => {}).finally(() => { menuSpinner.style.display = 'none' })
      }
      fetchRelayInfo(a.serverUrl).then(() => {
        protoEl.textContent = relayProtocolLabel(a.serverUrl)?.text ?? '?'
      }).catch(() => {})
    }

    // No trailing "+ New Relay" card any more (2026-08-12, user-requested):
    // it's a floating button pinned to the bottom of the page instead
    // (#cmd-acc-fab in renderAccountPage), which opens the same panel over
    // the card area. See openAddRelayPanel below.
  }

  // Device list — one row per device the MLS self group holds, which is the
  // same set this identity publishes (didcomm-devices.ts's
  // fullKeyAgreementKeys). Showing the group rather than a local cache means
  // the panel cannot disagree with what senders actually see, and that a
  // device removed here is removed cryptographically, not just hidden.
  //
  // Before the group exists (a fresh identity, or one that has not reached
  // its mediator yet) the only device there is to show is this one.
  async function loadIdentityDevices(deviceList: HTMLElement, did: string): Promise<void> {
    deviceList.textContent = 'Loading…'
    const rec = await getDidRecord(did).catch(() => null)
    if (!rec) { deviceList.textContent = 'Failed to load.'; return }
    // TWO sources, deliberately shown together.
    //
    // The MLS self group is what decides membership, and it is what gets
    // published — so a panel showing only the group is "correct" and useless
    // the moment something goes wrong: a device that has not joined shows one
    // row (itself) and no hint that anything is missing, which is exactly what
    // two devices of one identity looked like while neither had a group
    // (2026-08-13). The published document is the other half of the picture:
    // it says who senders can currently reach.
    //
    // Showing the union, labelled, makes the two distinguishable — and makes
    // "this device is not in the group yet" visible instead of silent.
    // ONE network-touching source, not three.
    //
    // `fullKeyAgreementKeys` already unions the MLS group with the devices the
    // mediator still has a registration for, resolving the document once to
    // learn their keys (didcomm-devices.ts). The panel used to redo that
    // resolve for itself and query the keylist a second time through
    // mediatorDeviceActivity — on a device that cannot authenticate with the
    // mediator right now, the extra round trips are exactly the ones that hang,
    // and the panel sat on "Loading…" indefinitely.
    //
    // Everything here is also time-boxed. A device list that renders late is
    // an annoyance; one that never renders hides the very state a person opened
    // this panel to inspect.
    const withTimeout = async <T>(p: Promise<T>, ms: number, fallback: T): Promise<T> => {
      let timer: ReturnType<typeof setTimeout> | undefined
      const timeout = new Promise<T>(resolve => { timer = setTimeout(() => resolve(fallback), ms) })
      try { return await Promise.race([p, timeout]) } finally { if (timer) clearTimeout(timer) }
    }
    const { fullKeyAgreementKeys } = await import('../did/didcomm-devices.ts')
    const { selfGroupTransportKeys } = await import('../mls/self-group.ts')
    const hexOf = (b: Uint8Array) => [...b].map(x => x.toString(16).padStart(2, '0')).join('')
    const [groupDevices, published] = await Promise.all([
      withTimeout(selfGroupTransportKeys(did).catch(() => undefined), 8000, undefined),
      withTimeout(fullKeyAgreementKeys(rec).catch(() => []), 12000, []),
    ])
    const inGroup = new Set((groupDevices ?? []).map(d => d.kid.slice(d.kid.indexOf('#'))))
    const entries = published.map(k => ({
      kid: k.kid,
      publicKey: hexOf(k.publicKey),
      isSelf: k.kid === rec.didCommOwnKid,
      state: !groupDevices ? 'local' as const : inGroup.has(k.kid) ? 'group' as const : 'published-only' as const,
    })) as Array<{ kid: string; publicKey: string; isSelf: boolean; state: 'group' | 'published-only' | 'local' | 'registered-only' }>
    deviceList.textContent = ''
    if (!entries.length) { deviceList.textContent = 'No devices.'; return }
    // Liveness from the mediator, the only party that sees whether a slot's
    // device still collects mail (didcomm-devices.ts's mediatorDeviceActivity).
    // A ghost — a browser whose storage was cleared, say — keeps its key
    // published and its queue filling forever, and this row is the only place
    // it can be recognised and removed. Null (couldn't ask) shows nothing at
    // all rather than mislabelling every device as never-seen.
    const activity = await withTimeout(mediatorDeviceActivity(did).catch(() => null), 8000, null)
    // Registrations outlive the devices that made them. A browser whose
    // storage was cleared, or a device that logged out while it could not
    // reach the mediator, leaves a keylist entry nothing else cleans up — and
    // an entry there is what keeps a device addressable and its key packages
    // handed out to anyone inviting this identity. Eleven had accumulated on
    // one identity by 2026-08-13, and none of them were listed here, so there
    // was no way to see them, let alone remove them.
    //
    // Shown last and labelled for what they are: not devices this identity
    // publishes, just registrations left behind.
    const listed = new Set(entries.map(e => e.kid))
    for (const kid of activity?.byKid.keys() ?? []) {
      if (listed.has(kid)) continue
      entries.push({ kid, publicKey: '', isSelf: kid === rec.didCommOwnKid, state: 'registered-only' })
    }
    for (const entry of entries) {
      const devRow = document.createElement('div')
      devRow.className = 'acc-device-row'
      const label = document.createElement('span')
      label.className = 'acc-device-label'
      // The kid alone identifies the device now: it is derived from that
      // device's own key (did/devicekid.ts), so showing the key next to it
      // said the same thing twice — once in a form nobody can read. The pair
      // made sense when a kid was a slot number (`#k2`) and the key was the
      // only thing telling two devices apart. The full key stays reachable on
      // hover for anyone verifying one out of band.
      label.title = entry.publicKey
      // `published-only` is a device senders can reach that the group does not
      // list — either it has not joined yet, or it was removed and the
      // document has not caught up. Both are worth seeing; neither is an
      // error, and MLS makes the second harmless (it can be addressed, not
      // read).
      const stateLabel = entry.state === 'registered-only' ? ' · stale registration (not published)'
        : entry.state === 'published-only' ? ' · not in the device group'
        : entry.state === 'local' ? ' · device group not set up yet'
        : ''
      label.textContent = `${entry.kid}${entry.isSelf ? ' · This device' : ''}${stateLabel}${deviceActivityLabel(activity, entry.kid, entry.isSelf)}`
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
          : entry.state === 'registered-only'
            ? `Clear the leftover registration for ${entry.kid}? This identity does not publish that device; the registration is what keeps it addressable and its key packages on offer.`
            : `Remove device ${entry.kid} from the published key list? This cannot be undone from here.`)) return
        trashBtn.disabled = true
        try {
          const { removeDeviceKey } = await import('../did/didcomm-devices.ts')
          await removeDeviceKey(did, entry.kid, entry.isSelf)
          showSysMsg(entry.isSelf ? 'Logged out of mediator' : 'Device removed')
          loadIdentityDevices(deviceList, did)
          renderAccountsList()
        } catch (e) {
          showSysMsg('Remove failed: ' + (e instanceof Error ? e.message : String(e)), 8000)
          trashBtn.disabled = false
        }
      })
      devRow.append(label, trashBtn)
      deviceList.appendChild(devRow)
    }
  }

  // Export/Import Messages — moved off the Devices panel's own icon row and
  // into the identity card's hamburger menu (2026-08-11, user-requested).
  // Still DIDComm-only data (buildMediatorArchiveEntries/parseMediatorArchive's
  // own notes: this history is local-only, unlike relay mail which can
  // always be re-synced from the server instead).
  let identityExportBusy = false
  async function exportIdentityMessages(did: string): Promise<void> {
    if (identityExportBusy) return
    identityExportBusy = true
    try {
      const rec = await getDidRecord(did).catch(() => null)
      if (!rec) { showSysMsg('Export failed'); return }
      // Public kid/key list only — never this device's private keys, even
      // though this is a local-only export.
      const { fullKeyAgreementKeys } = await import('../did/didcomm-devices.ts')
      const devices = (await fullKeyAgreementKeys(rec).catch(() => [])).map(k => ({
        kid: k.kid,
        publicKey: [...k.publicKey].map(x => x.toString(16).padStart(2, '0')).join(''),
        isSelf: k.kid === rec.didCommOwnKid,
      }))
      // Mediator delivery is pickup-and-persist-locally by design (no
      // server-side store to fetch from, unlike a relay) — every DIDComm
      // message this identity has ever received/sent already lives in the
      // same local Email store JMAP mail uses, under the synthetic
      // DIDComm pseudo-account (channel.ts's didCommAccount).
      const emails = messages.forAccount(accountKey({ email: did, serverUrl: DIDCOMM_SERVER_URL }))
      const { buildMediatorArchiveEntries } = await import('../vault/export.ts')
      const { buildZip } = await import('../vault/zip.ts')
      const entries = await buildMediatorArchiveEntries(did, emails, devices)
      const zipBytes = buildZip(entries)
      const blob = new Blob([zipBytes.buffer as ArrayBuffer], { type: 'application/zip' })
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      let host = rec.didCommMediatorUrl ?? 'mediator'
      try { if (rec.didCommMediatorUrl) host = new URL(rec.didCommMediatorUrl).hostname } catch { /* keep raw */ }
      link.download = `${host}-mediator-data.zip`
      link.click()
      URL.revokeObjectURL(url)
    } finally {
      identityExportBusy = false
    }
  }

  // File-picker input rather than drag/drop — matches every other one-shot
  // file-in action in this codebase, no new interaction pattern to learn.
  // The input element itself stays in the fixed page template
  // (renderAccountPage's cmd-acc-identity-devices-import-input) so this only
  // needs wiring once, not rebuilt on every renderAccountsList.
  let identityImportBusy = false
  function importIdentityMessages(): void {
    const importInput = document.getElementById('cmd-acc-identity-devices-import-input') as HTMLInputElement | null
    importInput?.click()
  }
  function setupIdentityImportInput(): void {
    const importInput = document.getElementById('cmd-acc-identity-devices-import-input') as HTMLInputElement | null
    if (!importInput) return
    importInput.addEventListener('click', ev => ev.stopPropagation())
    importInput.addEventListener('change', async () => {
      const file = importInput.files?.[0]
      importInput.value = ''
      if (!file || identityImportBusy) return
      identityImportBusy = true
      try {
        const bytes = new Uint8Array(await file.arrayBuffer())
        const { parseMediatorArchive } = await import('../vault/export.ts')
        const emails = parseMediatorArchive(bytes)
        if (!emails.length) { showSysMsg('No messages found in that file'); return }
        const { flushMessage } = await import('../vault/persist.ts')
        for (const email of emails) {
          messages.put(email)
          await flushMessage(email)
        }
        showSysMsg(`Imported ${emails.length} message${emails.length === 1 ? '' : 's'}`)
        loadLeftInboxes()
      } catch (e) {
        showSysMsg('Import failed: ' + (e instanceof Error ? e.message : String(e)), 8000)
      } finally {
        identityImportBusy = false
      }
    })
  }

  // The identity card's one click-to-expand handler (2026-08-11: merges what
  // used to be a separate, optional "Mediator" card into the always-present
  // identity heading — the mediator isn't something you can add or remove
  // any more, so there's nothing left to gate a whole card's existence on).
  // Expanding loads BOTH panels: Devices (the mediator's registered
  // keyAgreement keys for this identity) and the raw DID document.
  async function toggleIdentityExpanded(section: HTMLElement, deviceList: HTMLElement, docEl: HTMLElement, did: string): Promise<void> {
    const wasExpanded = section.classList.contains('expanded')
    section.classList.toggle('expanded')
    if (wasExpanded) return
    loadIdentityDevices(deviceList, did)
    docEl.textContent = 'Resolving…'
    try {
      // Was its own relay-sessions-only gateway list (relaysForId(did),
      // filtered) — empty for a relay-less (DID⊥relay) identity, which has no
      // relay session to draw a gateway from at all. resolveDidDocFull
      // (above) solves this by resolving from the DID string itself instead
      // of a gateway list. This is what made a standalone identity's own
      // #account page permanently report "No document found" even though the
      // record was resolvable everywhere else.
      const doc = await resolveDidDocFull(did)
      docEl.textContent = doc ? JSON.stringify(doc, null, 2) : 'No document found (not yet published, or no gateway reachable)'
    } catch {
      docEl.textContent = 'Failed to resolve DID document'
    }
  }


  function onShowAccounts() {
    renderAccountsList()
    setupIdentityImportInput()
    // The floating "+ New Relay" button and the ways out of the panel it
    // opens. Wired here (with the rest of this page's one-time setup) rather
    // than in renderAccountsList, which re-runs on every account change and
    // would stack duplicate listeners on these fixed template elements.
    document.getElementById('cmd-acc-fab')?.addEventListener('click', () => openAddRelayPanel())
    document.getElementById('cmd-acc-panel-backdrop')?.addEventListener('click', () => closeAddRelayPanel())
    positionAccFloating()
    const rightCol = document.getElementById('right-col')
    if (rightCol && typeof ResizeObserver !== 'undefined') {
      // One observer for the life of the page — the elements it positions are
      // recreated with the template, but #right-col itself never is.
      accFloatingObserver?.disconnect()
      accFloatingObserver = new ResizeObserver(() => positionAccFloating())
      accFloatingObserver.observe(rightCol)
    }
    document.addEventListener('keydown', (ev) => {
      if (ev.key !== 'Escape') return
      const panel = document.getElementById('cmd-acc-panel')
      if (panel?.classList.contains('open')) closeAddRelayPanel()
    })
    const form = document.getElementById('cmd-acc-form') as HTMLFormElement | null
    form?.addEventListener('submit', async (ev) => {
      ev.preventDefault()
      const relayInput = document.getElementById('cmd-acc-relay') as HTMLInputElement
      const emailInput = document.getElementById('cmd-acc-email') as HTMLInputElement
      const errEl = document.getElementById('cmd-acc-error')!
      const addBtn = document.getElementById('cmd-acc-add') as HTMLButtonElement

      const email = emailInput.value.trim()
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
      if (!email) { errEl.textContent = 'Email required'; errEl.style.display = 'block'; return }

      addBtn.disabled = true; addBtn.textContent = 'Connecting…'; errEl.style.display = 'none'

      // No password field at all any more (user's explicit call — third-party/
      // plain-password JMAP login isn't a use case worth keeping): "Log in" is
      // purely a reconnect via this device's own per-device key (devicebind.ts).
      // ownDid() is set independently of any session and never cleared by an
      // ordinary per-relay logout (removeRelayLocally only drops the
      // StoredAccount/session, never the DidRecord) — so this works whenever
      // this device was vouched at the typed relay before (e.g. logging back
      // in after logging out). Never vouched there, or revoked: no fallback,
      // just an error.
      const myDid = ownDid()
      const connected: Array<{ session: import('../types.ts').AccountSession; server: string }> = []
      if (myDid) {
        for (const server of servers) {
          const session = await initSession({ serverUrl: server, email, password: '', did: myDid }).catch(() => null)
          if (session) connected.push({ session, server })
        }
      }

      if (!connected.length) {
        errEl.textContent = myDid ? 'Could not reconnect this device at that relay' : 'No local identity on this device to reconnect with'
        errEl.style.display = 'block'
        addBtn.disabled = false; addBtn.textContent = 'Add'
        return
      }

      // One session = one identity (ARC.md 2026-07-14): a reconnected
      // session's own `.did` (only set when the device-key path above
      // succeeded) is this device's OWN identity, independent of whatever is
      // currently active — so logging into an account belonging to a
      // genuinely different identity must never silently merge into the
      // active one's sessions. Switching identity is logout-then-login only.
      const isFirst = sessions.length === 0
      if (!isFirst) {
        const activeIdKey = identityIds()[0]
        if (activeIdKey && myDid !== activeIdKey) {
          errEl.textContent = 'This account belongs to a different identity — log out first to switch.'
          errEl.style.display = 'block'
          addBtn.disabled = false; addBtn.textContent = 'Add'
          return
        }
      }

      // Persist + register each connected relay, deduped by (email, serverUrl)
      // so mail and AP for the same identity coexist as separate sessions. No
      // password to persist — every future login re-derives a fresh device
      // session instead (initSession's per-device branch).
      for (const c of connected) {
        const session = c.session
        const relayEmail: string = session.account.email || email
        const stored: StoredAccount = { serverUrl: c.server, email: relayEmail, password: '', did: myDid ?? undefined }
        persistSession(stored, session)
      }
      addBtn.disabled = false; addBtn.textContent = 'Add'
      resetAddAccountPanel()
      closeAddRelayPanel()
      renderAccountsList()
      loadLeftInboxes()
      if (isFirst) startPolling()
    })
  }

  const LP_COMMANDS: Array<{ name: string; page?: () => string; action: () => void; onShow?: () => void | Promise<void> }> = [
    { name: '/account', page: renderAccountPage, action: () => {}, onShow: onShowAccount },
    { name: '/config',  page: renderConfigPage,  action: () => {}, onShow: onShowConfig },
    { name: '/compose',     page: renderComposePage,     action: () => {}, onShow: onShowNew },
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
    // No conversation is on screen on a menu page, so nothing should have its
    // notifications suppressed (see switchInbox's counterpart).
    setActiveConversation(null)

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
      // Same reason renderAccountsList unmounts first: the account page may
      // be holding the live #new-user-page node inside the markup about to
      // be thrown away here (navigating away from /account, or re-rendering
      // it), and it must survive that.
      unmountNewUserPageInline()
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
