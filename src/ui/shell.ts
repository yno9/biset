import { sessions, currentInbox, activeSession, accountKey, sessionForRelay } from '../context.ts'
import { markProgrammaticScroll } from '../utils.ts'
import {
  processedMessages, renderedKeys,
  focusedThreadKey, setFocusedThreadKey,
  notifEnabled, isFirstFetch, setIsFirstFetch,
  groupMessages, latestGroup,
} from '../state.ts'
import { fetchInboxMessages, loadInboxSummaries, jmapCreateEmail, currentSenderSync } from '../app.ts'
import type { OutgoingAttachment } from '../pgp/crypto.ts'
import { buildEditBody, type ChatAction, type GroupOpts } from '../deltachat/protocol.ts'
import { freshestAddressFor } from '../did/discovery.ts'
import * as jmapEmail from '../jmap/email.ts'
import * as messages from '../store/messages.ts'
import { removeMessage } from '../vault/persist.ts'
import { start as startSync, stop as stopSync } from '../sync/index.ts'
import type { ProcessedMessage } from '../state.ts'
import type { AccountSession } from '../types.ts'
// Circular:
import { render, addMessage, isMeMsg, syncDockPosition } from './thread.ts'
import { loadLeftInboxes, markRead, inMenuMode } from './left-pane.ts'

// Mobile single-column mode toggles 'show-left' on #app from many places
// (hamburger, swipe gesture, switchInbox, ...) — rather than touching every
// call site to persist it, just observe the class and remember the last
// state, so a reload can restore it below instead of always landing on the
// conversation column.
const MOBILE_SHOW_LEFT_KEY = 'biset-mobile-show-left'
{
  const $app = document.getElementById('app')
  if ($app) {
    new MutationObserver(() => {
      try { localStorage.setItem(MOBILE_SHOW_LEFT_KEY, $app.classList.contains('show-left') ? '1' : '0') } catch {}
    }).observe($app, { attributes: true, attributeFilter: ['class'] })
  }
}

export function showApp() {
  const $overlay = document.getElementById('overlay')
  const $pwOverlay = document.getElementById('pw-overlay')
  const $app = document.getElementById('app')
  if ($overlay) $overlay.style.display = 'none'
  if ($pwOverlay) $pwOverlay.style.display = 'none'
  if ($app) $app.style.display = 'flex'
  setIsFirstFetch(true)
  syncDockPosition()
  render()
  if (currentInbox) {
    const ta = document.querySelector<HTMLElement>('.reply-box textarea')
    ta?.focus()
  }
  // Mobile: restore whichever column (inbox list vs conversation) was showing
  // before the last reload, instead of always landing back on the
  // conversation. Defaults to the right column (content) when there's no
  // saved state yet — the left pane is an overlay reached via the hamburger.
  if (window.innerWidth <= 520) {
    let showLeft = false
    try { showLeft = localStorage.getItem(MOBILE_SHOW_LEFT_KEY) === '1' } catch {}
    $app?.classList.toggle('show-left', showLeft)
  }
}

let _sysMsgTimer: ReturnType<typeof setTimeout> | null = null
export function showSysMsg(text: string) {
  const el = document.getElementById('sys-msg')
  if (!el) return
  el.textContent = text
  el.classList.add('show')
  if (_sysMsgTimer) clearTimeout(_sysMsgTimer)
  _sysMsgTimer = setTimeout(() => el.classList.remove('show'), 1800)
}

let _pendingCounter = 0
export function addPendingMessage(
  body: string, subject = '', inReplyTo = '', senderEmail = '', senderName = '',
): string {
  const tempId = `__pending_${++_pendingCounter}_${Date.now()}`
  const fromAddr = senderEmail || activeSession()?.account.email || 'me'
  const fromName = senderName || (fromAddr.includes('@') ? fromAddr.split('@')[0] : fromAddr)
  const processed: ProcessedMessage = {
    msg: {
      from: fromAddr, from_name: fromName, body, subject, ts: Date.now(),
      message_id: tempId,
      in_reply_to: inReplyTo || focusedThreadKey || '',
      thread_id: focusedThreadKey || '',
    },
    bodyText: body, encrypted: false, unreadable: false, pending: true, tempId,
  }
  processedMessages.push(processed)
  renderedKeys.add(`${processed.msg.from}:${processed.msg.ts}`)
  return tempId
}

export function updatePendingMessageSender(tempId: string, name: string) {
  const p = processedMessages.find(p => p.tempId === tempId)
  if (!p) return
  p.msg.from = name; p.msg.from_name = name
  render(false, true)
}

export function removePendingMessage(tempId: string) {
  const idx = processedMessages.findIndex(p => p.tempId === tempId)
  if (idx < 0) return
  const removed = processedMessages.splice(idx, 1)[0]!
  renderedKeys.delete(`${removed.msg.from}:${removed.msg.ts}`)
}

// Shared by sendReply and the edit/delete request senders below: who this
// conversation's messages go to, and (for groups) the Chat-Group-ID/Name that
// keeps the thread a writable DeltaChat group rather than a read-only ad-hoc
// one. Also the References chain (oldest → newest known message-id).
function computeConversationRecipients(): { toAddrs: string[]; groupOpts: GroupOpts | undefined; references: string[] } {
  const contact = currentInbox?.contact ?? ''
  const isGroup = currentInbox?.inbox_type === 'group'
  let groupRecipients: string[] = []
  let groupOpts: GroupOpts | undefined
  if (isGroup) {
    const selfEmail = activeSession()?.account.email ?? ''
    const allAddrs = new Set<string>()
    for (const p of processedMessages) {
      if (!p.pending) {
        if (p.msg.from) allAddrs.add(p.msg.from)
        for (const a of p.msg.to_addrs ?? []) allAddrs.add(a)
        for (const a of p.msg.cc_addrs ?? []) allAddrs.add(a)
      }
    }
    allAddrs.delete(selfEmail)
    groupRecipients = [...allAddrs]
    const gMsg = processedMessages.find(p => p.msg.group_id)
    if (gMsg) groupOpts = { id: gMsg.msg.group_id!, name: gMsg.msg.group_name ?? '' }
  }
  const references = processedMessages
    .filter(p => !p.pending)
    .sort((a, b) => a.msg.ts - b.msg.ts)
    .map(p => p.msg.message_id)
    .filter((id): id is string => !!id && !id.startsWith('__pending_') && !id.startsWith('srv-'))
  // DID.md option A: deliver a 1:1 to the contact's freshest verified address
  // (from their signed DID document), so a relay/domain move is followed
  // invisibly. No-op unless a verified fresher address is cached; groups are
  // left as-is (multi-recipient discovery is out of scope for the first cut).
  const dmTo = isGroup ? groupRecipients : [freshestAddressFor(contact)]
  return { toAddrs: dmTo, groupOpts, references }
}

export async function sendReply(
  ta: HTMLTextAreaElement, replySubject = '', inReplyTo = '',
  attachments: OutgoingAttachment[] = [],
) {
  const body = ta.value.trim()
  if (!body && !attachments.length) return
  ta.value = ''
  ta.style.height = 'auto'

  // biset-old actions.go 同等: 既存メッセージがあれば必ず最新メッセージを親としてチェーン。
  // 引数の inReplyTo が空のときに ts 最大の非pending メッセージにフォールバック。
  // (配列順はインクリメンタル同期後に ts 順とは限らないため必ず ts でソートする)
  const realMsgs = processedMessages
    .filter(p => !p.pending && p.msg.message_id && !p.msg.message_id.startsWith('__pending_'))
    .sort((a, b) => a.msg.ts - b.msg.ts)
  if (!inReplyTo && realMsgs.length) {
    inReplyTo = realMsgs[realMsgs.length - 1].msg.message_id
  }

  // Warm the contact's DID cache for next time (best-effort, non-blocking).
  if (currentInbox?.contact && currentInbox.inbox_type !== 'group') {
    import('../did/discovery.ts').then(m => m.refreshContact(currentInbox!.contact!)).catch(() => {})
  }

  const { toAddrs, groupOpts, references } = computeConversationRecipients()
  const sender = currentSenderSync()
  const outer = document.getElementById('outer')
  const distFromBottom = outer ? outer.scrollHeight - outer.scrollTop - outer.clientHeight : Infinity
  const tempId = addPendingMessage(body, replySubject, inReplyTo, sender.email, sender.name)
  render(false, true)
  requestAnimationFrame(() => {
    if (!outer) return
    const pb = parseFloat(outer.style.paddingBottom) || 0
    if (outer.scrollHeight - pb > outer.clientHeight + 1 && distFromBottom < 60) {
      markProgrammaticScroll()
      outer.scrollTo({ top: outer.scrollHeight, behavior: 'instant' })
    }
  })
  ta.focus()

  // Reply through the relay this conversation arrived on (mail vs ActivityPub).
  const { ok, error } = await jmapCreateEmail(
    toAddrs, body, replySubject, inReplyTo, groupOpts, references,
    currentInbox?.user, currentInbox?.relay, attachments,
  )
  if (ok) {
    await fetchMessages()
    loadLeftInboxes()
  } else {
    removePendingMessage(tempId)
    render()
    showSysMsg(error || 'Send failed')
  }
}

// Sends a Chat-Edit request (deltachat spec.md "Request editing") for a
// message the current user sent. Non-destructive on the wire — the target
// email is untouched; every recipient (including this device, once its own
// Sent-folder copy round-trips back) overlays the new text at display time
// (see collectEdits in deltachat/protocol.ts). Not offered for AP threads
// (DeltaChat-only feature) or messages carrying attachments (spec forbids it).
export async function sendEditRequest(target: ProcessedMessage, newText: string): Promise<void> {
  const text = newText.trim()
  if (!text) return
  const { toAddrs, groupOpts, references } = computeConversationRecipients()
  const editBody = buildEditBody(text)
  const chatAction: ChatAction = { editTarget: target.msg.message_id }
  const { ok, error } = await jmapCreateEmail(
    toAddrs, editBody, '', target.msg.message_id, groupOpts, references,
    currentInbox?.user, currentInbox?.relay, [], chatAction,
  )
  if (ok) {
    await fetchMessages()
    loadLeftInboxes()
  } else {
    showSysMsg(error || 'Edit failed')
  }
}

// Sends a Chat-Delete request (deltachat spec.md "Request deletion") for a
// message the current user sent, then removes this device's own copy right
// away — sync/session.ts's applyIncomingDelete handles it for every other
// device/recipient once the carrier reaches them, but that round-trip can
// take a few seconds, and "delete for everyone" includes the sender's own view.
export async function sendDeleteRequest(target: ProcessedMessage): Promise<void> {
  const { toAddrs, groupOpts, references } = computeConversationRecipients()
  const chatAction: ChatAction = { deleteTarget: target.msg.message_id }
  const { ok, error } = await jmapCreateEmail(
    toAddrs, 'deleted', '', target.msg.message_id, groupOpts, references,
    currentInbox?.user, currentInbox?.relay, [], chatAction,
  )
  if (!ok) { showSysMsg(error || 'Delete failed'); return }
  const inbox = currentInbox
  const jmapId = target.msg.jmap_id
  if (inbox?.user && jmapId) {
    const sess = sessionForRelay(inbox.user, inbox.relay ?? '') ?? activeSession()
    if (sess) {
      try { await jmapEmail.destroy(sess.jmapClient, sess.jmapAccountId, [jmapId]) }
      catch (err) { console.warn('[chat-delete] own-copy destroy failed', err) }
      const acct = accountKey({ email: inbox.user, serverUrl: sess.account.serverUrl })
      messages.remove(acct, jmapId)
      await removeMessage(acct, jmapId)
    }
  }
  await fetchMessages()
  loadLeftInboxes()
}

export async function fetchMessages() {
  const inbox = currentInbox
  if (!inbox) return

  const wasFirstLoad = isFirstFetch
  setIsFirstFetch(false)

  const msgs = await fetchInboxMessages(inbox)
  const previouslyKnownIds = new Set(processedMessages.map(p => p.msg.message_id))

  if (wasFirstLoad) {
    processedMessages.length = 0
    renderedKeys.clear()
  } else {
    // Prune messages no longer present server-side (Chat-Delete, manual
    // delete elsewhere) — addMessage only ever adds/patches, so without this
    // a deleted message's bubble stayed on screen until a full reload
    // rebuilt processedMessages from scratch.
    const liveIds = new Set(msgs.map(m => m.message_id))
    for (let i = processedMessages.length - 1; i >= 0; i--) {
      const p = processedMessages[i]
      if (p.pending || liveIds.has(p.msg.message_id)) continue
      processedMessages.splice(i, 1)
      renderedKeys.delete(`${p.msg.from}:${p.msg.ts}`)
    }
  }

  for (const msg of msgs) await addMessage(msg)

  const groups = groupMessages()
  // Always scroll to the latest message on new mail (scrollToFocused already
  // handles a message taller than the viewport by pinning its top instead of
  // its bottom) — keepScroll's "only if already near the bottom" gate was
  // silently leaving new messages scrolled out of view, behind the fixed
  // reply box, whenever the user had scrolled up even slightly.
  if (!groups.length) { render(false, false); return }

  const selfAddr = activeSession()?.account.email ?? ''
  const hasIncoming = msgs.some(m => m.from !== selfAddr)
  const latest = latestGroup(groups)
  if (wasFirstLoad || hasIncoming || latest.key !== focusedThreadKey) {
    setFocusedThreadKey(latest.key)
  }

  // Notify only for messages that weren't already known before this fetch —
  // hasIncoming above is true for a conversation's entire existing history,
  // so without this guard, simply opening (or re-polling) any conversation
  // that has ever had a reply fires a notification for messages already on
  // screen. wasFirstLoad is excluded outright: that's the initial load of
  // whichever conversation was just opened, never "new" mail.
  const hasNewIncoming = !wasFirstLoad && msgs.some(m => m.from !== selfAddr && !previouslyKnownIds.has(m.message_id))
  if (hasNewIncoming && notifEnabled && Notification.permission === 'granted') {
    const last = processedMessages.filter(p => !isMeMsg(p.msg.from)).pop()
    if (last && inbox.contact) new Notification(inbox.contact, { body: last.bodyText.slice(0, 100) })
  }
  // A message arriving in the conversation you're actively reading (thread
  // visible, not behind a menu page) has been seen — mark it read so it doesn't
  // linger as unread (inflating the badge / re-appearing the moment you leave).
  // markRead only ran on switchInbox before, so live arrivals stayed unread.
  if (hasNewIncoming && !inMenuMode()) markRead(inbox)

  render(false, false)
}

const _sseSources: EventSource[] = []
let _visibilityHandlerInstalled = false

// Reconnects with capped exponential backoff instead of permanently giving up
// on the first drop — a plain EventSource that errors once (mobile network
// changes, backgrounding, a relay restart) never came back on its own, so a
// client could go arbitrarily long without seeing new mail: fine for Web Push
// (which hits the relay directly), but the app's own left-pane/badge logic
// reads from the local synced cache, and a message that's never synced can
// never be marked seen either — it just sits there looking unread forever,
// with no way for the user to "read" it away.
function connectSSE(session: AccountSession, backoffMs = 2000): void {
  const eventUrl = session.eventSourceUrl?.replace(/\{[^}]+\}/g, '') ?? null
  if (!eventUrl) return
  try {
    const token = encodeURIComponent(session.account.email + ':' + session.account.password)
    const sep = eventUrl.includes('?') ? '&' : '?'
    const src = new EventSource(eventUrl + sep + `access_token=${token}`)
    src.addEventListener('state', async () => {
      const { sync } = await import('../sync/session.ts')
      await sync(session)
      fetchMessages()
      loadLeftInboxes()
    })
    src.onerror = () => {
      try { src.close() } catch {}
      const idx = _sseSources.indexOf(src)
      if (idx >= 0) _sseSources.splice(idx, 1)
      // Only reconnect if this session is still the one startPolling() last
      // set up for (a fresh startPolling()/logout call already tore this down).
      if (!sessions.includes(session)) return
      setTimeout(() => connectSSE(session, Math.min(backoffMs * 2, 60000)), backoffMs)
    }
    _sseSources.push(src)
  } catch {}
}

export function startPolling() {
  _sseSources.forEach(s => { try { s.close() } catch {} })
  _sseSources.length = 0
  stopSync()
  if (!sessions.length) return

  // Initial sync + UI refresh on completion
  startSync(sessions).then(() => { fetchMessages(); loadLeftInboxes() })

  for (const session of sessions) connectSSE(session)

  // Belt-and-suspenders for the reconnect above: a backgrounded/frozen tab's
  // JS (including the onerror handler and its setTimeout) doesn't get to run
  // at all until the tab is foregrounded again, so catch up on anything
  // missed the moment that happens rather than waiting for the next poll.
  if (!_visibilityHandlerInstalled) {
    _visibilityHandlerInstalled = true
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState !== 'visible' || !sessions.length) return
      startSync(sessions).then(() => { fetchMessages(); loadLeftInboxes() })
    })
  }
}
