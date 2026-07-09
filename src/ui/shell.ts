import { sessions, currentInbox, activeSession } from '../context.ts'
import { markProgrammaticScroll } from '../utils.ts'
import {
  processedMessages, renderedKeys,
  focusedThreadKey, setFocusedThreadKey,
  notifEnabled, isFirstFetch, setIsFirstFetch,
  groupMessages, latestGroup,
} from '../state.ts'
import { fetchInboxMessages, loadInboxSummaries, jmapCreateEmail, currentSenderSync } from '../app.ts'
import type { OutgoingAttachment } from '../pgp/crypto.ts'
import { start as startSync, stop as stopSync } from '../sync/index.ts'
import type { ProcessedMessage } from '../state.ts'
// Circular:
import { render, addMessage, isMeMsg, syncDockPosition } from './thread.ts'
import { loadLeftInboxes } from './left-pane.ts'

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

  const contact = currentInbox?.contact ?? ''
  const isGroup = currentInbox?.inbox_type === 'group'
  let groupRecipients: string[] = []
  let groupOpts: { id: string; name: string } | undefined
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

  // Build References from all known message IDs in the thread, ordered by ts (oldest first).
  const references = realMsgs
    .map(p => p.msg.message_id)
    .filter((id): id is string => !!id && !id.startsWith('__pending_') && !id.startsWith('srv-'))

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

  const toAddrs = isGroup ? groupRecipients : [contact]
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

export async function fetchMessages() {
  const inbox = currentInbox
  if (!inbox) return

  const wasFirstLoad = isFirstFetch
  setIsFirstFetch(false)

  const msgs = await fetchInboxMessages(inbox)

  if (wasFirstLoad) {
    processedMessages.length = 0
    renderedKeys.clear()
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

  if (hasIncoming && notifEnabled && Notification.permission === 'granted') {
    const last = processedMessages.filter(p => !isMeMsg(p.msg.from)).pop()
    if (last && inbox.contact) new Notification(inbox.contact, { body: last.bodyText.slice(0, 100) })
  }

  render(false, false)
}

const _sseSources: EventSource[] = []

export function startPolling() {
  _sseSources.forEach(s => { try { s.close() } catch {} })
  _sseSources.length = 0
  stopSync()
  if (!sessions.length) return

  // Initial sync + UI refresh on completion
  startSync(sessions).then(() => { fetchMessages(); loadLeftInboxes() })

  for (const session of sessions) {
    const eventUrl = session.eventSourceUrl?.replace(/\{[^}]+\}/g, '') ?? null
    if (!eventUrl) continue
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
      src.onerror = () => { try { src.close() } catch {} }
      _sseSources.push(src)
    } catch {}
  }
}
