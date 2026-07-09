import { currentInbox, activeSession, relayInfoFor, isApRelay } from '../context.ts'
import {
  processedMessages, renderedKeys,
  focusedThreadKey, setFocusedThreadKey,
  groupMessages, latestGroup,
  lastLeftInboxes,
} from '../state.ts'
import type { ProcessedMessage, ThreadGroup } from '../state.ts'
import { esc, linkify, formatTime, avatarStyle, stripQuoted, markProgrammaticScroll } from '../utils.ts'
import { avatarDataUrl } from '../deltachat/avatar.ts'
import { processIncoming } from '../processing.ts'
import type { OutgoingAttachment } from '../pgp/crypto.ts'
// Circular imports — used only inside function bodies, safe:
import { sendReply, sendEditRequest, sendDeleteRequest, showSysMsg } from './shell.ts'
import { inMenuMode, renderThreadAccordion } from './left-pane.ts'
import { currentSenderSync } from '../app.ts'

const threadVisibleCounts = new Map<string, number>()

// Transport label for a conversation's origin relay (serverUrl). Uses the relay's
// own advertised label/color (GET /relay-info, cached on connect) so biset stays
// relay-agnostic; falls back to the subdomain until that fetch lands.
function relayProtocolLabel(relay?: string): { text: string; color: string } | null {
  if (!relay) return null
  const info = relayInfoFor(relay)
  if (info) return { text: info.label, color: info.color }
  let sub = ''
  try { sub = new URL(relay).hostname.split('.')[0].toLowerCase() } catch { return null }
  if (sub === 'ap') return { text: 'AP', color: '#8b5cf6' }
  if (sub === 'mail') return { text: 'Mail', color: '#64748b' }
  return { text: sub.toUpperCase(), color: '#64748b' }
}

export function isMeMsg(from: string): boolean {
  return from === activeSession()?.account.email || (!!activeSession()?.jmapAccountId && from === activeSession()?.jmapAccountId)
}

// RFC 9078 reactions (src/mail/reactions.ts) arrive as their own message,
// synced AFTER their target is already on screen — so `reactions` is the one
// field on an already-rendered message that can still change. Shared by
// createMsgEl (initial render) and the in-place patch in addMessage below.
function renderReactionsHtml(reactions: ProcessedMessage['msg']['reactions']): string {
  if (!reactions?.length) return ''
  return `<div class="t-reactions">${reactions.map(r =>
    `<span class="t-reaction-chip" title="${esc(r.from)}">${esc(r.emoji)}</span>`
  ).join('')}</div>`
}

// Message attachments (display-only — see processing.ts / state.ts
// MsgAttachment). Images render as a clickable thumbnail (opens full-size in
// a new tab); anything else is a filename + download chip.
function renderAttachmentsHtml(attachments: ProcessedMessage['attachments']): string {
  if (!attachments?.length) return ''
  const items = attachments.map(a => {
    if (/^image\//i.test(a.contentType)) {
      return `<a class="t-attachment-img" href="${a.dataUrl}" target="_blank" rel="noopener"><img src="${a.dataUrl}" alt="${esc(a.filename ?? '')}"></a>`
    }
    const label = a.filename || 'attachment'
    return `<a class="t-attachment-file" href="${a.dataUrl}" download="${esc(label)}" title="${esc(label)}">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/></svg>
      <span>${esc(label)}</span>
    </a>`
  }).join('')
  return `<div class="t-attachments">${items}</div>`
}

// Edit/Delete (deltachat spec.md "Request editing" / "Request deletion") —
// DeltaChat-only, mail-relay-only. Own messages only (own = only-safe
// authorization: session.ts's applyIncomingDelete/collectEdits also verify
// the requester matches the target's original sender, but there's no reason
// to even offer it for someone else's message). Edit is additionally hidden
// for messages with attachments — the spec forbids editing those.
function canModifyOwn(msg: ProcessedMessage['msg']): boolean {
  return isMeMsg(msg.from) && !isApRelay(currentInbox?.relay) && !msg.message_id.startsWith('__pending_')
}

function renderMsgActionsHtml(msg: ProcessedMessage['msg'], attachments: ProcessedMessage['attachments']): string {
  if (!canModifyOwn(msg)) return ''
  const editBtn = attachments?.length ? '' : `<button type="button" class="t-msg-edit-btn">Edit</button>`
  return `
    <div class="t-msg-actions">
      <button type="button" class="t-msg-actions-btn" aria-label="Message actions">
        <svg viewBox="0 0 24 24" width="13" height="13" fill="currentColor"><circle cx="12" cy="5" r="1.6"/><circle cx="12" cy="12" r="1.6"/><circle cx="12" cy="19" r="1.6"/></svg>
      </button>
      <div class="t-msg-actions-menu" style="display:none">
        ${editBtn}
        <button type="button" class="t-msg-delete-btn">Delete for everyone</button>
      </div>
    </div>`
}

// Swaps a message's `.t-body` into an editable textarea (Save/Cancel). Built
// via DOM APIs rather than an HTML template for the textarea's initial value —
// esc() converts newlines to <br>, which is correct for display but would
// corrupt a textarea's plain-text value.
function enterEditMode(msgEl: HTMLElement, processed: ProcessedMessage) {
  const bodyEl = msgEl.querySelector('.t-body') as HTMLElement | null
  if (!bodyEl) return
  bodyEl.innerHTML = `<div class="t-edit-actions">
    <button type="button" class="t-edit-save">Save</button>
    <button type="button" class="t-edit-cancel">Cancel</button>
  </div>`
  const ta = document.createElement('textarea')
  ta.className = 't-edit-ta'
  ta.value = processed.bodyText
  bodyEl.prepend(ta)
  ta.style.height = ta.scrollHeight + 'px'
  ta.focus()
  ta.setSelectionRange(ta.value.length, ta.value.length)
}

// Closes any open per-message actions menu on an outside click. Registered
// once at module scope (not per-render) so it never accumulates listeners.
document.addEventListener('click', e => {
  if ((e.target as HTMLElement).closest?.('.t-msg-actions-btn')) return
  document.querySelectorAll('.t-msg-actions-menu').forEach(m => { (m as HTMLElement).style.display = 'none' })
})

function sameReactions(a: ProcessedMessage['msg']['reactions'], b: ProcessedMessage['msg']['reactions']): boolean {
  const an = a?.length ?? 0, bn = b?.length ?? 0
  if (an !== bn) return false
  for (let i = 0; i < an; i++) {
    if (a![i].emoji !== b![i].emoji || a![i].from !== b![i].from) return false
  }
  return true
}

export async function addMessage(msg: ProcessedMessage['msg']): Promise<boolean> {
  const key = `${msg.from}:${msg.ts}`
  if (renderedKeys.has(key)) {
    const existing = processedMessages.find(p => `${p.msg.from}:${p.msg.ts}` === key)
    if (existing && !sameReactions(existing.msg.reactions, msg.reactions)) {
      existing.msg.reactions = msg.reactions
      const el = document.querySelector(`.t-msg[data-message-id="${CSS.escape(existing.msg.message_id)}"] .t-meta`)
      el?.querySelector('.t-reactions')?.remove()
      if (msg.reactions?.length) el?.insertAdjacentHTML('beforeend', renderReactionsHtml(msg.reactions))
    }
    return false
  }
  renderedKeys.add(key)

  const { bodyText, encrypted, unreadable, attachments } = await processIncoming(
    msg, activeSession()?.account.email ?? '', processedMessages
  )

  processedMessages.push({ msg, bodyText, encrypted, unreadable, attachments })

  // If this incoming message matches a pending stub (same from), drop the stub.
  {
    const trimmed = bodyText.trim()
    let dropIdx = -1
    for (let i = 0; i < processedMessages.length - 1; i++) {
      const p = processedMessages[i]
      if (!p.pending || p.msg.from !== msg.from) continue
      if (!unreadable && p.bodyText.trim() === trimmed) { dropIdx = i; break }
      if (unreadable && dropIdx < 0) dropIdx = i
    }
    if (dropIdx >= 0) {
      const p = processedMessages[dropIdx]
      processedMessages.splice(dropIdx, 1)
      renderedKeys.delete(`${p.msg.from}:${p.msg.ts}`)
    }
  }

  return true
}

export function createMsgEl({ msg, bodyText, encrypted, unreadable, pending, attachments }: ProcessedMessage) {
  const div = document.createElement('div')
  if (msg.from === '[system]') {
    div.className = 't-msg t-system'
    div.innerHTML = `<div class="t-body" style="font-size:12px;color:var(--text-dim);font-style:italic;padding:4px 0">${esc(bodyText)}</div>`
    return div
  }
  div.className = 't-msg' + (isMeMsg(msg.from) ? ' me' : '')
  if (pending) div.style.opacity = '0.6'
  const display = unreadable
    ? `<span style="opacity:0.4;font-style:italic">Encrypted message</span>`
    : linkify(esc(stripQuoted(bodyText)))
  const senderName = msg.from_name || msg.from
  // DeltaChat avatar for the sender (works for group members too, unlike the
  // per-inbox avatar_url which only exists for 1:1 contacts).
  const senderAvatarURL = avatarDataUrl(msg.from)
    ?? lastLeftInboxes.find(x => x.contact === msg.from && x.avatar_url)?.avatar_url
    ?? null
  div.dataset.messageId = msg.message_id
  div.innerHTML = `
    <div class="t-avatar" style="${senderAvatarURL ? 'background:transparent' : avatarStyle(msg.from)}">${senderAvatarURL ? `<img src="${senderAvatarURL}" style="width:100%;height:100%;object-fit:cover;border-radius:50%;">` : senderName.charAt(0).toUpperCase()}</div>
    <div class="t-meta">
      <div class="t-hdr">
        <span class="t-sender">${esc(senderName)}</span>
        <span class="t-time">${formatTime(msg.ts)}${encrypted ? ' <svg style="vertical-align:middle;opacity:0.6" width="11" height="11" viewBox="0 0 24 24" fill="currentColor"><path d="M18 8h-1V6A5 5 0 0 0 7 6v2H6a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V10a2 2 0 0 0-2-2zm-6 9a2 2 0 1 1 0-4 2 2 0 0 1 0 4zm3.1-9H8.9V6a3.1 3.1 0 0 1 6.2 0v2z"/></svg>' : ''}</span>
        ${renderMsgActionsHtml(msg, attachments)}
      </div>
      <div class="t-body">${display}</div>
      ${renderAttachmentsHtml(attachments)}
      ${renderReactionsHtml(msg.reactions)}
    </div>
  `
  return div
}

export function appendMsgToDOM(processed: ProcessedMessage) {
  const k = processed.msg.thread_id || processed.msg.message_id || String(processed.msg.ts)
  if (k === focusedThreadKey) {
    const container = document.querySelector('#focused-thread-card .t-messages')
    if (container) {
      const outer = document.getElementById('outer')
      const distFromBottom = outer ? outer.scrollHeight - outer.scrollTop - outer.clientHeight : Infinity
      container.appendChild(createMsgEl(processed))
      if (outer && distFromBottom < 60) outer.scrollTo({ top: outer.scrollHeight, behavior: 'smooth' })
      return
    }
  }
  const savedText = (document.querySelector('#focused-thread-card textarea') as HTMLTextAreaElement)?.value ?? ''
  render()
  const ta = document.querySelector('#focused-thread-card textarea')
  if (ta && savedText) { (ta as HTMLTextAreaElement).value = savedText; autoResizeTA(ta as HTMLTextAreaElement) }
}

export function makeThreadCard(group: ThreadGroup, focused: boolean) {
  const card = document.createElement('div')
  card.className = 'thread-card' + (focused ? ' focused-card' : ' clickable')
  if (focused) { card.id = 'focused-thread-card' }

  const menuBtn = `<button class="t-menu-btn" aria-label="Menu"><svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><circle cx="12" cy="5" r="1.5"/><circle cx="12" cy="12" r="1.5"/><circle cx="12" cy="19" r="1.5"/></svg></button>`
  const hdr = group.subject
    ? `<div class="thread-header-row"><span class="thread-header">${esc(group.subject)}</span>${menuBtn}</div>`
    : `<div class="thread-header-row"><span class="thread-header untitled">no title</span>${menuBtn}</div>`

  card.innerHTML = `
    ${focused ? '' : hdr}
    <div class="t-messages"></div>
    ${focused ? `
    <div class="reply-box">
      <div class="reply-resize-handle"><span></span></div>
      <div class="reply-attachments" style="display:none"></div>
      <div class="reply-content">
        <button class="reply-compose-btn" title="New message">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/>
            <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>
          </svg>
        </button>
        <input class="reply-subject" type="text" placeholder="Subject (optional)">
        <textarea rows="1" placeholder="Reply…"></textarea>
        <button class="reply-attach-btn" type="button" title="Attach file">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/></svg>
        </button>
        <input class="reply-attach-input" type="file" multiple style="display:none">
        <div class="t-send-wrap">
          <div class="t-send-avatar"></div>
          <button class="t-send-btn">
            <svg viewBox="0 0 24 24"><path d="M2 12L22 2L12 22L10 14L2 12Z"/></svg>
          </button>
        </div>
      </div>
    </div>` : ''}
  `

  const container = card.querySelector('.t-messages') as HTMLElement
  const allMsgs = group.messages

  // Per-message Edit/Delete (delegated: allMsgs is re-populated on every
  // render, so one listener on the container covers every message, current
  // and future, without per-element attach/detach bookkeeping).
  container.addEventListener('click', async e => {
    const t = e.target as HTMLElement
    const msgEl = t.closest('.t-msg') as HTMLElement | null
    if (!msgEl) return
    const mid = msgEl.dataset.messageId
    const processed = mid ? allMsgs.find(p => p.msg.message_id === mid) : undefined

    if (t.closest('.t-msg-actions-btn')) {
      const menu = msgEl.querySelector('.t-msg-actions-menu') as HTMLElement | null
      if (menu) menu.style.display = menu.style.display === 'none' ? 'block' : 'none'
      return
    }
    if (t.closest('.t-msg-edit-btn')) {
      msgEl.querySelector('.t-msg-actions-menu')?.setAttribute('style', 'display:none')
      if (processed) enterEditMode(msgEl, processed)
      return
    }
    if (t.closest('.t-msg-delete-btn')) {
      msgEl.querySelector('.t-msg-actions-menu')?.setAttribute('style', 'display:none')
      if (processed && confirm('Delete this message for everyone?')) await sendDeleteRequest(processed)
      return
    }
    if (t.closest('.t-edit-save')) {
      const ta = msgEl.querySelector('.t-edit-ta') as HTMLTextAreaElement | null
      if (processed && ta) {
        if (!ta.value.trim()) { showSysMsg('Message cannot be empty'); return }
        await sendEditRequest(processed, ta.value)
      }
      return
    }
    if (t.closest('.t-edit-cancel')) { render(); return }
  })
  const INITIAL_COUNT = 100
  const LOAD_STEP = 100
  // Visible-count cache remembers "show older" expansions, but newly arrived
  // messages (allMsgs.length grew since the last render) must auto-extend the
  // window — otherwise a stale cache of e.g. 1 hides the message that just
  // arrived as #2 behind a "load older" button.
  const cached = threadVisibleCounts.get(group.key) ?? 0
  let visibleCount = Math.max(cached, Math.min(INITIAL_COUNT, allMsgs.length))
  visibleCount = Math.min(visibleCount, allMsgs.length)
  threadVisibleCounts.set(group.key, visibleCount)

  let renderToken = 0
  const FAST_TAIL = 20
  const CHUNK = 20
  const buildLoadOlderBtn = (remaining: number) => {
    const btn = document.createElement('button')
    btn.className = 't-load-older'
    btn.textContent = `Show older (${remaining} more)`
    btn.style.cssText = 'display:block;margin:8px auto;padding:6px 14px;border:1px solid var(--border);background:transparent;color:var(--text-dim);border-radius:14px;cursor:pointer;font-size:12px'
    btn.addEventListener('click', () => {
      visibleCount = Math.min(visibleCount + LOAD_STEP, allMsgs.length)
      threadVisibleCounts.set(group.key, visibleCount)
      const prevH = container.scrollHeight
      const outer = document.getElementById('outer')
      const prevScroll = outer?.scrollTop ?? 0
      renderVisible(false)
      if (outer) outer.scrollTop = prevScroll + (container.scrollHeight - prevH)
    })
    return btn
  }
  const renderVisible = (progressive: boolean) => {
    const myToken = ++renderToken
    container.innerHTML = ''
    const start = Math.max(0, allMsgs.length - visibleCount)
    if (start > 0) container.appendChild(buildLoadOlderBtn(start))

    if (!progressive) {
      for (let i = start; i < allMsgs.length; i++) container.appendChild(createMsgEl(allMsgs[i]))
      return
    }

    const fastN = Math.min(FAST_TAIL, allMsgs.length - start)
    const fastStart = allMsgs.length - fastN
    for (let i = fastStart; i < allMsgs.length; i++) container.appendChild(createMsgEl(allMsgs[i]))

    let cursor = fastStart - 1
    const insertAnchorIdx = start > 0 ? 1 : 0
    const renderChunk = () => {
      if (renderToken !== myToken || cursor < start) return
      const outer = document.getElementById('outer')
      const stayBottom = !!outer && (outer.scrollHeight - outer.scrollTop - outer.clientHeight < 20)
      const chunkStart = Math.max(start, cursor - CHUNK + 1)
      const frag = document.createDocumentFragment()
      for (let i = chunkStart; i <= cursor; i++) frag.appendChild(createMsgEl(allMsgs[i]))
      const ref = container.children[insertAnchorIdx] ?? null
      container.insertBefore(frag, ref)
      if (stayBottom && outer) outer.scrollTop = outer.scrollHeight
      cursor = chunkStart - 1
      if (cursor >= start) requestAnimationFrame(renderChunk)
    }
    if (cursor >= start) requestAnimationFrame(renderChunk)
  }
  renderVisible(true)

  if (focused) {
    // Send-button avatar
    const avatarEl = card.querySelector('.t-send-avatar') as HTMLElement | null
    if (avatarEl) {
      const sender = currentSenderSync()
      const ownAvatar = avatarDataUrl(sender.email)
      if (ownAvatar) {
        avatarEl.style.background = 'transparent'
        avatarEl.innerHTML = `<img src="${ownAvatar}" style="width:100%;height:100%;object-fit:cover;border-radius:50%">`
      } else {
        const initial = (sender.name[0] || sender.email[0] || '?').toUpperCase()
        avatarEl.style.background = (avatarStyle(sender.email).match(/background:([^;]+)/) ?? [])[1] || 'var(--accent)'
        avatarEl.textContent = initial
      }
    }

    const ta = card.querySelector('textarea') as HTMLTextAreaElement
    const replyBox = card.querySelector('.reply-box') as HTMLElement
    const subjectInput = card.querySelector('.reply-subject') as HTMLInputElement
    const composeBtn = card.querySelector('.reply-compose-btn') as HTMLElement
    let composeMode = false
    const replyPlaceholder = `Reply to ${currentInbox?.contact ?? ''}`
    const composePlaceholder = `New message from ${activeSession()?.account.email ?? ''}`
    ta.placeholder = replyPlaceholder
    const getReplyTo = () => {
      // Pick the genuinely latest message by timestamp (array order is not
      // reliably ts-sorted after incremental sync).
      const candidates = group.messages
        .filter(p => !p.pending && p.msg.message_id && !p.msg.message_id.startsWith('__pending_'))
        .sort((a, b) => a.msg.ts - b.msg.ts)
      return candidates.length ? candidates[candidates.length - 1].msg.message_id : ''
    }
    const resizeHandle = replyBox.querySelector('.reply-resize-handle') as HTMLElement
    const replyContent = replyBox.querySelector('.reply-content') as HTMLElement
    const sendWrap = card.querySelector('.t-send-wrap') as HTMLElement
    const attachBtn = replyBox.querySelector('.reply-attach-btn') as HTMLElement
    const attachInput = replyBox.querySelector('.reply-attach-input') as HTMLInputElement
    const attachmentsRow = replyBox.querySelector('.reply-attachments') as HTMLElement

    // Attachments (DeltaChat-compatible multipart, mail relay only — no
    // JMAP-native blob path for AP, see src/pgp/crypto.ts buildMultipartBody).
    let pendingAttachments: OutgoingAttachment[] = []
    const isApThread = isApRelay(currentInbox?.relay)
    if (isApThread) attachBtn.style.display = 'none'
    const renderPendingAttachments = () => {
      attachmentsRow.style.display = pendingAttachments.length ? 'flex' : 'none'
      attachmentsRow.innerHTML = pendingAttachments.map((a, i) => `
        <span class="reply-attachment-chip" data-idx="${i}">
          <span class="reply-attachment-name">${esc(a.filename)}</span>
          <button type="button" class="reply-attachment-remove" data-idx="${i}" aria-label="Remove">×</button>
        </span>
      `).join('')
      syncDockPosition()
    }
    attachmentsRow.addEventListener('click', e => {
      const btn = (e.target as HTMLElement).closest('.reply-attachment-remove') as HTMLElement | null
      if (!btn) return
      const idx = Number(btn.dataset.idx)
      pendingAttachments.splice(idx, 1)
      renderPendingAttachments()
    })
    attachBtn.addEventListener('click', () => attachInput.click())
    attachInput.addEventListener('change', async () => {
      const files = Array.from(attachInput.files ?? [])
      attachInput.value = ''
      for (const f of files) {
        const bytes = new Uint8Array(await f.arrayBuffer())
        pendingAttachments.push({ filename: f.name, contentType: f.type, bytes })
      }
      renderPendingAttachments()
    })

    const enterCompose = () => {
      const rowTop = document.createElement('div')
      rowTop.className = 'reply-row-top'
      rowTop.append(composeBtn, subjectInput, attachBtn, attachInput, sendWrap)
      const rowBottom = document.createElement('div')
      rowBottom.className = 'reply-row-bottom'
      rowBottom.append(ta)
      replyContent.innerHTML = ''
      replyContent.append(rowTop, rowBottom)
      subjectInput.focus()
    }
    const exitCompose = () => {
      replyContent.innerHTML = ''
      replyContent.append(composeBtn, ta, attachBtn, attachInput, sendWrap)
      ta.focus()
    }

    const resetTA = () => {
      delete ta.dataset.dragged
      ta.style.height = 'auto'
      ta.rows = 1
      syncDockPosition()
    }
    const sendFn = () => {
      const attachmentsToSend = pendingAttachments
      pendingAttachments = []
      renderPendingAttachments()
      if (composeMode) {
        const subj = subjectInput.value.trim()
        sendReply(ta, subj, '', attachmentsToSend)
        subjectInput.value = ''
        composeMode = false
        replyBox.classList.remove('compose-mode')
        ta.placeholder = replyPlaceholder
        exitCompose()
      } else {
        sendReply(ta, group.subject, getReplyTo(), attachmentsToSend)
      }
      resetTA()
    }
    const applyDragH = (h: number) => {
      const lineH = parseFloat(getComputedStyle(ta).lineHeight) || 21
      ta.style.height = Math.max(lineH + 8, Math.min(window.innerHeight * 0.8, h)) + 'px'
      const outer = document.getElementById('outer')
      const dock = document.getElementById('reply-dock')
      if (outer && dock) outer.style.paddingBottom = dock.offsetHeight + 'px'
    }
    resizeHandle.addEventListener('mousedown', e => {
      e.preventDefault()
      const startY = e.clientY
      const startH = ta.getBoundingClientRect().height
      ta.dataset.dragged = '1'
      const onMove = (ev: MouseEvent) => applyDragH(startH + startY - ev.clientY)
      const onUp = () => { document.removeEventListener('mousemove', onMove); document.removeEventListener('mouseup', onUp) }
      document.addEventListener('mousemove', onMove)
      document.addEventListener('mouseup', onUp)
    })
    resizeHandle.addEventListener('touchstart', e => {
      e.preventDefault()
      const startY = e.touches[0].clientY
      const startH = ta.getBoundingClientRect().height
      ta.dataset.dragged = '1'
      const onMove = (ev: TouchEvent) => applyDragH(startH + startY - ev.touches[0].clientY)
      const onEnd = () => { document.removeEventListener('touchmove', onMove); document.removeEventListener('touchend', onEnd) }
      document.addEventListener('touchmove', onMove, { passive: false })
      document.addEventListener('touchend', onEnd)
    }, { passive: false })
    composeBtn.addEventListener('mouseenter', () => { if (!composeMode) ta.placeholder = composePlaceholder })
    composeBtn.addEventListener('mouseleave', () => { if (!composeMode) ta.placeholder = replyPlaceholder })
    composeBtn.addEventListener('click', () => {
      composeMode = !composeMode
      replyBox.classList.toggle('compose-mode', composeMode)
      ta.placeholder = composeMode ? composePlaceholder : replyPlaceholder
      if (composeMode) { enterCompose() } else { exitCompose() }
    })
    sendWrap.querySelector('.t-send-btn')!.addEventListener('click', sendFn)
    ta.addEventListener('keydown', e => {
      if (e.key === 'Enter' && !e.isComposing && (e.metaKey || e.ctrlKey)) {
        e.preventDefault(); sendFn()
      }
      if (e.key === 'ArrowLeft' && ta.selectionStart === 0 && ta.selectionEnd === 0) {
        e.preventDefault()
        document.getElementById('lp-search')?.focus()
      }
    })
    ta.addEventListener('input', () => {
      if (!ta.dataset.dragged) autoResizeTA(ta)
      syncDockPosition()
    })
  } else {
    card.addEventListener('click', e => {
      if ((e.target as HTMLElement).closest('.t-menu-btn')) return
      setFocusedThreadKey(group.key)
      render()
      ;(document.querySelector('#focused-thread-card textarea') as HTMLElement)?.focus()
    })
  }

  return card
}

export function updateScrollSpacer() {
  const outer = document.getElementById('outer')
  const active = document.getElementById('active-thread')
  const titleRow = document.getElementById('thread-title-row')
  const spacer = document.getElementById('scroll-spacer')
  if (!outer || !active || !spacer) return
  const convMeta = document.getElementById('conv-meta')
  const titleH = (titleRow && outer.contains(titleRow) ? titleRow.offsetHeight : 0) + (convMeta ? convMeta.offsetHeight : 0)
  const dock = document.getElementById('reply-dock')
  const dockH = dock ? dock.offsetHeight : 0
  const clientH = outer.clientHeight || window.innerHeight
  const needed = clientH - titleH - active.offsetHeight - dockH
  spacer.style.height = needed > 0 ? needed + 'px' : '0'
}

export function scrollToBottomIfNear() {
  const outer = document.getElementById('outer')
  if (!outer) return
  updateScrollSpacer()
  const pb = parseFloat(outer.style.paddingBottom) || 0
  if (outer.scrollHeight - pb <= outer.clientHeight + 1) return
  const dist = outer.scrollHeight - outer.scrollTop - outer.clientHeight
  if (dist < 60) {
    markProgrammaticScroll()
    outer.scrollTo({ top: outer.scrollHeight, behavior: 'smooth' })
  }
}

export function scrollToFocused(smooth = false) {
  const doScroll = () => {
    updateScrollSpacer()
    const outer = document.getElementById('outer')
    if (!outer) return
    const msgs = outer.querySelectorAll('.t-msg')
    let target: number
    const past = document.getElementById('past-threads')
    const pastH = past && outer.contains(past) ? past.offsetHeight : 0
    // #reply-dock is position:fixed, so it doesn't shrink #outer's own
    // clientHeight — the bottom dockH px of "visible" area is actually
    // covered by it. Not accounting for that let the last message's tail
    // land exactly in the zone the dock covers (visible only as a blurred
    // sliver through its frosted background). Stowed (dock-hidden, see
    // main.ts's scroll handler) doesn't cover anything, so it doesn't count.
    const dock = document.getElementById('reply-dock')
    const dockH = dock && !dock.classList.contains('dock-hidden') ? dock.offsetHeight : 0
    const safeHeight = outer.clientHeight - dockH
    if (msgs.length > 0) {
      const last = msgs[msgs.length - 1] as HTMLElement
      const lastRect = last.getBoundingClientRect()
      const outerRect = outer.getBoundingClientRect()
      const lastTopInOuter = lastRect.top - outerRect.top + outer.scrollTop
      const titleRow = document.getElementById('thread-title-row')
      // Only #thread-title-row is position:sticky (style.css) — it's the only
      // thing that visually overlays scrolled-under content, so it's the only
      // height that needs compensating here. #conv-meta scrolls away normally;
      // including its height under-scrolled by that amount, leaving a sliver
      // of the previous message visible above the "focused" one.
      const titleH = titleRow && outer.contains(titleRow) ? titleRow.offsetHeight : 0
      if (lastTopInOuter >= pastH + safeHeight) {
        // Doesn't fit even in the dock-safe area — pin its top just below the
        // header (matches the "message itself taller than the viewport"
        // exception; its tail necessarily stays out of view either way).
        target = lastTopInOuter - titleH
      } else {
        // Fits without pinning the top, but plain pastH can still leave the
        // tail behind the dock if content only *just* fits within clientHeight
        // (not clientHeight - dockH) — scroll further when that's the case.
        const lastBottomInOuter = lastTopInOuter + last.offsetHeight
        target = Math.max(pastH, lastBottomInOuter - safeHeight)
      }
    } else {
      target = pastH
    }
    markProgrammaticScroll()
    if (smooth) {
      outer.scrollTo({ top: target, behavior: 'smooth' })
    } else {
      outer.scrollTop = target
    }
  }
  requestAnimationFrame(() => requestAnimationFrame(doScroll))
}

export function syncDockPosition() {
  const pane = document.getElementById('right-pane')
  if (!pane) return
  const dock = document.getElementById('reply-dock')
  if (dock) {
    requestAnimationFrame(() => {
      const outer = document.getElementById('outer')
      if (outer) outer.style.paddingBottom = dock.offsetHeight ? dock.offsetHeight + 'px' : '0'
      document.documentElement.style.setProperty('--dock-h', dock.offsetHeight ? dock.offsetHeight + 'px' : '0px')
      const titleRow = document.getElementById('thread-title-row')
      if (titleRow) document.documentElement.style.setProperty('--thread-title-h', titleRow.offsetHeight + 'px')
    })
  }
}

export function fmtRelDate(ts: number) {
  const d = new Date(ts)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}/${pad(d.getMonth()+1)}/${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`
}

export function makePastRow(g: ThreadGroup) {
  const $menu = document.getElementById('menu')
  const lastMsg = g.messages[g.messages.length - 1]
  const row = document.createElement('div')
  row.className = 'past-row'
  const titleClass = g.subject ? 'past-row-title' : 'past-row-title untitled'
  const titleText = g.subject ? esc(g.subject) : 'no title'
  const hdr = document.createElement('div')
  hdr.className = 'past-row-header'
  hdr.innerHTML = `<span class="${titleClass}">${titleText}</span><span class="past-row-time-wrap"><span class="past-row-date">${fmtRelDate(lastMsg.msg.ts)}</span></span>`
  hdr.addEventListener('click', () => {
    setFocusedThreadKey(g.key)
    render(true)
    ;(document.querySelector('#focused-thread-card textarea') as HTMLElement)?.focus()
  })
  row.appendChild(hdr)
  return row
}

export function render(smooth = false, keepScroll = false) {
  if (inMenuMode()) return
  const $past = document.getElementById('past-threads')
  const $active = document.getElementById('active-thread')
  if (!$past || !$active) return
  $past.innerHTML = ''
  $active.innerHTML = ''

  const $lpHamburger = document.getElementById('lp-hamburger')
  if (!currentInbox) {
    const dock = document.getElementById('reply-dock')
    if (dock) dock.innerHTML = ''
    const outer = document.getElementById('outer')
    if (outer) outer.style.paddingBottom = '0'
    const el = document.createElement('div')
    el.style.cssText = 'position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);display:flex;flex-direction:column;align-items:center;color:var(--text-dim);'
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg')
    svg.setAttribute('width', '40'); svg.setAttribute('height', '40'); svg.setAttribute('viewBox', '0 0 24 24')
    svg.setAttribute('fill', 'none'); svg.setAttribute('stroke', 'currentColor'); svg.setAttribute('stroke-width', '1.5'); svg.setAttribute('opacity', '0.3')
    svg.innerHTML = '<path d="M4 4h16v13H4z"/><path d="M4 4l8 8 8-8"/>'
    el.appendChild(svg)
    $active.appendChild(el)
    return
  }
  if ($lpHamburger) $lpHamburger.style.display = ''

  const groups = groupMessages()
  if (!groups.length) {
    const fakeGroup = { key: '__empty__', subject: '', messages: [] }
    const fullCard = makeThreadCard(fakeGroup, true)
    $active.appendChild(fullCard)
    const replyBox = document.querySelector('#focused-thread-card .reply-box')
    const dock = document.getElementById('reply-dock')
    if (replyBox && dock) {
      dock.innerHTML = ''
      dock.appendChild(replyBox)
      syncDockPosition()
      requestAnimationFrame(() => {
        const outer = document.getElementById('outer')
        if (outer) outer.style.paddingBottom = dock.offsetHeight + 'px'
      })
    }
    return
  }

  if (focusedThreadKey === null || !groups.find(g => g.key === focusedThreadKey)) {
    setFocusedThreadKey(latestGroup(groups).key)
  }

  const focused = groups.find(g => g.key === focusedThreadKey)!

  const others = groups
    .filter(g => g.key !== focusedThreadKey)
    .sort((a, b) => a.messages[a.messages.length - 1].msg.ts - b.messages[b.messages.length - 1].msg.ts)

  for (const g of others) $past.appendChild(makePastRow(g))

  const $headerTitle = document.getElementById('header-thread-title')
  const $groupIcon = document.getElementById('header-group-icon')
  if ($headerTitle) {
    $headerTitle.textContent = focused.subject || 'no title'
    $headerTitle.className = focused.subject ? '' : 'untitled'
  }
  if ($groupIcon) $groupIcon.style.display = 'none'

  const $convTo = document.getElementById('conv-to')
  const $convCc = document.getElementById('conv-cc')
  const $convBcc = document.getElementById('conv-bcc')
  if ($convTo) {
    const contact = currentInbox?.contact ?? ''
    const via = $convTo.querySelector('#conv-via') as HTMLElement | null
    $convTo.textContent = contact
    if (via) {
      // Protocol pill (left of the recipient) derived from the conversation's
      // origin relay. Label is the transport, not the relay binary name.
      const lbl = relayProtocolLabel(currentInbox?.relay)
      if (lbl) {
        via.textContent = lbl.text
        via.style.cssText = `font-size:10px;font-weight:700;color:#fff;background:${lbl.color};border-radius:4px;padding:1px 5px;margin-right:6px;flex-shrink:0`
      } else {
        via.textContent = ''
        via.style.cssText = ''
      }
      $convTo.prepend(via)
    }
    if ($convCc) $convCc.textContent = ''
    if ($convBcc) $convBcc.textContent = ''
  }

  const $convMeta = document.getElementById('conv-meta')
  const $expanded = document.getElementById('conv-meta-expanded')
  if ($convMeta) {
    $convMeta.classList.remove('expanded')
    if ($expanded) {
      const buildRaw = () => {
        const lines: string[] = []
        const firstMsg = focused?.messages?.[0]?.msg
        if (firstMsg?.message_id) lines.push('message-id: ' + firstMsg.message_id)
        if (firstMsg?.in_reply_to) lines.push('in-reply-to: ' + firstMsg.in_reply_to)
        if (firstMsg?.subject) lines.push('subject: ' + firstMsg.subject)
        if (firstMsg?.ts) lines.push('date: ' + new Date(firstMsg.ts).toISOString())
        const froms = [...new Set(focused?.messages?.map(p => p.msg.from) || [])]
        if (froms.length) lines.push('participants: ' + froms.join(', '))
        const allTo = [...new Set(focused?.messages?.flatMap(p => p.msg.to_addrs || []) || [])]
        if (allTo.length) lines.push('to: ' + allTo.join(', '))
        lines.push('inbox: ' + JSON.stringify(currentInbox))
        lines.push('thread_id: ' + (focusedThreadKey || ''))
        lines.push('messages: ' + (focused?.messages?.length || 0))
        return lines.join('\n')
      }
      $expanded.textContent = buildRaw()
    }
    const $convFields = document.getElementById('conv-fields')
    if ($convFields) $convFields.onclick = () => $convMeta.classList.toggle('expanded')
  }

  $active.appendChild(makeThreadCard(focused, true))

  const replyBox = document.querySelector('#focused-thread-card .reply-box')
  const dock = document.getElementById('reply-dock')
  if (replyBox && dock) {
    dock.innerHTML = ''
    dock.appendChild(replyBox)
    syncDockPosition()
    requestAnimationFrame(() => {
      const outer = document.getElementById('outer')
      if (outer) outer.style.paddingBottom = dock.offsetHeight + 'px'
      if (!keepScroll) scrollToFocused(smooth)
      else scrollToBottomIfNear()
    })
  } else if (dock) {
    dock.innerHTML = ''
    const outer = document.getElementById('outer')
    if (outer) outer.style.paddingBottom = ''
    requestAnimationFrame(() => keepScroll ? scrollToBottomIfNear() : scrollToFocused(smooth))
  } else {
    requestAnimationFrame(() => keepScroll ? scrollToBottomIfNear() : scrollToFocused(smooth))
  }
  renderThreadAccordion()
}

export function autoResizeTA(ta: HTMLTextAreaElement) {
  ta.style.height = 'auto'
  ta.style.height = ta.scrollHeight + 'px'
}
