import { currentInbox, activeSession, relayInfoFor } from '../context.ts'
import {
  processedMessages, renderedKeys,
  focusedThreadKey, setFocusedThreadKey,
  groupMessages, latestGroup,
  lastLeftInboxes,
} from '../state.ts'
import type { ProcessedMessage, ThreadGroup } from '../state.ts'
import { esc, linkify, formatTime, avatarStyle, stripQuoted } from '../utils.ts'
import { avatarDataUrl } from '../deltachat/avatar.ts'
import { processIncoming } from '../processing.ts'
// Circular imports — used only inside function bodies, safe:
import { sendReply, showSysMsg } from './shell.ts'
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

export async function addMessage(msg: ProcessedMessage['msg']): Promise<boolean> {
  const key = `${msg.from}:${msg.ts}`
  if (renderedKeys.has(key)) return false
  renderedKeys.add(key)

  const { bodyText, encrypted, unreadable } = await processIncoming(
    msg, activeSession()?.account.email ?? '', processedMessages
  )

  processedMessages.push({ msg, bodyText, encrypted, unreadable })

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

export function createMsgEl({ msg, bodyText, encrypted, unreadable, pending }: ProcessedMessage) {
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
  div.innerHTML = `
    <div class="t-avatar" style="${senderAvatarURL ? 'background:transparent' : avatarStyle(msg.from)}">${senderAvatarURL ? `<img src="${senderAvatarURL}" style="width:100%;height:100%;object-fit:cover;border-radius:50%;">` : senderName.charAt(0).toUpperCase()}</div>
    <div class="t-meta">
      <div class="t-hdr">
        <span class="t-sender">${esc(senderName)}</span>
        <span class="t-time">${formatTime(msg.ts)}${encrypted ? ' <svg style="vertical-align:middle;opacity:0.6" width="11" height="11" viewBox="0 0 24 24" fill="currentColor"><path d="M18 8h-1V6A5 5 0 0 0 7 6v2H6a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V10a2 2 0 0 0-2-2zm-6 9a2 2 0 1 1 0-4 2 2 0 0 1 0 4zm3.1-9H8.9V6a3.1 3.1 0 0 1 6.2 0v2z"/></svg>' : ''}</span>
      </div>
      <div class="t-body">${display}</div>
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
      <div class="reply-content">
        <button class="reply-compose-btn" title="New message">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/>
            <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>
          </svg>
        </button>
        <input class="reply-subject" type="text" placeholder="Subject (optional)">
        <textarea rows="1" placeholder="Reply…"></textarea>
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

    const enterCompose = () => {
      const rowTop = document.createElement('div')
      rowTop.className = 'reply-row-top'
      rowTop.append(composeBtn, subjectInput, sendWrap)
      const rowBottom = document.createElement('div')
      rowBottom.className = 'reply-row-bottom'
      rowBottom.append(ta)
      replyContent.innerHTML = ''
      replyContent.append(rowTop, rowBottom)
      subjectInput.focus()
    }
    const exitCompose = () => {
      replyContent.innerHTML = ''
      replyContent.append(composeBtn, ta, sendWrap)
      ta.focus()
    }

    const resetTA = () => {
      delete ta.dataset.dragged
      ta.style.height = 'auto'
      ta.rows = 1
      syncDockPosition()
    }
    const sendFn = () => {
      if (composeMode) {
        const subj = subjectInput.value.trim()
        sendReply(ta, subj, '')
        subjectInput.value = ''
        composeMode = false
        replyBox.classList.remove('compose-mode')
        ta.placeholder = replyPlaceholder
        exitCompose()
      } else {
        sendReply(ta, group.subject, getReplyTo())
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
  if (dist < 60) outer.scrollTo({ top: outer.scrollHeight, behavior: 'smooth' })
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
    if (msgs.length > 0) {
      const last = msgs[msgs.length - 1] as HTMLElement
      const lastRect = last.getBoundingClientRect()
      const outerRect = outer.getBoundingClientRect()
      const lastTopInOuter = lastRect.top - outerRect.top + outer.scrollTop
      const titleRow = document.getElementById('thread-title-row')
      const convMeta = document.getElementById('conv-meta')
      const titleH = (titleRow && outer.contains(titleRow) ? titleRow.offsetHeight : 0) + (convMeta ? convMeta.offsetHeight : 0)
      if (lastTopInOuter >= pastH + outer.clientHeight) {
        target = lastTopInOuter - titleH
      } else {
        target = pastH
      }
    } else {
      target = pastH
    }
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
