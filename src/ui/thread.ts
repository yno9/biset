// Ported at the rendering-logic level from src.bak/ui/thread.ts (1107 lines),
// cut down to what PLAN.md §7's read-only inbox first slice needs: message
// bubbles, the thread accordion (focused thread + past-threads list), and the
// scroll mechanics that keep a reader's position stable while it renders.
// Field names on MailMessageView (src/mail/message-view.ts) intentionally
// match the old ProcessedMessage['msg'] shape, so this logic ports with the
// import list changed and little else.
//
// Left out (all present in the pre-rewrite version, none ported yet):
//   - compose/reply (the reply-box, sendReply/sendEditRequest/sendDeleteRequest,
//     the attach/drag-resize/compose-mode machinery) -- send is out of scope
//     for a read-only slice (PLAN.md §7 plan).
//   - message actions: edit/delete-for-everyone, the "..." menu, PGP
//     encrypted/unreadable states, RFC 9078 reactions, attachments (image
//     lightbox / file chips), the edited-label patch path in addMessage --
//     all DeltaChat/PGP-relay concerns this rewrite's local-vault mail
//     doesn't have (mail is already plaintext at the vault layer).
//   - multi-relay/DID context: currentInbox/activeSession/isApRelay/
//     relayProtocolLabel (context.ts), contact display-name/DID resolution
//     (did/contacts.ts), MLS group-member chips -- this slice reads one
//     identity's one local vault, not a multi-relay session set.
//   - the reply-dock height/padding sync (syncDockPosition) -- there is no
//     dock in this slice, so scroll math needs none of that geometry.
import { emailToMessageView, groupMessages, latestGroup, processedMessages } from '../mail/message-view.ts'
import type { MailMessageView, ProcessedMessage, ThreadGroup } from '../mail/message-view.ts'
import { avatarStyle, esc, formatTime, linkify, stripQuoted } from './format.ts'
import type { LocalJmapReadModel } from '../local-jmap/gateway.ts'

let focusedThreadKey: string | null = null

export function setFocusedThreadKey(k: string | null): void { focusedThreadKey = k }
export function getFocusedThreadKey(): string | null { return focusedThreadKey }

const threadVisibleCounts = new Map<string, number>()

/** Replaces the whole message set from a fresh snapshot -- this slice has no
 * incremental sync yet, so a refresh is a full reload, not a merge. */
export async function loadMessages(readModel: LocalJmapReadModel): Promise<void> {
  const snapshot = await readModel.snapshot()
  const inbox = snapshot.emails.filter(email => email.mailboxIds.inbox === true)
  const views: ProcessedMessage[] = []
  for (const email of inbox) {
    if (!email.blobId) continue
    const raw = await readModel.download(email.blobId)
    const msg = emailToMessageView(email, raw)
    views.push({ msg, bodyText: msg.body })
  }
  processedMessages.length = 0
  processedMessages.push(...views)
}

export function createMsgEl({ msg, bodyText }: ProcessedMessage): HTMLElement {
  const div = document.createElement('div')
  div.className = 't-msg'
  const senderName = msg.from_name || msg.from || '?'
  div.dataset.messageId = msg.message_id
  div.innerHTML = `
    <div class="t-avatar" style="${avatarStyle(msg.from || senderName)}">${senderName.charAt(0).toUpperCase()}</div>
    <div class="t-meta">
      <div class="t-hdr">
        <span class="t-sender">${esc(senderName)}</span>
        <span class="t-time">${formatTime(msg.ts)}</span>
      </div>
      <div class="t-body">${linkify(esc(stripQuoted(bodyText)))}</div>
    </div>
  `
  return div
}

export function makeThreadCard(group: ThreadGroup, focused: boolean): HTMLElement {
  const card = document.createElement('div')
  card.className = 'thread-card' + (focused ? ' focused-card' : ' clickable')
  if (focused) card.id = 'focused-thread-card'

  const hdr = group.subject
    ? `<div class="thread-header-row"><span class="thread-header">${esc(group.subject)}</span></div>`
    : `<div class="thread-header-row"><span class="thread-header untitled">no title</span></div>`

  card.innerHTML = `${focused ? '' : hdr}<div class="t-messages"></div>`

  const container = card.querySelector('.t-messages') as HTMLElement
  const allMsgs = group.messages

  const INITIAL_COUNT = 100
  const LOAD_STEP = 100
  const cached = threadVisibleCounts.get(group.key) ?? 0
  let visibleCount = Math.max(cached, Math.min(INITIAL_COUNT, allMsgs.length))
  visibleCount = Math.min(visibleCount, allMsgs.length)
  threadVisibleCounts.set(group.key, visibleCount)

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
      renderVisible()
      if (outer) outer.scrollTop = prevScroll + (container.scrollHeight - prevH)
    })
    return btn
  }
  const renderVisible = () => {
    container.innerHTML = ''
    const start = Math.max(0, allMsgs.length - visibleCount)
    if (start > 0) container.appendChild(buildLoadOlderBtn(start))
    for (let i = start; i < allMsgs.length; i++) container.appendChild(createMsgEl(allMsgs[i]!))
  }
  renderVisible()

  if (!focused) {
    card.addEventListener('click', () => {
      setFocusedThreadKey(group.key)
      render()
    })
  }

  return card
}

function topFloor(outer: HTMLElement): number {
  const past = document.getElementById('past-threads')
  return past && outer.contains(past) ? past.offsetHeight : 0
}

const THREAD_BOTTOM_GAP = 14

function updateScrollSpacer(): void {
  const outer = document.getElementById('outer')
  const spacer = document.getElementById('scroll-spacer')
  if (!outer || !spacer) return
  spacer.style.height = '0'
  const floor = topFloor(outer)
  const overflow = outer.scrollHeight - outer.clientHeight
  spacer.style.height = (overflow <= floor ? floor - overflow : THREAD_BOTTOM_GAP) + 'px'
}

const NEAR_BOTTOM = 60

function scrollToEnd(outer: HTMLElement, behavior: ScrollBehavior = 'smooth'): void {
  if (outer.scrollHeight <= outer.clientHeight + 1) return
  outer.scrollTo({ top: outer.scrollHeight, behavior })
}

function scrollToFocused(smooth = false): void {
  const doScroll = () => {
    updateScrollSpacer()
    const outer = document.getElementById('outer')
    if (!outer) return
    let target = outer.scrollHeight - outer.clientHeight
    const msgs = outer.querySelectorAll('.t-msg')
    const last = msgs[msgs.length - 1] as HTMLElement | undefined
    if (last) {
      const titleRow = document.getElementById('thread-title-row')
      const titleH = titleRow && outer.contains(titleRow) ? titleRow.offsetHeight : 0
      const stickyTop = titleRow ? parseFloat(getComputedStyle(titleRow).top) || 0 : 0
      const viewTop = titleH + stickyTop
      if (last.offsetHeight > outer.clientHeight - viewTop) {
        const lastTopInOuter = last.getBoundingClientRect().top - outer.getBoundingClientRect().top + outer.scrollTop
        target = Math.max(topFloor(outer), lastTopInOuter - viewTop)
      }
    }
    if (smooth) outer.scrollTo({ top: target, behavior: 'smooth' })
    else outer.scrollTop = target
  }
  requestAnimationFrame(() => requestAnimationFrame(doScroll))
}

function fmtRelDate(ts: number): string {
  const d = new Date(ts)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}/${pad(d.getMonth() + 1)}/${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`
}

function makePastRow(g: ThreadGroup): HTMLElement {
  const lastMsg = g.messages[g.messages.length - 1]!
  const row = document.createElement('div')
  row.className = 'past-row'
  const titleClass = g.subject ? 'past-row-title' : 'past-row-title untitled'
  const titleText = g.subject ? esc(g.subject) : 'no title'
  const hdr = document.createElement('div')
  hdr.className = 'past-row-header'
  hdr.innerHTML = `<span class="${titleClass}">${titleText}</span><span class="past-row-time-wrap"><span class="past-row-date">${fmtRelDate(lastMsg.msg.ts)}</span></span>`
  hdr.addEventListener('click', () => {
    setFocusedThreadKey(g.key)
    render()
  })
  row.appendChild(hdr)
  return row
}

function participantsOf(msgs: MailMessageView[]): string {
  return [...new Set(msgs.map(m => m.from).filter(Boolean))].join(', ')
}

export function render(smooth = false): void {
  const $past = document.getElementById('past-threads')
  const $active = document.getElementById('active-thread')
  if (!$past || !$active) return
  $past.innerHTML = ''
  $active.innerHTML = ''

  const groups = groupMessages()
  if (!groups.length) {
    const $emptyTitle = document.getElementById('header-thread-title')
    if ($emptyTitle) { $emptyTitle.textContent = 'no title'; $emptyTitle.className = 'untitled' }
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

  if (focusedThreadKey === null || !groups.find(g => g.key === focusedThreadKey)) {
    setFocusedThreadKey(latestGroup(groups).key)
  }
  const focused = groups.find(g => g.key === focusedThreadKey)!
  const others = groups
    .filter(g => g.key !== focusedThreadKey)
    .sort((a, b) => a.messages[a.messages.length - 1]!.msg.ts - b.messages[b.messages.length - 1]!.msg.ts)
  for (const g of others) $past.appendChild(makePastRow(g))

  const $headerTitle = document.getElementById('header-thread-title')
  if ($headerTitle) {
    $headerTitle.textContent = focused.subject || 'no title'
    $headerTitle.className = focused.subject ? '' : 'untitled'
  }

  const $convTo = document.getElementById('conv-to')
  if ($convTo) $convTo.textContent = participantsOf(focused.messages.map(p => p.msg))

  const $convMeta = document.getElementById('conv-meta')
  const $expanded = document.getElementById('conv-meta-expanded')
  if ($convMeta) {
    $convMeta.classList.remove('expanded')
    if ($expanded) {
      const firstMsg = focused.messages[0]?.msg
      const lines: string[] = []
      if (firstMsg?.message_id) lines.push('message-id: ' + firstMsg.message_id)
      if (firstMsg?.in_reply_to) lines.push('in-reply-to: ' + firstMsg.in_reply_to)
      if (firstMsg?.subject) lines.push('subject: ' + firstMsg.subject)
      if (firstMsg?.ts) lines.push('date: ' + new Date(firstMsg.ts).toISOString())
      lines.push('participants: ' + participantsOf(focused.messages.map(p => p.msg)))
      lines.push('thread_id: ' + (focusedThreadKey || ''))
      lines.push('messages: ' + focused.messages.length)
      $expanded.textContent = lines.join('\n')
    }
    const $convFields = document.getElementById('conv-fields')
    if ($convFields) $convFields.onclick = () => $convMeta.classList.toggle('expanded')
  }

  $active.appendChild(makeThreadCard(focused, true))
  requestAnimationFrame(() => scrollToFocused(smooth))
}
