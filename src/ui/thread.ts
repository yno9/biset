// Ported at the rendering-logic level from src.bak/ui/thread.ts (1107 lines),
// cut down to what PLAN.md §7 needs: message bubbles, the thread accordion
// (focused thread + past-threads list), the scroll mechanics that keep a
// reader's position stable while it renders, and (compose slice 1) a
// minimal reply box on the focused thread. Field names on MailMessageView
// (src/mail/message-view.ts) intentionally match the old
// ProcessedMessage['msg'] shape, so this logic ports with the import list
// changed and little else.
//
// Left out (all present in the pre-rewrite version, none ported yet):
//   - starting a brand-new conversation (recipient picker, the
//     reply-compose-btn mode toggle), sendEditRequest/sendDeleteRequest, the
//     attach/drag-resize machinery, and the optimistic pending-echo bubble
//     -- reply-only, send-then-refresh is compose slice 1's explicit scope
//     (PLAN.md §7 plan).
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
//     resizable dock in this slice, so scroll math needs none of that
//     geometry.
import { computeReplyContext, emailToMessageView, groupMessages, latestGroup, processedMessages } from '../mail/message-view.ts'
import type { MailMessageView, ProcessedMessage, ThreadGroup } from '../mail/message-view.ts'
import { avatarStyle, esc, formatTime, linkify, stripQuoted } from './format.ts'
import type { LocalJmapReadModel } from '../local-jmap/gateway.ts'
import { shortWebvhDid, labelForDid, protocolFor, PROTO_COLOR, PROTO_TEXT } from './did-display.ts'
import type { Proto } from './did-display.ts'

/**
 * Compose's send path lives in main.ts (it needs the vault mutation sink,
 * the crypto boundary, and the outbound transport, none of which this
 * rendering module otherwise depends on). thread.ts stays decoupled from
 * all of that by taking a single injected callback instead -- also sidesteps
 * an import cycle, since shell.ts already imports FROM this module.
 */
export interface ReplySendInput {
  toAddrs: string[]
  subject: string
  body: string
  inReplyTo?: string
  references?: string[]
}

export interface ComposeConfig {
  /** This identity's own mail address, excluded from a reply's toAddrs. */
  selfAddress: string
  /** This identity's own DID, when DIDComm is enabled -- also excluded, so a
   * DIDComm thread's reply doesn't mistake this device's own DID for a
   * recipient (computeReplyContext's own note explains why that mattered). */
  selfDid?: string
  sendReply(input: ReplySendInput): Promise<void>
  onError?(message: string): void
}

let composeConfig: ComposeConfig | undefined

export function configureCompose(config: ComposeConfig): void {
  composeConfig = config
}

let focusedThreadKey: string | null = null

export function setFocusedThreadKey(k: string | null): void { focusedThreadKey = k }
export function getFocusedThreadKey(): string | null { return focusedThreadKey }

const threadVisibleCounts = new Map<string, number>()

/** Replaces the whole message set from a fresh snapshot -- this slice has no
 * incremental sync yet, so a refresh is a full reload, not a merge. Every
 * locally-committed message is shown regardless of mailbox: there is no
 * folder/trash/spam concept yet, and a sent reply lives in outbox then sent,
 * never inbox, so filtering to inbox would make it vanish after sending. */
export async function loadMessages(readModel: LocalJmapReadModel): Promise<void> {
  const snapshot = await readModel.snapshot()
  const views: ProcessedMessage[] = []
  for (const email of snapshot.emails) {
    if (!email.blobId) continue
    const raw = await readModel.download(email.blobId)
    const msg = emailToMessageView(email, raw)
    views.push({ msg, bodyText: msg.body })
  }
  processedMessages.length = 0
  processedMessages.push(...views)
}

// Ported verbatim from src.bak/ui/thread.ts (PLAN-mimi.md §4.5/§4.3):
// Conversation Group reactions/edits, one t-reaction-chip per reactor (no
// count-collapsing -- each reactor's own emoji stays its own chip) and an
// "edited" label next to the timestamp. Attachments and the msg-actions
// menu stay out of scope (this file's own header comment).
function renderReactionsHtml(reactions: MailMessageView['reactions']): string {
  if (!reactions?.length) return ''
  return `<div class="t-reactions">${reactions.map(r =>
    `<span class="t-reaction-chip" title="${esc(r.from)}">${esc(r.emoji)}</span>`
  ).join('')}</div>`
}

export function createMsgEl({ msg, bodyText }: ProcessedMessage): HTMLElement {
  const div = document.createElement('div')
  div.className = 't-msg'
  // A DIDComm message's own from/from_name is always the raw DID. Per-
  // message sender labels use the bare username (labelForDid: "d157"), not
  // the fuller did:webvh:d157.biset.md form -- that longer form is for the
  // ONE-per-thread header pill (displayParticipantsOf below), where it
  // isn't repeated on every single message the way a bubble's sender name
  // is (found live, 2026-08-25: showed the whole DID; 2026-08-26: briefly
  // used the long form here too, corrected -- the long/short split is by
  // "how often does this repeat on screen", not one rule everywhere).
  const rawSenderName = msg.from_name || msg.from || '?'
  const senderName = rawSenderName.startsWith('did:') ? labelForDid(rawSenderName) : rawSenderName
  div.dataset.messageId = msg.message_id
  div.innerHTML = `
    <div class="t-avatar" style="${avatarStyle(msg.from || senderName)}">${senderName.charAt(0).toUpperCase()}</div>
    <div class="t-meta">
      <div class="t-hdr">
        <span class="t-sender">${esc(senderName)}</span>
        <span class="t-time">${formatTime(msg.ts)}</span>
        ${msg.edited ? '<span class="t-edited">edited</span>' : ''}
      </div>
      <div class="t-body">${linkify(esc(stripQuoted(bodyText)))}</div>
      ${renderReactionsHtml(msg.reactions)}
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

  // Verbatim from src.bak/ui/thread.ts's makeThreadCard (2026-08-25, user
  // direction: HTML/CSS is ported byte-for-byte, never hand-simplified).
  // reply-compose-btn (new-message mode toggle), reply-subject, and the
  // attach button/input stay present but unwired -- no corresponding
  // backend concept yet, same as every other inert element left over from
  // this restoration.
  const replyBoxHtml = focused && composeConfig
    ? `<div class="reply-box">
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
    </div>`
    : ''
  card.innerHTML = `${focused ? '' : hdr}<div class="t-messages"></div>${replyBoxHtml}`

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
  } else if (composeConfig) {
    wireReplyBox(card, group, composeConfig)
  }

  return card
}

function wireReplyBox(card: HTMLElement, group: ThreadGroup, config: ComposeConfig): void {
  const ta = card.querySelector('.reply-box textarea') as HTMLTextAreaElement | null
  const btn = card.querySelector('.t-send-btn') as HTMLButtonElement | null
  if (!ta || !btn) return
  let sending = false
  const send = async () => {
    const body = ta.value.trim()
    if (!body || sending) return
    sending = true
    ta.disabled = true
    btn.disabled = true
    try {
      const { toAddrs, references } = computeReplyContext(group.messages, config.selfDid ? [config.selfAddress, config.selfDid] : config.selfAddress)
      const last = [...group.messages].sort((a, b) => a.msg.ts - b.msg.ts).at(-1)
      await config.sendReply({
        toAddrs,
        subject: group.subject,
        body,
        inReplyTo: last?.msg.message_id || undefined,
        references,
      })
      ta.value = ''
    } catch (e) {
      config.onError?.(e instanceof Error ? e.message : 'Could not send')
    } finally {
      sending = false
      ta.disabled = false
      btn.disabled = false
    }
  }
  btn.addEventListener('click', () => { void send() })
  ta.addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.isComposing && (e.metaKey || e.ctrlKey)) {
      e.preventDefault()
      void send()
    }
  })
}

function topFloor(outer: HTMLElement): number {
  const past = document.getElementById('past-threads')
  return past && outer.contains(past) ? past.offsetHeight : 0
}

/** Single source of truth for the reply-dock -> #outer geometry (ported
 * as-is from src.bak/ui/thread.ts). #reply-dock is position:fixed, so it
 * doesn't shrink #outer on its own -- #outer's bottom padding has to be
 * kept equal to the dock's height by hand, or the last message ends up
 * hidden underneath it. Synchronous: reading offsetHeight forces layout,
 * so callers that adjust scroll right after see the current padding. */
export function syncDockPosition(): void {
  const outer = document.getElementById('outer')
  const dock = document.getElementById('reply-dock')
  const h = dock?.offsetHeight ?? 0
  if (outer) outer.style.paddingBottom = h ? h + 'px' : '0'
  document.documentElement.style.setProperty('--dock-h', h ? h + 'px' : '0px')
  const titleRow = document.getElementById('thread-title-row')
  if (titleRow) document.documentElement.style.setProperty('--thread-title-h', titleRow.offsetHeight + 'px')
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

// Excludes this identity's own address(es) -- without this, a 1:1 thread
// where both sides have sent something (i.e. every real conversation past
// the first message) always included the reader's own address alongside
// the actual counterparty, since `from` alternates between the two (found
// live, 2026-08-26: a DIDComm chat's header/conv-meta showed both DIDs
// instead of just who the reader was talking to). Returns raw addresses --
// callers that render this for a human go through displayParticipantsOf
// below instead; threadProtocol needs the raw did: prefix, which a
// human-readable label has already thrown away.
function participantsOf(msgs: MailMessageView[]): string {
  const self = new Set([composeConfig?.selfAddress, composeConfig?.selfDid].filter((a): a is string => !!a).map(a => a.toLowerCase()))
  return [...new Set(msgs.map(m => m.from).filter(Boolean))].filter(a => !self.has(a.toLowerCase())).join(', ')
}

/** participantsOf, but every did:webvh address run through shortWebvhDid --
 * the human-facing form (did:webvh:d157.biset.md, SCID hidden), everywhere
 * a participant list is actually shown (the thread header, conv-meta's
 * "participants:" line). Nobody needs to see the 46-character SCID itself
 * (found live, 2026-08-26: the header showed the full did:webvh string,
 * SCID and all, right next to the DID pill that was already saying "this
 * is a DID"). */
function displayParticipantsOf(msgs: MailMessageView[]): string {
  return participantsOf(msgs).split(', ').filter(Boolean).map(a => a.startsWith('did:') ? shortWebvhDid(a) : a).join(', ')
}

/** The transport this thread actually used -- the FIRST participant's
 * address shape decides it, same rule main.ts's own sendReply uses to pick
 * a transport in the first place (a DID recipient sends over DIDComm, never
 * mixed with mail in one thread). Falls back to 'mail' for a thread with no
 * participants left after excluding self (shouldn't happen for a real
 * conversation, but "no pill" would be a worse failure mode than a
 * possibly-wrong default one). */
function threadProtocol(msgs: MailMessageView[]): Proto {
  const participants = participantsOf(msgs)
  const first = participants.split(', ')[0]
  return first ? protocolFor(first) : 'mail'
}

export function render(smooth = false): void {
  const $past = document.getElementById('past-threads')
  const $active = document.getElementById('active-thread')
  if (!$past || !$active) return
  $past.innerHTML = ''
  $active.innerHTML = ''

  const groups = groupMessages()
  if (!groups.length) {
    const $dock = document.getElementById('reply-dock')
    if ($dock) $dock.innerHTML = ''
    syncDockPosition()
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
  if ($convTo) {
    // #conv-to holds src.bak's #conv-did/#conv-via badges (DID-mediated/
    // protocol pills, both unwired here -- no DID/multi-relay concept this
    // rewrite has). Plain `$convTo.textContent =` destroys those child
    // elements outright; src.bak's own render() avoided this by grabbing
    // them first and prepending them back after -- same move here, not the
    // shortcut that silently deleted them (user-reported: DID/via badges
    // gone after a re-render).
    const didBadge = document.getElementById('conv-did')
    const viaBadge = document.getElementById('conv-via')
    const msgs = focused.messages.map(p => p.msg)
    $convTo.textContent = displayParticipantsOf(msgs)
    // src.bak's applyConvViaPill prepends #conv-via, then (mail/AP path)
    // prepends #conv-did last so it lands leftmost -- [did, via, address].
    // Mail vs DID actually decided per-thread now (threadProtocol) -- this
    // used to hardcode 'Mail' unconditionally, written before DIDComm chat
    // send existed and never revisited once it did (found live, 2026-08-26:
    // a DIDComm conversation's header still showed a Mail pill). #conv-did
    // stays unwired (no separate DID-mediated-contact concept from the
    // transport pill itself here).
    if (viaBadge) {
      const proto = threadProtocol(msgs)
      viaBadge.textContent = PROTO_TEXT[proto]
      viaBadge.style.cssText = `font-size:10px;font-weight:700;color:#fff;background:${PROTO_COLOR[proto]};border-radius:4px;padding:1px 5px;margin-right:6px;flex-shrink:0`
      $convTo.prepend(viaBadge)
    }
    if (didBadge) $convTo.prepend(didBadge)
  }
  const $convCc = document.getElementById('conv-cc')
  const $convBcc = document.getElementById('conv-bcc')
  if ($convCc) $convCc.textContent = ''
  if ($convBcc) $convBcc.textContent = ''

  const $convMeta = document.getElementById('conv-meta')
  const $expanded = document.getElementById('conv-meta-expanded')
  if ($convMeta) {
    // account-page.ts/compose-page.ts set this to 'none' while their own
    // page occupies #active-thread; render() is the one place that always
    // means "a real thread is on screen now", so it's the right place to
    // unconditionally clear it back -- relying on every hide*Page() call
    // site to do it first is exactly the kind of state that silently goes
    // stale (found live: #conv-meta stayed hidden after opening a thread,
    // user-reported).
    $convMeta.style.display = ''
    $convMeta.classList.remove('expanded')
    if ($expanded) {
      const firstMsg = focused.messages[0]?.msg
      const lines: string[] = []
      if (firstMsg?.message_id) lines.push('message-id: ' + firstMsg.message_id)
      if (firstMsg?.in_reply_to) lines.push('in-reply-to: ' + firstMsg.in_reply_to)
      if (firstMsg?.subject) lines.push('subject: ' + firstMsg.subject)
      if (firstMsg?.ts) lines.push('date: ' + new Date(firstMsg.ts).toISOString())
      lines.push('participants: ' + displayParticipantsOf(focused.messages.map(p => p.msg)))
      // didCommThreadId (didcomm/basicmessage.ts) joins two full DIDs with
      // '|' for a DIDComm thread's key -- elide each segment the same way,
      // not just the strings this panel already shortens.
      lines.push('thread_id: ' + (focusedThreadKey ?? '').split('|').map(s => s.startsWith('did:') ? shortWebvhDid(s) : s).join('|'))
      lines.push('messages: ' + focused.messages.length)
      $expanded.textContent = lines.join('\n')
    }
    const $convFields = document.getElementById('conv-fields')
    if ($convFields) $convFields.onclick = () => $convMeta.classList.toggle('expanded')
  }

  $active.appendChild(makeThreadCard(focused, true))

  // The reply-box makeThreadCard just built lives inside #focused-thread-card
  // at this point (needed there so its querySelector-based wiring can find
  // it), but its real home is #reply-dock -- a fixed dock outside the
  // scrolling message strip, same as src.bak's own render() always moved it
  // there. Leaving it inside the card (2026-08-24 compose slice 1's own
  // first cut) is what put "Reply" and the send button's arrow on top of
  // each other -- #reply-dock's CSS assumes it lives there, not mid-scroll.
  const replyBox = document.querySelector('#focused-thread-card .reply-box')
  const dock = document.getElementById('reply-dock')
  if (replyBox && dock) dock.replaceChildren(replyBox)
  else if (dock) dock.innerHTML = ''
  syncDockPosition()

  requestAnimationFrame(() => scrollToFocused(smooth))
}

let _scrollButtonsSetUp = false

/** #scroll-to-top/#scroll-to-bottom's src.bak/main.ts wiring, ported as-is
 * (pure #outer scroll math, no relay/menu-page concept this rewrite has --
 * inMenuMode() is always false here, there being no #account/#config/
 * #compose page to be "in"). */
export function setupScrollButtons(): void {
  if (_scrollButtonsSetUp) return
  _scrollButtonsSetUp = true
  const outer = document.getElementById('outer')
  const btn = document.getElementById('scroll-to-bottom')
  const btnTop = document.getElementById('scroll-to-top')
  if (!outer) return

  outer.addEventListener('scroll', () => {
    const distFromBottom = outer.scrollHeight - outer.scrollTop - outer.clientHeight
    const bottomVisible = distFromBottom > 120
    btn?.classList.toggle('visible', bottomVisible)
    const floor = topFloor(outer)
    btnTop?.classList.toggle('visible', outer.scrollTop > floor + 40)
    btnTop?.classList.toggle('above-bottom', bottomVisible)
    const lastMsg = outer.querySelector('.t-messages')?.lastElementChild as HTMLElement | null
    const lastMsgVisible = !lastMsg || lastMsg.getBoundingClientRect().top < outer.getBoundingClientRect().bottom
    const titleHidden = outer.scrollTop > floor && bottomVisible && !lastMsgVisible
    document.getElementById('header-left')?.classList.toggle('title-hidden', titleHidden)
    document.getElementById('main-toggle-right')?.classList.toggle('title-hidden', titleHidden)
    document.getElementById('lp-hamburger')?.classList.toggle('title-hidden', titleHidden)
  }, { passive: true })
  btn?.addEventListener('click', () => outer.scrollTo({ top: outer.scrollHeight, behavior: 'smooth' }))
  btnTop?.addEventListener('click', () => outer.scrollTo({ top: topFloor(outer), behavior: 'smooth' }))

  // Re-settle scroll position on viewport resize (rotation, devtools panel,
  // window resize) -- src.bak also resynced its reply-dock's height here,
  // which has no equivalent in this slice's reply-box.
  window.addEventListener('resize', () => { syncDockPosition(); scrollToFocused() })
}
