// The right column: the thread's title row, what sits under it (who it is with), the page (the
// thread, or account / config / compose), the strip of the row's other threads above, and the reply
// dock below.
import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { useStore } from '../react/store.ts'
import { DIDCOMM_GROUP_THREAD_PREFIX } from './message/message-view.ts'
import type { ThreadGroup } from './message/message-view.ts'
import { avatarOf, displayName, labelForDid, shortDid, avatarSeed } from './did-display.ts'
import { GeneratedAvatar } from './generated-avatar.tsx'
import { avatarColor } from './format.ts'
import { hamburgerTrigger } from './hamburger-menu.tsx'
import { PageHost } from './page-host.tsx'
import { ReplyBox, composeConfig } from './reply-box.tsx'
import { readScroll, scrollUi } from './scroll-buttons.tsx'
import { scrollToFocused, syncDockPosition, topFloor } from './scroll.ts'
import { patchShell, shell, isNarrow, threadMotion } from './stores.ts'
import { markSeen } from './seen.ts'
import { attachPullReveal } from './pull-reveal.ts'
import type { PullReveal } from './pull-reveal.ts'
import { counterpartLabel, displayParticipantsOf, latestOf, participantsOf } from './thread-model.ts'
import { showComposePage } from './pages/index.ts'
import { composeDraft, sendProblem, signingUp } from './pages/compose-page.tsx'
import { heldIdentity } from './signup-preload.ts'
import { AccountFoot, AccountIsland, AccountPast, accountTab } from './pages/account-page.tsx'
import { accountConfig } from './account/state.ts'
import { IslandNav, useIslandWheel, type ThreadNav } from './island.tsx'
import { uiPage } from './state.ts'
import { useSelf, useThreads } from './use-threads.ts'

const remember = (key: string, value: string): void => { try { localStorage.setItem(key, value) } catch { /* private browsing */ } }

/** The left pane has three states on a wide screen: none, compact (pictures only), normal. Each press goes to the next. */
export function togglePane(): void {
  const current = shell.get()
  if (current.showLeft) patchShell({ showLeft: false })
  else if (isNarrow()) patchShell({ showLeft: true })
  else if (current.singleCol) { patchShell({ singleCol: false, paneCompact: true }); remember('lp-open', '1'); remember('lp-compact', '1') }
  else if (current.paneCompact) { patchShell({ paneCompact: false }); remember('lp-compact', '0') }
  else { patchShell({ singleCol: true }); remember('lp-open', '0') }
}

/** Two equal vertical bars, as at rest in the compact state: the button that opens and closes the left pane. */
const PaneIcon = () => (
  <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
    <path d="M9 5v14M15 5v14" />
  </svg>
)

/** Where the pane stands: 0 none, 1 compact, 2 normal. */
const paneState = (shown: { singleCol: boolean; paneCompact: boolean; showLeft: boolean }): 0 | 1 | 2 =>
  isNarrow() ? (shown.showLeft ? 2 : 0) : shown.singleCol ? 0 : shown.paneCompact ? 1 : 2

/** The pane button: fixed at the bottom left of the window, whatever the pane's state; a press goes none, compact, normal, none.
 * The icon turns like the hand of a clock with it, always clockwise: left (bars lying) for none, up (bars standing) for
 * compact, right (lying) for normal. Normal back to none is the half turn through down. */
export function PaneButton() {
  const { singleCol, paneCompact, showLeft } = useStore(shell)
  const state = paneState({ singleCol, paneCompact, showLeft })
  const angle = useRef(-90 + state * 90)
  const last = useRef(state)
  if (last.current !== state) {
    // Always on clockwise, to wherever the new state points.
    const target = ((-90 + state * 90) % 360 + 360) % 360
    angle.current += (target - ((angle.current % 360) + 360) % 360 + 360) % 360
    last.current = state
  }
  return (
    <button id="pane-btn" type="button" title="Menu" aria-label="Toggle pane" onClick={togglePane}>
      <span className="pane-btn-icon" style={{ transform: `rotate(${angle.current}deg)` }}><PaneIcon /></span>
    </button>
  )
}

export const HamburgerDots = ({ id }: { id: string }) => (
  <svg id={id} width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><circle cx="8" cy="3.5" r="1.5" /><circle cx="8" cy="8" r="1.5" /><circle cx="8" cy="12.5" r="1.5" /></svg>
)

function fmtRelDate(ts: number): string {
  const d = new Date(ts)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}/${pad(d.getMonth() + 1)}/${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`
}

/** The row's other threads, oldest first, above the open one. */
function PastThreads({ groups }: { groups: ThreadGroup[] }) {
  return (
    <>
      {groups.map(group => (
        <div key={group.key} className="past-row">
          <div className="past-row-header" onClick={() => patchShell({ focusedThreadKey: group.key, lpFocusedKey: null })}>
            <span className={group.subject ? 'past-row-title' : 'past-row-title untitled'}>{group.subject || 'no title'}</span>
            <span className="past-row-time-wrap"><span className="past-row-date">{fmtRelDate(latestOf(group).ts)}</span></span>
          </div>
        </div>
      ))}
    </>
  )
}

/** A DIDComm group chat's own title, when it has one (it replaces the thread's subject). */
function useGroupName(groupId: string | undefined): string | undefined {
  const hooks = useStore(composeConfig)?.didcommGroup
  const [name, setName] = useState<string>()
  useEffect(() => {
    let current = true
    setName(undefined)
    if (groupId) hooks?.groupName(groupId).then(found => { if (current) setName(found) }).catch(() => {})
    return () => { current = false }
  }, [hooks, groupId])
  return name
}

/** A DIDComm group chat: its title and the other members, read-only (changing who is in it is
 * replying to a different set of people). */
function GroupStrip({ groupId, name }: { groupId: string; name: string }) {
  const hooks = useStore(composeConfig)?.didcommGroup
  const selfDid = useStore(composeConfig)?.selfDid
  const [members, setMembers] = useState<string[]>([])
  useEffect(() => {
    let current = true
    hooks?.membersOf(groupId).then(found => { if (current) setMembers(found.filter(m => m !== selfDid)) }).catch(() => {})
    return () => { current = false }
  }, [hooks, groupId, selfDid])
  return (
    <>
      <span>{name}</span>
      <span className="conv-members">
        {hooks ? members.map(did => <span key={did} className="conv-member-chip conv-member-static" title={did}>{did.startsWith('did:') ? displayName(did) : did}</span>) : null}
      </span>
    </>
  )
}

/** The thread's headers, shown under the title when the subject is clicked. */
function MetaInfo({ group, open }: { group: ThreadGroup | undefined; open: boolean }) {
  const self = useSelf()
  const msgs = group?.messages.map(p => p.msg) ?? []
  const first = msgs[0]
  const lines: string[] = []
  if (group && first) {
    if (first.message_id) lines.push(`message-id: ${first.message_id}`)
    if (first.in_reply_to) lines.push(`in-reply-to: ${first.in_reply_to}`)
    if (first.subject) lines.push(`subject: ${first.subject}`)
    if (first.ts) lines.push(`date: ${new Date(first.ts).toISOString()}`)
    lines.push(`participants: ${displayParticipantsOf(msgs, self)}`)
    // A DIDComm thread's key joins two full DIDs with '|': each is elided the same way.
    lines.push(`thread_id: ${group.key.split('|').map(s => s.startsWith('did:') ? shortDid(s) : s).join('|')}`)
    lines.push(`messages: ${group.messages.length}`)
  }
  return open && group ? <div id="conv-meta-expanded">{lines.join('\n')}</div> : null
}

/** With no account, the line under the island says what sending does: the account is made first, and the message goes out right after. */
function SendAsNotice() {
  const asking = useStore(signingUp)
  const problem = useStore(sendProblem)
  const held = useStore(heldIdentity)
  if (problem) return <div id="conv-meta-expanded" className="conv-problem">{`The message was not sent: ${problem}`}</div>
  // This browser's wallet may already hold an identity: then sending is a log-in as it, not a new account.
  if (held) return <div id="conv-meta-expanded">{asking ? `Log in as ${held} here; the message goes out right after.` : `Sending asks you to log in as ${held}; the message goes out right after.`}</div>
  return <div id="conv-meta-expanded">{asking ? 'Make your account here; the message goes out right after.' : 'Sending makes your account first (you save a passphrase on the way); the message goes out right after.'}</div>
}

/** The island of a conversation that has not begun: the recipient and the subject are typed where an open one shows who it is with
 * and its title. */
/** The draft's recipients are kept as one string of addresses separated by spaces; what ends with a space (or a comma) is settled and
 * shown as a chip, what follows the last separator is still being typed. */
const splitRecipients = (to: string): { chips: string[]; typing: string } => {
  const tokens = to.split(/[\s,]+/)
  const typing = tokens.pop() ?? ''
  return { chips: tokens.filter(Boolean), typing }
}
const joinRecipients = (chips: string[], typing: string): string => [...chips, typing].join(' ')

function ComposeMeta() {
  const draft = useStore(composeDraft)
  const to = useRef<HTMLInputElement>(null)
  useEffect(() => { to.current?.focus() }, [])
  const { chips, typing } = splitRecipients(draft.to)
  const known = chips[0] ?? typing.trim()
  // Two or more recipients are a group: the picture is then drawn in the other style (Bauhaus), from all their names.
  const everyone = [...chips, ...(typing.trim() ? [typing.trim()] : [])]
  const group = everyone.length >= 2
  const setTo = (next: string) => composeDraft.set(current => ({ ...current, to: next }))
  // The chip the arrow keys have taken: chips are selected whole, not by the letters in them (null: the cursor is in the field).
  const [selected, setSelected] = useState<number | null>(null)
  const removeChip = (index: number) => { setTo(joinRecipients(chips.filter((_, other) => other !== index), typing)); setSelected(null) }
  const editChip = (index: number) => { setTo(joinRecipients(chips.filter((_, other) => other !== index), chips[index]!)); setSelected(null); to.current?.focus() }
  return (
    <div id="conv-meta" className="conv-line2-low">
      <div id="conv-fields">
        <div id="conv-to">
          {known
            ? <div id="conv-avatar" className="lp-avatar" style={{ background: avatarColor(avatarSeed(known)) }}><GeneratedAvatar name={group ? everyone.map(avatarSeed).join(' ') : avatarSeed(known)} variant={group ? 'bauhaus' : 'beam'} /></div>
            : <div id="conv-avatar" className="lp-avatar lp-new-avatar conv-avatar-to">To</div>}
          <div id="conv-text">
            <div id="conv-line1" className="conv-recipients">
              {chips.map((address, index) => (
                // A click takes a chip back to be edited.
                <span key={`${address}-${index}`} className={selected === index ? 'conv-chip selected' : 'conv-chip'} title={address}
                  onClick={() => editChip(index)}>{address}</span>
              ))}
              <input id="conv-to-input" ref={to} className="conv-input" type="text" inputMode="email" name="recipient" placeholder={chips.length ? '' : 'name@example.com'} autoComplete="off" autoCapitalize="off" autoCorrect="off" spellCheck={false}
                data-bwignore="true" data-1p-ignore="true" data-lpignore="true" data-form-type="other"
                value={typing}
                // A space or a comma settles what was typed (as a paste of several addresses does).
                onChange={event => { const more = splitRecipients(event.target.value); setTo(joinRecipients([...chips, ...more.chips], more.typing)) }}
                onKeyDown={event => {
                  const field = event.currentTarget
                  const atStart = field.selectionStart === 0 && field.selectionEnd === 0
                  if (selected !== null) {
                    // A chip is taken: the keys act on it as a whole.
                    if (event.key === 'ArrowLeft') { event.preventDefault(); setSelected(Math.max(0, selected - 1)) }
                    else if (event.key === 'ArrowRight') { event.preventDefault(); setSelected(selected < chips.length - 1 ? selected + 1 : null) }
                    else if (event.key === 'Backspace' || event.key === 'Delete') { event.preventDefault(); removeChip(selected) }
                    else if (event.key === 'Enter') { event.preventDefault(); editChip(selected) }
                    else if (event.key === 'Escape') { event.preventDefault(); setSelected(null) }
                    else if (event.key.length === 1 && !event.metaKey && !event.ctrlKey) setSelected(null) // typing goes on in the field
                    return
                  }
                  if ((event.key === 'ArrowLeft' || event.key === 'Backspace') && atStart && chips.length > 0 && !event.metaKey && !event.ctrlKey) { event.preventDefault(); setSelected(chips.length - 1) }
                  else if (event.key === 'Enter' && !event.nativeEvent.isComposing && typing.trim()) { event.preventDefault(); setTo(joinRecipients([...chips, typing.trim()], '')) }
                }}
                onBlur={() => { setSelected(null); if (typing.trim()) setTo(joinRecipients([...chips, typing.trim()], '')) }} />
            </div>
            <div id="conv-line2">
              <svg className="conv-subject-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7" /><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z" /></svg>
              <input id="conv-subject-input" className="conv-input" type="text" name="subject" placeholder={group ? 'Group Name' : 'Subject (optional)'} autoComplete="off"
                data-bwignore="true" data-1p-ignore="true" data-lpignore="true" data-form-type="other"
                value={draft.subject} onChange={event => composeDraft.set(current => ({ ...current, subject: event.target.value }))} />
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

/** Who the thread is with. */
function ConvMeta({ group, hidden, groupName, titleLine, nav }: { group: ThreadGroup | undefined; hidden: boolean; groupName: string | undefined; titleLine: ReactNode; nav: ThreadNav | undefined }) {
  const self = useSelf()
  const msgs = group?.messages.map(p => p.msg) ?? []
  const first = msgs[0]
  const isGroup = !!first?.thread_id.startsWith(DIDCOMM_GROUP_THREAD_PREFIX)
  const counterpart = participantsOf(msgs, self).split(', ')[0] ?? ''
  const name = group ? counterpartLabel([group], self) : ''
  const address = counterpart.startsWith('did:') ? labelForDid(counterpart) : counterpart
  const fields = useRef<HTMLDivElement>(null)
  useIslandWheel(fields, nav)
  return (
    <div id="conv-meta" style={hidden ? { display: 'none' } : undefined}>
      <div id="conv-fields" ref={fields}>
        <div id="conv-to">
          <span id="conv-did" />
          {isGroup ? <>
            <div id="conv-text">
              <div id="conv-line1"><GroupStrip groupId={first.thread_id.slice(DIDCOMM_GROUP_THREAD_PREFIX.length)} name={groupName ?? 'Group'} /></div>
              <div id="conv-line2">{titleLine}</div>
            </div>
          </> : group ? (
            // Like the account page's identity card: the counterparty's picture, and beside it two lines: the name and the address, then the new-message button and the subject.
            <>
              <div id="conv-avatar" className="lp-avatar" style={{ background: avatarColor(avatarSeed(counterpart) || name) }}>{avatarOf(counterpart) ? <img className="lp-avatar-img" src={avatarOf(counterpart)} alt="" /> : <GeneratedAvatar name={avatarSeed(counterpart) || name} />}</div>
              <div id="conv-text">
                <div id="conv-line1">
                  <span id="conv-name">{name}</span>
                  {address && address !== name ? <span id="conv-address">{address}</span> : null}
                </div>
                <div id="conv-line2">{titleLine}</div>
              </div>
            </>
          ) : null}
          <IslandNav nav={nav} />
        </div>
        <div id="conv-cc" />
        <div id="conv-bcc" />
      </div>
    </div>
  )
}

const TITLES = { account: 'account', compose: 'compose' } as const

export function RightCol() {
  const page = useStore(uiPage)
  const { focused, others, rows } = useThreads()
  // What the reply box keeps per inbox: the open thread's inbox, the new message, the account.
  const draftKey = page === 'compose' ? 'new' : page === 'account' ? 'me' : focused ? rows.find(row => row.groups.some(group => group.key === focused.key))?.key ?? focused.key : ''
  // The inbox's threads in time order, the open one among them.
  const inboxThreads = focused ? [...others, focused].sort((a, b) => latestOf(a).ts - latestOf(b).ts) : []
  const position = focused ? inboxThreads.findIndex(group => group.key === focused.key) : -1
  const nav: ThreadNav | undefined = focused ? {
    position, count: inboxThreads.length,
    go: step => {
      const target = inboxThreads[position + step]
      if (!target) return
      threadMotion.key = target.key
      threadMotion.dir = step
      patchShell({ focusedThreadKey: target.key, lpFocusedKey: null })
    },
  } : undefined
  const { titleHidden } = useStore(scrollUi)
  const outer = useRef<HTMLDivElement>(null)
  const column = useRef<HTMLDivElement>(null)
  const onThread = page === 'thread'
  // The account is a conversation too once there is an identity (before that its page is the sign-up).
  const accountReady = useStore(accountConfig)?.did != null
  const accountless = useStore(accountConfig)?.did === null
  // Asked for an account in the middle of sending: the sign-up takes the place of the box.
  const asking = useStore(signingUp)
  const problem = useStore(sendProblem)
  const [metaOpen, setMetaOpen] = useState(false)
  // The island's shadow shows only once the conversation has scrolled under it.
  const [scrolled, setScrolled] = useState(false)
  // Three seconds into being scrolled, the island shrinks to the avatar; back at the top it opens again.
  const [compact, setCompact] = useState(false)
  useEffect(() => {
    if (!scrolled) { setCompact(false); return }
    const timer = window.setTimeout(() => setCompact(true), 3000)
    return () => window.clearTimeout(timer)
  }, [scrolled])
  // While the pointer is on the new-message button, the title names what it would do.
  const [composeHover, setComposeHover] = useState(false)
  const focusedKey = focused?.key
  useEffect(() => { setMetaOpen(false) }, [focusedKey])
  const titleClass = titleHidden ? 'title-hidden' : undefined

  // A thread that is open is read: what it holds that was not read before is marked now (not while the page is hidden).
  useEffect(() => {
    if (!onThread || !focused || document.visibilityState === 'hidden') return
    markSeen(focused.messages.map(item => item.msg))
  }, [onThread, focused])

  const first = focused?.messages[0]?.msg
  const groupName = useGroupName(first?.thread_id.startsWith(DIDCOMM_GROUP_THREAD_PREFIX) ? first.thread_id.slice(DIDCOMM_GROUP_THREAD_PREFIX.length) : undefined)
  const subject = groupName || focused?.subject
  const title = composeHover ? 'New Thread' : onThread ? (subject || 'no title') : TITLES[page]
  const untitled = onThread && !subject && !composeHover

  // #outer's bottom padding follows the dock's height, whatever just changed.
  useLayoutEffect(() => { syncDockPosition() })

  const pull = useRef<PullReveal>(undefined)
  useEffect(() => {
    pull.current = attachPullReveal(outer.current!)
    return () => pull.current?.detach()
  }, [])
  // A new message has nothing to scroll (its page can no longer be scrolled, ui/style.css): wherever the page before it was scrolled to
  // must not be kept, or the island would stand at a scroll position nobody can scroll back from.
  useLayoutEffect(() => {
    if (page !== 'compose') return
    const el = outer.current
    if (el) { el.scrollTop = 0; setScrolled(false) }
  }, [page])
  // Another thread: the strip of the others is closed again.
  const tab = useStore(accountTab)
  useEffect(() => { pull.current?.reset() }, [focusedKey, tab, page])
  // The jump-to-end button and its count describe the page on screen: read again once another page (or thread, or tab) has laid out,
  // not left as the page before had it.
  useEffect(() => {
    const frame = requestAnimationFrame(() => requestAnimationFrame(() => { if (outer.current) readScroll(outer.current) }))
    return () => cancelAnimationFrame(frame)
  }, [focusedKey, tab, page])

  useEffect(() => {
    const el = outer.current!
    // The conversation's own scroll position is 0 where it meets the open strip of other threads; the strip lies in the negatives.
    const onScroll = () => { readScroll(el); setScrolled(el.scrollTop - topFloor(el) > 2) }
    const onResize = () => { syncDockPosition(); scrollToFocused() }
    el.addEventListener('scroll', onScroll, { passive: true })
    window.addEventListener('resize', onResize)
    return () => { el.removeEventListener('scroll', onScroll); window.removeEventListener('resize', onResize) }
  }, [])

  // Narrow screen: a swipe right anywhere in the conversation column reveals the inbox list. The
  // direction is locked early (a few px) rather than at touchend: a diagonal touch judged only at
  // the end both scrolls the list and counts as a swipe, which reads as the screen wobbling.
  useEffect(() => {
    const el = column.current!
    let startX = 0, startY = 0, tracking = false
    let axis: 'x' | 'y' | null = null
    const start = (e: TouchEvent) => {
      if (!isNarrow()) { tracking = false; return }
      tracking = !shell.get().showLeft
      axis = null
      startX = e.touches[0]!.clientX
      startY = e.touches[0]!.clientY
    }
    const move = (e: TouchEvent) => {
      if (!tracking) return
      const dx = e.touches[0]!.clientX - startX
      const dy = e.touches[0]!.clientY - startY
      if (!axis) {
        if (Math.abs(dx) < 10 && Math.abs(dy) < 10) return
        axis = Math.abs(dx) > Math.abs(dy) * 1.5 ? 'x' : 'y'
      }
      if (axis === 'x') e.preventDefault()
    }
    const end = (e: TouchEvent) => {
      if (!tracking) return
      tracking = false
      if (axis === 'x' && e.changedTouches[0]!.clientX - startX > 70) patchShell({ showLeft: true })
    }
    el.addEventListener('touchstart', start, { passive: true })
    el.addEventListener('touchmove', move, { passive: false })
    el.addEventListener('touchend', end, { passive: true })
    return () => { el.removeEventListener('touchstart', start); el.removeEventListener('touchmove', move); el.removeEventListener('touchend', end) }
  }, [])


  const newThreadButton = (
    <button className="reply-compose-btn" type="button" title="New message" aria-label="New message" onClick={showComposePage} onMouseEnter={() => setComposeHover(true)} onMouseLeave={() => setComposeHover(false)} onFocus={() => setComposeHover(true)} onBlur={() => setComposeHover(false)}>
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7" />
        <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z" />
      </svg>
    </button>
  )
  // Moving between threads rolls the title: the old one slides out one way while the new one slides in from the other.
  const [ghost, setGhost] = useState<{ text: string; dir: -1 | 1 }>()
  const shownTitle = useRef(title)
  useEffect(() => {
    if (focusedKey && threadMotion.key === focusedKey && threadMotion.dir) {
      setGhost({ text: shownTitle.current, dir: threadMotion.dir })
      const timer = window.setTimeout(() => { setGhost(undefined); threadMotion.key = undefined; threadMotion.dir = 0 }, 360)
      return () => window.clearTimeout(timer)
    }
    setGhost(undefined)
  }, [focusedKey])
  useEffect(() => { shownTitle.current = title })
  const rolling = focusedKey !== undefined && threadMotion.key === focusedKey && threadMotion.dir !== 0
  const titleSlide = rolling ? `title-in-from-${threadMotion.dir > 0 ? 'below' : 'above'}` : undefined
  const titleGhost = ghost ? <span className={`title-ghost title-out-to-${ghost.dir > 0 ? 'above' : 'below'}`} aria-hidden="true">{ghost.text}</span> : null
  const titleText = <span className="title-clip"><span key={focusedKey} id="header-thread-title" className={[untitled ? 'untitled' : '', titleSlide].filter(Boolean).join(' ') || undefined} onClick={onThread ? () => setMetaOpen(open => !open) : undefined} style={onThread ? { cursor: 'pointer' } : undefined}>{title}</span>{titleGhost}</span>

  return (
    <div id="right-col" ref={column}>
      <div id="outer" ref={outer}>
        <div id="past-threads"><div className="past-inner">{onThread ? <PastThreads groups={others} /> : accountReady && page === 'account' ? <AccountPast /> : null}</div></div>
        <div id="conv-top" className={[scrolled ? 'scrolled' : '', compact ? 'compact' : ''].filter(Boolean).join(' ') || undefined}>
          {page === 'account' ? <AccountIsland /> : null}
          {page === 'compose' ? <ComposeMeta /> : null}
          <ConvMeta group={focused} hidden={!onThread} groupName={groupName} titleLine={<>{newThreadButton}{titleText}</>} nav={nav} />
          {/* On the account page the menu button sits at the end of the identity card instead (pages/account-page.tsx). */}
          {page === 'account' ? null : <div id="header-right">
            <button id="lp-hamburger" aria-label="menu" className={titleClass} {...hamburgerTrigger}><HamburgerDots id="lp-hamburger-icon" /></button>
          </div>}
        </div>
        {onThread || page === 'compose' ? null : (
          <div id="thread-title-row" style={page === 'account' ? { display: 'none' } : undefined}>
            <div id="header-left" className={titleClass}>
              {newThreadButton}
              {titleText}
            </div>
          </div>
        )}
        <div id="right-pane">
          <MetaInfo group={focused} open={onThread && metaOpen} />
          {/* No account: the message can be written, but sending needs one. The line is said in the field the thread's headers use. */}
          {page === 'compose' && (accountless || problem) ? <SendAsNotice /> : null}
          <PageHost />
          <div id="scroll-spacer" />
        </div>
      </div>
      <div id="reply-dock">{onThread && focused ? <ReplyBox key={draftKey} draftKey={draftKey} group={focused} /> : page === 'compose' ? (asking ? null : <ReplyBox key={draftKey} draftKey={draftKey} />) : accountReady && page === 'account' ? <ReplyBox key={draftKey} draftKey={draftKey} mode="me" command={<AccountFoot />} /> : null}</div>
    </div>
  )
}

