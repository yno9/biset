// The right column: the thread's title row, what sits under it (who it is with), the page (the
// thread, or account / config / compose), the strip of the row's other threads above, and the reply
// dock below.
import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import { useStore } from '../react/store.ts'
import { DIDCOMM_GROUP_THREAD_PREFIX } from './message/message-view.ts'
import type { ThreadGroup } from './message/message-view.ts'
import { displayName, PROTO_COLOR, PROTO_TEXT, shortWebvhDid } from './did-display.ts'
import { hamburgerTrigger } from './hamburger-menu.tsx'
import { PageHost } from './page-host.tsx'
import { ReplyBox, composeConfig } from './reply-box.tsx'
import { readScroll, scrollUi } from './scroll-buttons.tsx'
import { scrollToFocused, syncDockPosition } from './scroll.ts'
import { patchShell, shell, isNarrow } from './stores.ts'
import { displayParticipantsOf, latestOf, threadProtocol } from './thread-model.ts'
import { uiPage } from './state.ts'
import { useSelf, useThreads } from './use-threads.ts'

export function togglePane(): void {
  const current = shell.get()
  if (current.showLeft) patchShell({ showLeft: false })
  else if (current.singleCol) { patchShell({ singleCol: false }); try { localStorage.setItem('lp-open', '1') } catch { /* private browsing */ } }
  else if (isNarrow()) patchShell({ showLeft: true })
  else { patchShell({ singleCol: true }); try { localStorage.setItem('lp-open', '0') } catch { /* private browsing */ } }
}

export const PaneToggleIcons = () => (
  <>
    <svg className="lp-ico-split" width="16" height="16" viewBox="0 0 16 16">
      <path d="M5.5 1.5H4A2.5 2.5 0 0 0 1.5 4v8A2.5 2.5 0 0 0 4 14.5h1.5z" fill="currentColor" opacity="0.65" />
      <rect x="1.5" y="1.5" width="13" height="13" rx="2.5" fill="none" stroke="currentColor" strokeWidth="1.4" />
      <line x1="5.5" y1="1.5" x2="5.5" y2="14.5" stroke="currentColor" strokeWidth="1" opacity="0.5" />
    </svg>
    <svg className="lp-ico-right" width="16" height="16" viewBox="0 0 16 16">
      <rect x="1.5" y="1.5" width="13" height="13" rx="2.5" fill="none" stroke="currentColor" strokeWidth="1.4" />
      <line x1="5.5" y1="1.5" x2="5.5" y2="14.5" stroke="currentColor" strokeWidth="1" opacity="0.5" />
    </svg>
  </>
)

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

/** Who the thread is with, and over which transport; its headers behind a click. */
function ConvMeta({ group, hidden, groupName }: { group: ThreadGroup | undefined; hidden: boolean; groupName: string | undefined }) {
  const self = useSelf()
  const [expanded, setExpanded] = useState(false)
  const key = group?.key
  useEffect(() => { setExpanded(false) }, [key])
  const msgs = group?.messages.map(p => p.msg) ?? []
  const first = msgs[0]
  const proto = threadProtocol(msgs, self)
  const lines: string[] = []
  if (group && first) {
    if (first.message_id) lines.push(`message-id: ${first.message_id}`)
    if (first.in_reply_to) lines.push(`in-reply-to: ${first.in_reply_to}`)
    if (first.subject) lines.push(`subject: ${first.subject}`)
    if (first.ts) lines.push(`date: ${new Date(first.ts).toISOString()}`)
    lines.push(`participants: ${displayParticipantsOf(msgs, self)}`)
    // A DIDComm thread's key joins two full DIDs with '|': each is elided the same way.
    lines.push(`thread_id: ${group.key.split('|').map(s => s.startsWith('did:') ? shortWebvhDid(s) : s).join('|')}`)
    lines.push(`messages: ${group.messages.length}`)
  }
  return (
    <div id="conv-meta" className={expanded ? 'expanded' : undefined} style={hidden ? { display: 'none' } : undefined}>
      <div id="conv-fields" onClick={() => setExpanded(open => !open)}>
        <div id="conv-to">
          <span id="conv-did" />
          {group ? <span id="conv-via" style={{ fontSize: 11, fontWeight: 700, color: '#fff', background: PROTO_COLOR[proto], borderRadius: 4, padding: '1px 5px', marginRight: 6, flexShrink: 0 }}>{PROTO_TEXT[proto]}</span> : <span id="conv-via" />}
          {first?.thread_id.startsWith(DIDCOMM_GROUP_THREAD_PREFIX) ? <GroupStrip groupId={first.thread_id.slice(DIDCOMM_GROUP_THREAD_PREFIX.length)} name={groupName ?? 'Group'} /> : (group ? displayParticipantsOf(msgs, self) : null)}
        </div>
        <div id="conv-cc" />
        <div id="conv-bcc" />
      </div>
      <div id="conv-meta-expanded">{lines.join('\n')}</div>
    </div>
  )
}

const TITLES = { account: 'account', config: 'config', compose: 'compose' } as const

export function RightCol() {
  const page = useStore(uiPage)
  const { focused, others } = useThreads()
  const { titleHidden } = useStore(scrollUi)
  const outer = useRef<HTMLDivElement>(null)
  const column = useRef<HTMLDivElement>(null)
  const onThread = page === 'thread'
  const titleClass = titleHidden ? 'title-hidden' : undefined

  const first = focused?.messages[0]?.msg
  const groupName = useGroupName(first?.thread_id.startsWith(DIDCOMM_GROUP_THREAD_PREFIX) ? first.thread_id.slice(DIDCOMM_GROUP_THREAD_PREFIX.length) : undefined)
  const subject = groupName || focused?.subject
  const title = onThread ? (subject || 'no title') : TITLES[page]
  const untitled = onThread && !subject

  // #outer's bottom padding follows the dock's height, whatever just changed.
  useLayoutEffect(() => { syncDockPosition() })

  useEffect(() => {
    const el = outer.current!
    const onScroll = () => readScroll(el)
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

  return (
    <div id="right-col" ref={column}>
      <div id="outer" ref={outer}>
        <div id="past-threads">{onThread ? <PastThreads groups={others} /> : null}</div>
        <div id="thread-title-row">
          <button id="main-toggle-right" aria-label="Toggle pane" className={titleClass} onClick={togglePane}><PaneToggleIcons /></button>
          <div id="header-left" className={titleClass}>
            <span id="header-thread-title" className={untitled ? 'untitled' : undefined}>{title}</span>
          </div>
          <div id="header-right">
            <button id="lp-hamburger" aria-label="menu" className={titleClass} {...hamburgerTrigger}><HamburgerDots id="lp-hamburger-icon" /></button>
          </div>
        </div>
        <div id="right-pane">
          <ConvMeta group={focused} hidden={!onThread} groupName={groupName} />
          <PageHost />
          <div id="scroll-spacer" />
        </div>
      </div>
      <div id="reply-dock">{onThread && focused ? <ReplyBox group={focused} /> : null}</div>
    </div>
  )
}

