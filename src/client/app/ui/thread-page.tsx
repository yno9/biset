// The open thread: its messages, newest at the bottom, the oldest hidden behind "Show older".
import { useLayoutEffect, useRef, useState } from 'react'
import type { MailMessageView, ProcessedMessage, ThreadGroup } from './message/message-view.ts'
import { esc, formatFullTime, linkify, stripQuoted } from './format.ts'
import { scrollToFocused } from './scroll.ts'
import { threadMotion } from './stores.ts'
import { useSelf, useThreads } from './use-threads.ts'

const INITIAL_COUNT = 100
const LOAD_STEP = 100

// How many messages of each thread are shown: kept across leaving a thread and coming back.
const visibleCounts = new Map<string, number>()

function Reactions({ reactions }: { reactions: MailMessageView['reactions'] }) {
  if (!reactions?.length) return null
  // One chip per reactor, no counting: each reactor's own emoji stays its own chip.
  return <div className="t-reactions">{reactions.map(r => <span key={r.from} className="t-reaction-chip" title={r.from}>{r.emoji}</span>)}</div>
}

function Message({ message: { msg, bodyText } }: { message: ProcessedMessage }) {
  const timeLabel = msg.edited ? `${formatFullTime(msg.ts)} edited` : formatFullTime(msg.ts)
  const mine = useSelf().has((msg.from ?? '').toLowerCase())
  return (
    <div className={mine ? 't-msg me' : 't-msg'} data-message-id={msg.message_id}>
      <div className="t-meta">
        {msg.auth && msg.auth.dmarc !== 'pass' ? <div className="t-hdr">
          {/* A bridged mail whose From: domain did not pass DMARC may be forged (didmail PROTOCOL.md §4.3). No `auth` is "not checked": a DIDComm message is authenticated by its own encryption. */}
          <span className="t-unverified" title={`The sender's mail domain did not verify this message (DMARC ${msg.auth.dmarc ?? 'none'}). It may not be from ${msg.auth.domain ?? 'that domain'}.`}>unverified</span>
        </div> : null}
        <div className="t-row">
          {/* esc() leaves nothing but text, and linkify() only adds anchors: the body is never markup. */}
          <div className="t-body" dangerouslySetInnerHTML={{ __html: linkify(esc(stripQuoted(bodyText))) }} />
          <button className="t-more" aria-label={timeLabel}>⋯<span className="t-time-bubble">{timeLabel}</span></button>
        </div>
        {/* External Feed Post only: a link to the original post. The value arrives over unauthenticated anoncrypt, so only http(s) is linked. */}
        {msg.sourceUrl && /^https?:\/\//.test(msg.sourceUrl)
          ? <div className="t-source-link"><a href={msg.sourceUrl} target="_blank" rel="noopener noreferrer">元の投稿を見る</a></div> : null}
        <Reactions reactions={msg.reactions} />
      </div>
    </div>
  )
}

function Messages({ group }: { group: ThreadGroup }) {
  const all = group.messages
  const [, setTick] = useState(0)
  const container = useRef<HTMLDivElement>(null)
  const before = useRef<{ height: number; scroll: number } | undefined>(undefined)
  const visible = Math.min(Math.max(visibleCounts.get(group.key) ?? 0, Math.min(INITIAL_COUNT, all.length)), all.length)
  visibleCounts.set(group.key, visible)
  const start = Math.max(0, all.length - visible)

  // "Show older" adds messages above the ones being read: the view must not jump.
  useLayoutEffect(() => {
    const outer = document.getElementById('outer')
    if (!before.current || !outer || !container.current) return
    outer.scrollTop = before.current.scroll + (container.current.scrollHeight - before.current.height)
    before.current = undefined
  })

  return (
    <div className="t-messages" ref={container}>
      {start > 0 ? (
        <button className="t-load-older" style={{ display: 'block', margin: '8px auto', padding: '6px 14px', border: '1px solid var(--border)', background: 'transparent', color: 'var(--text-dim)', borderRadius: 14, cursor: 'pointer', fontSize: 13 }}
          onClick={() => {
            before.current = { height: container.current?.scrollHeight ?? 0, scroll: document.getElementById('outer')?.scrollTop ?? 0 }
            visibleCounts.set(group.key, Math.min(visible + LOAD_STEP, all.length))
            setTick(tick => tick + 1)
          }}>{`Show older (${start} more)`}</button>
      ) : null}
      {all.slice(start).map(message => <Message key={message.msg.message_id || `${message.msg.from}:${message.msg.ts}`} message={message} />)}
    </div>
  )
}

/** The envelope shown when there is nothing yet. */
function Empty() {
  return (
    <div style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', display: 'flex', flexDirection: 'column', alignItems: 'center', color: 'var(--text-dim)' }}>
      <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" opacity="0.3"><path d="M4 4h16v13H4z" /><path d="M4 4l8 8 8-8" /></svg>
    </div>
  )
}

export function ThreadPage() {
  const { focused } = useThreads()
  const key = focused?.key
  const count = focused?.messages.length ?? 0
  // Open at the end of the thread, again whenever another thread opens or a message arrives.
  useLayoutEffect(() => { scrollToFocused() }, [key, count])
  return (
    <div id="active-thread">
      {focused
        ? <div key={key} className={threadMotion.key === key && threadMotion.dir ? `thread-card focused-card slide-from-${threadMotion.dir > 0 ? 'below' : 'above'}` : 'thread-card focused-card'} id="focused-thread-card"><Messages group={focused} /></div>
        : <Empty />}
    </div>
  )
}

