// The reply box in #reply-dock: a textarea that grows with its text, and a send button (or
// Ctrl/Cmd+Enter). What was typed survives refreshes and switching threads; it is cleared when it
// is sent, and put back if the send fails.
import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import { createStore, useStore } from '../react/store.ts'
import { computeReplyContext } from './message/message-view.ts'
import type { ThreadGroup } from './message/message-view.ts'
import { syncDockPosition } from './scroll.ts'

export interface ReplySendInput {
  toAddrs: string[]
  subject: string
  body: string
  inReplyTo?: string
  references?: string[]
}

/** The read-only member strip a DIDComm group chat thread needs: its participants and name, as its
 * latest message has them (group-chat.ts's `groupConversation`). Changing who is in it is replying
 * to a different set of people, like email. */
interface DidCommGroupUiHooks {
  membersOf(groupId: string): Promise<string[]>
  groupName(groupId: string): Promise<string | undefined>
}

export interface ComposeConfig {
  /** This identity's own mail address, excluded from a reply's toAddrs. */
  selfAddress: string
  /** This identity's own DID, when DIDComm is enabled -- also excluded, so a DIDComm thread's reply
   * doesn't mistake this device's own DID for a recipient. */
  selfDid?: string
  sendReply(input: ReplySendInput): Promise<void>
  onError?(message: string): void
  /** DIDComm group chat's own read-only counterpart -- always present once DIDComm itself is enabled. */
  didcommGroup?: DidCommGroupUiHooks
}

export const composeConfig = createStore<ComposeConfig | undefined>(undefined)
export const configureCompose = (config: ComposeConfig): void => composeConfig.set(config)

/** Two overlapping filled speech bubbles. */
const ChatsIcon = () => (
  <svg width="28" height="28" viewBox="0 0 24 24" fill="currentColor">
    <path d="M3 3h11a2 2 0 0 1 2 2v6a2 2 0 0 1-2 2H8l-3 3v-3H3a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2z" />
    <path d="M18 8h3a2 2 0 0 1 2 2v6a2 2 0 0 1-2 2h-1v3l-3-3h-6a2 2 0 0 1-2-2v-.5h5a4 4 0 0 0 4-4V8z" />
  </svg>
)

const REPLY_MAX_HEIGHT = 200
const REPLY_MIN_DRAGGED = 24

// The height the reader dragged the field to (px), kept across threads; undefined while it fits its text.
let draggedHeight: number | undefined

export function ReplyBox({ group, onToggleChats }: { group: ThreadGroup; onToggleChats: () => void }) {
  const config = useStore(composeConfig)
  const [text, setText] = useState('')
  const [sending, setSending] = useState(false)
  const area = useRef<HTMLTextAreaElement>(null)
  const [dragged, setDragged] = useState(draggedHeight)
  const latest = useRef({ group, config })
  latest.current = { group, config }

  // Grow/shrink to fit the text (capped), and keep the thread's bottom padding in step with the dock.
  useLayoutEffect(() => {
    const el = area.current
    if (!el) return
    el.style.height = 'auto'
    if (dragged !== undefined) {
      // A height chosen by hand holds, whatever the text: scrolling inside takes over when it overflows.
      el.style.height = `${dragged}px`
      el.style.overflowY = el.scrollHeight > dragged ? 'auto' : 'hidden'
    } else if (text) {
      el.style.height = `${Math.min(el.scrollHeight, REPLY_MAX_HEIGHT)}px`
      el.style.overflowY = el.scrollHeight > REPLY_MAX_HEIGHT ? 'auto' : 'hidden'
    } else el.style.height = el.style.overflowY = ''
    syncDockPosition()
  }, [text, dragged])
  // After a send the (disabled, so unfocused) box gets the cursor back.
  const refocus = useRef(false)
  useEffect(() => {
    if (sending || !refocus.current) return
    refocus.current = false
    area.current?.focus({ preventScroll: true })
  }, [sending])

  if (!config) return null

  // Dragging the handle up makes the field taller, down shorter (a double click gives the automatic height back).
  const startDrag = (event: React.PointerEvent<HTMLDivElement>) => {
    const el = area.current
    if (!el) return
    event.preventDefault()
    const handle = event.currentTarget
    handle.setPointerCapture(event.pointerId)
    const startY = event.clientY
    const startHeight = el.getBoundingClientRect().height
    const move = (e: PointerEvent) => {
      const max = Math.round(window.innerHeight * 0.6)
      draggedHeight = Math.min(max, Math.max(REPLY_MIN_DRAGGED, Math.round(startHeight + startY - e.clientY)))
      setDragged(draggedHeight)
    }
    const end = () => {
      handle.removeEventListener('pointermove', move)
      handle.removeEventListener('pointerup', end)
      handle.removeEventListener('pointercancel', end)
    }
    handle.addEventListener('pointermove', move)
    handle.addEventListener('pointerup', end)
    handle.addEventListener('pointercancel', end)
  }

  const send = async () => {
    const body = text.trim()
    if (!body || sending) return
    const { group: thread, config: current } = latest.current
    if (!current) return
    setSending(true)
    try {
      const { toAddrs, references } = computeReplyContext(thread.messages, current.selfDid ? [current.selfAddress, current.selfDid] : current.selfAddress)
      const last = [...thread.messages].sort((a, b) => a.msg.ts - b.msg.ts).at(-1)
      // Cleared before the await: a refresh during the send must not bring the sent text back.
      setText('')
      await current.sendReply({ toAddrs, subject: thread.subject, body, inReplyTo: last?.msg.message_id || undefined, references })
    } catch (error) {
      setText(now => now || body)
      current.onError?.(error instanceof Error ? error.message : 'Could not send')
    } finally {
      refocus.current = true
      setSending(false)
    }
  }

  return (
    <div className="reply-box">
      <div className="reply-content">
        {/* Outside the field, to its left: opens and closes the left pane. */}
        <button className="reply-menu-btn" type="button" title="Chats" aria-label="Toggle pane" onClick={onToggleChats}>
          <ChatsIcon />
        </button>
        <div className="reply-field">
        <div className="reply-resize-handle" onPointerDown={startDrag} onDoubleClick={() => { draggedHeight = undefined; setDragged(undefined) }}><span /></div>
          <input className="reply-subject" type="text" placeholder="Subject (optional)" />
          <textarea ref={area} rows={1} placeholder="Reply…" value={text} disabled={sending}
            onChange={event => setText(event.target.value)}
            onKeyDown={event => {
              if (event.key === 'Enter' && !event.nativeEvent.isComposing && (event.metaKey || event.ctrlKey)) { event.preventDefault(); void send() }
            }} />
          <button className="reply-attach-btn" type="button" title="Attach file">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48" /></svg>
          </button>
          <div className="t-send-wrap">
            <div className="t-send-avatar" />
            <button className="t-send-btn" disabled={sending} onClick={() => { void send() }}>
              <svg viewBox="0 0 24 24"><path d="M2 12L22 2L12 22L10 14L2 12Z" /></svg>
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
