// The reply box in #reply-dock: a textarea that grows with its text, and a send button (or
// Ctrl/Cmd+Enter). What was typed survives refreshes and switching threads; it is cleared when it
// is sent, and put back if the send fails.
import { useEffect, useLayoutEffect, useRef, useState, useSyncExternalStore } from 'react'
import type { ReactNode } from 'react'
import { createStore, useStore } from '../react/store.ts'
import { computeReplyContext } from './message/message-view.ts'
import type { ThreadGroup } from './message/message-view.ts'
import { syncDockPosition } from './scroll.ts'
import { savePendingSend, sendComposed, sendProblem, signingUp } from './pages/compose-page.tsx'
import { randomAlias, canSignUpInBackground, createAccountInBackground, heldIdentity, provisionalAlias } from './signup-preload.ts'
import { getAccountConfig } from './account/state.ts'
import { shell } from './stores.ts'
import { sendToHelper } from './helper.ts'

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
  /** Writes `body` in the Notepad: a message to oneself, kept on this identity's devices and sent to nobody. */
  sendNote?(body: string): Promise<void>
  onError?(message: string): void
  /** DIDComm group chat's own read-only counterpart -- always present once DIDComm itself is enabled. */
  didcommGroup?: DidCommGroupUiHooks
}

export const composeConfig = createStore<ComposeConfig | undefined>(undefined)
export const configureCompose = (config: ComposeConfig): void => composeConfig.set(config)

const REPLY_MAX_HEIGHT = 200
const REPLY_MIN_DRAGGED = 24

/** What a new message's box opens at: tall enough for the field to reach from just under the island to the foot of the screen. The 62px
 * are what is not the text: the box's bottom margin (16), the field's padding and borders and the textarea's own top margin (38), and
 * the 8px left between the island and the field. */
const openFullHeight = (): number => {
  const island = document.getElementById('conv-fields') ?? document.getElementById('conv-top')
  // A line under the island (the notice that an account is needed, say) is above the field too.
  const notice = document.getElementById('conv-meta-expanded')
  // Under such a line the field is set 48px further down than under the island alone: the line is a note of its own, not part of the island.
  const top = Math.max(island?.getBoundingClientRect().bottom ?? 0, notice ? notice.getBoundingClientRect().bottom + 48 : 0)
  // Not all the way up: a little less (24px) than the room there is, so that the field does not crowd what is above it.
  return Math.max(REPLY_MIN_DRAGGED, Math.round(window.innerHeight - top - 62 - 24))
}

// The height the reader dragged the field to (px), kept across threads; undefined while it fits its text.
let draggedHeight: number | undefined

/** The reply box of an open conversation, or, with no `group`, the first message of a new one (its recipient and subject are the
 * draft's, typed in the island). Two states: `normal` (replying, and the first message of a new conversation: they share it) and
 * `me` (the account's: a line for /commands, with no handle to resize it, and `command`, the shortcuts, where the attach and send
 * buttons are). */
export type ReplyBoxMode = 'normal' | 'me'

// What is typed and not yet sent, per inbox (the box is mounted again for each: a key in right-col.tsx), so that going from one
// inbox to another leaves each one's text where it was.
const drafts = new Map<string, string>()
/** Puts text in an inbox's box before it is shown (what was written before the trip to make an account). */
export const setReplyDraft = (key: string, text: string): void => { drafts.set(key, text) }

export function ReplyBox({ draftKey, group, mode = 'normal', command }: { draftKey: string; group?: ThreadGroup; mode?: ReplyBoxMode; command?: ReactNode }) {
  const config = useStore(composeConfig)
  const [text, setText] = useState(() => drafts.get(draftKey) ?? '')
  useEffect(() => { if (text) drafts.set(draftKey, text); else drafts.delete(draftKey) }, [draftKey, text])
  const [sending, setSending] = useState(false)
  const area = useRef<HTMLTextAreaElement>(null)
  const [dragged, setDragged] = useState(draggedHeight)
  // A new message opens full height (the box is mounted again for it: a key in right-col.tsx), whatever height the others were dragged to. It is
  // measured once the app is on screen: a page opened before that (a link to an address, with no account) has no boxes to measure, and the field would open far too tall.
  const appShown = useSyncExternalStore(shell.subscribe, () => shell.get().appShown)
  useLayoutEffect(() => { if (appShown && !group && mode === 'normal') setDragged(openFullHeight()) }, [group, mode, appShown])
  const latest = useRef({ group, config })
  latest.current = { group, config }

  // Grow/shrink to fit the text (capped), and keep the thread's bottom padding in step with the dock.
  useLayoutEffect(() => {
    const el = area.current
    if (!el) return
    el.style.height = 'auto'
    if (dragged !== undefined && mode === 'normal') {
      // A height chosen by hand holds, whatever the text: scrolling inside takes over when it overflows.
      el.style.height = `${dragged}px`
      el.style.overflowY = el.scrollHeight > dragged ? 'auto' : 'hidden'
    } else if (text) {
      el.style.height = `${Math.min(el.scrollHeight, REPLY_MAX_HEIGHT)}px`
      el.style.overflowY = el.scrollHeight > REPLY_MAX_HEIGHT ? 'auto' : 'hidden'
    } else el.style.height = el.style.overflowY = ''
    syncDockPosition()
  }, [text, dragged, mode])
  // After a send the (disabled, so unfocused) box gets the cursor back.
  const refocus = useRef(false)
  useEffect(() => {
    if (sending || !refocus.current) return
    refocus.current = false
    area.current?.focus({ preventScroll: true })
  }, [sending])

  // Without an account there is still a new message to write (it waits for the account to be made); every other box needs one.
  if (!config && group) return null

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
    // A line that starts with `/` is a command, for the helper, from whichever box it is typed in.
    const forHelper = body.startsWith('/')
    const { group: thread, config: current } = latest.current
    if (!current) {
      // No account: what is written stays in the box; the way to send it is to make one.
      // The message is kept while the account is made (the wallet leaves this page and comes back to it).
      savePendingSend(body)
      // The wallet's create form is already loaded out of sight: the account is made at once, and the tab goes to the wallet's page where
      // the Passphrase is saved (the one step that cannot be done for the person). Without such a wallet the form itself is shown.
      // A wallet that already holds an identity gets the log-in as it (an account is not made over it).
      if (!canSignUpInBackground() || heldIdentity.get()) { signingUp.set(true); return }
      setSending(true)
      void (async () => {
        try {
          // The account is made with the name its face was drawn from (the tab's icon); a name that is taken is replaced, and the face with it.
          try { await createAccountInBackground(provisionalAlias.get()) }
          catch (error) { if (!/taken/.test(String(error instanceof Error ? error.message : error))) throw error; provisionalAlias.set(randomAlias()); await createAccountInBackground(provisionalAlias.get()) }
        } catch (error) {
          const reason = error instanceof Error ? error.message : String(error)
          console.info('[signup] the account was not made in the background:', reason)
          // A browser that already holds an identity gets the wallet's own form, which opens on its log-in.
          if (/already holds/.test(reason)) signingUp.set(true)
          else getAccountConfig()?.showMessage?.(`The account could not be made: ${reason}`)
          setSending(false)
        }
      })()
      return
    }
    setSending(true)
    try {
      if (forHelper) {
        setText('')
        await sendToHelper(body)
        return
      }
      if (mode === 'me') {
        // The account's box writes to the Notepad.
        if (!current.sendNote) throw new Error('The Notepad is not available yet')
        setText('')
        await current.sendNote(body)
        return
      }
      if (!thread) {
        // A new conversation: what is sent is the draft's recipient and subject, with this text.
        setText('')
        sendProblem.set(undefined)
        await sendComposed(body)
        return
      }
      const { toAddrs, references } = computeReplyContext(thread.messages, current.selfDid ? [current.selfAddress, current.selfDid] : current.selfAddress)
      const last = [...thread.messages].sort((a, b) => a.msg.ts - b.msg.ts).at(-1)
      // Cleared before the await: a refresh during the send must not bring the sent text back.
      setText('')
      await current.sendReply({ toAddrs, subject: thread.subject, body, inReplyTo: last?.msg.message_id || undefined, references })
    } catch (error) {
      setText(now => now || body)
      const reason = error instanceof Error ? error.message : 'Could not send'
      if (!thread) sendProblem.set(reason)
      console.error('[send]', error)
      current.onError?.(reason)
    } finally {
      refocus.current = true
      setSending(false)
    }
  }

  return (
    <div className={mode === 'me' ? 'reply-box me' : 'reply-box'}>
      <div className="reply-content">
        <div className="reply-field">
        {mode === 'me' ? null : <div className="reply-resize-handle" onPointerDown={startDrag} onDoubleClick={() => { draggedHeight = undefined; setDragged(undefined) }}><span /></div>}
          <input className="reply-subject" type="text" placeholder="Subject (optional)" />
          <textarea ref={area} rows={1} placeholder={mode === 'me' ? 'Note, or /command' : 'Message'} value={text} disabled={sending}
            onChange={event => setText(event.target.value)}
            onKeyDown={event => {
              if (event.key !== 'Enter' || event.nativeEvent.isComposing) return
              // Cmd/Ctrl+Enter sends; so does a plain Enter on a command (a line that starts with `/`, or any line in the account's box).
              const command = mode === 'me' || text.trimStart().startsWith('/')
              if (event.metaKey || event.ctrlKey || (command && !event.shiftKey)) { event.preventDefault(); void send() }
            }} />
          {/* The account's box shows its shortcuts while it is empty; once something is typed they step aside for the send button. */}
          {mode === 'me' ? command : (
            <button className="reply-attach-btn" type="button" title="Attach file">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48" /></svg>
            </button>
          )}
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
