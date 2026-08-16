import type { InboxSummary } from './types.ts'
import { computeThreadKeys, nodeId } from './threading.ts'

// A decrypted (or cleartext) message attachment, ready to render — dataUrl
// works both as an <img src> (images) and an <a download href> (anything
// else). Display-only for now: extracted from PGP/MIME on receive, see
// processing.ts and pgp/crypto.ts's DecryptedMime.attachments.
export interface MsgAttachment {
  filename?: string
  contentType: string
  dataUrl: string
}

export interface ProcessedMessage {
  msg: {
    from: string
    from_name: string
    body: string
    subject: string
    ts: number
    message_id: string
    jmap_id?: string
    in_reply_to: string
    references?: string[]
    // JMAP サーバが付けた threadId。表示上のスレッド分けには使わない
    // （threading.ts 参照）。JMAP 側の照合が要る箇所のためだけに保持。
    thread_id: string
    to_addrs?: string[]
    cc_addrs?: string[]
    group_id?: string
    group_name?: string
    seen?: boolean
    keywords?: Record<string, boolean>
    // RFC 9078 reactions targeting this message (src/mail/reactions.ts) —
    // display-only, one entry per sender (their latest, non-retracted emoji).
    reactions?: { emoji: string; from: string }[]
    // Set when a Chat-Edit request overlaid msg.body (see collectEdits in
    // deltachat/protocol.ts) — display-only "edited" label next to the time.
    edited?: boolean
  }
  bodyText: string
  encrypted: boolean
  unreadable: boolean
  attachments?: MsgAttachment[]
  pending?: boolean
  tempId?: string
}

export interface ThreadGroup {
  key: string
  subject: string
  messages: ProcessedMessage[]
}

export const processedMessages: ProcessedMessage[] = []
export const renderedKeys = new Set<string>()

/** Identity of a message for the render cache — which bubble on screen IS this
 * message, across re-fetches and re-renders.
 *
 * `message_id` and nothing else. This used to be `from:ts`, which silently
 * merged any two messages from the same sender bearing the same timestamp into
 * one bubble — and worse, addMessage() then read the second one's differing
 * body as an EDIT of the first and overwrote it, so the earlier message was
 * gone from the screen for good (a reload rebuilt from the store and collapsed
 * them again identically). Two DIDComm messages picked up in the same cycle hit
 * this every time, because channel.ts stamped a whole pickup with one
 * timestamp; two mails arriving in the same second hit it too.
 *
 * Every producer supplies a unique one: app.ts falls back to the JMAP id when a
 * message carries no Message-ID, and an optimistic local echo uses its tempId
 * (shell.ts's addPendingMessage). The `from:ts` fallback below is therefore
 * dead code kept only so a message with no id at all can't collapse every other
 * such message into one. */
export function messageKey(msg: { message_id?: string; from: string; ts: number }): string {
  return msg.message_id || `${msg.from}:${msg.ts}`
}
export let focusedThreadKey: string | null = null
export let lastTs = 0
export let notifEnabled = false
export let isFirstFetch = true

export function setFocusedThreadKey(k: string | null): void { focusedThreadKey = k }
export function setLastTs(ts: number): void { lastTs = ts }
export function setNotifEnabled(v: boolean): void { notifEnabled = v }
export function setIsFirstFetch(v: boolean): void { isFirstFetch = v }

export let lastLeftInboxes: InboxSummary[] = []
export function setLastLeftInboxes(v: InboxSummary[]): void { lastLeftInboxes = v }

export function groupMessages(): ThreadGroup[] {
  const keys = computeThreadKeys(processedMessages.map(p => p.msg))
  const groups = new Map<string, ThreadGroup>()
  for (const p of processedMessages) {
    const k = keys.get(nodeId(p.msg)) ?? nodeId(p.msg)
    // DeltaChat hides the real subject (outer = "[...]"); the group title lives in
    // the Chat-Group-Name protected header (msg.group_name). Fall back to it so the
    // thread header shows "gt" instead of "no title" for DeltaChat groups.
    const rawSubj = (p.msg.subject && p.msg.subject !== '[...]') ? p.msg.subject : ''
    const subj = rawSubj || p.msg.group_name || ''
    if (!groups.has(k)) groups.set(k, { key: k, subject: subj, messages: [] })
    const g = groups.get(k)!
    if (!g.subject && subj) g.subject = subj
    g.messages.push(p)
  }
  return Array.from(groups.values())
}

export function latestGroup(groups: ThreadGroup[]): ThreadGroup {
  return groups.reduce((best, g) =>
    g.messages[g.messages.length - 1].msg.ts > best.messages[best.messages.length - 1].msg.ts ? g : best
  )
}
