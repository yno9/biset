import type { InboxSummary } from './types.ts'

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
    thread_id: string
    to_addrs?: string[]
    cc_addrs?: string[]
    group_id?: string
    group_name?: string
    seen?: boolean
    keywords?: Record<string, boolean>
  }
  bodyText: string
  encrypted: boolean
  unreadable: boolean
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
  const groups = new Map<string, ThreadGroup>()
  for (const p of processedMessages) {
    const k = p.msg.thread_id || p.msg.message_id || String(p.msg.ts)
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
