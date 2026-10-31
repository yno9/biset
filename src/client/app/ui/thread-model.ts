// What a thread is, for display: who it is with, over which transport, which row of the left list
// it belongs to. Pure; the screens call these with the identity's own addresses.
import { groupMessages, inboxKeyForThread, latestGroup } from './message/message-view.ts'
import type { MailMessageView, ProcessedMessage, ThreadGroup } from './message/message-view.ts'
import { displayName, labelForDid, protocolFor } from './did-display.ts'
import type { Proto } from './did-display.ts'

/** This identity's own address(es), lower-cased: its mail address and, once DIDComm is on, its DID. */
export type SelfAddresses = ReadonlySet<string>

export function selfAddressesOf(selfAddress?: string, selfDid?: string): SelfAddresses {
  return new Set([selfAddress, selfDid].filter((a): a is string => !!a).map(a => a.toLowerCase()))
}

/** Raw addresses of everyone in the messages but this identity -- without the exclusion a 1:1 thread
 * where both sides have written always listed the reader next to the counterparty, since `from`
 * alternates between the two. Callers that show it to a human go through displayParticipantsOf;
 * threadProtocol needs the raw did: prefix a label has already thrown away. */
export function participantsOf(msgs: readonly MailMessageView[], self: SelfAddresses): string {
  // Who a message came from; and for what this identity wrote, who it was written to -- otherwise a thread of which only our
  // first message exists has nobody in it (no transport, no name) until the other side answers.
  const others = msgs.flatMap(m => m.from && self.has(m.from.toLowerCase()) ? m.to_addrs ?? [] : [m.from])
  return [...new Set(others.filter(Boolean))].filter(a => !self.has(a.toLowerCase())).join(', ')
}

/** participantsOf, every DID as the address it stands for (labelForDid): the form shown wherever a participant list is. */
export function displayParticipantsOf(msgs: readonly MailMessageView[], self: SelfAddresses): string {
  return participantsOf(msgs, self).split(', ').filter(Boolean).map(a => a.startsWith('did:') ? labelForDid(a) : a).join(', ')
}

/** The transport the thread used: the first participant's address shape decides it (a DID recipient
 * goes over DIDComm, never mixed with mail in one thread); 'mail' for a thread with nobody left. */
export function threadProtocol(msgs: readonly MailMessageView[], self: SelfAddresses): Proto {
  const first = participantsOf(msgs, self).split(', ')[0]
  return first ? protocolFor(first) : 'mail'
}

/** The members of a group chat other than this identity, as the short names a list row shows: what
 * tells two groups apart when neither has a title. */
export function groupMembersLabel(groups: readonly ThreadGroup[], self: SelfAddresses): string {
  const members = new Set<string>()
  for (const group of groups) {
    for (const { msg } of group.messages) {
      for (const address of [msg.from, ...(msg.to_addrs ?? [])]) if (address && !self.has(address.toLowerCase())) members.add(address)
    }
  }
  return [...members].map(address => address.startsWith('did:') ? displayName(address) : address).join(', ')
}

/** Who a 1:1 row is with: the name (or short address) of the latest message that came from the other side, so what we sent last
 * does not name the row after ourselves. Empty when nothing came from them yet (then the members label is the way). */
export function counterpartLabel(groups: readonly ThreadGroup[], self: SelfAddresses): string {
  const received = groups.flatMap(group => group.messages.map(p => p.msg)).filter(msg => msg.from && !self.has(msg.from.toLowerCase())).sort((a, b) => b.ts - a.ts)[0]
  if (received) {
    const name = received.from_name && !received.from_name.startsWith('did:') ? received.from_name : ''
    return name || (received.from.startsWith('did:') ? displayName(received.from) : received.from)
  }
  return groupMembersLabel(groups, self)
}

/** The DID of the other side of a 1:1 row (the latest message that came from them), for its picture; undefined when none did. */
export function counterpartDid(groups: readonly ThreadGroup[], self: SelfAddresses): string | undefined {
  return groups.flatMap(group => group.messages.map(p => p.msg)).filter(msg => msg.from.startsWith('did:') && !self.has(msg.from.toLowerCase())).sort((a, b) => b.ts - a.ts)[0]?.from
}

/** Which row of the left list a thread belongs to: the counterparty (a group chat is its own row). */
function inboxKeyOf(group: ThreadGroup, self: SelfAddresses): string {
  if (group.messages[0]?.msg.thread_id === NOTEPAD_THREAD_ID) return SELF_INBOX_KEY
  return inboxKeyForThread(group.messages[0]?.msg.thread_id, participantsOf(group.messages.map(p => p.msg), self))
}

export const latestOf = (group: ThreadGroup): MailMessageView => group.messages[group.messages.length - 1]!.msg

/** The special inboxes: rows like the others (they sort, the keyboard walks onto them, they are lit while open), each made of one
 * made-up message dated at the end of time, so that newest-first always puts them on top: yourself, then "New message" (which
 * opens a new message). They are never among a conversation's real threads (`groups`), only among the rows. */
/** The `thread_id` of the messages one writes to oneself: the Notepad, a thread of the account's own inbox. */
export const NOTEPAD_THREAD_ID = 'notepad'
export const SELF_INBOX_KEY = 'self:me'
export const NEW_INBOX_KEY = 'new:message'
const END_OF_TIME = 8.64e15
export const SELF_THREAD_KEY = `thread:${SELF_INBOX_KEY}`
export const NEW_THREAD_KEY = `thread:${NEW_INBOX_KEY}`
const specialGroup = (address: string, name: string, ts: number): ThreadGroup => ({
  key: `thread:${address}`,
  subject: name,
  messages: [{
    bodyText: '',
    msg: { from: address, from_name: name, body: '', subject: name, ts, message_id: `<${address}@comail>`, jmap_id: '', in_reply_to: '', thread_id: address, seen: true },
  }],
})
const SPECIAL_GROUPS = [specialGroup(SELF_INBOX_KEY, 'Me', END_OF_TIME), specialGroup(NEW_INBOX_KEY, 'New message', END_OF_TIME - 1)]
export const isSpecialInbox = (key: string): boolean => key === SELF_INBOX_KEY || key === NEW_INBOX_KEY

/** One row of the left list: a counterparty and every thread shared with them, newest first. */
export interface InboxRow { key: string; groups: ThreadGroup[] }

function inboxRows(groups: readonly ThreadGroup[], self: SelfAddresses): InboxRow[] {
  const byKey = new Map<string, ThreadGroup[]>()
  for (const group of groups) {
    const key = inboxKeyOf(group, self)
    const list = byKey.get(key)
    if (list) list.push(group)
    else byKey.set(key, [group])
  }
  return [...byKey.entries()]
    .map(([key, list]) => ({ key, groups: [...list].sort((a, b) => latestOf(b).ts - latestOf(a).ts) }))
    .sort((a, b) => latestOf(b.groups[0]!).ts - latestOf(a.groups[0]!).ts)
}

/** The open thread: the one asked for, else the one with the newest message. */
function openThread(groups: readonly ThreadGroup[], key: string | null): ThreadGroup | undefined {
  return groups.find(g => g.key === key) ?? (groups.length ? latestGroup([...groups]) : undefined)
}

export interface Threads {
  /** The conversations with others: not the Notepad, which is a thread of the account. */
  groups: ThreadGroup[]
  /** The Notepad (empty until something is written in it). */
  notepad: ThreadGroup
  focused: ThreadGroup | undefined
  /** The focused thread's own row's other threads, oldest first: the "past threads" strip. */
  others: ThreadGroup[]
  rows: InboxRow[]
}

export function threadsOf(messages: readonly ProcessedMessage[], focusedKey: string | null, self: SelfAddresses): Threads {
  const everything = groupMessages(messages)
  const notepadGroup = everything.find(g => g.messages[0]?.msg.thread_id === NOTEPAD_THREAD_ID)
  const groups = everything.filter(g => g !== notepadGroup)
  const focused = openThread(groups, focusedKey)
  const focusedInbox = focused && inboxKeyOf(focused, self)
  // Every conversation shares one message set, so "every other thread of this row" has to be asked
  // by the row's key, or the strip lists the threads of every other counterparty too.
  const others = focused
    ? groups.filter(g => g.key !== focused.key && inboxKeyOf(g, self) === focusedInbox).sort((a, b) => latestOf(a).ts - latestOf(b).ts)
    : []
  const notepad = notepadGroup ?? { key: NOTEPAD_THREAD_ID, subject: 'Notepad', messages: [] }
  return { groups, notepad, focused, others, rows: inboxRows([...groups, ...(notepadGroup ? [notepadGroup] : []), ...SPECIAL_GROUPS], self) }
}
