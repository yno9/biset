// What a thread is, for display: who it is with, over which transport, which row of the left list
// it belongs to. Pure; the screens call these with the identity's own addresses.
import { groupMessages, inboxKeyForThread, latestGroup } from './message/message-view.ts'
import type { MailMessageView, ProcessedMessage, ThreadGroup } from './message/message-view.ts'
import { labelForDid, protocolFor, shortWebvhDid } from './did-display.ts'
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
function participantsOf(msgs: readonly MailMessageView[], self: SelfAddresses): string {
  return [...new Set(msgs.map(m => m.from).filter(Boolean))].filter(a => !self.has(a.toLowerCase())).join(', ')
}

/** participantsOf, every did:webvh shortened (SCID hidden): the form shown wherever a participant
 * list is. */
export function displayParticipantsOf(msgs: readonly MailMessageView[], self: SelfAddresses): string {
  return participantsOf(msgs, self).split(', ').filter(Boolean).map(a => a.startsWith('did:') ? shortWebvhDid(a) : a).join(', ')
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
  return [...members].map(address => address.startsWith('did:') ? labelForDid(address) : address).join(', ')
}

/** Which row of the left list a thread belongs to: the counterparty (a group chat is its own row). */
function inboxKeyOf(group: ThreadGroup, self: SelfAddresses): string {
  return inboxKeyForThread(group.messages[0]?.msg.thread_id, participantsOf(group.messages.map(p => p.msg), self))
}

export const latestOf = (group: ThreadGroup): MailMessageView => group.messages[group.messages.length - 1]!.msg

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
  groups: ThreadGroup[]
  focused: ThreadGroup | undefined
  /** The focused thread's own row's other threads, oldest first: the "past threads" strip. */
  others: ThreadGroup[]
  rows: InboxRow[]
}

export function threadsOf(messages: readonly ProcessedMessage[], focusedKey: string | null, self: SelfAddresses): Threads {
  const groups = groupMessages(messages)
  const focused = openThread(groups, focusedKey)
  const focusedInbox = focused && inboxKeyOf(focused, self)
  // Every conversation shares one message set, so "every other thread of this row" has to be asked
  // by the row's key, or the strip lists the threads of every other counterparty too.
  const others = focused
    ? groups.filter(g => g.key !== focused.key && inboxKeyOf(g, self) === focusedInbox).sort((a, b) => latestOf(a).ts - latestOf(b).ts)
    : []
  return { groups, focused, others, rows: inboxRows(groups, self) }
}

