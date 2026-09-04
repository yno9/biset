// ── スレッド判定 ──────────────────────────────────────────────────────────────
//
// biset は JMAP クライアントなので、スレッドの単位は JMAP の Thread
// （email.threadId）そのもの。こちらで Subject 等から独自に推測はしない。
//
// ただし DeltaChat は In-Reply-To / References を暗号化 MIME の中にしか置かない。
// サーバからは参照が一切見えないので、1つのグループ会話が Thread に細かく割れて
// 届く。そこでクライアント側で「サーバに見えていなかった参照」だけを根拠に
// Thread を併合する。併合の辺は復元した参照ヘッダのみで、それ以外の材料は使わない。
//
// 参照先がローカルに無くてもファントムノードとして union するのが肝。以前は
// In-Reply-To の親を1本辿って親の thread_id を継承していたので、親が欠けた瞬間
// そこから先が丸ごと別スレッドに割れていた。ファントム経由なら同じ欠落親を指す
// 兄弟同士が繋がる。（src.bak/threading.ts より移植、ロジックは無変更）
import type { LocalJmapEmail } from '../local-jmap/gateway.ts'
import { extractPlainTextBody } from './body-text.ts'
import { readRfc5322HeaderSummary } from './rfc5322-headers.ts'

export interface ThreadableMsg {
  message_id?: string
  in_reply_to?: string
  references?: string[]
  thread_id?: string
  from?: string
  ts?: number
}

const LOCAL_PREFIX = 'local:'
const PHANTOM_PREFIX = 'mid:'

function nodeId(msg: ThreadableMsg): string {
  return msg.message_id || `${msg.from ?? ''}:${msg.ts ?? 0}`
}

function threadNode(msg: ThreadableMsg): string {
  return msg.thread_id || LOCAL_PREFIX + nodeId(msg)
}

function refsOf(msg: ThreadableMsg): string[] {
  const out = msg.in_reply_to ? [msg.in_reply_to] : []
  for (const r of msg.references ?? []) if (r) out.push(r)
  return out
}

function find(parent: Map<string, string>, x: string): string {
  let root = x
  while (true) {
    const p = parent.get(root)
    if (p === undefined || p === root) break
    root = p
  }
  let cur = x
  while (cur !== root) {
    const next = parent.get(cur) ?? cur
    parent.set(cur, root)
    cur = next
  }
  parent.set(root, root)
  return root
}

function union(parent: Map<string, string>, a: string, b: string): void {
  const ra = find(parent, a)
  const rb = find(parent, b)
  if (ra === rb) return
  if (ra < rb) parent.set(rb, ra)
  else parent.set(ra, rb)
}

function rank(node: string): number {
  if (node.startsWith(PHANTOM_PREFIX)) return 2
  if (node.startsWith(LOCAL_PREFIX)) return 1
  return 0
}

export function computeThreadKeys(msgs: ThreadableMsg[]): Map<string, string> {
  const threadByMessageId = new Map<string, string>()
  const knownThreads = new Set<string>()
  for (const msg of msgs) {
    const t = threadNode(msg)
    knownThreads.add(t)
    if (msg.message_id) threadByMessageId.set(msg.message_id, t)
  }

  const parent = new Map<string, string>()
  for (const t of knownThreads) find(parent, t)

  for (const msg of msgs) {
    const self = threadNode(msg)
    for (const ref of refsOf(msg)) {
      const target = threadByMessageId.get(ref)
      if (target) union(parent, self, target)
      else if (knownThreads.has(ref) || ref.startsWith(PHANTOM_PREFIX)) union(parent, self, ref)
      else union(parent, self, PHANTOM_PREFIX + ref)
    }
  }

  const keyByRoot = new Map<string, string>()
  for (const node of parent.keys()) {
    const root = find(parent, node)
    const cur = keyByRoot.get(root)
    if (cur === undefined) { keyByRoot.set(root, node); continue }
    const rn = rank(node), rc = rank(cur)
    if (rn < rc || (rn === rc && node < cur)) keyByRoot.set(root, node)
  }

  const out = new Map<string, string>()
  for (const msg of msgs) {
    const self = threadNode(msg)
    out.set(nodeId(msg), keyByRoot.get(find(parent, self)) ?? self)
  }
  return out
}

function threadKeyOf(msg: ThreadableMsg, all: ThreadableMsg[]): string {
  return computeThreadKeys(all).get(nodeId(msg)) ?? threadNode(msg)
}

// ── メッセージ表示モデル ────────────────────────────────────────────────────
//
// src.bak/state.ts の ProcessedMessage['msg'] と同じフィールド名を維持する
// （snake_case を含めて）。理由は移植予定の thread.ts がこのフィールド名を
// 直接参照するため -- 新設計に寄せるとその移植で無用な差分が増える。
// DeltaChat 由来の group_id/group_name、リアクション、編集マークは
// このスライスの対象外なので持たない。

export interface MailMessageView {
  from: string
  from_name: string
  body: string
  subject: string
  ts: number
  message_id: string
  jmap_id: string
  in_reply_to: string
  references?: string[]
  thread_id: string
  to_addrs?: string[]
  seen?: boolean
  keywords?: Record<string, boolean>
  blob_id?: string
  /** PLAN-mimi.md §4.5. Array shape (not the Vault's Record<sender, emoji>)
   * to match src.bak's ProcessedMessage['msg']['reactions'] -- this is the
   * one field renderReactionsHtml (ported verbatim, thread.ts) reads.
   * Absent for ordinary mail/1:1 DIDComm chat -- only Conversation Group
   * messages carry this. */
  reactions?: Array<{ from: string; emoji: string }>
  /** PLAN-mimi.md §4.3: set once any message.edit has landed on this email. */
  edited?: boolean
}

export interface ProcessedMessage {
  msg: MailMessageView
  bodyText: string
}

export interface ThreadGroup {
  key: string
  subject: string
  messages: ProcessedMessage[]
}

export const processedMessages: ProcessedMessage[] = []

function messageKey(msg: { message_id?: string; from: string; ts: number }): string {
  return msg.message_id || `${msg.from}:${msg.ts}`
}

export function groupMessages(): ThreadGroup[] {
  const keys = computeThreadKeys(processedMessages.map(p => p.msg))
  const groups = new Map<string, ThreadGroup>()
  for (const p of processedMessages) {
    const k = keys.get(nodeId(p.msg)) ?? nodeId(p.msg)
    if (!groups.has(k)) groups.set(k, { key: k, subject: p.msg.subject, messages: [] })
    const g = groups.get(k)!
    if (!g.subject && p.msg.subject) g.subject = p.msg.subject
    g.messages.push(p)
  }
  // Chronological (oldest first), not insertion order -- processedMessages
  // is appended in whatever order this device happened to load/receive each
  // message locally, which is NOT the same across two devices in one
  // conversation (a message this device sent lands before a reply that
  // actually arrived earlier in wall-clock time, or vice versa). Every
  // reader here already assumes ascending ts (thread.ts's own
  // `latestOf` reads `messages[messages.length - 1]` as "the latest"), so
  // this is the one place that has to actually guarantee it -- found live,
  // 2026-08-25: two sides of the same DIDComm chat showed "a"/"aa" in
  // opposite order.
  for (const g of groups.values()) g.messages.sort((a, b) => a.msg.ts - b.msg.ts)
  return Array.from(groups.values())
}

export function latestGroup(groups: ThreadGroup[]): ThreadGroup {
  return groups.reduce((best, g) =>
    g.messages[g.messages.length - 1]!.msg.ts > best.messages[best.messages.length - 1]!.msg.ts ? g : best
  )
}

// ── LocalJmapEmail → MailMessageView ───────────────────────────────────────
//
// 新設計の LocalJmapEmail は from/to/subject を（書き込み時のメタデータ経由で）
// 直接持っているので、そこは MIME を読み直さない。生 RFC5322 バイト列からは
// 本文と threading 用ヘッダ（Message-Id/In-Reply-To/References）だけを補う。

export function emailToMessageView(email: LocalJmapEmail, rawRfc5322: Uint8Array): MailMessageView {
  const headers = readRfc5322HeaderSummary(rawRfc5322)
  const from = email.from?.[0] ?? headers.from
  const ts = Date.parse(email.sentAt ?? email.receivedAt)
  return {
    from: from?.email ?? '',
    from_name: from?.name ?? from?.email ?? '',
    body: extractPlainTextBody(rawRfc5322),
    subject: email.subject ?? headers.subject ?? '',
    ts: Number.isNaN(ts) ? 0 : ts,
    message_id: headers.messageId ?? email.id,
    jmap_id: email.id,
    // Falls back to email.inReplyTo (PLAN-mimi.md §4.2, MimiContent
    // inReplyTo carried as a Vault email id) when there's no RFC 5322
    // In-Reply-To header to read -- a Conversation Group message has no
    // MIME headers at all (its rawRfc5322 is just the SinglePart bytes),
    // so without this fallback every reply in a group thread would show up
    // as an unthreaded top-level message despite computeThreadKeys already
    // knowing how to chain them by id.
    in_reply_to: headers.inReplyTo || email.inReplyTo || '',
    references: headers.references,
    thread_id: email.threadId,
    to_addrs: (email.to ?? []).map(recipient => recipient.email ?? recipient.name ?? '').filter(Boolean),
    seen: email.keywords['$seen'] === true,
    keywords: email.keywords,
    blob_id: email.blobId,
    reactions: email.reactions ? Object.entries(email.reactions).map(([from, emoji]) => ({ from, emoji })) : undefined,
    edited: email.edited,
  }
}

// ── Reply context ───────────────────────────────────────────────────────────
//
// The reply-only, no-groups version of src.bak/ui/shell.ts's
// computeConversationRecipients: this rewrite has no DID/multi-relay group
// concept, so it reduces to "who else is in this thread" (every from/to_addrs
// entry, minus this identity's own address) and the References chain
// (oldest -> newest message-id).

export interface ReplyContext {
  toAddrs: string[]
  references: string[]
}

// `selfAddress` accepts more than one identifier because this identity has
// more than one under different transports (its mail address AND its own
// DID, for a DIDComm thread) -- filtering against only the mail address left
// a DIDComm thread's OWN DID unrecognized as "self", so it landed in
// `toAddrs` alongside the real recipient. `toAddrs.length` becoming 2
// instead of 1 then failed main.ts's own `toAddrs.length === 1 &&
// toAddrs[0].startsWith('did:')` DIDComm check, silently falling through to
// a mail submission addressed to a DID string (found live, 2026-08-25: the
// core rejected it with "invalid recipient address").
export function computeReplyContext(thread: ProcessedMessage[], selfAddress: string | string[]): ReplyContext {
  // A DIDComm group chat thread's "recipient" is the group itself
  // (`didcomm-group:<groupId>`, didcomm/group-chat.ts's `didcommGroupAddress`),
  // never the per-participant from/to_addrs union the generic algorithm
  // below computes -- that union would hand main.ts's `sendReply` N-1 raw
  // DIDs instead of one group address, which it has no way to tell apart
  // from "reply to N-1 different 1:1 recipients at once" (not a thing this
  // app supports). `references` still comes from the ordinary chain below.
  //
  // An OLD `mls:<groupId>` thread (Conversation Groups, retired from active
  // deployment) deliberately has NO special case here any more: main.ts's
  // sendReply dropped its `mls:` send branch entirely, so keeping this
  // thread's toAddrs pinned to the dead group address would only route a
  // reply into the mail-submission fallback, addressed to the literal
  // string "mls:...". Falling through to the generic algorithm below
  // instead reads this thread's real per-message from/to_addrs (real DIDs,
  // mimi-content-projector.ts's old `projectMimiConversationMessage` always
  // wrote actual DIDs there, never the group address) and lands the reply
  // in whichever live branch fits: a single other DID goes to 1:1 DIDComm
  // chat, multiple DIDs start a fresh DIDComm group chat (createAndSendDidCommGroup)
  // with the same membership -- a graceful forward-migration, not a crash.
  const groupThreadId = thread[0]?.msg.thread_id
  if (groupThreadId?.startsWith('didcomm-group:')) {
    const references = [...thread].sort((a, b) => a.msg.ts - b.msg.ts).map(p => p.msg.message_id).filter(Boolean)
    return { toAddrs: [groupThreadId], references }
  }
  const self = (Array.isArray(selfAddress) ? selfAddress : [selfAddress]).map(a => a.toLowerCase())
  const toAddrs: string[] = []
  const seen = new Set<string>(self)
  for (const { msg } of thread) {
    for (const address of [msg.from, ...(msg.to_addrs ?? [])]) {
      if (!address) continue
      const key = address.toLowerCase()
      if (seen.has(key)) continue
      seen.add(key)
      toAddrs.push(address)
    }
  }
  const references = [...thread]
    .sort((a, b) => a.msg.ts - b.msg.ts)
    .map(p => p.msg.message_id)
    .filter(Boolean)
  return { toAddrs, references }
}
