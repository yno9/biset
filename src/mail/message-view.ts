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

export function nodeId(msg: ThreadableMsg): string {
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

export function threadKeyOf(msg: ThreadableMsg, all: ThreadableMsg[]): string {
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

export function messageKey(msg: { message_id?: string; from: string; ts: number }): string {
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
  const from = email.from?.[0]
  const ts = Date.parse(email.sentAt ?? email.receivedAt)
  return {
    from: from?.email ?? '',
    from_name: from?.name ?? from?.email ?? '',
    body: extractPlainTextBody(rawRfc5322),
    subject: email.subject ?? headers.subject ?? '',
    ts: Number.isNaN(ts) ? 0 : ts,
    message_id: headers.messageId ?? email.id,
    jmap_id: email.id,
    in_reply_to: headers.inReplyTo ?? '',
    references: headers.references,
    thread_id: email.threadId,
    to_addrs: (email.to ?? []).map(recipient => recipient.email ?? recipient.name ?? '').filter(Boolean),
    seen: email.keywords['$seen'] === true,
    keywords: email.keywords,
    blob_id: email.blobId,
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

export function computeReplyContext(thread: ProcessedMessage[], selfAddress: string): ReplyContext {
  const self = selfAddress.toLowerCase()
  const toAddrs: string[] = []
  const seen = new Set<string>([self])
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
