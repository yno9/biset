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
// そこから先が丸ごと別スレッドに割れていた（Secure-Join の破棄、Chat-Edit/Delete
// /reaction のフィルタ除去、同期窓の外、で親は普通に消える）。ファントム経由なら
// 同じ欠落親を指す兄弟同士が繋がる。

export interface ThreadableMsg {
  message_id?: string
  in_reply_to?: string
  references?: string[]
  thread_id?: string
  from?: string
  ts?: number
}

// threadId を持たないメッセージ（送信直後のローカルエコー等）用の代用ノード。
const LOCAL_PREFIX = 'local:'
// ローカルに存在しない参照先を表すノード。
const PHANTOM_PREFIX = 'mid:'

// グラフ上でこのメッセージを指すノードID。message_id が無い場合だけ from:ts に
// 落ちる（state.ts の messageKey と同じ方針）。
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

// 辞書順で小さい方を根にする。到着順に依存しない決定的な結果になる。
function union(parent: Map<string, string>, a: string, b: string): void {
  const ra = find(parent, a)
  const rb = find(parent, b)
  if (ra === rb) return
  if (ra < rb) parent.set(rb, ra)
  else parent.set(ra, rb)
}

// 代表キーの選好順。実在の JMAP threadId > ローカル代用 > ファントム。
function rank(node: string): number {
  if (node.startsWith(PHANTOM_PREFIX)) return 2
  if (node.startsWith(LOCAL_PREFIX)) return 1
  return 0
}

// 各メッセージの nodeId → スレッドキー。
// キーは連結成分内で rank が最小、同 rank なら辞書順最小のノード。
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
      // 送信直後のローカルエコーは in_reply_to に表示中のスレッドキーを入れる
      // （shell.ts の addPendingMessage）。message-id ではなくスレッドキーなので
      // 直接そのノードに繋ぐ。
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

// 単発の問い合わせ用（全体集合が要るのでその都度計算する）。
export function threadKeyOf(msg: ThreadableMsg, all: ThreadableMsg[]): string {
  return computeThreadKeys(all).get(nodeId(msg)) ?? threadNode(msg)
}
