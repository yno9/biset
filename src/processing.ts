import type { Email } from 'jmap-rfc-types'
import type { ProcessedMessage } from './state.ts'
import { decryptAndParse } from './pgp/crypto.ts'
import { emailToMsg } from './app.ts'

export interface ProcessResult {
  bodyText: string
  encrypted: boolean
  unreadable: boolean
}

// PGP復号 + inner In-Reply-To 採用 + チェーン辿りで thread_id 継承。
// msg の in_reply_to / thread_id を in-place で書き換える。
// prior は先に処理済みの ProcessedMessage 配列（時系列順、古い→新しい）。
// UI と MD render の両方が同じロジックでスレッディングするための共通関数。
export async function processIncoming(
  msg: ProcessedMessage['msg'],
  selfEmail: string,
  prior: ProcessedMessage[],
): Promise<ProcessResult> {
  let bodyText = msg.body ?? ''
  let encrypted = false
  let unreadable = false

  if (bodyText.includes('-----BEGIN PGP MESSAGE-----')) {
    encrypted = !!(msg.keywords?.['$e2e'])
    const decrypted = await decryptAndParse(bodyText, selfEmail)
    if (decrypted != null) {
      bodyText = decrypted.body
      if (decrypted.inReplyTo && !msg.in_reply_to) {
        msg.in_reply_to = decrypted.inReplyTo
      }
    } else {
      unreadable = true
    }
  } else if (msg.keywords?.['$e2e']) {
    encrypted = true
  }

  console.log('[chain]', msg.message_id?.slice(0, 30), 'from:', msg.from, 'irt:', msg.in_reply_to?.slice(0, 40) || 'EMPTY', 'tid:', msg.thread_id?.slice(0, 30))
  if (msg.in_reply_to) {
    const parent = prior.find(p => p.msg.message_id === msg.in_reply_to)
    console.log('[chain] parent:', parent?.msg.message_id?.slice(0, 30) ?? 'MISS', 'parent.tid:', parent?.msg.thread_id?.slice(0, 30))
    if (parent && parent.msg.thread_id && parent.msg.thread_id !== msg.thread_id) {
      msg.thread_id = parent.msg.thread_id
    }
  }

  return { bodyText, encrypted, unreadable }
}

// 全 Email を時系列順に processIncoming で処理し、effective thread_id でグループ化。
// 返り値: { groups: Map<effectiveThreadId, Email[]>, emailById }。
// MD render が UI と同じスレッディング結果を再現するために使用。
export async function buildEffectiveGroups(
  emails: Email[], selfEmail: string,
): Promise<{ groups: Map<string, Email[]>; emailById: Map<string, Email> }> {
  const sorted = [...emails].sort(
    (a, b) => new Date(a.receivedAt as string).getTime() - new Date(b.receivedAt as string).getTime()
  )
  const emailById = new Map<string, Email>(sorted.map(e => [e.id as string, e]))
  const processed: ProcessedMessage[] = []
  const tidByEmailId = new Map<string, string>()

  for (const email of sorted) {
    const msg = emailToMsg(email, selfEmail)
    const r = await processIncoming(msg, selfEmail, processed)
    processed.push({ msg, bodyText: r.bodyText, encrypted: r.encrypted, unreadable: r.unreadable })
    const tid = msg.thread_id || msg.message_id
    if (tid) tidByEmailId.set(email.id as string, tid)
  }

  const groups = new Map<string, Email[]>()
  for (const email of sorted) {
    const tid = tidByEmailId.get(email.id as string)
    if (!tid) continue
    if (!groups.has(tid)) groups.set(tid, [])
    groups.get(tid)!.push(email)
  }

  return { groups, emailById }
}
