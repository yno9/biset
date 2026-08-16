import type { Email } from 'jmap-rfc-types'
import type { ProcessedMessage, MsgAttachment } from './state.ts'
import { decryptAndParse } from './pgp/crypto.ts'
import { emailToMsg } from './app.ts'
import { bytesToDataUrl } from './utils.ts'
import { computeThreadKeys, nodeId } from './threading.ts'

export interface ProcessResult {
  bodyText: string
  encrypted: boolean
  unreadable: boolean
  attachments?: MsgAttachment[]
}

// PGP復号 + 暗号化MIMEの内側にしかない参照ヘッダ（In-Reply-To / References）の
// 採用。msg を in-place で書き換える。DeltaChat は参照ヘッダを暗号化部の中にしか
// 置かないので、ここで拾わないと threading.ts が Thread 併合の辺を張れない。
// スレッド判定そのものは threading.ts（computeThreadKeys）が全メッセージを
// まとめて見て行う。UI と MD render が同じ結果になるよう共通化してある。
export async function processIncoming(
  msg: ProcessedMessage['msg'],
  selfEmail: string,
): Promise<ProcessResult> {
  let bodyText = msg.body ?? ''
  let encrypted = false
  let unreadable = false
  let attachments: MsgAttachment[] | undefined

  if (bodyText.includes('-----BEGIN PGP MESSAGE-----')) {
    encrypted = !!(msg.keywords?.['$e2e'])
    const decrypted = await decryptAndParse(bodyText, selfEmail)
    if (decrypted != null) {
      bodyText = decrypted.body
      if (decrypted.inReplyTo && !msg.in_reply_to) {
        msg.in_reply_to = decrypted.inReplyTo
      }
      if (decrypted.references?.length) {
        const merged = new Set([...(msg.references ?? []), ...decrypted.references])
        msg.references = [...merged]
      }
      if (decrypted.attachments?.length) {
        attachments = decrypted.attachments.map(a => ({
          filename: a.filename,
          contentType: a.contentType,
          dataUrl: bytesToDataUrl(a.bytes, a.contentType),
        }))
      }
    } else {
      unreadable = true
    }
  } else if (msg.keywords?.['$e2e']) {
    encrypted = true
  }

  return { bodyText, encrypted, unreadable, attachments }
}

// 全 Email を時系列順に processIncoming で処理し、threading.ts のスレッドキーで
// グループ化。返り値: { groups: Map<threadKey, Email[]>, emailById }。
// MD render が UI と同じスレッディング結果を再現するために使用。
export async function buildEffectiveGroups(
  emails: Email[], selfEmail: string,
): Promise<{ groups: Map<string, Email[]>; emailById: Map<string, Email> }> {
  const sorted = [...emails].sort(
    (a, b) => new Date(a.receivedAt as string).getTime() - new Date(b.receivedAt as string).getTime()
  )
  const emailById = new Map<string, Email>(sorted.map(e => [e.id as string, e]))
  const msgs: ProcessedMessage['msg'][] = []

  for (const email of sorted) {
    const msg = emailToMsg(email, selfEmail)
    await processIncoming(msg, selfEmail)
    msgs.push(msg)
  }

  const keys = computeThreadKeys(msgs)
  const groups = new Map<string, Email[]>()
  sorted.forEach((email, i) => {
    const tid = keys.get(nodeId(msgs[i]!))
    if (!tid) return
    if (!groups.has(tid)) groups.set(tid, [])
    groups.get(tid)!.push(email)
  })

  return { groups, emailById }
}
