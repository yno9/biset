import type { PendingSubmission } from '../types.ts'
import { mailboxRoutes } from '../context.ts'
import * as submissions from '../store/submissions.ts'
import * as messages from '../store/messages.ts'
import * as storeMailboxes from '../store/mailboxes.ts'
import * as storeIdentities from '../store/identities.ts'
import * as persist from '../vault/persist.ts'
import * as jmapEmail from '../jmap/email.ts'
import * as jmapSubmission from '../jmap/submission.ts'
import { parseFrontmatter, extractBody, writeThreadMD } from '../vault/render.ts'
import { readText, writeText } from '../vault/fs.ts'
import { encryptText } from '../pgp/crypto.ts'
import { groupDraftHeaders } from '../deltachat/protocol.ts'
import { mailboxNameFromId } from '../utils.ts'
import { buildEffectiveGroups } from '../processing.ts'

// ── markThreadSeen (共通) ─────────────────────────────────────────────────────
// status:seen 押下時 (flushActions) と 返信時 (flushOutgoing) の両方が呼ぶ単一エントリ。
// unseen → seen への遷移 (prefix `_` 除去) は必ずこのロジックを通す。
//
// 処理:
//   1. buildEffectiveGroups で effective thread 集合を引く
//   2. JMAP server に markSeen
//   3. local store の keywords.$seen 更新 + persist
//   4. clearMDStatus で元 path を上書き (cui editor とのコンテンツ差異を発生させて
//      cui の loadFile を強制 → autosave 残骸が削除済 path に再書き込みする loop 防止)
//   5. writeThreadMD で全 dir に再描画 (prefix `_` ありの旧ファイル削除込み)
async function markThreadSeen(
  mailboxName: string,
  mdPath: string[],
  content: string,
  threadId: string,
): Promise<void> {
  const session = mailboxRoutes.get(mailboxName)
  const selfEmail = session?.account.email ?? mailboxName
  const { groups } = await buildEffectiveGroups(messages.forIdentity(selfEmail), selfEmail)
  const threadMsgs = groups.get(threadId) ?? []
  if (!threadMsgs.length) return

  const emailIds = threadMsgs.map(e => e.id as string).filter(Boolean)
  if (session && emailIds.length) {
    try {
      await jmapEmail.markSeen(session.jmapClient, session.jmapAccountId, emailIds)
    } catch (e) { console.log('[markThreadSeen] markSeen failed', e) }
  }

  for (const m of threadMsgs) {
    const keywords = ((m as any).keywords ?? {}) as Record<string, boolean>
    if (!keywords['$seen']) {
      keywords['$seen'] = true
      ;(m as any).keywords = keywords
      messages.put(m)
      await persist.flushMessage(m)
    }
  }

  await clearMDStatus(mdPath, content, true)

  const allMbxIds = new Set<string>()
  for (const m of threadMsgs) {
    for (const id of Object.keys((m as any).mailboxIds ?? {})) allMbxIds.add(id)
  }
  const dirs = [...allMbxIds].map(id => mailboxNameFromId(id)).filter(Boolean)
  for (const dir of dirs) {
    await writeThreadMD(dir, selfEmail, threadMsgs, threadId)
  }
}

// ── flushOutgoing ─────────────────────────────────────────────────────────────

export async function flushOutgoing(mailboxName: string, mdPath: string[]): Promise<void> {
  console.log('[flushOutgoing] start', mailboxName, mdPath.join('/'))
  const content = await readText(mdPath)
  const fm = parseFrontmatter(content)
  let body = extractBody(content)
  console.log('[flushOutgoing] body len', body.length, 'fm keys', Object.keys(fm))
  if (!body) { console.log('[flushOutgoing] no body, bail'); return }
  if (body.includes('!b')) body = body.replace(/!b/g, '').trim()
  if (!body) return

  // biset-old actions.go:95-129 同等: threadId から最新 msg を引き、
  // その RFC Message-Id を inReplyTo に。 subject も "Re: " 補完。
  let inReplyTo = fm['inReplyTo'] ?? ''
  let subject = fm['subject'] ?? ''
  let contact = fm['contact'] ?? ''
  const threadId = fm['id'] ?? ''
  if (threadId) {
    const acct = mailboxRoutes.get(mailboxName)?.account.email ?? mailboxName
    const threadMsgs = messages.byThread(acct, threadId)
      .sort((a, b) => new Date(a.receivedAt!).getTime() - new Date(b.receivedAt!).getTime())
    const orig = threadMsgs[threadMsgs.length - 1]
    if (orig) {
      if (!contact) {
        const fromAddr = orig.from?.[0]?.email ?? ''
        if (fromAddr.toLowerCase() === mailboxName.toLowerCase() && orig.to?.[0]?.email) {
          contact = orig.to[0].email
        } else {
          contact = fromAddr
        }
      }
      if (!subject) {
        subject = orig.subject ?? ''
        if (subject && !/^re:/i.test(subject)) subject = 'Re: ' + subject
      }
      if (!inReplyTo) {
        const mid = (orig.messageId as string[] | undefined)?.[0]
        if (mid) inReplyTo = mid
      }
    }
  }

  if (!contact) return

  const sub: PendingSubmission = {
    id: crypto.randomUUID(),
    mailboxName,
    contact,
    subject,
    body,
    threadId,
    inReplyTo,
    createdAt: new Date().toISOString(),
  }

  console.log('[flushOutgoing] sub', { contact, subject, threadId, inReplyTo, bodyLen: body.length })
  submissions.put(sub)
  await persist.flushSubmission(sub)

  if (threadId) {
    await markThreadSeen(mailboxName, mdPath, content, threadId)
  } else {
    await clearMDStatus(mdPath, content, true)
  }

  await dispatchSubmissions()
}

// ── dispatchSubmissions ───────────────────────────────────────────────────────

export async function dispatchSubmissions(): Promise<void> {
  const pending = submissions.all()
  console.log('[dispatchSubmissions] pending:', pending.length)
  await Promise.allSettled(pending.map(dispatch))
}

async function dispatch(sub: PendingSubmission): Promise<void> {
  console.log('[dispatch] start', sub.id, sub.mailboxName, '→', sub.contact)
  const session = mailboxRoutes.get(sub.mailboxName)
  if (!session) { console.log('[dispatch] no session for', sub.mailboxName); return }

  const { jmapClient: client, jmapAccountId: accountId } = session
  const mailbox = storeMailboxes.byName(sub.mailboxName)
  if (!mailbox) { console.log('[dispatch] no mailbox', sub.mailboxName); return }

  const identityList = storeIdentities.all()
  const identity = identityList.find(i => (i.email as string) === session.account.email)
    ?? identityList[0]
  if (!identity) { console.log('[dispatch] no identity'); return }

  const fromEmail = session.account.email
  const recipients = sub.recipients?.length ? sub.recipients : [sub.contact]
  let emailBody = sub.body
  try {
    const enc = await encryptText(
      sub.body, recipients, fromEmail,
      session.account.serverUrl, session.account.password,
      sub.inReplyTo ?? '',
      sub.group_id ? { id: sub.group_id, name: sub.group_name ?? '' } : undefined,
    )
    if (enc) emailBody = enc
  } catch (e) {
    console.log('[dispatch] encrypt failed', e)
  }

  const draft: Record<string, any> = {
    mailboxIds: { [mailbox.id as string]: true },
    keywords: { $draft: true },
    from: [{ email: fromEmail }],
    to: [{ email: recipients[0] }],
    subject: sub.subject || '',
    textBody: [{ partId: '1', type: 'text/plain' }],
    bodyValues: { '1': { value: emailBody, isEncodingProblem: false, isTruncated: false } },
  }
  if (recipients.length > 1) draft['cc'] = recipients.slice(1).map(e => ({ email: e }))
  if (sub.inReplyTo) draft['inReplyTo'] = [sub.inReplyTo]
  if (sub.group_id) Object.assign(draft, groupDraftHeaders({ id: sub.group_id, name: sub.group_name ?? '' }))

  try {
    await jmapSubmission.send(client, accountId, draft, identity.id as string)
  } catch (e) {
    console.log('[dispatch] send failed', sub.id, e)
    return
  }
  submissions.remove(sub.id)
  await persist.removeSubmission(sub.id)
}

// ── flushActions ──────────────────────────────────────────────────────────────

export async function flushActions(
  mailboxName: string,
  mdPath: string[],
  status: string,
): Promise<void> {
  const session = mailboxRoutes.get(mailboxName)
  if (!session) return

  const { jmapClient: client, jmapAccountId: accountId } = session
  const content = await readText(mdPath)
  const fm = parseFrontmatter(content)
  const threadId = fm['id']
  if (!threadId) return

  const emailIds = messages.byThread(session.account.email, threadId).map(e => e.id as string)
  if (!emailIds.length) return

  switch (status) {
    case 'seen': {
      // 返信時 (flushOutgoing) と完全に同一ロジック経由
      await markThreadSeen(mailboxName, mdPath, content, threadId)
      return
    }
    case 'archived':
      await jmapEmail.markArchived(client, accountId, emailIds)
      break
    case 'deleted':
      await jmapEmail.destroy(client, accountId, emailIds)
      break
    case 'spam':
      await jmapEmail.markSpam(client, accountId, emailIds)
      break
    case 'follow': {
      const contact = fm['contact'] ?? ''
      if (!contact) return
      const mailbox = storeMailboxes.byName(mailboxName)
      if (!mailbox) return
      await (client.api as any).Email.set({
        accountId,
        create: {
          follow: {
            from: [{ email: session.account.email }],
            to: [{ email: contact }],
            mailboxIds: { [mailbox.id as string]: true },
            keywords: { '$follow': true },
          },
        },
      })
      break
    }
  }

  await clearMDStatus(mdPath, content, false)
}

// ── helpers ───────────────────────────────────────────────────────────────────

async function clearMDStatus(
  mdPath: string[],
  content: string,
  clearBody: boolean,
): Promise<void> {
  let updated = content.replace(/^status:.*$/m, 'status:')
  if (clearBody) {
    const lines = updated.split('\n')
    if (lines[0] === '---') {
      let fmEnd = -1
      for (let i = 1; i < lines.length; i++) {
        if (lines[i] === '---') { fmEnd = i; break }
      }
      if (fmEnd > 0) {
        let bodyEnd = lines.length
        for (let i = fmEnd + 1; i < lines.length; i++) {
          if (lines[i] === '- - -') { bodyEnd = i; break }
        }
        const fm = lines.slice(0, fmEnd + 1)
        const rest = lines.slice(bodyEnd)
        // biset-old ClearBody 同等: FM close と `- - -` 間に 3 空行
        updated = [...fm, '', '', '', ...rest].join('\n')
      }
    }
  }
  await writeText(mdPath, updated)
}
