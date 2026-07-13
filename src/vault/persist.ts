import type { Email, Thread, Mailbox, Identity } from 'jmap-rfc-types'
import type { PendingSubmission } from '../types.ts'
import { vaultHandle, sessions, identityKey } from '../context.ts'
import { readJson, writeJson, scanDir, scanEntries, deleteFile } from './fs.ts'
import { writeThreadMD, ensureNewFile } from './render.ts'
import { mailboxNameFromId } from '../utils.ts'
import * as messages from '../store/messages.ts'
import * as threads from '../store/threads.ts'
import * as mailboxes from '../store/mailboxes.ts'
import * as identities from '../store/identities.ts'
import * as submissions from '../store/submissions.ts'
import * as cache from '../store/cache.ts'
import { buildEffectiveGroups } from '../processing.ts'

export async function loadFromVault(): Promise<void> {
  if (!vaultHandle) return

  await Promise.all([
    loadMessages(),
    loadThreads(),
    loadMailboxes(),
    loadIdentities(),
    loadSubmissions(),
  ])
}

async function loadMessages(): Promise<void> {
  try {
    // Messages live in per-account subdirs (.data/messages/<enc(account)>/<id>.json).
    // Each file is the full Email incl. its `_account` stamp, so messages.put keys
    // it correctly. Legacy flat files (pre-partitioning) lack the stamp and would
    // collide across accounts — delete them; they get re-fetched on next sync.
    const entries = await scanEntries(['.data', 'messages'])
    await Promise.all(entries.map(async ({ name, kind }) => {
      if (kind === 'directory') {
        for (const f of await scanDir(['.data', 'messages', name])) {
          if (!f.endsWith('.json')) continue
          const data = await readJson(['.data', 'messages', name, f])
          messages.put(data as Email)
        }
      } else if (name.endsWith('.json')) {
        try { await deleteFile(['.data', 'messages', name]) } catch { /* ignore */ }
      }
    }))
  } catch { /* dir may not exist */ }
}

async function loadThreads(): Promise<void> {
  try {
    const files = await scanDir(['.data', 'threads'])
    await Promise.all(
      files.filter(f => f.endsWith('.json')).map(async f => {
        const data = await readJson(['.data', 'threads', f])
        threads.put(data as Thread)
      })
    )
  } catch { /* dir may not exist */ }
}

async function loadMailboxes(): Promise<void> {
  try {
    const data = await readJson(['.data', 'mailboxes.json'])
    mailboxes.set(data as Mailbox[])
  } catch { /* file may not exist */ }
}

async function loadIdentities(): Promise<void> {
  try {
    const data = await readJson(['.data', 'identities.json'])
    identities.set(data as Identity[])
  } catch { /* file may not exist */ }
}

async function loadSubmissions(): Promise<void> {
  try {
    const files = await scanDir(['.data', 'submissions'])
    await Promise.all(
      files.filter(f => f.endsWith('.json')).map(async f => {
        const data = await readJson(['.data', 'submissions', f])
        submissions.put(data as PendingSubmission)
      })
    )
  } catch { /* dir may not exist */ }
}

function acctDir(account: string): string {
  return encodeURIComponent(account || '_unknown')
}

// A JMAP id doubles as a filename here. AP ids are URLs ('https://ap…/…') whose
// '/' and ':' make FileSystemDirectoryHandle.getFileHandle throw "Name is not
// allowed" — encode them. Reversible and collision-free; load paths key off the
// file's content, not its name, so encoding never has to be undone. Safe mail
// ids are unchanged by the encode, so existing vault files need no migration.
function fileId(id: string): string {
  return encodeURIComponent(id)
}

export async function flushMessage(email: Email): Promise<void> {
  await cache.putMessage(email)
  if (!vaultHandle) return
  await writeJson(['.data', 'messages', acctDir(messages.accountOf(email)), `${fileId(email.id as string)}.json`], email)
}

export async function removeMessage(account: string, id: string): Promise<void> {
  await cache.deleteMessage(account, id)
  if (!vaultHandle) return
  try {
    await deleteFile(['.data', 'messages', acctDir(account), `${fileId(id)}.json`])
  } catch { /* already gone */ }
}

export async function flushThread(thread: Thread): Promise<void> {
  await cache.putThread(thread)
  if (!vaultHandle) return
  await writeJson(['.data', 'threads', `${fileId(thread.id as string)}.json`], thread)
}

export async function flushMailboxes(): Promise<void> {
  await cache.putMailboxes(mailboxes.all())
  if (!vaultHandle) return
  await writeJson(['.data', 'mailboxes.json'], mailboxes.all())
}

export async function flushIdentities(): Promise<void> {
  await cache.putIdentities(identities.all())
  if (!vaultHandle) return
  await writeJson(['.data', 'identities.json'], identities.all())
}

export async function flushSubmission(sub: PendingSubmission): Promise<void> {
  if (!vaultHandle) return
  await writeJson(['.data', 'submissions', `${fileId(sub.id)}.json`], sub)
}

export async function flushAll(): Promise<void> {
  console.log('[vault] flushAll start, vaultHandle:', !!vaultHandle, 'messages:', messages.all().length, 'threads:', threads.all().length)
  if (!vaultHandle) { console.log('[vault] no handle, skip'); return }
  try {
    await Promise.all([
      ...messages.all().map(flushMessage),
      ...threads.all().map(flushThread),
      flushMailboxes(),
      flushIdentities(),
      ...submissions.all().map(flushSubmission),
    ])
    // MD render: UI と同じ effective thread_id でグループ化してから書き出す。
    // アカウントごとに own メッセージだけでグループ化する（JMAP id はアカウント
    // 間で衝突しうるため混ぜると誤スレッド化する）。
    const mailboxDirs = new Set<string>()
    for (const session of sessions) {
      const selfEmail = session.account.email
      const { groups } = await buildEffectiveGroups(messages.forIdentity(identityKey(session)), selfEmail)
      for (const [effectiveTid, threadEmails] of groups) {
        if (!threadEmails.length) continue
        const allMbxIds = new Set<string>()
        for (const e of threadEmails) {
          for (const id of Object.keys((e as any).mailboxIds ?? {})) allMbxIds.add(id)
        }
        const dirs = [...allMbxIds].map(id => mailboxNameFromId(id)).filter(Boolean)
        if (!dirs.length) continue
        for (const dirName of dirs) {
          mailboxDirs.add(dirName)
          await writeThreadMD(dirName, selfEmail, threadEmails, effectiveTid)
        }
      }
    }
    for (const dir of mailboxDirs) await ensureNewFile(dir)
    console.log('[vault] flushAll done, MD dirs:', [...mailboxDirs])
  } catch (e) {
    console.error('[vault] flushAll error:', e)
  }
}

export async function removeSubmission(id: string): Promise<void> {
  if (!vaultHandle) return
  try {
    await deleteFile(['.data', 'submissions', `${fileId(id)}.json`])
  } catch { /* already gone */ }
}
