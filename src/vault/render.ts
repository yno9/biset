import type { Email } from 'jmap-rfc-types'
import { readText, writeText, deleteFile, scanDir } from './fs.ts'
import { decryptAndParse } from '../pgp/crypto.ts'

// ── Pure helpers ──────────────────────────────────────────────────────────────

export function safeFilename(s: string): string {
  return s.replace(/[/\\:*?"<>|]/g, '_')
}

function formatTs(receivedAt: string): string {
  const d = new Date(receivedAt)
  const yyyy = d.getFullYear()
  const mm = String(d.getMonth() + 1).padStart(2, '0')
  const dd = String(d.getDate()).padStart(2, '0')
  const HH = String(d.getHours()).padStart(2, '0')
  const MM = String(d.getMinutes()).padStart(2, '0')
  return `${yyyy}-${mm}-${dd}-${HH}:${MM}`
}

function emailBodyRaw(e: Email): string {
  if (e.bodyValues && e.textBody?.length) {
    const partId = (e.textBody[0] as any).partId as string
    return (e.bodyValues as any)[partId]?.value ?? ''
  }
  return (e as any).preview ?? ''
}

async function emailBodyDecrypted(e: Email, selfEmail: string): Promise<string> {
  const raw = emailBodyRaw(e)
  if (!raw.includes('-----BEGIN PGP MESSAGE-----')) return raw
  const decrypted = await decryptAndParse(raw, selfEmail)
  return decrypted?.body ?? raw
}

export function threadContact(selfEmail: string, emails: Email[]): string {
  for (const e of emails) {
    const from = e.from?.[0]?.email ?? ''
    if (from.toLowerCase() !== selfEmail.toLowerCase()) return from
    for (const a of [...(e.to ?? []), ...(e.cc ?? [])]) {
      if ((a as any).email?.toLowerCase() !== selfEmail.toLowerCase()) return (a as any).email ?? ''
    }
  }
  return selfEmail
}

export function isSeen(selfEmail: string, emails: Email[]): boolean {
  for (const e of emails) {
    const from = e.from?.[0]?.email ?? ''
    if (from.toLowerCase() !== selfEmail.toLowerCase() && !e.keywords?.['$seen']) return false
  }
  return true
}

export function threadShortId(emails: Email[]): string {
  const oldest = [...emails].sort(
    (a, b) => new Date(a.receivedAt!).getTime() - new Date(b.receivedAt!).getTime()
  )[0]!
  const d = new Date(oldest.receivedAt!)
  const mm = String(d.getMonth() + 1).padStart(2, '0')
  const dd = String(d.getDate()).padStart(2, '0')
  const HH = String(d.getHours()).padStart(2, '0')
  const MM = String(d.getMinutes()).padStart(2, '0')
  return `${mm}${dd}${HH}${MM}`
}

// ── Frontmatter / body parsing ────────────────────────────────────────────────

function splitFM(content: string): [string, string, string] | null {
  const i1 = content.indexOf('---')
  if (i1 < 0) return null
  const i2 = content.indexOf('---', i1 + 3)
  if (i2 < 0) return null
  return [content.slice(0, i1), content.slice(i1 + 3, i2), content.slice(i2 + 3)]
}

export function parseFrontmatter(content: string): Record<string, string> {
  const fm: Record<string, string> = {}
  const parts = splitFM(content)
  if (!parts) return fm
  for (const line of parts[1].split('\n')) {
    const idx = line.indexOf(': ')
    if (idx < 0) continue
    fm[line.slice(0, idx).trim()] = line.slice(idx + 2).trim().replace(/^"|"$/g, '')
  }
  return fm
}

export function extractBody(content: string): string {
  const parts = splitFM(content)
  if (!parts) return ''
  const after = parts[2].replace(/^\n+/, '')
  if (after.startsWith('- - -')) return ''
  const idx = after.indexOf('\n- - -')
  const body = idx < 0 ? after : after.slice(0, idx)
  return body.trim()
}

export function injectBody(content: string, body: string): string {
  const parts = splitFM(content)
  if (!parts) return content
  const rest = parts[2].replace(/^\n+/, '')
  return parts[0] + '---' + parts[1] + '---\n' + body + '\n\n' + rest
}

// ── Render ────────────────────────────────────────────────────────────────────

export async function renderContent(
  selfEmail: string, emails: Email[], effectiveThreadId?: string,
): Promise<string> {
  const sorted = [...emails].sort(
    (a, b) => new Date(b.receivedAt!).getTime() - new Date(a.receivedAt!).getTime()
  )
  const latest = sorted[0]!
  const contact = threadContact(selfEmail, emails)
  const threadId = effectiveThreadId ?? (latest.threadId as string | undefined) ?? ''

  const fmLines = ['---']
  if (latest.subject) fmLines.push(`subject: "${latest.subject.replace(/"/g, '\\"')}"`)
  fmLines.push(`contact: ${contact}`)
  if (threadId) fmLines.push(`id: ${threadId}`)
  fmLines.push('status: ')
  fmLines.push('---')
  fmLines.push('')

  const msgBlocks = await Promise.all(sorted.map(async e => {
    const from = e.from?.[0]?.email ?? ''
    const ts = formatTs(e.receivedAt!)
    const body = await emailBodyDecrypted(e, selfEmail)
    return `- - -\n${ts} ${from}\n\n${body}`
  }))

  return fmLines.join('\n') + '\n\n\n' + msgBlocks.join('\n\n')
}

// ── File path helpers ─────────────────────────────────────────────────────────

export function threadFilename(contact: string, shortId: string, seen: boolean): string {
  const base = `${safeFilename(contact)}_${shortId}.md`
  return seen ? base : `_${base}`
}

function dirSegments(dirName: string): string[] {
  return dirName.split('/').filter(Boolean)
}

async function findExistingMDs(dirName: string, shortId: string): Promise<string[]> {
  let files: string[]
  try {
    files = await scanDir(dirSegments(dirName))
  } catch {
    return []
  }
  const out: string[] = []
  for (const name of files) {
    if (!name.endsWith('.md') || name === '_new.md') continue
    const base = name.startsWith('_') ? name.slice(1) : name
    if (base.endsWith(`_${shortId}.md`)) out.push(name)
  }
  return out
}

// ── Write ─────────────────────────────────────────────────────────────────────

export async function writeThreadMD(
  dirName: string, selfEmail: string, emails: Email[], effectiveThreadId?: string,
): Promise<boolean> {
  if (!emails.length) return false

  const contact = threadContact(selfEmail, emails)
  const shortId = threadShortId(emails)
  const seen = isSeen(selfEmail, emails)
  const newFilename = threadFilename(contact, shortId, seen)
  const segs = dirSegments(dirName)
  const newPath = [...segs, newFilename]

  let content = await renderContent(selfEmail, emails, effectiveThreadId)

  // 同一 shortId の MD が複数あれば全部対象。 draft は最初に見つかったものから採用。
  const oldFilenames = await findExistingMDs(dirName, shortId)
  console.log('[writeThreadMD]', dirName, 'new:', newFilename, 'old:', oldFilenames, 'seen:', seen)
  let draft = ''
  for (const name of oldFilenames) {
    try {
      const existing = await readText([...segs, name])
      const d = extractBody(existing)
      if (d && !draft) draft = d
    } catch { /* ignore */ }
  }
  if (draft) content = injectBody(content, draft)

  // newFilename と一致しない旧ファイルは全削除 (orphan 防止)
  for (const name of oldFilenames) {
    if (name === newFilename) continue
    try {
      await deleteFile([...segs, name])
      console.log('[writeThreadMD] deleted', name)
    } catch (e) {
      console.log('[writeThreadMD] delete failed', name, (e as Error)?.message)
    }
  }

  await writeText(newPath, content)
  console.log('[writeThreadMD] wrote', newFilename)
  return true
}

export async function ensureNewFile(dirName: string): Promise<void> {
  const path = [...dirSegments(dirName), '_new.md']
  try {
    await readText(path)
  } catch {
    await writeText(path, '---\ncontact: \nstatus: \n---\n')
  }
}
