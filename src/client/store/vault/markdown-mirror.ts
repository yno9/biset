import { bytesToBase64url, sha256Bytes } from '../../../protocol/canonical.ts'
import type { LocalJmapEmail, LocalJmapSnapshot } from '../projection/gateway.ts'

interface MarkdownFrontmatter { subject?: string; contact: string; id: string; status: string }
export interface ParsedMarkdown { frontmatter: MarkdownFrontmatter; draft: string }

export async function renderMarkdownThread(selfEmail: string, emails: LocalJmapEmail[], body: (email: LocalJmapEmail) => Promise<string>, preservedDraft = ''): Promise<string> {
  if (!emails.length) throw new TypeError('Markdown thread is empty')
  const sorted = [...emails].sort((a, b) => b.receivedAt.localeCompare(a.receivedAt)); const latest = sorted[0]!; const contact = threadContact(selfEmail, emails)
  const frontmatter = ['---', ...(latest.subject ? [`subject: "${latest.subject.replaceAll('"', '\\"')}"`] : []), `contact: ${contact}`, `id: ${latest.threadId}`, 'status: ', '---', '']
  const blocks = await Promise.all(sorted.map(async email => `- - -\n${formatTimestamp(email.receivedAt)} ${email.from?.[0]?.email ?? ''}\n\n${await body(email)}`))
  return `${frontmatter.join('\n')}\n${preservedDraft.trim()}${preservedDraft.trim() ? '\n\n' : ''}${blocks.join('\n\n')}`
}

export function parseMarkdownThread(content: string): ParsedMarkdown {
  const match = /^---\n([\s\S]*?)\n---\n?([\s\S]*)$/.exec(content)
  if (!match) throw new TypeError('Markdown frontmatter is invalid')
  const values: Record<string, string> = {}
  for (const line of match[1]!.split('\n')) { const index = line.indexOf(':'); if (index >= 0) values[line.slice(0, index).trim()] = line.slice(index + 1).trim().replace(/^"|"$/g, '') }
  const remainder = match[2]!.replace(/^\n+/, ''); const divider = remainder.indexOf('- - -')
  return { frontmatter: { ...(values.subject ? { subject: values.subject } : {}), contact: values.contact ?? '', id: values.id ?? '', status: values.status ?? '' }, draft: (divider < 0 ? remainder : remainder.slice(0, divider)).trim() }
}

export function markdownThreadFilename(selfEmail: string, emails: LocalJmapEmail[]): string {
  const oldest = [...emails].sort((a, b) => a.receivedAt.localeCompare(b.receivedAt))[0]!; const date = new Date(oldest.receivedAt); const short = `${pad(date.getMonth() + 1)}${pad(date.getDate())}${pad(date.getHours())}${pad(date.getMinutes())}`
  const unread = emails.some(email => email.from?.[0]?.email?.toLowerCase() !== selfEmail.toLowerCase() && !email.keywords.$seen)
  return `${unread ? '_' : ''}${safeFilename(threadContact(selfEmail, emails))}_${short}.md`
}

/** Hashes written content so observer callbacks can suppress only the exact
 * self-write while still accepting a user's immediate subsequent edit. */
export class MarkdownSelfWriteGuard {
  private readonly hashes = new Map<string, string>()
  note(path: string, content: string): void { this.hashes.set(path, hash(content)) }
  consumeIfSelfWrite(path: string, content: string): boolean { const expected = this.hashes.get(path); if (expected !== hash(content)) return false; this.hashes.delete(path); return true }
}
export function markdownStatusMutation(status: string, thread: LocalJmapEmail[], snapshot: LocalJmapSnapshot): Record<string, unknown> | undefined {
  const normalized = status.trim().toLowerCase()
  if (!thread.length || !normalized) return
  if (normalized === 'deleted') return { destroy: thread.map(email => email.id) }
  const destination = snapshot.mailboxes.find(mailbox => mailbox.role === (normalized === 'spam' ? 'junk' : normalized === 'archived' ? 'archive' : ''))
  const update: Record<string, { keywords?: Record<string, boolean>; mailboxIds?: Record<string, boolean> }> = {}
  for (const email of thread) {
    if (normalized === 'seen') update[email.id] = { keywords: { ...email.keywords, $seen: true } }
    if (normalized === 'follow') update[email.id] = { keywords: { ...email.keywords, $flagged: true } }
    if (destination) update[email.id] = { mailboxIds: { [destination.id]: true } }
  }
  return Object.keys(update).length ? { update } : undefined
}
function hash(value: string): string { return bytesToBase64url(sha256Bytes(new TextEncoder().encode(value))) }
function threadContact(self: string, emails: LocalJmapEmail[]): string { for (const email of emails) { const from = email.from?.[0]?.email ?? ''; if (from.toLowerCase() !== self.toLowerCase()) return from; for (const to of email.to ?? []) if (to.email && to.email.toLowerCase() !== self.toLowerCase()) return to.email } return self }
function safeFilename(value: string): string { return value.replace(/[/\\:*?"<>|]/g, '_') }
function pad(value: number): string { return String(value).padStart(2, '0') }
function formatTimestamp(value: string): string { const date = new Date(value); return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}-${pad(date.getHours())}:${pad(date.getMinutes())}` }
