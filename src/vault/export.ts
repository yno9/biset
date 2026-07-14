// "How your data is stored" archive export — reuses the SAME rendering logic
// vault sync already uses to write conversations as human-readable markdown
// (render.ts), so an exported archive isn't just the raw on-disk JSON but
// also a `Markdown/` folder that reads the same way the vault does.
import type { Email } from 'jmap-rfc-types'
import { renderContent, threadContact, threadShortId, isSeen, threadFilename } from './render.ts'
import { buildZip, type ZipEntryInput } from './zip.ts'

function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

// `files` is exportAccountStorage's raw relative-path → base64 map (one
// relay's worth). Returns zip entries under `JSON/<path>` (every file exactly
// as it sits on disk) plus `Markdown/<contact>_<shortId>.md` per thread
// (grouped by threadId, rendered with the same renderContent vault sync uses
// — including PGP decryption for encrypted bodies, since this runs in an
// already-unlocked session same as any other vault write).
export async function buildAccountArchiveEntries(selfEmail: string, files: Record<string, string>): Promise<ZipEntryInput[]> {
  const entries: ZipEntryInput[] = []
  const byThread = new Map<string, Email[]>()

  for (const [path, b64] of Object.entries(files)) {
    const data = b64ToBytes(b64)
    entries.push({ path: `JSON/${path}`, data })
    if (!path.startsWith('messages/') || !path.endsWith('.json')) continue
    try {
      const email = JSON.parse(new TextDecoder().decode(data)) as Email
      const tid = (email.threadId as string) || (email.id as string) || path
      const group = byThread.get(tid)
      if (group) group.push(email)
      else byThread.set(tid, [email])
    } catch { /* skip unparseable message files, JSON/ copy is still included */ }
  }

  const enc = new TextEncoder()
  for (const emails of byThread.values()) {
    if (!emails.length) continue
    const contact = threadContact(selfEmail, emails)
    const shortId = threadShortId(emails)
    const seen = isSeen(selfEmail, emails)
    const filename = threadFilename(contact, shortId, seen)
    const content = await renderContent(selfEmail, emails)
    entries.push({ path: `Markdown/${filename}`, data: enc.encode(content) })
  }

  return entries
}

export { buildZip }
