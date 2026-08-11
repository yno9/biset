// "How your data is stored" archive export — reuses the SAME rendering logic
// vault sync already uses to write conversations as human-readable markdown
// (render.ts), so an exported archive isn't just the raw on-disk JSON but
// also a `Markdown/` folder that reads the same way the vault does.
import type { Email } from 'jmap-rfc-types'
import { renderContent, threadContact, threadShortId, isSeen, threadFilename } from './render.ts'
import { buildZip, readZip, type ZipEntryInput } from './zip.ts'

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

/** Local-only counterpart to buildAccountArchiveEntries, for the mediator
 * card's "Download" button. There is no server copy to fetch from here —
 * mediator delivery is pickup-and-persist-locally by design (the queue
 * itself is deliberately volatile, queue.ts's own header), so DIDComm
 * messages only ever exist in this device's local Email store. Same
 * `JSON/` + `Markdown/` shape as the relay export so the two read
 * consistently, just built straight from local `Email[]` (store/messages.ts)
 * instead of a server-fetched base64 file bundle. `devices` is the public
 * kid/key list only (didcomm-devices.ts's own local record also carries this
 * device's private keys — never included in a downloadable file). */
export async function buildMediatorArchiveEntries(selfDid: string, emails: Email[], devices: Array<{ kid: string; publicKey: string; isSelf: boolean }>): Promise<ZipEntryInput[]> {
  const entries: ZipEntryInput[] = [
    { path: 'JSON/devices.json', data: new TextEncoder().encode(JSON.stringify(devices, null, 2)) },
  ]
  const byThread = new Map<string, Email[]>()

  for (const email of emails) {
    entries.push({ path: `JSON/messages/${email.id}.json`, data: new TextEncoder().encode(JSON.stringify(email, null, 2)) })
    const tid = (email.threadId as string) || (email.id as string)
    const group = byThread.get(tid)
    if (group) group.push(email)
    else byThread.set(tid, [email])
  }

  const enc = new TextEncoder()
  for (const threadEmails of byThread.values()) {
    if (!threadEmails.length) continue
    const contact = threadContact(selfDid, threadEmails)
    const shortId = threadShortId(threadEmails)
    const seen = isSeen(selfDid, threadEmails)
    const filename = threadFilename(contact, shortId, seen)
    const content = await renderContent(selfDid, threadEmails)
    entries.push({ path: `Markdown/${filename}`, data: enc.encode(content) })
  }

  return entries
}

/** The other direction of buildMediatorArchiveEntries — restores local DIDComm
 * message history from a zip this same feature produced earlier. Scoped to
 * `JSON/messages/*.json` only: `devices.json` is public key metadata with no
 * private key alongside it (buildMediatorArchiveEntries's own note on why),
 * so there is nothing an import could actually DO with it — no device to
 * re-register, just inert data — and `Markdown/` is a rendering of the same
 * messages, re-parsing it back into Email would be lossy and redundant.
 * Returns the parsed emails for the caller to `messages.put()` (kept
 * store-agnostic here, matching the rest of this file); a message that fails
 * to parse is skipped rather than aborting the whole import — one corrupt
 * entry in an otherwise-good backup shouldn't cost the rest of it. */
export function parseMediatorArchive(zipBytes: Uint8Array): Email[] {
  const emails: Email[] = []
  for (const entry of readZip(zipBytes)) {
    if (!entry.path.startsWith('JSON/messages/') || !entry.path.endsWith('.json')) continue
    try {
      emails.push(JSON.parse(new TextDecoder().decode(entry.data)) as Email)
    } catch { /* skip unparseable entry, rest of the archive still imports */ }
  }
  return emails
}

export { buildZip }
