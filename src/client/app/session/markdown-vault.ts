// The Markdown vault: the identity's threads mirrored into a folder the person chose (File System Access API), where a file's
// status (read, archived, ...) is written back to the Vault and a draft marked to be sent goes out.
import { MarkdownDirectoryConnection, observeMarkdownDirectory, removeMarkdownMirrorFile, scanMarkdownProjection, writeMarkdownProjection, type MarkdownMirrorFile } from '../../store/vault/markdown-directory.ts'
import { MarkdownSelfWriteGuard, markdownStatusMutation } from '../../store/vault/markdown-mirror.ts'
import { rotatedEmail, rotationReader } from '../../store/projection/contacts.ts'
import type { LocalJmapSnapshot } from '../../store/projection/gateway.ts'
import { sameIdentity } from '../../../protocol/vh/identifier.ts'
import { configureMarkdownVaultToggle } from '../ui/pages/index.ts'
import type { ReplySendInput } from '../ui/reply-box.tsx'
import type { AccountVault } from './account-vault.ts'
import { timed } from './boot-timing.ts'

const SEND_MARK = /(^|\n)!b(?:\n|$)/
/** The id of the scaffold a new message is written in (Drafts/_new.md): the one file whose recipient the person names freely. */
const NEW_DRAFT_ID = 'new'

/** Where a draft in a thread's file may go: only to someone already in that thread (read as the projection reads it: a rotated
 * DID as its counterparty's). The file is plain text anyone with the folder can edit, and a thread's text comes from others. */
function isThreadParticipant(contact: string, threadId: string, snapshot: LocalJmapSnapshot): boolean {
  const reader = rotationReader(snapshot.contactCards)
  const same = (address: string) => sameIdentity(address, contact) || address.toLowerCase() === contact.toLowerCase()
  return snapshot.emails.some(email => {
    if (email.threadId !== threadId) return false
    const shown = rotatedEmail(email, reader) ?? email
    return [...(shown.from ?? []), ...(shown.to ?? [])].some(party => party.email !== undefined && same(party.email))
  })
}

export async function startMarkdownVault(vault: AccountVault, send: (input: ReplySendInput) => Promise<void>): Promise<void> {
  const { identityId, readModel } = vault
  const directories = await MarkdownDirectoryConnection.open()
  const guard = new MarkdownSelfWriteGuard()
  let root = await timed('markdownDirectories.restore', directories.restore(identityId))
  let observer: { disconnect(): void; supported: boolean } | undefined

  const sendDraft = async (file: MarkdownMirrorFile, snapshot: LocalJmapSnapshot) => {
    const { id, contact } = file.parsed.frontmatter
    if (id !== NEW_DRAFT_ID && !isThreadParticipant(contact, id, snapshot)) throw new Error(`Markdown draft not sent: ${contact} is not in thread ${id}`)
    const last = snapshot.emails.filter(email => email.threadId === id).at(-1)
    await send({
      toAddrs: [file.parsed.frontmatter.contact], subject: file.parsed.frontmatter.subject ?? '',
      body: file.parsed.draft.replace(new RegExp(SEND_MARK.source, 'g'), '$1').trim(),
      ...(last ? { inReplyTo: last.id } : {}),
    })
  }
  const start = async (directory: FileSystemDirectoryHandle): Promise<void> => {
    observer?.disconnect()
    await writeMarkdownProjection(directory, readModel, identityId, guard)
    observer = observeMarkdownDirectory(directory, () => {
      void scanMarkdownProjection(directory, guard).then(async files => {
        const snapshot = await readModel.snapshot()
        for (const file of files) {
          const thread = snapshot.emails.filter(email => email.threadId === file.parsed.frontmatter.id)
          const status = file.parsed.frontmatter.status.trim().toLowerCase()
          if (status === 'send' || SEND_MARK.test(file.parsed.draft)) {
            try { await sendDraft(file, snapshot); await removeMarkdownMirrorFile(directory, file.path) } catch (error) { console.warn('[Markdown Vault send]', error) }
            continue
          }
          if (!thread.length || !status) continue
          const mutation = markdownStatusMutation(status, thread, snapshot)
          if (mutation) await vault.mutationSink.emailSet({ accountId: vault.accountId, ...mutation }, snapshot)
        }
        await writeMarkdownProjection(directory, readModel, identityId, guard)
      }).catch(error => console.warn('[Markdown Vault]', error))
    })
  }

  if (root) void start(root).catch(error => console.warn('[Markdown Vault restore]', error))
  configureMarkdownVaultToggle({
    enabled: () => root !== undefined,
    observerSupported: () => observer?.supported ?? false,
    async rescan() { if (root) await start(root) },
    async toggle() {
      if (root) {
        observer?.disconnect(); observer = undefined; root = undefined
        await directories.remove(identityId)
        return
      }
      const picker = (window as unknown as { showDirectoryPicker(options?: { mode?: 'read' | 'readwrite' }): Promise<FileSystemDirectoryHandle> }).showDirectoryPicker
      root = await picker({ mode: 'readwrite' })
      await directories.save(identityId, root)
      await start(root)
    },
  })
}
