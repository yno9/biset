// The Markdown vault: the identity's threads mirrored into a folder the person chose (File System Access API), where a file's
// status (read, archived, ...) is written back to the Vault and a draft marked to be sent goes out.
import { MarkdownDirectoryConnection, observeMarkdownDirectory, removeMarkdownMirrorFile, scanMarkdownProjection, writeMarkdownProjection, type MarkdownMirrorFile } from '../../store/vault/markdown-directory.ts'
import { MarkdownSelfWriteGuard, markdownStatusMutation } from '../../store/vault/markdown-mirror.ts'
import { configureMarkdownVaultToggle } from '../ui/pages/index.ts'
import type { ReplySendInput } from '../ui/reply-box.tsx'
import type { AccountVault } from './account-vault.ts'
import { timed } from './boot-timing.ts'

const SEND_MARK = /(^|\n)!b(?:\n|$)/

export async function startMarkdownVault(vault: AccountVault, send: (input: ReplySendInput) => Promise<void>): Promise<void> {
  const { identityId, readModel } = vault
  const directories = await MarkdownDirectoryConnection.open()
  const guard = new MarkdownSelfWriteGuard()
  let root = await timed('markdownDirectories.restore', directories.restore(identityId))
  let observer: { disconnect(): void; supported: boolean } | undefined

  const sendDraft = async (file: MarkdownMirrorFile, emails: { id: string; threadId: string }[]) => {
    const last = emails.filter(email => email.threadId === file.parsed.frontmatter.id).at(-1)
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
          if (status === 'send' || SEND_MARK.test(file.parsed.draft)) { await sendDraft(file, snapshot.emails); await removeMarkdownMirrorFile(directory, file.path); continue }
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
