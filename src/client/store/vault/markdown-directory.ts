const DATABASE = 'biset-markdown-mirror'
const STORE = 'directory_handles'

import type { LocalJmapReadModel, LocalJmapSnapshot } from '../projection/gateway.ts'
import { MarkdownSelfWriteGuard, markdownThreadFilename, parseMarkdownThread, renderMarkdownThread, type ParsedMarkdown } from './markdown-mirror.ts'

export class MarkdownDirectoryConnection {
  private constructor(private readonly database: IDBDatabase) {}
  static async open(): Promise<MarkdownDirectoryConnection> {
    const database = await new Promise<IDBDatabase>((resolve, reject) => { const request = indexedDB.open(DATABASE, 1); request.onupgradeneeded = () => { if (!request.result.objectStoreNames.contains(STORE)) request.result.createObjectStore(STORE) }; request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error) })
    return new MarkdownDirectoryConnection(database)
  }
  async save(identityId: string, handle: FileSystemDirectoryHandle): Promise<void> { const tx = this.database.transaction(STORE, 'readwrite'); tx.objectStore(STORE).put(handle, identityId); await done(tx) }
  async remove(identityId: string): Promise<void> { const tx = this.database.transaction(STORE, 'readwrite'); tx.objectStore(STORE).delete(identityId); await done(tx) }
  async restore(identityId: string, request = false): Promise<FileSystemDirectoryHandle | undefined> {
    const tx = this.database.transaction(STORE, 'readonly'); const handle = await result<FileSystemDirectoryHandle | undefined>(tx.objectStore(STORE).get(identityId)); await done(tx); if (!handle) return
    const permissionHandle = handle as FileSystemDirectoryHandle & { queryPermission(options: { mode: 'readwrite' }): Promise<PermissionState>; requestPermission(options: { mode: 'readwrite' }): Promise<PermissionState> }
    let permission = await permissionHandle.queryPermission({ mode: 'readwrite' }); if (permission !== 'granted' && request) permission = await permissionHandle.requestPermission({ mode: 'readwrite' })
    return permission === 'granted' ? handle : undefined
  }
  close(): void { this.database.close() }
}

export interface MarkdownMirrorFile { path: string; parsed: ParsedMarkdown }

/** Rebuilds the disposable filesystem view from the authoritative projection. */
export async function writeMarkdownProjection(root: FileSystemDirectoryHandle, model: LocalJmapReadModel, selfEmail: string, guard: MarkdownSelfWriteGuard): Promise<void> {
  const snapshot = await model.snapshot()
  const scaffoldPath = 'Drafts/_new.md'; const scaffold = '---\nsubject: ""\ncontact: \nid: new\nstatus: \n---\n\n'
  if (await readOptional(root, 'Drafts', '_new.md') === undefined) { guard.note(scaffoldPath, scaffold); await writeMarkdownFile(root, ['Drafts'], '_new.md', scaffold) }
  const mailboxes = new Map(snapshot.mailboxes.map(mailbox => [mailbox.id, mailbox.name]))
  const threads = groupThreads(snapshot)
  for (const emails of threads.values()) {
    const mailboxId = Object.keys(emails[0]!.mailboxIds).sort()[0]
    if (!mailboxId) continue
    const directory = safeDirectoryName(mailboxes.get(mailboxId) ?? mailboxId)
    const filename = markdownThreadFilename(selfEmail, emails)
    const previous = await findThreadFile(root, directory, emails[0]!.threadId)
    const existing = previous?.content ?? await readOptional(root, directory, filename)
    let draft = ''
    if (existing !== undefined) { try { draft = parseMarkdownThread(existing).draft } catch { /* projection repairs malformed mirrors */ } }
    const content = await renderMarkdownThread(selfEmail, emails, async email => email.blobId ? new TextDecoder().decode(await model.download(email.blobId)) : email.preview ?? '', draft)
    guard.note(`${directory}/${filename}`, content)
    await writeMarkdownFile(root, [directory], filename, content)
    if (previous && previous.filename !== filename) await (await root.getDirectoryHandle(directory)).removeEntry(previous.filename)
  }
}

/** Reads user-editable frontmatter/draft data; message blocks remain read-only. */
export async function scanMarkdownProjection(root: FileSystemDirectoryHandle, guard: MarkdownSelfWriteGuard): Promise<MarkdownMirrorFile[]> {
  const result: MarkdownMirrorFile[] = []
  const iterable = root as FileSystemDirectoryHandle & { entries(): AsyncIterableIterator<[string, FileSystemHandle]> }
  for await (const [directoryName, entry] of iterable.entries()) {
    if (entry.kind !== 'directory') continue
    const directory = entry as FileSystemDirectoryHandle & { entries(): AsyncIterableIterator<[string, FileSystemHandle]> }
    for await (const [filename, child] of directory.entries()) {
      if (child.kind !== 'file' || !filename.endsWith('.md')) continue
      const content = await (await (child as FileSystemFileHandle).getFile()).text()
      const path = `${directoryName}/${filename}`
      if (guard.consumeIfSelfWrite(path, content)) continue
      try { result.push({ path, parsed: parseMarkdownThread(content) }) } catch { /* unrelated Markdown is ignored */ }
    }
  }
  return result
}
export async function removeMarkdownMirrorFile(root: FileSystemDirectoryHandle, path: string): Promise<void> { const split = path.lastIndexOf('/'); if (split < 1) throw new TypeError('Markdown mirror path is invalid'); await (await root.getDirectoryHandle(path.slice(0, split))).removeEntry(path.slice(split + 1)) }

async function writeMarkdownFile(root: FileSystemDirectoryHandle, directories: string[], filename: string, content: string): Promise<void> {
  let directory = root; for (const name of directories) directory = await directory.getDirectoryHandle(name, { create: true })
  const file = await directory.getFileHandle(filename, { create: true }); const writable = await file.createWritable(); await writable.write(content); await writable.close()
}
export function observeMarkdownDirectory(root: FileSystemDirectoryHandle, changed: () => void): { disconnect(): void; supported: boolean } {
  const Observer = (globalThis as unknown as { FileSystemObserver?: new (callback: () => void) => { observe(handle: FileSystemDirectoryHandle, options: { recursive: boolean }): Promise<void>; disconnect(): void } }).FileSystemObserver
  if (!Observer) return { supported: false, disconnect() {} }
  let timer: ReturnType<typeof setTimeout> | undefined; const observer = new Observer(() => { if (timer) clearTimeout(timer); timer = setTimeout(changed, 500) }); void observer.observe(root, { recursive: true })
  return { supported: true, disconnect() { if (timer) clearTimeout(timer); observer.disconnect() } }
}
function done(tx: IDBTransaction): Promise<void> { return new Promise((resolve, reject) => { tx.oncomplete = () => resolve(); tx.onabort = tx.onerror = () => reject(tx.error) }) }
function result<T>(request: IDBRequest<T>): Promise<T> { return new Promise((resolve, reject) => { request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error) }) }
function groupThreads(snapshot: LocalJmapSnapshot): Map<string, LocalJmapSnapshot['emails']> { const result = new Map<string, LocalJmapSnapshot['emails']>(); for (const email of snapshot.emails) { const list = result.get(email.threadId) ?? []; list.push(email); result.set(email.threadId, list) } return result }
function safeDirectoryName(value: string): string { return value.replace(/[/\\:*?"<>|]/g, '_') || 'Archive' }
async function readOptional(root: FileSystemDirectoryHandle, directoryName: string, filename: string): Promise<string | undefined> { try { const directory = await root.getDirectoryHandle(directoryName); const file = await directory.getFileHandle(filename); return (await file.getFile()).text() } catch (error) { if (error instanceof DOMException && error.name === 'NotFoundError') return; throw error } }
async function findThreadFile(root: FileSystemDirectoryHandle, directoryName: string, threadId: string): Promise<{ filename: string; content: string } | undefined> { try { const directory = await root.getDirectoryHandle(directoryName) as FileSystemDirectoryHandle & { entries(): AsyncIterableIterator<[string, FileSystemHandle]> }; for await (const [filename, entry] of directory.entries()) { if (entry.kind !== 'file' || !filename.endsWith('.md')) continue; const content = await (await (entry as FileSystemFileHandle).getFile()).text(); try { if (parseMarkdownThread(content).frontmatter.id === threadId) return { filename, content } } catch { /* unrelated file */ } } return } catch (error) { if (error instanceof DOMException && error.name === 'NotFoundError') return; throw error } }
