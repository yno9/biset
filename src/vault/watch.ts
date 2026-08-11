import { vaultHandle } from '../context.ts'
import { flushOutgoing, flushActions } from '../sync/actions.ts'
import { parseFrontmatter, extractBody } from './render.ts'
import { readText } from './fs.ts'

const DEBOUNCE_MS = 500

let observer: FileSystemObserver | null = null
const timers = new Map<string, ReturnType<typeof setTimeout>>()

export async function startWatch(): Promise<void> {
  if (!vaultHandle) throw new Error('vault not initialized')
  if (!('FileSystemObserver' in window)) throw new Error('FileSystemObserver not available')

  observer = new FileSystemObserver(handleRecords)
  await observer.observe(vaultHandle, { recursive: true })
}

export function stopWatch(): void {
  observer?.disconnect()
  observer = null
  for (const t of timers.values()) clearTimeout(t)
  timers.clear()
}

function handleRecords(records: FileSystemChangeRecord[]): void {
  for (const record of records) {
    if (record.type !== 'modified' && record.type !== 'appeared') continue

    const parts = record.relativePathComponents
    if (parts.length !== 2) continue
    const [mailboxName, filename] = parts as [string, string]
    if (mailboxName.startsWith('.')) continue
    if (!filename.endsWith('.md')) continue

    const key = parts.join('/')
    const existing = timers.get(key)
    if (existing) clearTimeout(existing)
    timers.set(key, setTimeout(() => {
      timers.delete(key)
      handleMDChange(mailboxName, filename).catch(err =>
        console.error('[watch]', key, err)
      )
    }, DEBOUNCE_MS))
  }
}

async function handleMDChange(mailboxName: string, filename: string): Promise<void> {
  const mdPath = [mailboxName, filename]
  let content: string
  try {
    content = await readText(mdPath)
  } catch {
    return
  }

  const fm = parseFrontmatter(content)
  const status = (fm['status'] ?? '').trim()
  const body = extractBody(content)
  const hasBangB = body.includes('!b')

  console.log('[watch] handleMDChange', mailboxName, filename, 'status:', status, 'hasBangB:', hasBangB, 'bodyLen:', body.length)
  if (status === 'send' || hasBangB) {
    await flushOutgoing(mailboxName, mdPath)
  } else if (['seen', 'follow', 'archived', 'deleted', 'spam'].includes(status)) {
    await flushActions(mailboxName, mdPath, status)
  }
}
