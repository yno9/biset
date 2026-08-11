import { vaultHandle } from '../context.ts'

function root(): FileSystemDirectoryHandle {
  if (!vaultHandle) throw new Error('vault not initialized')
  return vaultHandle
}

async function traverseDir(path: string[]): Promise<FileSystemDirectoryHandle> {
  let dir = root()
  for (const segment of path) {
    dir = await dir.getDirectoryHandle(segment)
  }
  return dir
}

async function traverseDirCreate(path: string[]): Promise<FileSystemDirectoryHandle> {
  let dir = root()
  for (const segment of path) {
    dir = await dir.getDirectoryHandle(segment, { create: true })
  }
  return dir
}

export async function readJson(path: string[]): Promise<unknown> {
  const dir = await traverseDir(path.slice(0, -1))
  const fh = await dir.getFileHandle(path[path.length - 1]!)
  const file = await fh.getFile()
  return JSON.parse(await file.text())
}

export async function writeJson(path: string[], data: unknown): Promise<void> {
  const dir = await traverseDirCreate(path.slice(0, -1))
  const fh = await dir.getFileHandle(path[path.length - 1]!, { create: true })
  const writable = await fh.createWritable()
  await writable.write(JSON.stringify(data))
  await writable.close()
}

export async function readText(path: string[]): Promise<string> {
  const dir = await traverseDir(path.slice(0, -1))
  const fh = await dir.getFileHandle(path[path.length - 1]!)
  const file = await fh.getFile()
  return file.text()
}

export async function writeText(path: string[], content: string): Promise<void> {
  const dir = await traverseDirCreate(path.slice(0, -1))
  const fh = await dir.getFileHandle(path[path.length - 1]!, { create: true })
  const writable = await fh.createWritable()
  await writable.write(content)
  await writable.close()
}

export async function deleteFile(path: string[]): Promise<void> {
  const dir = await traverseDir(path.slice(0, -1))
  await dir.removeEntry(path[path.length - 1]!)
}

export async function scanDir(path: string[]): Promise<string[]> {
  const dir = await traverseDir(path)
  const names: string[] = []
  for await (const name of dir.keys()) {
    names.push(name)
  }
  return names
}

// Like scanDir but reports each entry's kind ('file' | 'directory'), needed to
// walk per-account subdirectories.
export async function scanEntries(path: string[]): Promise<{ name: string; kind: 'file' | 'directory' }[]> {
  const dir = await traverseDir(path)
  const out: { name: string; kind: 'file' | 'directory' }[] = []
  for await (const [name, handle] of (dir as any).entries()) {
    out.push({ name, kind: handle.kind })
  }
  return out
}

export async function deleteEntry(path: string[]): Promise<void> {
  const dir = await traverseDir(path.slice(0, -1))
  await dir.removeEntry(path[path.length - 1]!, { recursive: true })
}
