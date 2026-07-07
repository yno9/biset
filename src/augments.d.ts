interface FileSystemChangeRecord {
  changedHandle: FileSystemHandle
  relativePathComponents: string[]
  relativePathMovedFrom?: string[]
  type: 'appeared' | 'disappeared' | 'modified' | 'moved' | 'unknown' | 'errored'
}

declare class FileSystemObserver {
  constructor(callback: (records: FileSystemChangeRecord[], observer: FileSystemObserver) => void)
  observe(handle: FileSystemHandle, options?: { recursive?: boolean }): Promise<void>
  unobserve(handle: FileSystemHandle): void
  disconnect(): void
}
