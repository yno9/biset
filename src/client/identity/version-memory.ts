// The newest version of each identity's log this browser has accepted (protocol/freshness.ts), kept between page loads so that a
// copy older than one already seen, or another continuation of it, is refused next time. Not secret and tiny (one versionId per
// identity), so plain localStorage; where that is unavailable (private window, blocked storage) the memory lasts for the page.
//
// Downside, on purpose: a rollback the owner *meant* (a host restored from backup) is refused too, until "forget" clears the entry.
// An identity recovers by extending its log, never by republishing an old copy.
import type { KnownVersion, VersionMemory } from '../../protocol/freshness.ts'

const KEY = 'biset.log-versions'

function isKnown(value: unknown): value is KnownVersion {
  return typeof value === 'object' && value !== null
    && Number.isInteger((value as KnownVersion).versionNumber) && typeof (value as KnownVersion).versionId === 'string'
}

export class StoredVersionMemory implements VersionMemory {
  private readonly versions = new Map<string, KnownVersion>()

  constructor(private readonly storage: Pick<Storage, 'getItem' | 'setItem'> | undefined = safeStorage()) {
    try {
      const parsed: unknown = JSON.parse(storage?.getItem(KEY) ?? '{}')
      if (typeof parsed === 'object' && parsed !== null) for (const [key, value] of Object.entries(parsed)) if (isKnown(value)) this.versions.set(key, value)
    } catch { /* damaged: start empty, as a first visit */ }
  }

  get(key: string): KnownVersion | undefined { return this.versions.get(key) }

  set(key: string, version: KnownVersion): void {
    this.versions.set(key, version)
    this.save()
  }

  /** Forget one identity (a rollback the owner meant), or all. */
  forget(key?: string): void {
    if (key === undefined) this.versions.clear()
    else this.versions.delete(key)
    this.save()
  }

  private save(): void {
    try { this.storage?.setItem(KEY, JSON.stringify(Object.fromEntries(this.versions))) } catch { /* kept for the page only */ }
  }
}

function safeStorage(): Storage | undefined {
  try { return globalThis.localStorage } catch { return undefined }
}
