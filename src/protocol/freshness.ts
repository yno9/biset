// Remembering the newest version of a log that was verified, so that an older copy, or another continuation of the same log, is
// refused later (dito packages/vh/src/freshness.ts, same rules).
//
// A log is verified by its SCID, hash chain and signatures; none of that says whether it is the *newest* log. A host, a cache
// or a mirror can hand over a copy from before a key rotation (a removed device's key still listed, a rotated key still
// trusted), and a party holding the update keys can write a second continuation of the same history. Both verify. What exposes
// them is a comparison with what this party has already accepted.
//
// Method-neutral: it needs only `versionId` (`<number>-<hash>`), which every did:vh log has.
export interface KnownVersion { versionNumber: number; versionId: string }

/** Where a log stands against the newest version already accepted for its identity. */
export type LogStanding = 'new' | 'same' | 'newer'

/** The log is shorter than a version already accepted: an old copy. */
export class StaleLogError extends Error {
  readonly known: KnownVersion
  constructor(known: KnownVersion, got: number) {
    super(`The log ends at version ${got}, but version ${known.versionNumber} was already accepted.`)
    this.name = 'StaleLogError'
    this.known = known
  }
}

/** The log does not contain a version already accepted: another continuation of the history. */
export class ForkedLogError extends Error {
  readonly known: KnownVersion
  readonly found: string
  constructor(known: KnownVersion, found: string) {
    super(`Version ${known.versionNumber} of the log is ${found}, but ${known.versionId} was already accepted.`)
    this.name = 'ForkedLogError'
    this.known = known
    this.found = found
  }
}

export function versionNumberOf(versionId: string): number {
  const match = /^([1-9]\d*)-.+$/.exec(versionId)
  if (!match) throw new Error(`Invalid versionId ${JSON.stringify(versionId)}.`)
  return Number(match[1])
}

export function latestVersion(entries: ReadonlyArray<{ versionId: string }>): KnownVersion {
  const last = entries[entries.length - 1]
  if (!last) throw new Error('The log has no entries.')
  return { versionNumber: versionNumberOf(last.versionId), versionId: last.versionId }
}

/**
 * Compares an already verified log with the newest version accepted before. `entries` must have passed full verification: only
 * then does finding the known `versionId` at its position prove that the log extends the known one (each `versionId` carries a
 * hash chained to its predecessor).
 */
export function standingOf(entries: ReadonlyArray<{ versionId: string }>, known?: KnownVersion): LogStanding {
  if (!known) return 'new'
  if (entries.length < known.versionNumber) throw new StaleLogError(known, entries.length)
  const found = entries[known.versionNumber - 1]!.versionId
  if (found !== known.versionId) throw new ForkedLogError(known, found)
  return entries.length === known.versionNumber ? 'same' : 'newer'
}

/** Storage for the newest accepted version of each identity, keyed by identityKey (`did:vh:<SCID>`). */
export interface VersionMemory {
  get(key: string): KnownVersion | undefined | Promise<KnownVersion | undefined>
  set(key: string, version: KnownVersion): void | Promise<void>
}

export class InMemoryVersionMemory implements VersionMemory {
  private readonly versions = new Map<string, KnownVersion>()
  get(key: string): KnownVersion | undefined { return this.versions.get(key) }
  set(key: string, version: KnownVersion): void { this.versions.set(key, version) }
}

/** Refuses a verified log that is old or forked relative to `memory` (StaleLogError, ForkedLogError); otherwise remembers its newest version. */
export async function checkAndRemember(memory: VersionMemory, key: string, entries: ReadonlyArray<{ versionId: string }>): Promise<LogStanding> {
  const standing = standingOf(entries, await memory.get(key))
  if (standing !== 'same') await memory.set(key, latestVersion(entries))
  return standing
}
