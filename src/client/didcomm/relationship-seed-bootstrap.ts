// The relationship seed's authority: whether this device may use the Vault's
// seed (store/vault/relationship-seed.ts) right now, and who mints a new one.
//
// Every answer comes from the did:webvh log -- this identity's one authority
// on which devices exist -- never from the mediator, which only relays, and
// never from a device's own memory of what it did. The log is append-only and
// the Wallet signs one entry at a time, so every device reading it reaches
// the same answer:
//
// - A device whose key is no longer in the log's keyAgreement was removed:
//   it may not act as this identity at all.
// - A seed is valid from the log version it was minted at. Once a later entry
//   removes a device key, the seed is stale: the removed device has it.
// - Exactly one device mints a seed. Before any device was ever removed, that
//   is the identity's first device: the one whose key entered the log alone.
//   After a removal, it is the device among those that survived it whose key
//   sorts first. Every other device waits for Vault Sync to bring the seed --
//   minting its own would give two devices two different seeds, and so two
//   different relationship did:peers for every counterparty.
//
// Keys are compared by `#fragment`: a domain move rewrites the DID part of
// every id, never the fragment (a key's fragment is derived from the key).
import { entryVersionNumber, type LogEntry } from '../../protocol/webvh/log.ts'

function fragmentOf(id: string): string {
  const hash = id.indexOf('#')
  return hash < 0 ? id : id.slice(hash)
}

function keyAgreementOf(entry: LogEntry): string[] {
  const state = entry.state as { keyAgreement?: unknown }
  if (!Array.isArray(state.keyAgreement)) return []
  return state.keyAgreement.filter((id): id is string => typeof id === 'string').map(fragmentOf)
}

/** True when `ownKid` entered the log alone: the entry that first lists it
 * lists no other keyAgreement key. False when it was never listed. */
export function isFirstDidCommDevice(entries: readonly LogEntry[], ownKid: string): boolean {
  const own = fragmentOf(ownKid)
  for (const entry of entries) {
    const keys = keyAgreementOf(entry)
    if (keys.includes(own)) return keys.length === 1
  }
  return false
}

/** The latest entry that removed a keyAgreement key (a device), or undefined
 * when no device was ever removed. */
export function lastDeviceRemoval(entries: readonly LogEntry[]): { version: number; survivors: string[] } | undefined {
  let found: { version: number; survivors: string[] } | undefined
  for (let index = 1; index < entries.length; index++) {
    const after = keyAgreementOf(entries[index]!)
    if (keyAgreementOf(entries[index - 1]!).some(key => !after.includes(key))) {
      found = { version: entryVersionNumber(entries[index]!.versionId), survivors: after }
    }
  }
  return found
}

/** The current log version (its last entry's). */
function logVersion(entries: readonly LogEntry[]): number {
  const last = entries[entries.length - 1]
  if (!last) throw new Error('the did:webvh log is empty')
  return entryVersionNumber(last.versionId)
}

/** Whether this device is the one that mints the seed now, given no usable
 * seed. After a removal: the first-sorting key among those that survived it
 * and are still listed (or among all listed ones, if none of the survivors
 * is left). Before any: the identity's first device. */
export function isDesignatedSeedMinter(entries: readonly LogEntry[], ownKid: string): boolean {
  const own = fragmentOf(ownKid)
  const removal = lastDeviceRemoval(entries)
  if (!removal) return isFirstDidCommDevice(entries, ownKid)
  const listed = keyAgreementOf(entries[entries.length - 1]!)
  const survivors = removal.survivors.filter(key => listed.includes(key))
  return [...(survivors.length ? survivors : listed)].sort()[0] === own
}

/** Thrown where a relationship needs the seed and this device does not have
 * a usable one yet -- the operation is retried once Vault Sync delivers it. */
export class RelationshipSeedPendingError extends Error {
  constructor() {
    super('This device is still syncing with your other devices. If you no longer use them, remove them on the Account page.')
    this.name = 'RelationshipSeedPendingError'
  }
}

/** Thrown when this device's key is no longer in the identity's DID
 * document: it was removed, and may not act as the identity any more. */
export class DeviceRemovedError extends Error {
  constructor() {
    super('This device was removed from your account. Sign in with did.md Wallet again to use it.')
    this.name = 'DeviceRemovedError'
  }
}

interface UsableRelationshipSeed { seed: Uint8Array; seedId: string }

interface StoredSeed extends UsableRelationshipSeed { afterVersion: number }

export interface RelationshipSeedAuthorityOptions {
  /** This device's own front-door kid (a key of the identity's DID). */
  ownKid: string
  seeds: { current(): Promise<StoredSeed | undefined> }
  /** The identity's did:webvh log, read past the host's CDN. */
  readLog(): Promise<readonly LogEntry[]>
  /** Mints a seed valid from `afterVersion`, replacing `supersedes`, and
   * stores it in the Vault (where Vault Sync carries it to siblings). */
  mintAndStore(afterVersion: number, supersedes: StoredSeed | undefined): Promise<StoredSeed>
  /** How long a read of the log is reused. */
  logMaxAgeMs?: number
  now?: () => number
}

export interface RelationshipSeedAuthority {
  /** The seed this device may derive relationships from now. Mints it when
   * this device is the designated one; throws RelationshipSeedPendingError
   * while waiting for a sibling's, DeviceRemovedError once removed. */
  require(): Promise<UsableRelationshipSeed>
}

export function createRelationshipSeedAuthority(options: RelationshipSeedAuthorityOptions): RelationshipSeedAuthority {
  const maxAge = options.logMaxAgeMs ?? 60_000
  const now = options.now ?? (() => Date.now())
  let cached: { at: number; entries: Promise<readonly LogEntry[]> } | undefined
  let minting: Promise<StoredSeed> | undefined

  function log(): Promise<readonly LogEntry[]> {
    if (!cached || now() - cached.at > maxAge) {
      const entries = options.readLog()
      cached = { at: now(), entries }
      entries.catch(() => { if (cached?.entries === entries) cached = undefined })
    }
    return cached.entries
  }

  return {
    async require() {
      const entries = await log()
      if (!keyAgreementOf(entries[entries.length - 1]!).includes(fragmentOf(options.ownKid))) throw new DeviceRemovedError()
      const staleBefore = lastDeviceRemoval(entries)?.version ?? 0
      const current = await options.seeds.current()
      if (current && current.afterVersion >= staleBefore) return { seed: current.seed, seedId: current.seedId }
      if (!isDesignatedSeedMinter(entries, options.ownKid)) throw new RelationshipSeedPendingError()
      // One mint per device at a time; a concurrent caller shares it.
      minting ??= options.mintAndStore(logVersion(entries), current).finally(() => { minting = undefined })
      const minted = await minting
      return { seed: minted.seed, seedId: minted.seedId }
    },
  }
}
