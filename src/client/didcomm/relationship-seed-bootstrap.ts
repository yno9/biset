// The relationship seed's authority: which seed this identity uses now, and
// whether it needs replacing (PLAN-refactor.md §4.2, §7-1, §7-2, §9.2).
//
// Every answer comes from the did:webvh log -- this identity's one authority
// on its devices and keys -- never from the mediator, and never from a
// device's own memory of what it did. The seed in use is the one whose
// rotation key (rotation-key.ts) the DID document publishes: a device's
// candidate becomes it only when the Wallet publishes its key (`ifAbsent` at
// sign-in, so the first device approved wins; `replace` when removing other
// devices). Every device reading the log reaches the same answer.
//
// - A device whose key is no longer in the log's keyAgreement was removed:
//   it may not act as the identity at all.
// - No rotation key published: the identity has no seed yet ("unpublished").
// - The published key's seed is in this device's Vault: "usable".
// - It is not, yet: "pending" -- Vault Sync brings it from the device that
//   minted it. The designated device (the first-sorting key of the identity)
//   decides it is "lost" when no other device could have it (it is the only
//   one) or a day after the key was published.
// - A device key was removed after the rotation key was published -- removed
//   from the Wallet itself, which knows nothing of this key and so left it in
//   place -- and the removed device holds its seed: "stale".
// "unpublished", "lost" and "stale" need a Wallet approval to publish a fresh
// seed's key (did-md-oauth.ts's beginDidMdRotationKeyRenewal).
//
// Keys are compared by `#fragment`: a domain move rewrites the DID part of
// every id, never the fragment (a key's fragment is derived from the key).
import type { LogEntry } from '../../protocol/webvh/log.ts'
import { authenticationKeySince, deviceRemovedSince, fragmentOf, keyAgreementOf } from '../../protocol/didcomm/from-prior.ts'
import { ROTATION_KEY_FRAGMENT, rotationSigningKey } from './rotation-key.ts'

/** A seed's decision is not made sooner than this after its key was published. */
export const SEED_LOST_AFTER_MS = 24 * 60 * 60 * 1000

export type SeedStatus =
  | { state: 'usable'; seed: Uint8Array; seedId: string }
  | { state: 'unpublished' }
  | { state: 'pending' }
  | { state: 'lost' }
  | { state: 'stale'; designated: boolean }

/** Thrown where something needs the seed and it is not usable right now. */
export class RelationshipSeedPendingError extends Error {
  constructor(readonly status: Exclude<SeedStatus['state'], 'usable'> = 'pending') {
    super(status === 'pending'
      ? 'This device is still syncing with your other devices. If you no longer use them, remove them on the Account page.'
      : 'The key that lets your devices move a conversation to a private address needs renewing on the Account page.')
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

interface StoredSeed { seed: Uint8Array; seedId: string }

/** The seed status `entries` (the whole log) give this device (`ownKid`),
 * holding `seeds` in its Vault, at `now`. */
export function seedStatus(entries: readonly LogEntry[], ownKid: string, seeds: readonly StoredSeed[], now: number): SeedStatus {
  const last = entries[entries.length - 1]
  if (!last) throw new Error('the did:webvh log is empty')
  const listed = keyAgreementOf(last)
  if (!listed.includes(fragmentOf(ownKid))) throw new DeviceRemovedError()
  const published = authenticationKeySince(entries, ROTATION_KEY_FRAGMENT)
  if (!published) return { state: 'unpublished' }
  const { key, since } = published
  const designated = [...listed].sort()[0] === fragmentOf(ownKid)
  // The same check a counterparty makes on this key (from-prior.ts, §7-2).
  if (deviceRemovedSince(entries, since)) return { state: 'stale', designated }
  const seed = seeds.find(value => rotationSigningKey(value.seed).publicKeyMultibase === key)
  if (seed) return { state: 'usable', seed: seed.seed, seedId: seed.seedId }
  if (!designated) return { state: 'pending' }
  const publishedAt = Date.parse(entries[since]!.versionTime)
  return listed.length === 1 || now - publishedAt >= SEED_LOST_AFTER_MS ? { state: 'lost' } : { state: 'pending' }
}

export interface RelationshipSeedAuthorityOptions {
  /** This device's own front-door kid (a key of the identity's DID). */
  ownKid: string
  seeds: { readAll(): Promise<StoredSeed[]> }
  /** The identity's did:webvh log, read past the host's CDN. */
  readLog(): Promise<readonly LogEntry[]>
  /** How long a read of the log is reused. */
  logMaxAgeMs?: number
  now?: () => number
}

export interface RelationshipSeedAuthority {
  status(): Promise<SeedStatus>
  /** The seed in use; throws RelationshipSeedPendingError when there is none
   * this device may use now, DeviceRemovedError once removed. */
  require(): Promise<StoredSeed>
  /** Forgets the cached log (after this device changed the document). */
  refresh(): void
}

export function createRelationshipSeedAuthority(options: RelationshipSeedAuthorityOptions): RelationshipSeedAuthority {
  const maxAge = options.logMaxAgeMs ?? 60_000
  const now = options.now ?? (() => Date.now())
  let cached: { at: number; entries: Promise<readonly LogEntry[]> } | undefined

  function log(): Promise<readonly LogEntry[]> {
    if (!cached || now() - cached.at > maxAge) {
      const entries = options.readLog()
      cached = { at: now(), entries }
      entries.catch(() => { if (cached?.entries === entries) cached = undefined })
    }
    return cached.entries
  }

  const authority: RelationshipSeedAuthority = {
    async status() { return seedStatus(await log(), options.ownKid, await options.seeds.readAll(), now()) },
    async require() {
      const status = await authority.status()
      if (status.state !== 'usable') throw new RelationshipSeedPendingError(status.state)
      return { seed: status.seed, seedId: status.seedId }
    },
    refresh() { cached = undefined },
  }
  return authority
}
