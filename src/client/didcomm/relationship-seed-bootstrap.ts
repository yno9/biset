// Who may mint the identity's first relationship seed (store/vault/
// relationship-seed.ts) without having been given one.
//
// Only the identity's first device. Every later device waits until Vault
// Sync delivers the seed from a sibling: minting its own would hand two
// devices two different seeds, and so two different relationship did:peers
// for every counterparty. "First" is read off the did:webvh log -- this
// identity's one authority on which devices exist -- not from the mediator,
// which only relays. The log is append-only and Wallet signs one entry at a
// time, so for any device key exactly one answer exists: whether the entry
// that ADDED that key listed any other keyAgreement key beside it. Two
// devices can never both see themselves as first, however their reads race.
import type { LogEntry } from '../../protocol/webvh/log.ts'

function keyAgreementOf(entry: LogEntry, did: string): string[] {
  const state = entry.state as { keyAgreement?: unknown }
  if (!Array.isArray(state.keyAgreement)) return []
  return state.keyAgreement.filter((id): id is string => typeof id === 'string').map(id => id.startsWith('#') ? `${did}${id}` : id)
}

/** True when `ownKid` entered the log alone: the entry that first lists it
 * lists no other keyAgreement key. False when it was never listed. */
export function isFirstDidCommDevice(did: string, entries: readonly LogEntry[], ownKid: string): boolean {
  for (const entry of entries) {
    const keys = keyAgreementOf(entry, did)
    if (keys.includes(ownKid)) return keys.length === 1
  }
  return false
}

export interface RelationshipSeedSource {
  current(): Promise<{ seed: Uint8Array } | undefined>
}

/** Thrown where a relationship needs the seed and this device has not
 * received it yet -- the operation is retried once Vault Sync delivers it. */
export class RelationshipSeedPendingError extends Error {
  constructor() {
    super('This device is still syncing with your other devices. If you no longer use them, remove them on the Account page.')
    this.name = 'RelationshipSeedPendingError'
  }
}

export async function requireRelationshipSeed(source: RelationshipSeedSource): Promise<Uint8Array> {
  const current = await source.current()
  if (!current) throw new RelationshipSeedPendingError()
  return current.seed
}

/** Run on every boot of a messaging-enabled device: nothing when the Vault
 * already holds a seed; mints and stores one when this device is the
 * identity's first (per the did:webvh log); otherwise leaves it to Vault Sync
 * and reports 'waiting'. */
export async function provisionRelationshipSeed(input: {
  did: string
  ownKid: string
  seeds: RelationshipSeedSource
  readLog(): Promise<readonly LogEntry[]>
  mintAndStore(): Promise<unknown>
}): Promise<'present' | 'minted' | 'waiting'> {
  if (await input.seeds.current()) return 'present'
  if (!isFirstDidCommDevice(input.did, await input.readLog(), input.ownKid)) return 'waiting'
  await input.mintAndStore()
  return 'minted'
}

/** The local half of "remove other devices", run on boot after the Wallet
 * has dropped their keys from the DID document: replaces the relationship
 * seed, so the removed devices can derive no relationship from here on.
 * Idempotent across a crash -- a seed already minted since `requestedAt`
 * counts as done. */
export async function finishDeviceRemoval<S extends { seed: Uint8Array; seedId: string; createdAt: string }>(input: {
  identityId: string
  requestedAt: string
  seeds: { current(): Promise<S | undefined> }
  storeSeed(seed: S): Promise<unknown>
  mint(identityId: string, supersedes: S | undefined): S
}): Promise<S> {
  const current = await input.seeds.current()
  if (current && Date.parse(current.createdAt) >= Date.parse(input.requestedAt)) return current
  const next = input.mint(input.identityId, current)
  await input.storeSeed(next)
  return next
}
