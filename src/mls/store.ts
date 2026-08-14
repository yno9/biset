// Where a device's MLS state actually lives between page loads.
//
// This is the browser half of the MLS layer (group.ts is platform-free and
// knows nothing about storage). It holds two things, both of them **key
// material rather than cache**:
//
//   - **Group states.** ts-mls's encoded `ClientState` per group. There is no
//     server copy to re-fetch — that is the whole point of MLS — so losing a
//     row means being unable to read that group again, and the only recovery
//     is another member re-adding this device (a fresh Welcome).
//   - **Key package privates.** For each key package this device published,
//     the private half, keyed by the key package ref a Welcome names. Deleted
//     once used: an MLS key package is single-use, and keeping the private
//     half after a join would keep a compromise window open for nothing.
//
// Every write goes through a per-group lock. MLS state advances strictly one
// message at a time (each operation consumes keys the next one depends on), so
// two concurrent read-modify-writes on the same group don't merely race on the
// database — they can produce a state that has skipped a message. The lock is
// per group id rather than global so an unrelated group's traffic is never
// serialized behind it.
import { STORES, get, getAll, put, del } from '../store/idb.ts'
import {
  generateOwnKeyPackage, encodeKeyPackage, decodeKeyPackage, keyPackageRefOf, welcomeRecipientRefs,
  decodeState, encodeState, memberDids, epochOf, type OwnKeyPackage,
} from './group.ts'
import type { ClientState } from './vendor/index.ts'

/** How many unused key packages this device keeps published. A key package is
 * single-use, so the pool is what lets several people invite this device to
 * several groups before it next comes online to refill (PLANMLS.md's mediator
 * KeyPackage Store holds the public halves). */
const POOL_TARGET = 5

interface StoredKeyPackage {
  ref: string          // hex key package ref — the primary key
  kid: string          // the DIDComm device key id this was minted for
  publicWire: Uint8Array
  privatePackage: OwnKeyPackage['privatePackage']
  createdAt: number
}

/** A group as stored. `state` is authoritative; everything else is either
 * routing (which mediator is the DS) or display, and nothing derivable from
 * `state` is duplicated here — a second copy of the member list or the epoch
 * would only be one more thing that can disagree with the group itself. */
export interface StoredGroup {
  id: string           // hex of the MLS group id
  selfKid: string      // which of this identity's devices is the member
  dsDid: string        // the Mediator acting as this group's Delivery Service
  name: string
  state: Uint8Array
  /** The highest DS sequence number this device has APPLIED to `state`.
   *
   * Kept because push is not proof of completeness: the DS fans out to the
   * roster a committer declared, and cannot verify it (mls-ds.ts's
   * everMembers). This is what the device asks the DS to continue from, and it
   * counts applied rather than seen deliberately — a delivery that arrived and
   * would not apply is still missing. */
  lastSeq: number
  updatedAt: number
}

/** A group with its state decoded, which is how callers want it. */
export interface LoadedGroup extends Omit<StoredGroup, 'state'> { state: ClientState }

const locks = new Map<string, Promise<unknown>>()

/** Run `fn` with exclusive access to one group's row. */
export function withGroupLock<T>(id: string, fn: () => Promise<T>): Promise<T> {
  const prev = locks.get(id) ?? Promise.resolve()
  const next = prev.then(fn, fn)
  // Keep the chain alive but don't let a rejection break the NEXT waiter: the
  // catch here only guards the queue, callers still see their own rejection.
  locks.set(id, next.catch(() => undefined))
  return next
}

export function groupIdHex(groupId: Uint8Array): string {
  return Array.from(groupId, b => b.toString(16).padStart(2, '0')).join('')
}

/** A fresh, random group id. Random rather than derived from the members: the
 * membership changes over a group's life, and an id that encoded it would
 * either go stale or leak who is in the group to anyone who sees the id. */
export function newGroupId(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32))
}

// ---------------------------------------------------------------- key packages

/** Top the pool back up to POOL_TARGET and return every unused key package
 * this device has, in wire form — what gets (re)published to the mediator.
 * Idempotent: calling it when the pool is full generates nothing. */
export async function ensureKeyPackages(kid: string, target = POOL_TARGET): Promise<Uint8Array[]> {
  const existing = (await getAll(STORES.mlskeys) as StoredKeyPackage[]).filter(k => k.kid === kid)
  const created: StoredKeyPackage[] = []
  for (let i = existing.length; i < target; i++) {
    const own = await generateOwnKeyPackage(kid)
    const rec: StoredKeyPackage = {
      ref: await keyPackageRefOf(own.publicPackage),
      kid,
      publicWire: encodeKeyPackage(own.publicPackage),
      privatePackage: own.privatePackage,
      createdAt: Date.now(),
    }
    await put(STORES.mlskeys, rec)
    created.push(rec)
  }
  return [...existing, ...created].map(k => k.publicWire)
}

/** Find the key package a Welcome was addressed to, and consume it.
 *
 * Returns undefined when none of the Welcome's recipients is us — which is not
 * an error: a Welcome fans out to every joiner, and a device that already used
 * (and deleted) its key package for this group will see the same Welcome again
 * on a resend. The caller treats "not for us" as "already handled or not ours"
 * rather than failing. */
export async function takeKeyPackageForWelcome(welcomeBytes: Uint8Array): Promise<OwnKeyPackage | undefined> {
  for (const ref of welcomeRecipientRefs(welcomeBytes)) {
    const rec = await get(STORES.mlskeys, ref) as StoredKeyPackage | undefined
    if (!rec) continue
    await del(STORES.mlskeys, ref)
    return { publicPackage: decodeKeyPackage(rec.publicWire), privatePackage: rec.privatePackage }
  }
  return undefined
}

// --------------------------------------------------------------------- groups

export async function saveGroup(group: Omit<LoadedGroup, 'updatedAt' | 'lastSeq'> & { lastSeq?: number }): Promise<void> {
  const rec: StoredGroup = {
    id: group.id,
    selfKid: group.selfKid,
    dsDid: group.dsDid,
    name: group.name,
    state: encodeState(group.state),
    lastSeq: group.lastSeq ?? 0,
    updatedAt: Date.now(),
  }
  await put(STORES.mlsgroups, rec)
}

export async function loadGroup(id: string): Promise<LoadedGroup | undefined> {
  const rec = await get(STORES.mlsgroups, id) as StoredGroup | undefined
  // `lastSeq` defaults for a row written before it existed: 0 means "ask for
  // everything the DS still holds", which is the safe direction — the worst
  // case is re-applying deliveries this device already has, and MLS refuses
  // those on its own.
  return rec === undefined ? undefined : { ...rec, lastSeq: rec.lastSeq ?? 0, state: decodeState(rec.state) }
}

export async function listGroups(): Promise<LoadedGroup[]> {
  const rows = await getAll(STORES.mlsgroups) as StoredGroup[]
  return rows.map(rec => ({ ...rec, lastSeq: rec.lastSeq ?? 0, state: decodeState(rec.state) }))
}

/** Forget a group entirely. This is irreversible in the strong sense — no
 * amount of re-syncing brings it back, only another member's Welcome does. */
export async function deleteGroup(id: string): Promise<void> {
  await del(STORES.mlsgroups, id)
}

/** Read-modify-write one group under its lock: the only safe way to advance a
 * group's state. `fn` gets the loaded group and returns the new MLS state
 * (plus whatever the caller wanted out of the operation). */
export async function updateGroup<T>(id: string, fn: (group: LoadedGroup) => Promise<{ state: ClientState; result: T }>): Promise<T> {
  return withGroupLock(id, async () => {
    const group = await loadGroup(id)
    if (!group) throw new Error(`updateGroup: no such group ${id}`)
    const { state, result } = await fn(group)
    await saveGroup({ ...group, state })
    return result
  })
}

/** A one-line summary per group, for the conversation list — derived from the
 * state each time rather than stored, so it cannot go stale. */
export async function groupSummaries(): Promise<Array<{ id: string; name: string; epoch: bigint; members: string[] }>> {
  return (await listGroups()).map(g => ({ id: g.id, name: g.name, epoch: epochOf(g.state), members: memberDids(g.state) }))
}
