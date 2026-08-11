// Durable record of the device-sync copies this device still owes its own
// other devices.
//
// A message the user sends goes two places: to the recipient, and to this
// identity's OWN other devices so their thread gains it too
// (channel.ts's syncToSiblingDevices — DIDComm has no carbon-copy protocol,
// so the sender does the fan-out). The first has a person watching it and an
// error path they can act on. The second was fire-and-forget with no retry
// anywhere: if resolving our own DID document came back empty, or the mediator
// was briefly unreachable, or the document was a stale cached copy that didn't
// list a sibling registered moments earlier, that ONE message was never sent
// to the other device — not late, not queued, never sent. Nothing anywhere
// recorded that it should have been, so nothing could ever fix it, and the two
// devices disagreed about the conversation permanently and silently.
//
// This is the missing durable step. A sync copy is written down BEFORE it is
// attempted and only erased once every sibling has actually been handed one,
// with the poll loop retrying whatever is left. It is deliberately a
// send-side outbox rather than anything server-held: the mediator's queue is
// per-recipient-kid, so a copy that was never sent to a sibling was never
// queued for it either, and there is nothing to pull. See the DIDComm routing
// spec's own framing of a mediator as "partly trusted" — the fix belongs on
// the device that knows the plaintext.
//
// What this still cannot do, by construction: reach a device that registered
// AFTER the send (there was no kid to send to), and make progress while the
// SENDING device is closed (it is the only party holding the copy).
import * as idb from '../../store/idb.ts'

const STORE_KEY = 'didcomm_sibling_outbox'

/** Give up on an entry this old. Long enough to cover a laptop shut for a
 * working week, short enough that a permanently-unreachable sibling doesn't
 * make this grow without end. */
const MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000

/** Hard cap, oldest evicted first — the age bound alone can't stop a burst. */
const MAX_ENTRIES = 500

/** Retry backoff, doubling from 5s up to 5 minutes. The poll tick offers a
 * flush every few seconds; without this, a sibling whose mediator is down
 * would be retried at the poll cadence for as long as it stayed down. */
const RETRY_BASE_MS = 5_000
const RETRY_MAX_MS = 5 * 60 * 1000

export interface SiblingSync {
  /** The chat message's own id — also this entry's key, so re-enqueuing the
   * same message (a retry that raced) can never duplicate it. */
  id: string
  /** Whose devices these are: the sending identity's DID. */
  selfDid: string
  /** Who the message was actually addressed to, carried so the sibling files
   * it under the right conversation rather than as a self-to-self message. */
  toDid: string
  body: { content: string; id: string; sentAt: string; subject?: string }
  fromName?: string
  /** Sibling kids that have already been handed a copy — a retry skips these,
   * so a mediator that already queued one doesn't end up holding two. */
  deliveredKids: string[]
  attempts: number
  lastAttemptAt: number
  createdAt: number
}

type Stored = Record<string, SiblingSync>

/** Where the outbox lives between page loads. Injected rather than being
 * IndexedDB directly, for the same reason dht/freshness.ts injects its seq
 * store and did/keycache.ts injects its persistence: this file's actual
 * subject is a POLICY (what is owed, when it may be retried, when the debt is
 * settled) that has nothing to do with browser storage, and wiring it directly
 * to IndexedDB would make it testable only in a browser. */
export interface SiblingOutboxStore {
  load(): Promise<Stored>
  save(all: Stored): Promise<void>
}

const idbStore: SiblingOutboxStore = {
  async load() {
    const raw = await idb.get(idb.STORES.accounts, STORE_KEY).catch(() => undefined)
    return raw && typeof raw === 'object' ? { ...(raw as Stored) } : {}
  },
  // Written through on every change, never debounced: the window this closes
  // is "the browser went away between sending and syncing", so a delayed write
  // would leave open exactly the case it exists for.
  async save(all) {
    await idb.put(idb.STORES.accounts, { ...all }, STORE_KEY).catch(() => {})
  },
}

let store: SiblingOutboxStore = idbStore
let cache: Stored | null = null

/** Swaps the backing store (and forgets anything already read). */
export function useSiblingOutboxStore(s: SiblingOutboxStore): void {
  store = s
  cache = null
}

/** Drops the in-memory copy so the next read comes from storage — what a page
 * reload does, and the only way to prove the outbox actually survives one. */
export function forgetSiblingOutboxCache(): void {
  cache = null
}

async function load(): Promise<Stored> {
  if (cache) return cache
  cache = await store.load()
  return cache
}

async function save(): Promise<void> {
  await store.save(cache ?? {})
}

/** Records a sync copy as owed, before any attempt is made. */
export async function rememberSiblingSync(entry: Omit<SiblingSync, 'deliveredKids' | 'attempts' | 'lastAttemptAt' | 'createdAt'>): Promise<void> {
  const all = await load()
  if (all[entry.id]) return // already owed — an enqueue racing its own retry
  all[entry.id] = { ...entry, deliveredKids: [], attempts: 0, lastAttemptAt: 0, createdAt: Date.now() }
  evict(all)
  await save()
}

/** Entries for this identity that are due for another attempt. Prunes expired
 * ones as it goes, so nothing else has to run a sweep. */
export async function dueSiblingSyncs(selfDid: string): Promise<SiblingSync[]> {
  const all = await load()
  const now = Date.now()
  let pruned = false
  const due: SiblingSync[] = []
  for (const [id, e] of Object.entries(all)) {
    if (now - e.createdAt > MAX_AGE_MS) {
      console.warn(`[didcomm] giving up on a device-sync copy after ${Math.round(MAX_AGE_MS / 86_400_000)}d`, { id, to: e.toDid })
      delete all[id]
      pruned = true
      continue
    }
    if (e.selfDid !== selfDid) continue
    if (e.attempts > 0 && now - e.lastAttemptAt < backoffMs(e.attempts)) continue
    due.push(e)
  }
  if (pruned) await save()
  return due
}

/** True when this identity owes nothing — lets the caller skip the flush
 * entirely, which is the normal case on every poll tick. */
export async function hasPendingSiblingSyncs(selfDid: string): Promise<boolean> {
  const all = await load()
  return Object.values(all).some(e => e.selfDid === selfDid)
}

function backoffMs(attempts: number): number {
  return Math.min(RETRY_BASE_MS * 2 ** (attempts - 1), RETRY_MAX_MS)
}

/** Records an attempt and which siblings it reached. Deletes the entry once
 * `remaining` is empty — i.e. every sibling the sending device could see has
 * been handed a copy. */
export async function noteSiblingAttempt(id: string, deliveredKids: string[], done: boolean): Promise<void> {
  const all = await load()
  const e = all[id]
  if (!e) return
  if (done) delete all[id]
  else {
    e.attempts++
    e.lastAttemptAt = Date.now()
    for (const kid of deliveredKids) if (!e.deliveredKids.includes(kid)) e.deliveredKids.push(kid)
  }
  await save()
}

/** Oldest-first eviction once past the cap — a Map-like object literal keeps
 * insertion order, and `createdAt` breaks ties from a reloaded blob. */
function evict(all: Stored): void {
  const ids = Object.keys(all)
  if (ids.length <= MAX_ENTRIES) return
  ids.sort((a, b) => (all[a]!.createdAt) - (all[b]!.createdAt))
  for (const id of ids.slice(0, ids.length - MAX_ENTRIES)) {
    console.warn('[didcomm] dropping the oldest device-sync copy — outbox full', { id })
    delete all[id]
  }
}
