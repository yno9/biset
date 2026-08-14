// The DID document's device list, seen as a projection of the self group.
//
// `did/didcomm-devices.ts` decides which devices an identity has by merging
// gossip (whatever each device last saw published), subtracting tombstones,
// and letting the mediator's keylist break ties. `mls/self-group.ts` answers
// the same question from the ratchet tree, where membership is not a merge
// result but a consequence of ordered commits.
//
// Two answers to one question is the situation this file exists to end — but
// not yet by switching. It runs **alongside** the existing mechanism and
// reports where the two disagree, because the migration has an ordering hazard
// that only real data can rule out: publish the tree's answer before every
// device has joined the self group, and a device that hasn't joined disappears
// from the document. (It can recover — it only needs its mediator registration
// to fetch a GroupInfo and commit itself back in — but it stops receiving
// until it next runs.)
//
// ## What each side is actually authoritative for, after the switch
//
// The tree decides MEMBERSHIP. The document keeps doing what only it can do:
// carry each device's X25519 key so a DIDComm envelope can be addressed to it.
// So the end state is not "delete the document list" but "stop deciding
// anything with it" — publish `projectedKids` and drop the merge, the
// tombstone-based resurrection guard and the keylist prune.
//
// **One job of the tombstones does NOT transfer.** `removedKeyNs` prevents a
// retired slot NUMBER from being handed out again, and that hazard is nothing
// to do with membership: the mediator caches a resolved key per kid for ten
// minutes, so a reused `#kN` naming a different key breaks every authcrypt to
// that device until the cache expires (ARC.md's "integrity check failed"
// investigation). MLS has no opinion here — a removed leaf simply stops
// existing, and the tree cannot say which numbers were once used. Slot
// numbering needs its own answer before the tombstones can go; the real fix is
// to stop using positional numbers for kids at all.
import type { ClientState } from './vendor/index.ts'
import { memberKids } from './group.ts'
import { loadGroup } from './store.ts'
import { selfGroupIdHex } from './self-group.ts'

/** A device key id as each side names it. The document side uses bare
 * fragments (`#k1`, `DidRecord.didCommOwnKid`); MLS credentials are full DID
 * URLs (`did:webvh:x#k1`). Comparing them without normalizing would report
 * total divergence every time, which is exactly the sort of mismatch this is
 * meant to catch rather than produce. */
export function fullKid(did: string, kidOrFragment: string): string {
  return kidOrFragment.startsWith('#') ? `${did}${kidOrFragment}` : kidOrFragment
}

export interface DeviceProjection {
  /** What the self group says. */
  projectedKids: string[]
  /** What the document/gossip side currently believes. */
  documentKids: string[]
  /** In the group but not published — senders cannot address these yet. */
  unpublished: string[]
  /** Published but not in the group. Harmless once MLS is in use (they receive
   * envelopes they cannot read), and the reason a stale entry stops being a
   * security bug — but still a device that will not be able to participate
   * until it joins, and still wasted delivery. */
  stale: string[]
  /** True when the two sides already agree — the state a switch is safe in. */
  agrees: boolean
}

/** Compare the group's membership with the document's, both normalized to full
 * DID URLs. Pure: the loader below is what touches storage. */
export function projectDevices(state: ClientState, did: string, documentKids: string[]): DeviceProjection {
  const projectedKids = memberKids(state, did)
  const document = documentKids.map(k => fullKid(did, k))
  const inTree = new Set(projectedKids)
  const inDoc = new Set(document)
  const unpublished = projectedKids.filter(k => !inDoc.has(k))
  const stale = document.filter(k => !inTree.has(k))
  return { projectedKids, documentKids: document, unpublished, stale, agrees: unpublished.length === 0 && stale.length === 0 }
}

/** The projection for this identity, or undefined when this device holds no
 * self group state — a device that has not joined yet, or one whose storage
 * was cleared. Undefined is not a divergence and must never be read as "the
 * group is empty": publishing an empty device list from a missing local state
 * would unpublish every device the identity has. */
export async function selfGroupProjection(did: string, documentKids: string[]): Promise<DeviceProjection | undefined> {
  // No IndexedDB at all means this is not a browser (a test, the anchor) —
  // "no local state", not a failure worth reporting.
  if (typeof indexedDB === 'undefined') return undefined
  const group = await loadGroup(selfGroupIdHex(did))
  if (!group) return undefined
  return projectDevices(group.state, did, documentKids)
}

/** Log where the two mechanisms disagree, and change nothing.
 *
 * This is the whole of the parallel-run: a divergence here is information
 * about the migration, not an error to act on. It is a `warn` rather than a
 * `log` because a persistent divergence means the switch is not yet safe, and
 * that should be visible without anyone looking for it. */
export async function reportDeviceProjection(did: string, documentKids: string[]): Promise<DeviceProjection | undefined> {
  let projection: DeviceProjection | undefined
  try {
    projection = await selfGroupProjection(did, documentKids)
  } catch (e) {
    // Never let an observation break a registration path that works today.
    console.warn('[mls] device projection could not be computed:', e instanceof Error ? e.message : e)
    return undefined
  }
  if (!projection || projection.agrees) return projection
  console.warn(
    `[mls] device list divergence for ${did}: ` +
    `in the group but unpublished [${projection.unpublished.join(', ')}], ` +
    `published but not in the group [${projection.stale.join(', ')}]`,
  )
  return projection
}
