// Deletes did:webvh locations abandoned by a move, once they've sat unused
// long enough that reclaiming them is unlikely — the other half of
// webvh-server/core.ts's reclaim rule. That rule lets the SAME identity move
// back into a name it once held; this is what eventually frees a name for
// anyone ELSE, since webvh-store.ts never deletes on move by itself (a peer
// still holding only the old DID string has to keep resolving to the new
// location for as long as did:webvh's portability guarantee is worth
// anything). Configured via anchor/index.ts's `webvh_reclaim_ttl_days`
// (2026-08-18, user-requested after the versionId-gap bug this reclaim
// mechanism was built to fix).
import { parseLog } from '../did/webvh/log.ts'
import { buildWebvhDid } from '../did/webvh/identifier.ts'
import type { WebvhLogStore } from './webvh-store.ts'

export interface SweepResult {
  checked: number
  deleted: Array<{ domain: string; username: string }>
}

/** A name is swept when its stored log's LAST entry points (`state.id`)
 * somewhere other than this location's own DID — i.e. this location was
 * moved away from, not merely never updated — and that entry's versionTime
 * is older than `ttlMs`. A location nobody ever moved away from (still
 * resolving to itself) is never touched, no matter how old. */
export function sweepAbandonedWebvhLocations(store: WebvhLogStore, ttlMs: number, now = Date.now()): SweepResult {
  const deleted: Array<{ domain: string; username: string }> = []
  const names = store.list()
  for (const { domain, username } of names) {
    const jsonl = store.read(domain, username)
    if (!jsonl) continue
    let entries: ReturnType<typeof parseLog>
    try {
      entries = parseLog(jsonl)
    } catch {
      continue // unreadable — leave it for a human, sweeping is not a repair tool
    }
    const first = entries[0]
    const last = entries[entries.length - 1]
    const scid = first?.parameters?.scid
    if (!first || !last || !scid) continue

    const locationDid = buildWebvhDid({ scid, domain, pathSegments: [username] })
    const currentId = (last.state as { id?: string } | undefined)?.id
    const movedAway = currentId !== undefined && currentId !== locationDid
    if (!movedAway) continue

    const lastChangeMs = Date.parse(last.versionTime)
    if (!Number.isFinite(lastChangeMs) || now - lastChangeMs < ttlMs) continue

    store.delete(domain, username)
    deleted.push({ domain, username })
  }
  return { checked: names.length, deleted }
}

/** Runs the sweep once now and then on a fixed interval — anchor/index.ts's
 * only background timer (everything else here is request-driven or
 * lazy-expiry; a sweep needs an actual clock because nothing else touches an
 * abandoned name to trigger it). `checkIntervalMs` only needs to be short
 * relative to `ttlMs`, not fine-grained — an hour's slop on a week-plus TTL
 * is immaterial. */
export function startWebvhSweep(store: WebvhLogStore, ttlMs: number, checkIntervalMs: number): void {
  const run = () => {
    const { checked, deleted } = sweepAbandonedWebvhLocations(store, ttlMs)
    if (deleted.length > 0) {
      console.log(`[anchor] webvh sweep: freed ${deleted.length}/${checked} name(s): ${deleted.map(d => `${d.username}@${d.domain}`).join(', ')}`)
    }
  }
  run()
  setInterval(run, checkIntervalMs)
}
