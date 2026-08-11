// Web Push subscriptions held by the mediator, keyed by RECIPIENT KID.
//
// Kid, not client DID, because that is what the queue is keyed by (queue.ts)
// and what a Forward names in `next`: one device = one kid = one browser
// install = one push subscription. Keying by the shared identity DID instead
// would wake every device of an identity for a message addressed to one of
// them — the same undirected fan-out that was quietly killing subscriptions on
// the relay side (go-jmapserver/push.go's pushAccounts note).
//
// Persisted with the same file-backed pattern as connections.ts, one directory
// over, and for the same reason: an anchor restart must not silently unsubscribe
// every client until each happens to reopen its app.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'
import type { WebPushSubscription } from './webpush.ts'

/** A device re-subscribing gets a NEW endpoint from the push service while the
 * old one may still linger here until it 410s, so a handful per kid is normal.
 * Past that, something is wrong and the list is just a send amplifier. */
const MAX_SUBS_PER_KID = 8

interface StoredEntry { kid: string; subs: WebPushSubscription[] }

export class PushSubscriptionStore {
  private byKid = new Map<string, WebPushSubscription[]>()
  private persistPath?: string

  constructor(persistPath?: string) {
    this.persistPath = persistPath
    if (!persistPath || !existsSync(persistPath)) return
    try {
      const stored: StoredEntry[] = JSON.parse(readFileSync(persistPath, 'utf-8'))
      for (const e of stored) this.byKid.set(e.kid, e.subs)
    } catch (e) {
      console.warn('[mediator] push subs file unreadable, starting empty:', e instanceof Error ? e.message : e)
    }
  }

  private save(): void {
    if (!this.persistPath) return
    try {
      const out: StoredEntry[] = [...this.byKid.entries()].map(([kid, subs]) => ({ kid, subs }))
      mkdirSync(dirname(this.persistPath), { recursive: true, mode: 0o700 })
      writeFileSync(this.persistPath, JSON.stringify(out), { mode: 0o600 })
    } catch (e) {
      // In-memory registration already succeeded; a write failure only costs
      // this change its survival across a restart (connections.ts, same note).
      console.warn('[mediator] push subs persist failed:', e instanceof Error ? e.message : e)
    }
  }

  /** Idempotent on endpoint — re-registering on every app boot (which the
   * client does deliberately, as its only recovery path on iOS) must not grow
   * the list. Newest wins on the keys, since a re-subscribe can rotate them. */
  add(kid: string, sub: WebPushSubscription): void {
    const list = this.byKid.get(kid) ?? []
    const existing = list.findIndex(s => s.endpoint === sub.endpoint)
    if (existing >= 0) list[existing] = sub
    else {
      // Oldest out rather than refusing: unlike the message queue (where
      // dropping destroys something the recipient had a right to), an old push
      // subscription here is at worst a dead endpoint, and refusing would lock
      // a device out of notifications entirely.
      if (list.length >= MAX_SUBS_PER_KID) list.shift()
      list.push(sub)
    }
    this.byKid.set(kid, list)
    this.save()
  }

  remove(kid: string, endpoint: string): void {
    const list = this.byKid.get(kid)
    if (!list) return
    const next = list.filter(s => s.endpoint !== endpoint)
    if (next.length) this.byKid.set(kid, next)
    else this.byKid.delete(kid)
    this.save()
  }

  /** Drops every subscription held for a kid, for when its owner deregisters it
   * (keylist-update remove). Left behind, they would keep waking a browser that
   * has logged this device out and can no longer decrypt anything addressed to
   * it — a push it can only respond to by showing nothing, which is exactly the
   * silent-push pattern that gets a subscription dropped by iOS. */
  removeKid(kid: string): void {
    if (!this.byKid.delete(kid)) return
    this.save()
  }

  /** Drops an endpoint from EVERY kid. Used when the push service reports it
   * gone (404/410) — at that point it is dead for all of them, and the sender
   * only knows which kid it happened to be sending to. */
  removeEndpointEverywhere(endpoint: string): void {
    let changed = false
    for (const [kid, list] of [...this.byKid.entries()]) {
      const next = list.filter(s => s.endpoint !== endpoint)
      if (next.length === list.length) continue
      changed = true
      if (next.length) this.byKid.set(kid, next)
      else this.byKid.delete(kid)
    }
    if (changed) this.save()
  }

  get(kid: string): WebPushSubscription[] {
    return this.byKid.get(kid) ?? []
  }

  /** Total across every kid — diagnostics only. */
  count(): number {
    let n = 0
    for (const list of this.byKid.values()) n += list.length
    return n
  }
}
