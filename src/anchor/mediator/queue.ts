// Recipient-kid → queued packed message store, persisted to disk.
//
// This used to be deliberately volatile ("losing the queue on restart just
// means senders' Forward messages sat unconsumed"). That reasoning assumed a
// sender who would notice and retry — there is none. A Forward is answered with
// 202 the moment it is queued, so the sending client has already declared
// success and moved on; a restart between then and the recipient's next pickup
// destroys the message with nobody left holding a copy. Every anchor deploy was
// silently eating whatever was in flight. Now it survives, in the same
// file-backed way connections.ts already stores the keylist one directory over.
//
// What lands on disk is the packed JWE exactly as it arrived: opaque to the
// mediator, which cannot read it and holds no key that could. Persisting it
// extends how long that ciphertext sits on the anchor's disk, so the retention
// bound below is part of the design, not housekeeping.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'

/** Per recipient, not global. Registering costs nothing — a did:peer is free to
 * mint and the mediator grants mediation to whoever asks, as a DIDComm mediator
 * is meant to — so one shared bucket would let an attacker who filled it stop
 * delivery to everyone. Per-recipient, the only queue they can fill is their
 * own. Unbounded was fine while the mediator was unreachable; it stopped being
 * fine the moment it was published. */
const MAX_PER_RECIPIENT = 256

/** How long an undelivered message is kept. Now that the queue outlives the
 * process it needs a bottom, or a recipient who never comes back leaves their
 * ciphertext on the anchor's disk forever. Long enough that a phone left off
 * over a holiday still gets its messages. */
const MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000

export class QueueFullError extends Error {
  constructor(recipientKid: string) {
    super(`mediator: queue full for ${recipientKid}`)
  }
}

/** A queued message and the id the mediator assigns it. Pickup 3.0 delivery is
 * non-destructive: the id travels to the recipient as the delivery attachment's
 * id, and the recipient later names it in `messages-received` to have it
 * removed. So the queue must hold a stable id per entry, not just the bytes.
 *
 * `silent` marks a message that must not wake the recipient with a
 * notification: one of that identity's OWN devices sent it (server.ts's FORWARD
 * case proves this — an authenticated forward whose `next` is a sibling kid of
 * the sender's own connection), so it is a device-sync copy of something the
 * user themselves just did. It is queued and delivered exactly like any other
 * message; the flag only keeps it out of the Web Push count, which is what
 * decides whether a banner appears. Everything about the payload stays as
 * opaque as ever — this says who queued it, never what it says. */
export interface QueuedMessage { id: string; packed: string; queuedAt?: number; silent?: boolean }

interface StoredEntry { kid: string; messages: QueuedMessage[] }

export class MessageQueue {
  private queues = new Map<string, QueuedMessage[]>()
  private persistPath?: string

  /** `persistPath`, when given, is loaded on construction and rewritten after
   * every mutation — omit it (tests, an ephemeral mediator) to keep the old
   * in-memory-only behaviour. A missing or corrupt file just starts empty,
   * which is exactly where every restart used to begin anyway. */
  constructor(persistPath?: string) {
    this.persistPath = persistPath
    if (!persistPath || !existsSync(persistPath)) return
    try {
      const stored: StoredEntry[] = JSON.parse(readFileSync(persistPath, 'utf-8'))
      for (const e of stored) {
        if (e.messages?.length) this.queues.set(e.kid, e.messages)
      }
      this.expire()
    } catch (e) {
      console.warn('[mediator] queue file unreadable, starting empty:', e instanceof Error ? e.message : e)
    }
  }

  private save(): void {
    if (!this.persistPath) return
    try {
      const out: StoredEntry[] = [...this.queues.entries()].map(([kid, messages]) => ({ kid, messages }))
      mkdirSync(dirname(this.persistPath), { recursive: true, mode: 0o700 })
      writeFileSync(this.persistPath, JSON.stringify(out), { mode: 0o600 })
    } catch (e) {
      // The message is already queued in memory and will still be delivered to
      // a client that picks up before the next restart — a write failure costs
      // it only its durability (connections.ts, same note).
      console.warn('[mediator] queue persist failed:', e instanceof Error ? e.message : e)
    }
  }

  /** Drops anything past MAX_AGE_MS. Runs on load and on every push, which is
   * often enough without a timer: a queue nobody writes to isn't growing, and
   * one nobody reads is bounded by MAX_PER_RECIPIENT regardless. Entries from
   * before this file started stamping a time are treated as current, so an
   * upgrade doesn't discard a live queue. */
  private expire(): void {
    const cutoff = Date.now() - MAX_AGE_MS
    for (const [kid, list] of [...this.queues.entries()]) {
      const kept = list.filter(m => (m.queuedAt ?? Date.now()) >= cutoff)
      if (kept.length === list.length) continue
      if (kept.length) this.queues.set(kid, kept)
      else this.queues.delete(kid)
    }
  }

  /** Refuses rather than evicting. Both bound the damage; they differ in who
   * pays. Dropping the oldest keeps accepting, so a flood destroys messages the
   * recipient had every right to — quietly, at the one point in the system that
   * knows they arrived. Refusing tells the sender, who can retry or route
   * another way, and costs the attacker nothing they were not already going to
   * lose: the only queue they can fill is the one they registered. Returns the
   * assigned message id. */
  push(recipientKid: string, packedMessage: string, opts: { silent?: boolean } = {}): string {
    this.expire()
    const q = this.queues.get(recipientKid) ?? []
    if (q.length >= MAX_PER_RECIPIENT) throw new QueueFullError(recipientKid)
    const id = crypto.randomUUID()
    const entry: QueuedMessage = { id, packed: packedMessage, queuedAt: Date.now() }
    if (opts.silent) entry.silent = true
    q.push(entry)
    this.queues.set(recipientKid, q)
    this.save()
    return id
  }

  count(recipientKid: string): number {
    return this.queues.get(recipientKid)?.length ?? 0
  }

  /** How many queued messages are worth interrupting the user for — `count`
   * minus the device-sync copies (QueuedMessage.silent). This, not `count`, is
   * what the Web Push payload carries: the recipient's Service Worker turns
   * that number into both a banner and a badge, and a copy of the user's own
   * just-sent message is neither news nor unread. Pickup is unaffected and
   * still hands over everything — delivery and notification are separate
   * questions, and only the second one has an answer here. */
  loudCount(recipientKid: string): number {
    const q = this.queues.get(recipientKid)
    if (!q) return 0
    let n = 0
    for (const m of q) if (!m.silent) n++
    return n
  }

  /** Drops everything queued for a kid, for when its owner deregisters it
   * (keylist-update remove). Nothing will ever pick these up again — that
   * device is gone — and now that the queue outlives the process, leaving them
   * means ciphertext for a logged-out device sitting here until the retention
   * bound eventually catches it. */
  clear(recipientKid: string): void {
    if (!this.queues.delete(recipientKid)) return
    this.save()
  }

  /** Non-destructive: returns up to `limit` queued messages WITHOUT removing
   * them (Pickup 3.0 — removal waits for `messages-received`). */
  peek(recipientKid: string, limit: number): QueuedMessage[] {
    return (this.queues.get(recipientKid) ?? []).slice(0, limit)
  }

  /** Removes the named messages (Pickup 3.0 `messages-received`) and returns how
   * many remain queued for the recipient. Ids the queue doesn't hold are
   * ignored — an ack is idempotent and a duplicate must not error. */
  remove(recipientKid: string, ids: string[]): number {
    const q = this.queues.get(recipientKid)
    if (!q) return 0
    const drop = new Set(ids)
    const kept = q.filter(m => !drop.has(m.id))
    // Drop the bucket once it empties, or every recipient that ever received a
    // message keeps an entry for the life of the process.
    if (kept.length === 0) this.queues.delete(recipientKid)
    else this.queues.set(recipientKid, kept)
    this.save()
    return kept.length
  }
}
