// In-memory recipient-kid → queued packed message store. Deliberately volatile
// (PLAN.md, v1 decision): losing the queue on restart just means senders'
// Forward messages sat unconsumed. Nothing about the mediator's own identity is
// at stake here — that's identity.ts's job, and it does persist.

/** Per recipient, not global. Registering costs nothing — a did:peer is free to
 * mint and the mediator grants mediation to whoever asks, as a DIDComm mediator
 * is meant to — so one shared bucket would let an attacker who filled it stop
 * delivery to everyone. Per-recipient, the only queue they can fill is their
 * own. Unbounded was fine while the mediator was unreachable; it stopped being
 * fine the moment it was published. */
const MAX_PER_RECIPIENT = 256

export class QueueFullError extends Error {
  constructor(recipientKid: string) {
    super(`mediator: queue full for ${recipientKid}`)
  }
}

export class MessageQueue {
  private queues = new Map<string, string[]>()

  /** Refuses rather than evicting. Both bound the damage; they differ in who
   * pays. Dropping the oldest keeps accepting, so a flood destroys messages the
   * recipient had every right to — quietly, at the one point in the system that
   * knows they arrived. Refusing tells the sender, who can retry or route
   * another way, and costs the attacker nothing they were not already going to
   * lose: the only queue they can fill is the one they registered. */
  push(recipientKid: string, packedMessage: string): void {
    const q = this.queues.get(recipientKid) ?? []
    if (q.length >= MAX_PER_RECIPIENT) throw new QueueFullError(recipientKid)
    q.push(packedMessage)
    this.queues.set(recipientKid, q)
  }

  count(recipientKid: string): number {
    return this.queues.get(recipientKid)?.length ?? 0
  }

  take(recipientKid: string, limit: number): string[] {
    const q = this.queues.get(recipientKid) ?? []
    const taken = q.splice(0, limit)
    // Drop the bucket once it empties, or every recipient that ever received a
    // message keeps an entry for the life of the process.
    if (q.length === 0) this.queues.delete(recipientKid)
    return taken
  }
}
