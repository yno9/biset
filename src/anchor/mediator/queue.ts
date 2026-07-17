// In-memory recipient-kid → queued packed message store. Deliberately volatile
// (PLAN.md, v1 decision): losing the queue on restart just means senders'
// Forward messages sat unconsumed. Nothing about the mediator's own identity is
// at stake here — that's identity.ts's job, and it does persist.
export class MessageQueue {
  private queues = new Map<string, string[]>()

  push(recipientKid: string, packedMessage: string): void {
    const q = this.queues.get(recipientKid) ?? []
    q.push(packedMessage)
    this.queues.set(recipientKid, q)
  }

  count(recipientKid: string): number {
    return this.queues.get(recipientKid)?.length ?? 0
  }

  take(recipientKid: string, limit: number): string[] {
    const q = this.queues.get(recipientKid) ?? []
    return q.splice(0, limit)
  }
}
