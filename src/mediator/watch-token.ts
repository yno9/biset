// Short-lived, opaque, in-memory tokens authorizing one `GET /stream`
// connection (server.ts) -- the mediator's own version of
// mls-ds/watch-token.ts's ConversationWatchTokenIssuer, for the identical
// reason: an `EventSource` GET can't carry a request body or custom
// headers, so the signed, authcrypt'd WATCH_REQUEST (server.ts's dispatch)
// mints one of these ahead of time; the stream request itself just proves
// possession of the token, not a fresh signature.
//
// A server-held lookup table, not a stateless signed token (HMAC/JWT):
// revocation is a map delete, no key material to manage, and this mediator
// is already single-process (queue.ts's own in-process `watchers` pub/sub
// note) -- an in-memory table adds no new constraint.
const DEFAULT_TTL_MS = 60 * 60 * 1000 // 1h -- the client re-mints on every reconnect, so this only bounds a truly idle, disconnected watch's resumability, not steady-state operation.

export class MediatorWatchTokenIssuer {
  private readonly tokens = new Map<string, { recipientKid: string; expiresAt: number }>()

  constructor(private readonly ttlMs: number = DEFAULT_TTL_MS) {}

  issue(recipientKid: string): { token: string; expiresAt: string } {
    const token = crypto.randomUUID().replace(/-/g, '') + crypto.randomUUID().replace(/-/g, '')
    const expiresAt = Date.now() + this.ttlMs
    this.tokens.set(token, { recipientKid, expiresAt })
    return { token, expiresAt: new Date(expiresAt).toISOString() }
  }

  /** Undefined for a missing OR expired token -- an expired one is also
   * deleted here, so this doubles as the table's only cleanup path. */
  resolve(token: string): { recipientKid: string } | undefined {
    const record = this.tokens.get(token)
    if (!record) return undefined
    if (record.expiresAt < Date.now()) {
      this.tokens.delete(token)
      return undefined
    }
    return { recipientKid: record.recipientKid }
  }

  revoke(token: string): void {
    this.tokens.delete(token)
  }
}
