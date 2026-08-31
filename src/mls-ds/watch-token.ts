// Short-lived, opaque, in-memory tokens authorizing one `GET
// /deliveries/stream` connection (mls-ds/http.ts). An `EventSource` GET
// can't carry a request body or custom headers, so the signed
// `ConversationDeliveriesWatchV1` request (POST /deliveries/watch,
// mls-ds/authorizer.ts's `issueConversationDeliveriesWatch`) mints one of
// these ahead of time; the stream request itself just proves possession of
// the token, not a fresh signature.
//
// Deliberately a server-held lookup table rather than a stateless signed
// token (HMAC/JWT): revocation is a map delete, no key material to manage,
// and the DS is already single-process/single-SQLite-file (store.ts's own
// `watchers` pub/sub note) -- an in-memory table is no new constraint.
import { bytesToHex } from '../protocol/canonical.ts'
import type { GroupLocalId } from '../protocol/conversation-mls-ds.ts'

export interface ConversationWatchTokenRecord {
  groupId: string
  requesterId: GroupLocalId
}

const DEFAULT_TTL_MS = 60 * 60 * 1000 // 1h -- the client re-mints on every reconnect (conversation-group-watch.ts), so this only bounds a truly idle, disconnected watch's resumability, not steady-state operation.

export class ConversationWatchTokenIssuer {
  private readonly tokens = new Map<string, ConversationWatchTokenRecord & { expiresAt: number }>()

  constructor(private readonly ttlMs: number = DEFAULT_TTL_MS) {}

  issue(groupId: string, requesterId: GroupLocalId): { token: string; expiresAt: string } {
    const token = bytesToHex(crypto.getRandomValues(new Uint8Array(24)))
    const expiresAt = Date.now() + this.ttlMs
    this.tokens.set(token, { groupId, requesterId, expiresAt })
    return { token, expiresAt: new Date(expiresAt).toISOString() }
  }

  /** Undefined for a missing OR expired token -- an expired one is also
   * deleted here, so this doubles as the table's only cleanup path (no
   * separate sweep needed; a token nobody ever tries to resolve again just
   * sits harmlessly until the process restarts). */
  resolve(token: string): ConversationWatchTokenRecord | undefined {
    const record = this.tokens.get(token)
    if (!record) return undefined
    if (record.expiresAt < Date.now()) {
      this.tokens.delete(token)
      return undefined
    }
    return { groupId: record.groupId, requesterId: record.requesterId }
  }

  revoke(token: string): void {
    this.tokens.delete(token)
  }
}
