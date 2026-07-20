// Tracks which client DIDs have registered via mediate-request, and which
// recipient kids each has authorized via keylist-update. This is the mediator's
// allow-list gate: a Forward message's `next` kid must appear in some
// connection's keylist or it's rejected — otherwise anyone could use the
// mediator as an open relay to queue traffic at arbitrary recipients. Mirrors
// adorsys/didcomm-mediator-rs's forward/src/handler.rs::checks(), verified
// against directly.
//
// Persisted to disk (unlike the in-memory message queue, which is fine to
// lose — senders re-send): every anchor restart used to silently deregister
// every client at once, so ANY deploy — even one wholly unrelated to
// mediation — broke delivery for every relay-less identity until each one
// happened to reopen its client and re-register. Same file-backed pattern
// as identity.ts's own keypair persistence, one directory over.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'

interface Connection {
  clientDid: string
  keylist: Set<string>
}

interface StoredConnection {
  clientDid: string
  keylist: string[]
}

/** Registering is free and open by design, so the list has to have a bottom.
 * Both numbers exist to bound memory, not to ration a resource: an ordinary
 * client registers once and lists one or two kids, and these are orders of
 * magnitude above that. */
const MAX_CONNECTIONS = 10_000
const MAX_KEYS_PER_CONNECTION = 32

export class ConnectionFullError extends Error {}

export class ConnectionStore {
  private byClientDid = new Map<string, Connection>()
  private persistPath?: string

  /** `persistPath`, when given, is loaded on construction and rewritten after
   * every mutation — omit it (tests, an ephemeral mediator) to keep the old
   * in-memory-only behavior. A missing or corrupt file just starts empty and
   * self-heals as clients re-register, same as today's restart behavior. */
  constructor(persistPath?: string) {
    this.persistPath = persistPath
    if (!persistPath || !existsSync(persistPath)) return
    try {
      const stored: StoredConnection[] = JSON.parse(readFileSync(persistPath, 'utf-8'))
      for (const s of stored) {
        this.byClientDid.set(s.clientDid, { clientDid: s.clientDid, keylist: new Set(s.keylist) })
      }
    } catch (e) {
      console.warn('[mediator] connections file unreadable, starting empty:', e instanceof Error ? e.message : e)
    }
  }

  private save(): void {
    if (!this.persistPath) return
    try {
      const out: StoredConnection[] = [...this.byClientDid.values()]
        .map(c => ({ clientDid: c.clientDid, keylist: [...c.keylist] }))
      mkdirSync(dirname(this.persistPath), { recursive: true, mode: 0o700 })
      writeFileSync(this.persistPath, JSON.stringify(out), { mode: 0o600 })
    } catch (e) {
      // Registration itself already succeeded in memory — a write failure
      // (disk full, permissions) shouldn't fail the request, just mean this
      // one change won't survive a restart. Loud in the log either way.
      console.warn('[mediator] connections persist failed:', e instanceof Error ? e.message : e)
    }
  }

  /** Throws once the mediator is full rather than growing without end. A public
   * mediator that grants mediation to anyone — which is what a DIDComm mediator
   * is — otherwise hands every passer-by an unbounded allocation. */
  register(clientDid: string): void {
    if (this.byClientDid.has(clientDid)) return
    if (this.byClientDid.size >= MAX_CONNECTIONS) {
      throw new ConnectionFullError('mediator: too many registered clients')
    }
    this.byClientDid.set(clientDid, { clientDid, keylist: new Set() })
    this.save()
  }

  addKey(clientDid: string, recipientKid: string): void {
    this.register(clientDid)
    const conn = this.byClientDid.get(clientDid)!
    if (conn.keylist.size >= MAX_KEYS_PER_CONNECTION && !conn.keylist.has(recipientKid)) {
      throw new ConnectionFullError('mediator: too many keys for this connection')
    }
    conn.keylist.add(recipientKid)
    this.save()
  }

  removeKey(clientDid: string, recipientKid: string): void {
    this.byClientDid.get(clientDid)?.keylist.delete(recipientKid)
    this.save()
  }

  isAuthorized(recipientKid: string): boolean {
    for (const conn of this.byClientDid.values()) {
      if (conn.keylist.has(recipientKid)) return true
    }
    return false
  }
}
