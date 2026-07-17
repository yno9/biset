// Tracks which client DIDs have registered via mediate-request, and which
// recipient kids each has authorized via keylist-update. This is the mediator's
// allow-list gate: a Forward message's `next` kid must appear in some
// connection's keylist or it's rejected — otherwise anyone could use the
// mediator as an open relay to queue traffic at arbitrary recipients. Mirrors
// adorsys/didcomm-mediator-rs's forward/src/handler.rs::checks(), verified
// against directly.
interface Connection {
  clientDid: string
  keylist: Set<string>
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

  /** Throws once the mediator is full rather than growing without end. A public
   * mediator that grants mediation to anyone — which is what a DIDComm mediator
   * is — otherwise hands every passer-by an unbounded allocation. */
  register(clientDid: string): void {
    if (this.byClientDid.has(clientDid)) return
    if (this.byClientDid.size >= MAX_CONNECTIONS) {
      throw new ConnectionFullError('mediator: too many registered clients')
    }
    this.byClientDid.set(clientDid, { clientDid, keylist: new Set() })
  }

  addKey(clientDid: string, recipientKid: string): void {
    this.register(clientDid)
    const conn = this.byClientDid.get(clientDid)!
    if (conn.keylist.size >= MAX_KEYS_PER_CONNECTION && !conn.keylist.has(recipientKid)) {
      throw new ConnectionFullError('mediator: too many keys for this connection')
    }
    conn.keylist.add(recipientKid)
  }

  removeKey(clientDid: string, recipientKid: string): void {
    this.byClientDid.get(clientDid)?.keylist.delete(recipientKid)
  }

  isAuthorized(recipientKid: string): boolean {
    for (const conn of this.byClientDid.values()) {
      if (conn.keylist.has(recipientKid)) return true
    }
    return false
  }
}
