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

export class ConnectionStore {
  private byClientDid = new Map<string, Connection>()

  register(clientDid: string): void {
    if (!this.byClientDid.has(clientDid)) {
      this.byClientDid.set(clientDid, { clientDid, keylist: new Set() })
    }
  }

  addKey(clientDid: string, recipientKid: string): void {
    this.register(clientDid)
    this.byClientDid.get(clientDid)!.keylist.add(recipientKid)
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
