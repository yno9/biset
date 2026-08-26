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
  /** kid → epoch ms of the last pickup that device authenticated. The only
   * evidence anywhere that a registered kid still belongs to a device that
   * actually exists: registration is a one-shot event, and a browser whose
   * storage was cleared (or that was simply never opened again) leaves its kid
   * registered and its published key live forever. Nothing may auto-delete on
   * this — the keylist stays authoritative for removal (mediator keylist =
   * 権威), and a phone that's off for a month is not a dead device — but
   * without it, a user staring at nine device rows has no way to tell which
   * ones are ghosts. Absent for a kid that has never picked anything up. */
  lastSeen: Map<string, number>
  /** kid → the string the client actually used when it registered that kid.
   *
   * The mediator normalizes a bare DID to a kid for its own bookkeeping
   * (server.ts's normalizeKid), which is right for routing and wrong to say out
   * loud: a client that registered `did:peer:2.Ez6…` and then asked for its
   * keylist got back `did:peer:2.Ez6…#key-1` and could not match the answer to
   * what it had registered. Keeping the original is the only way to answer in
   * the client's own terms while still routing in the mediator's.
   *
   * Absent for a kid registered before this was recorded (and for files written
   * by an older build) — the kid itself is then the best available answer,
   * which is exactly what was returned before. */
  asGiven: Map<string, string>
  /** kid → the X25519 public key that kid authenticated with when it was
   * registered, hex.
   *
   * This is what lets a device keep talking to its mediator after the
   * published document has moved on. Every request is authenticated by
   * resolving the sender's kid, and resolving means reading the identity's
   * DID document — so a device that is momentarily absent from it (mid-publish,
   * or dropped by another device) could do NOTHING, including the one thing it
   * needed to do: deregister, or re-register. It deadlocked two devices of one
   * identity in production (2026-08-13).
   *
   * Recording the key at registration is only correct because a device kid is
   * DERIVED FROM ITS KEY now (did/devicekid.ts): kid → key is one-to-one and
   * permanent, so a key remembered here can never become the wrong answer for
   * that kid. Under the old positional scheme (`#k1`) it would have been
   * exactly wrong — a reused slot number meant a kid whose key legitimately
   * changed, which is the "integrity check failed" incident ARC.md records.
   *
   * The security property is unchanged: joining a keylist still requires
   * resolving the document, so only a device the identity has PUBLISHED can
   * ever be registered. What changes is that it stays authenticated afterwards.
   *
   * Absent for kids registered before this existed — those fall back to
   * resolving, exactly as they always did. */
  keyByKid: Map<string, string>
}

interface StoredConnection {
  clientDid: string
  keylist: string[]
  lastSeen?: Record<string, number>
  asGiven?: Record<string, string>
  keyByKid?: Record<string, string>
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
        this.byClientDid.set(s.clientDid, {
          clientDid: s.clientDid,
          keylist: new Set(s.keylist),
          // Absent in files written before this field existed — read as "never
          // seen", which is exactly right: nothing was recorded, so nothing is
          // known. It fills in on each device's next pickup.
          lastSeen: new Map(Object.entries(s.lastSeen ?? {})),
          asGiven: new Map(Object.entries(s.asGiven ?? {})),
          keyByKid: new Map(Object.entries(s.keyByKid ?? {})),
        })
      }
    } catch (e) {
      console.warn('[mediator] connections file unreadable, starting empty:', e instanceof Error ? e.message : e)
    }
  }

  private save(): void {
    if (!this.persistPath) return
    try {
      const out: StoredConnection[] = [...this.byClientDid.values()]
        .map(c => ({
          clientDid: c.clientDid, keylist: [...c.keylist],
          lastSeen: Object.fromEntries(c.lastSeen), asGiven: Object.fromEntries(c.asGiven),
          keyByKid: Object.fromEntries(c.keyByKid),
        }))
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
    this.byClientDid.set(clientDid, { clientDid, keylist: new Set(), lastSeen: new Map(), asGiven: new Map(), keyByKid: new Map() })
    this.save()
  }

  /** Records that `recipientKid`'s own device just collected mail (a pickup
   * this mediator authenticated as coming from that device). Not persisted on
   * every call — a device polls on a timer, and rewriting the whole file
   * fifteen times a minute per client buys nothing: an hour's granularity is
   * far finer than the "is this device weeks dead?" question this answers, so
   * it saves only when the recorded day changes. */
  touch(recipientKid: string): void {
    for (const conn of this.byClientDid.values()) {
      if (!conn.keylist.has(recipientKid)) continue
      const now = Date.now()
      const prev = conn.lastSeen.get(recipientKid) ?? 0
      conn.lastSeen.set(recipientKid, now)
      if (now - prev > 60 * 60 * 1000) this.save()
      return
    }
  }

  /** Returns whether the keylist actually CHANGED — false means the kid was
   * already registered. Coordinate Mediation 2.0 distinguishes the two in its
   * keylist-update-response (`success` vs `no_change`), and answering
   * `success` for a no-op tells the client its request did something it
   * didn't. */
  addKey(clientDid: string, recipientKid: string, asGiven = recipientKid, publicKeyHex?: string): boolean {
    this.register(clientDid)
    const conn = this.byClientDid.get(clientDid)!
    if (conn.keylist.has(recipientKid)) return false
    if (conn.keylist.size >= MAX_KEYS_PER_CONNECTION) {
      throw new ConnectionFullError('mediator: too many keys for this connection')
    }
    // After the capacity check, never before — a refused add must leave nothing
    // behind.
    if (asGiven !== recipientKid) conn.asGiven.set(recipientKid, asGiven)
    // Recorded at the one moment it is known to be right: this request was
    // authenticated by resolving the document, so the key it arrived with IS
    // the published one.
    if (publicKeyHex) conn.keyByKid.set(recipientKid, publicKeyHex)
    conn.keylist.add(recipientKid)
    this.save()
    return true
  }

  /** Drops the whole connection entry once its keylist empties, mirroring
   * MessageQueue.remove's identical bucket-eviction — otherwise a client that
   * registers, then logs every device out, keeps a hollow entry (empty
   * keylist, clientDid still present) in `byClientDid`/on disk forever, since
   * nothing else ever revisits it. Registering is free and reversible
   * (register's own comment), so there is no relay-style "log out vs. delete
   * account" distinction worth keeping here — logging out THIS device's kid
   * is already the whole story; if it was the last one, the connection is
   * genuinely gone, not just quiet. Safe for multi-device: only the entry
   * whose keylist is now truly empty is removed, so a sibling device's own
   * kid (and thus its connection) is untouched. */
  /** Returns whether the keylist actually CHANGED — false means there was
   * nothing to remove (see addKey's note on why the distinction is reported). */
  /** The key this kid registered with, if it was recorded. */
  keyFor(recipientKid: string): string | undefined {
    for (const conn of this.byClientDid.values()) {
      const k = conn.keyByKid.get(recipientKid)
      if (k) return k
    }
    return undefined
  }

  removeKey(clientDid: string, recipientKid: string): boolean {
    const conn = this.byClientDid.get(clientDid)
    if (!conn || !conn.keylist.has(recipientKid)) return false
    conn.keylist.delete(recipientKid)
    conn.lastSeen.delete(recipientKid)
    conn.asGiven.delete(recipientKid)
    if (conn.keylist.size === 0) this.byClientDid.delete(clientDid)
    this.save()
    return true
  }

  /** Does THIS client own that kid — i.e. are the two the same identity's
   * devices? isAuthorized asks "may anything be queued for this kid at all",
   * which every registered stranger passes; this asks the narrower question of
   * whether the kid belongs to one specific connection's keylist.
   *
   * It exists so the mediator can recognize a device-sync copy (server.ts's
   * FORWARD case) from what it ALREADY stores, rather than from anything the
   * sender asserts. That distinction is the whole point: a flag on a message
   * could be set by any stranger — anoncrypt forwards have no authenticated
   * sender — and would hand every passer-by the power to silence a recipient's
   * notifications. Connection membership is this mediator's own record, written
   * only by an authenticated keylist-update from the owner. */
  ownsKey(clientDid: string, recipientKid: string): boolean {
    return this.byClientDid.get(clientDid)?.keylist.has(recipientKid) ?? false
  }

  isAuthorized(recipientKid: string): boolean {
    for (const conn of this.byClientDid.values()) {
      if (conn.keylist.has(recipientKid)) return true
    }
    return false
  }

  /** The kids THIS client (a shared identity DID across all its devices)
   * currently has registered — the authoritative live-device set for that
   * identity. A logged-out device's keylist-update remove drops its kid here
   * immediately and point-to-point (no DHT last-writer-wins race), which is
   * why keylist-query against this is the backstop that lets every device's
   * next republish converge on removing a key, overriding stale sibling
   * caches. Empty array for an unknown client (never registered) — a caller
   * must treat that as "no authoritative answer", not "zero live devices",
   * exactly as it must treat a failed query. */
  listKeys(clientDid: string): string[] {
    const conn = this.byClientDid.get(clientDid)
    return conn ? [...conn.keylist] : []
  }

  /** listKeys plus each kid's last pickup (epoch ms, undefined = never) — what
   * keylist-query answers with, so a client's device list can show which of
   * its own registered devices are still collecting mail and which are the
   * ghosts left behind by a cleared browser. */
  listKeysWithActivity(clientDid: string): Array<{ kid: string; asGiven: string; lastSeen?: number }> {
    const conn = this.byClientDid.get(clientDid)
    if (!conn) return []
    return [...conn.keylist].map(kid => {
      const lastSeen = conn.lastSeen.get(kid)
      const asGiven = conn.asGiven.get(kid) ?? kid
      return lastSeen === undefined ? { kid, asGiven } : { kid, asGiven, lastSeen }
    })
  }
}
