// One cache policy for "the public key behind a kid", shared by both sides of
// the DIDComm wire.
//
// Both sides need the same thing and had grown their own answer to it. The
// mediator resolves the client's key to authenticate every pickup request
// (anchor/mediator/server.ts's resolveViaCache); a browser resolves the
// SENDER's key to decrypt every message it picks up (didcomm/channel.ts), and
// that one had no cache at all beyond the 60s document cache underneath it.
//
// The property both rely on is the same, and it is worth stating once: a kid
// maps to ONE key, permanently. biset's identity keys are rotation-less by
// design (DID.md), and a new device takes a NEW `#kN` slot rather than
// replacing an existing one's key — so `did:...#k3` names the same bytes for
// as long as it names anything at all. That is what makes a long TTL, a
// stale-on-failure fallback and (in the browser) persistence across reloads
// safe rather than reckless.
//
// Why it matters on the receive side: authcrypt is ECDH-1PU, so the sender's
// public key is not an optimization — nothing can be decrypted without it.
// Every incoming message therefore blocked on a DID resolve, which is 3-6.5s
// against a production Pkarr gateway whenever the record isn't already in a
// cache. That delay sat squarely between "the push notification arrived" and
// "the message appears in the thread", which is exactly the gap this exists
// to close.
//
// No DOM, no storage assumptions: persistence is injected, so the anchor can
// use this with none and a browser can back it with IndexedDB.

/** Where a cache keeps its entries between processes. `save` is best-effort
 * and must not throw — losing a persisted key costs one resolve, which must
 * never cost the caller its message. */
interface KeyCachePersistence {
  load(): Promise<Map<string, Uint8Array>>
  save(kid: string, key: Uint8Array): void
  drop(kid: string): void
}

/** Resolves `kid` to its public key, or null when the identity genuinely has
 * no such key published. Throwing and returning null are treated alike — both
 * mean "no answer this time" — so an existing resolver can be passed as-is. */
export type KeyResolver = (kid: string) => Promise<Uint8Array | null>

export interface KeyCacheOptions {
  /** How long an entry is served without re-checking. */
  ttlMs: number
  /** Names this cache in log lines (`mediator did:dht`, `didcomm sender`, …). */
  label: string
  /** Past the TTL, serve the stale entry IMMEDIATELY and refresh in the
   * background instead of making the caller wait for the network.
   *
   * For the browser's receive path this is the whole point: the key cannot
   * have changed (see the header note), so waiting on a refresh buys nothing
   * and costs the user seconds of blank thread. The mediator leaves it off —
   * it is authenticating a request it is about to answer, and there is no
   * screen waiting on it. */
  staleWhileRevalidate?: boolean
  persist?: KeyCachePersistence
}

interface Entry { key: Uint8Array; freshUntil: number }

export class ResolvedKeyCache {
  private entries = new Map<string, Entry>()
  private loaded: Promise<void> | null = null
  private refreshing = new Set<string>()

  constructor(private readonly opts: KeyCacheOptions) {}

  private async ready(): Promise<void> {
    if (!this.opts.persist) return
    if (!this.loaded) {
      this.loaded = this.opts.persist.load()
        .then(saved => {
          for (const [kid, key] of saved) {
            // Restored entries come back STALE on purpose: they are served
            // immediately (that's the point of persisting them) but the first
            // use also schedules a refresh, so a key that somehow did change
            // while this browser was closed corrects itself rather than being
            // trusted for another full TTL.
            if (!this.entries.has(kid)) this.entries.set(kid, { key, freshUntil: 0 })
          }
        })
        .catch(() => {}) // an unreadable cache is an empty cache, never a failure
    }
    return this.loaded
  }

  /** The key for `kid`, resolving it only when there is no usable cached one.
   *
   * `fresh` bypasses the cache entirely and replaces whatever was there — for
   * a caller that has evidence the cached key is wrong (a decrypt that failed
   * with it, say), which is the only way a permanently-cached key could ever
   * become a permanent failure. */
  async get(kid: string, resolve: KeyResolver, opts?: { fresh?: boolean }): Promise<Uint8Array> {
    await this.ready()
    const now = Date.now()
    const cached = this.entries.get(kid)

    if (!opts?.fresh && cached) {
      if (cached.freshUntil > now) return cached.key
      if (this.opts.staleWhileRevalidate) {
        this.refreshInBackground(kid, resolve)
        return cached.key
      }
    }

    const key = await this.resolveOnce(kid, resolve)
    if (key) { this.remember(kid, key); return key }
    if (cached && !opts?.fresh) {
      // The refresh came back empty but a previously-good key is on record.
      // Serve it rather than failing — a gateway hiccup must not break a peer
      // that has been talking to us successfully — and say so, because
      // "resolution started returning nothing" and "resolution is merely slow"
      // are otherwise indistinguishable from the outside.
      console.warn(`[keycache] ${this.opts.label}: resolve for ${kid} came back empty — serving the cached key`)
      return cached.key
    }
    throw new Error(`[keycache] ${this.opts.label}: could not resolve ${kid}`)
  }

  /** Drops a kid, so the next get() must resolve it again. */
  forget(kid: string): void {
    this.entries.delete(kid)
    this.opts.persist?.drop(kid)
  }

  private async resolveOnce(kid: string, resolve: KeyResolver): Promise<Uint8Array | null> {
    try {
      return await resolve(kid)
    } catch (e) {
      console.warn(`[keycache] ${this.opts.label}: resolve threw for ${kid}:`, e instanceof Error ? e.message : e)
      return null
    }
  }

  private remember(kid: string, key: Uint8Array): void {
    this.entries.set(kid, { key, freshUntil: Date.now() + this.opts.ttlMs })
    this.opts.persist?.save(kid, key)
  }

  /** At most one background refresh per kid at a time — a stale entry is read
   * on every message in a batch, and each read would otherwise start its own. */
  private refreshInBackground(kid: string, resolve: KeyResolver): void {
    if (this.refreshing.has(kid)) return
    this.refreshing.add(kid)
    void this.resolveOnce(kid, resolve)
      .then(key => { if (key) this.remember(kid, key) })
      .finally(() => { this.refreshing.delete(kid) })
  }
}
