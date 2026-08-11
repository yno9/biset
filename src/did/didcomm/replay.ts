// Bounded, TTL-based replay guard for DIDComm message `id`s (threading.md:
// "The value of an `id` property SHOULD be globally, universally unique ...
// MUST be unique across all interactions"). A DIDComm message id is a fresh
// UUID per send, so a second arrival of the same id is a replay — a captured
// anoncrypt Forward re-POSTed to the mediator (the recipient can't decrypt it,
// but the mediator would re-queue it), or a resent authcrypt request.
//
// Two properties keep this from being a DoS vector in its own right:
//   - bounded: the set never exceeds `max` entries (oldest evicted first), so
//     an attacker flooding distinct ids can't grow memory without limit.
//   - TTL'd: an id is only remembered for `ttlMs`, matched to how long a
//     message could plausibly still be in flight; past that a replay is no
//     longer meaningfully distinguishable from a fresh message anyway, and
//     `expires_time` (see message.ts isExpired) is the sender-side backstop.
//
// Insertion-ordered Map == LRU-by-insertion: the first key is always the
// oldest, so eviction is an O(1) delete of `keys().next()`.
export class SeenIds {
  private seen = new Map<string, number>() // id -> expiry epoch ms

  constructor(private ttlMs = 10 * 60 * 1000, private max = 50_000) {}

  /** Records `id` and returns true if it is NEW (not seen within the TTL), or
   * false if it is a replay. Case-insensitive: threading.md requires ids be
   * compared case-insensitively (their UUID affinity), so a replay that only
   * flips case is still caught. */
  check(id: string): boolean {
    const key = id.toLowerCase()
    const now = Date.now()
    const expiry = this.seen.get(key)
    if (expiry !== undefined && expiry > now) return false // still-live replay
    // Either never seen, or its TTL lapsed — (re)record it. Delete-then-set so
    // a refreshed entry moves to the end of the insertion order (stays newest).
    this.seen.delete(key)
    this.seen.set(key, now + this.ttlMs)
    this.evictExpiredAndOverflow(now)
    return true
  }

  private evictExpiredAndOverflow(now: number): void {
    // Drop lapsed entries from the front (oldest) until one is still live —
    // insertion order isn't strictly expiry order once entries are refreshed,
    // but refreshed entries move to the back, so the front skews oldest and
    // this keeps the common case cheap without scanning the whole map.
    for (const [k, exp] of this.seen) {
      if (exp > now) break
      this.seen.delete(k)
    }
    while (this.seen.size > this.max) {
      const oldest = this.seen.keys().next().value
      if (oldest === undefined) break
      this.seen.delete(oldest)
    }
  }
}
