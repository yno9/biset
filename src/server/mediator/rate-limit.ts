/** Bounded fixed-window limiter for the public HTTP crypto boundary. It is
 * intentionally identity-agnostic: the key is a transport address supplied by
 * the reverse proxy, never a DID, recipient kid, or Vault identifier. */
export class IpRateLimiter {
  private readonly windows = new Map<string, { startedAt: number; count: number }>()

  constructor(
    private readonly maxPerWindow: number,
    private readonly windowMs = 60_000,
    private readonly maxTrackedAddresses = 10_000,
  ) {
    for (const [name, value] of Object.entries({ maxPerWindow, windowMs, maxTrackedAddresses })) {
      if (!Number.isSafeInteger(value) || value <= 0) throw new TypeError(`${name} must be a positive safe integer`)
    }
  }

  allow(address: string, now = Date.now()): boolean {
    const existing = this.windows.get(address)
    if (!existing || now - existing.startedAt >= this.windowMs) {
      this.windows.delete(address)
      this.windows.set(address, { startedAt: now, count: 1 })
      this.prune(now)
      return true
    }
    if (existing.count >= this.maxPerWindow) return false
    existing.count++
    return true
  }

  private prune(now: number): void {
    for (const [address, window] of this.windows) {
      if (now - window.startedAt < this.windowMs) break
      this.windows.delete(address)
    }
    while (this.windows.size > this.maxTrackedAddresses) {
      const oldest = this.windows.keys().next().value
      if (oldest === undefined) break
      this.windows.delete(oldest)
    }
  }
}
