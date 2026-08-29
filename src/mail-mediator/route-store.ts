// Pure state machine for address -> pickup holder bindings
// (PLAN_biset-mail-mediator.md section 5 "Address route registration").
//
// One address, one active holder generation at a time (section 10 --
// "正式対応は一address・一active pickup holder"): a bind carrying a NEW
// routeGeneration replaces every existing holder outright, exactly like a
// mail operational key rotation invalidating the relationships built on
// the key it replaced. A bind carrying the SAME routeGeneration adds (or
// refreshes) one holder within it -- this is what lets a re-bind after a
// relationship kid's own expiry renew without forcing a full rotation.
//
// No crypto, no I/O: same "pure state machine first" shape as
// src/mediator/connections.ts, so this can be unit-tested without a
// server, a clock mock is a plain number, and a durable-store adapter can
// wrap it later without touching this file.

export interface RouteHolder {
  relationshipKid: string
  pickupPublicKey: Uint8Array
  expiresAt: string
}

export interface MailRoute {
  address: string
  routeGeneration: string
  holders: RouteHolder[]
  updatedAt: string
}

/** Registering a route costs nothing but proof of the front-door key, same
 * reasoning as mediator/connections.ts's MAX_KEYS_PER_CONNECTION -- bounds
 * memory, not a legitimate use. */
const MAX_HOLDERS_PER_ADDRESS = 8
const MAX_ADDRESSES = 100_000

export class RouteStoreFullError extends Error {}

export interface MailRouteStore {
  bind(address: string, holder: RouteHolder, routeGeneration: string, nowIso: string): MailRoute
  routeFor(address: string): MailRoute | undefined
  holderFor(address: string, relationshipKid: string): RouteHolder | undefined
  addressForRelationshipKid(relationshipKid: string): string | undefined
  unbind(address: string, relationshipKid: string): boolean
  expireHolders(nowIso: string): void
}

export class RouteStore implements MailRouteStore {
  private byAddress = new Map<string, MailRoute>()
  private addressByRelationshipKid = new Map<string, string>()

  bind(address: string, holder: RouteHolder, routeGeneration: string, nowIso: string): MailRoute {
    const existing = this.byAddress.get(address)
    if (!existing || existing.routeGeneration !== routeGeneration) {
      // New address, or a generation bump: every prior holder is
      // invalidated outright (section 11 -- rotation revokes the old
      // relationship set, not just adds to it).
      if (existing) for (const h of existing.holders) this.addressByRelationshipKid.delete(h.relationshipKid)
      if (!existing && this.byAddress.size >= MAX_ADDRESSES) {
        throw new RouteStoreFullError('mail-mediator: too many routed addresses')
      }
      const route: MailRoute = { address, routeGeneration, holders: [holder], updatedAt: nowIso }
      this.byAddress.set(address, route)
      this.addressByRelationshipKid.set(holder.relationshipKid, address)
      return route
    }
    // Same generation: refresh in place if this relationship kid is
    // already a holder, otherwise add it.
    const already = existing.holders.findIndex(h => h.relationshipKid === holder.relationshipKid)
    if (already >= 0) {
      existing.holders[already] = holder
    } else {
      if (existing.holders.length >= MAX_HOLDERS_PER_ADDRESS) {
        throw new RouteStoreFullError(`mail-mediator: too many holders for ${address}`)
      }
      existing.holders.push(holder)
    }
    existing.updatedAt = nowIso
    this.addressByRelationshipKid.set(holder.relationshipKid, address)
    return existing
  }

  routeFor(address: string): MailRoute | undefined {
    return this.byAddress.get(address)
  }

  holderFor(address: string, relationshipKid: string): RouteHolder | undefined {
    return this.byAddress.get(address)?.holders.find(h => h.relationshipKid === relationshipKid)
  }

  /** The address a relationship kid currently authenticates pickup/submit
   * for -- the reverse index a request carrying only an authcrypt
   * sender kid needs, since neither pickup-request nor submit repeats the
   * address in a way the mediator should trust unverified. */
  addressForRelationshipKid(relationshipKid: string): string | undefined {
    return this.addressByRelationshipKid.get(relationshipKid)
  }

  unbind(address: string, relationshipKid: string): boolean {
    const route = this.byAddress.get(address)
    if (!route) return false
    const index = route.holders.findIndex(h => h.relationshipKid === relationshipKid)
    if (index < 0) return false
    route.holders.splice(index, 1)
    this.addressByRelationshipKid.delete(relationshipKid)
    if (route.holders.length === 0) this.byAddress.delete(address)
    return true
  }

  /** Drops holders past their own expiresAt. Does not touch routeGeneration
   * or delete the address -- an empty holder set just means nobody can
   * pick up right now, exactly like a route that was never bound. */
  expireHolders(nowIso: string): void {
    for (const [address, route] of [...this.byAddress.entries()]) {
      const kept = route.holders.filter(h => h.expiresAt > nowIso)
      if (kept.length === route.holders.length) continue
      for (const h of route.holders) if (!kept.includes(h)) this.addressByRelationshipKid.delete(h.relationshipKid)
      if (kept.length === 0) this.byAddress.delete(address)
      else route.holders = kept
    }
  }
}
