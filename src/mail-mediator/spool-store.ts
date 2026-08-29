// Pure state machine for the encrypted mail spool: enqueue on SMTP DATA
// acceptance, claim/ack for one-of-N competing pickup holders, expiry for
// leases and records (PLAN_biset-mail-mediator.md sections 6-7, 14).
//
// No crypto, no I/O -- same reasoning as route-store.ts. `encryptedBody` is
// opaque bytes to this store; encrypting/wrapping happens in the SMTP
// ingress adapter, not here.

export type SpoolState = 'pending' | 'claimed' | 'acknowledged'

export interface SpoolRecord {
  address: string
  spoolId: string
  semanticIngressId: string
  mailFrom: string
  encryptedBody: Uint8Array
  bodyHash: Uint8Array
  state: SpoolState
  claimHolderId?: string
  claimExpiresAt?: string
  createdAt: string
  expiresAt: string
}

export interface EnqueueInput {
  address: string
  semanticIngressId: string
  mailFrom: string
  encryptedBody: Uint8Array
  bodyHash: Uint8Array
  createdAt: string
  expiresAt: string
}

/** Bounds memory the same way mediator/queue.ts's MAX_PER_RECIPIENT does --
 * SMTP acceptance is otherwise open to anyone who can route mail here. */
const MAX_PENDING_PER_ADDRESS = 10_000

export class SpoolFullError extends Error {}

export interface MailSpoolStore {
  enqueue(input: EnqueueInput): SpoolRecord
  claim(address: string, holderId: string, leaseMs: number, limit: number, nowIso: string): SpoolRecord[]
  acknowledge(address: string, holderId: string, spoolIds: string[]): number
  expireLeases(nowIso: string): void
  expireRecords(nowIso: string): number
  pendingCount(address: string): number
}

export class SpoolStore implements MailSpoolStore {
  private byAddress = new Map<string, SpoolRecord[]>()
  private bySpoolId = new Map<string, SpoolRecord>()
  /** address -> semanticIngressId -> spoolId, for idempotent re-enqueue on
   * SMTP DATA retry (section 9). */
  private bySemanticId = new Map<string, Map<string, string>>()

  /** Returns the existing record unchanged when `semanticIngressId` was
   * already enqueued for this address -- an SMTP retry of the same DATA
   * must not create a second spool entry the recipient would see twice. */
  enqueue(input: EnqueueInput): SpoolRecord {
    const semanticIndex = this.bySemanticId.get(input.address)
    const existingId = semanticIndex?.get(input.semanticIngressId)
    if (existingId) {
      const existing = this.bySpoolId.get(existingId)
      if (existing) return existing
    }
    const pending = this.byAddress.get(input.address) ?? []
    const pendingCount = pending.filter(r => r.state !== 'acknowledged').length
    if (pendingCount >= MAX_PENDING_PER_ADDRESS) {
      throw new SpoolFullError(`mail-mediator: spool full for ${input.address}`)
    }
    const record: SpoolRecord = {
      address: input.address,
      spoolId: crypto.randomUUID(),
      semanticIngressId: input.semanticIngressId,
      mailFrom: input.mailFrom,
      encryptedBody: input.encryptedBody,
      bodyHash: input.bodyHash,
      state: 'pending',
      createdAt: input.createdAt,
      expiresAt: input.expiresAt,
    }
    pending.push(record)
    this.byAddress.set(input.address, pending)
    this.bySpoolId.set(record.spoolId, record)
    const index = semanticIndex ?? new Map<string, string>()
    index.set(input.semanticIngressId, record.spoolId)
    this.bySemanticId.set(input.address, index)
    return record
  }

  /** One-of-N claim: takes up to `limit` records currently `pending` (or
   * whose lease has already expired -- expireLeases lazily rolls those
   * back to pending first) and marks them `claimed` under a fresh lease.
   * Non-destructive to the ciphertext: acknowledge is what actually
   * removes an entry (section 7). */
  claim(address: string, holderId: string, leaseMs: number, limit: number, nowIso: string): SpoolRecord[] {
    this.expireLeases(nowIso)
    const list = this.byAddress.get(address) ?? []
    const claimExpiresAt = new Date(Date.parse(nowIso) + leaseMs).toISOString()
    const claimed: SpoolRecord[] = []
    for (const record of list) {
      if (claimed.length >= limit) break
      if (record.state !== 'pending') continue
      record.state = 'claimed'
      record.claimHolderId = holderId
      record.claimExpiresAt = claimExpiresAt
      claimed.push(record)
    }
    return claimed
  }

  /** Only the holder that currently holds the claim may acknowledge it --
   * a lease that already expired and was reclaimed by someone else must
   * not be torn out from under the new holder by a late ACK from the old
   * one. Returns how many of the named ids were actually acknowledged. */
  acknowledge(address: string, holderId: string, spoolIds: string[]): number {
    let count = 0
    for (const spoolId of spoolIds) {
      const record = this.bySpoolId.get(spoolId)
      if (!record || record.address !== address) continue
      if (record.state !== 'claimed' || record.claimHolderId !== holderId) continue
      record.state = 'acknowledged'
      this.remove(record)
      count++
    }
    return count
  }

  /** Rolls a claim back to `pending` once its lease has lapsed, so another
   * holder can pick it up (section 7 -- "lease失効後は別holderが引き継げる"). */
  expireLeases(nowIso: string): void {
    for (const record of this.bySpoolId.values()) {
      if (record.state !== 'claimed') continue
      if (!record.claimExpiresAt || record.claimExpiresAt > nowIso) continue
      record.state = 'pending'
      record.claimHolderId = undefined
      record.claimExpiresAt = undefined
    }
  }

  /** Drops records past their own `expiresAt` regardless of state.
   * Generating a DSN for what's dropped is the ingress workflow's
   * responsibility, not this pure store's -- it only reports the count so
   * a caller can tell something was lost. */
  expireRecords(nowIso: string): number {
    let dropped = 0
    for (const record of [...this.bySpoolId.values()]) {
      if (record.expiresAt > nowIso) continue
      this.remove(record)
      dropped++
    }
    return dropped
  }

  pendingCount(address: string): number {
    return (this.byAddress.get(address) ?? []).filter(r => r.state === 'pending').length
  }

  private remove(record: SpoolRecord): void {
    this.bySpoolId.delete(record.spoolId)
    this.bySemanticId.get(record.address)?.delete(record.semanticIngressId)
    const list = this.byAddress.get(record.address)
    if (!list) return
    const kept = list.filter(r => r.spoolId !== record.spoolId)
    if (kept.length === 0) this.byAddress.delete(record.address)
    else this.byAddress.set(record.address, kept)
  }
}
