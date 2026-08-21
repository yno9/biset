import { Database } from 'bun:sqlite'
import { equalBytes, sha256Bytes } from '../../protocol/canonical.ts'
import { assertDeliverySeq, deliverySeq, type DeliverySeq, type DeviceId, type IdentityId } from '../../protocol/ids.ts'
import type { DeliveryPullResult, RestoreRequiredReason, VaultDeliveryAckV1, VaultDeliveryAppendV1, VaultDeliveryItemV1, VaultDeliveryPullV1 } from '../../protocol/vault.ts'
import { assertVaultDeliveryAck, assertVaultDeliveryAppend, assertVaultDeliveryPull, ProtocolValidationError } from '../../protocol/validate.ts'
import type { VaultDeliveryAuthorizer, VaultDeliveryStatus, VaultDeliveryStore, VaultDeliveryStoreLimits } from './vault-delivery-store.ts'

const DEFAULT_LIMITS: VaultDeliveryStoreLimits = {
  maxPayloadBytes: 25 * 1024 * 1024,
  maxIdentityPayloadBytes: 100 * 1024 * 1024,
  maxIdentityPendingItems: 128,
  deliveryTtlMs: 24 * 60 * 60 * 1000,
}

type State = 'pending' | 'completed' | 'expired'
interface EntryRow { identity_id: string; seq: string; append_id: string; payload: Uint8Array; payload_hash: Uint8Array; created_at: string; expires_at: string; state: State; gap_reason: RestoreRequiredReason | null }

/**
 * Crash-safe bounded mediator persistence. This schema deliberately contains
 * no plaintext, mailbox projection, query index, or historical blob archive:
 * only unacknowledged ciphertext, frozen recipients, ACKs, and gap metadata.
 */
export class SqliteVaultDeliveryStore implements VaultDeliveryStore {
  private readonly limits: VaultDeliveryStoreLimits

  constructor(
    private readonly database: Database,
    private readonly authorizer: VaultDeliveryAuthorizer,
    limits: VaultDeliveryStoreLimits = DEFAULT_LIMITS,
  ) {
    if (!Number.isSafeInteger(limits.deliveryTtlMs) || limits.deliveryTtlMs <= 0) throw new TypeError('deliveryTtlMs must be a positive safe integer')
    this.limits = limits
    installSchema(database)
  }

  static open(path: string, authorizer: VaultDeliveryAuthorizer, limits?: VaultDeliveryStoreLimits): SqliteVaultDeliveryStore {
    if (!path) throw new TypeError('SQLite delivery store path is required')
    return new SqliteVaultDeliveryStore(new Database(path), authorizer, limits)
  }

  close(): void { this.database.close() }

  async append(input: VaultDeliveryAppendV1, now = new Date()): Promise<VaultDeliveryItemV1> {
    assertVaultDeliveryAppend(input)
    if (!equalBytes(sha256Bytes(input.payload), input.payloadHash)) throw new ProtocolValidationError('payloadHash must equal SHA-256(payload)')
    if (!(await this.authorizer.verifyAppend(input))) throw new ProtocolValidationError('delivery append is not authorised')
    if (input.payload.length > this.limits.maxPayloadBytes) throw new ProtocolValidationError('delivery payload exceeds maxPayloadBytes')
    await this.expire(now)

    const existing = this.database.query<EntryRow, [string, string]>('SELECT * FROM vault_delivery_entries WHERE identity_id = ? AND append_id = ?').get(input.identityId, input.appendId)
    if (existing) {
      if (!equalBytes(bytes(existing.payload_hash), input.payloadHash)) throw new ProtocolValidationError('appendId is already bound to a different payload')
      return item(existing)
    }
    const recipients = await this.authorizer.recipientsAtAppend(input.identityId)
    if (recipients.length === 0 || new Set(recipients).size !== recipients.length || recipients.some(value => !value)) throw new ProtocolValidationError('core returned an invalid recipient snapshot')

    const createdAt = now.toISOString()
    const expiresAt = new Date(now.getTime() + this.limits.deliveryTtlMs).toISOString()
    const append = this.database.transaction(() => {
      const current = this.database.query<{ latest_seq: string } | null, [string]>('SELECT latest_seq FROM vault_delivery_identities WHERE identity_id = ?').get(input.identityId)
      const seq = deliverySeq((current ? BigInt(current.latest_seq) : 0n) + 1n)
      this.database.query('INSERT INTO vault_delivery_identities (identity_id, latest_seq) VALUES (?, ?) ON CONFLICT(identity_id) DO UPDATE SET latest_seq = excluded.latest_seq').run(input.identityId, seq)
      this.database.query('INSERT INTO vault_delivery_entries (identity_id, seq, append_id, payload, payload_hash, created_at, expires_at, state, gap_reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)').run(input.identityId, seq, input.appendId, input.payload, input.payloadHash, createdAt, expiresAt, 'pending')
      for (const deviceId of recipients) this.database.query('INSERT INTO vault_delivery_recipients (identity_id, seq, device_id) VALUES (?, ?, ?)').run(input.identityId, seq, deviceId)
      return seq
    })
    const seq = append()
    this.enforceQuota(input.identityId)
    return { version: 1, identityId: input.identityId, seq, payload: input.payload.slice(), payloadHash: input.payloadHash.slice(), createdAt, expiresAt }
  }

  async pull(input: VaultDeliveryPullV1, now = new Date()): Promise<DeliveryPullResult> {
    assertVaultDeliveryPull(input)
    if (!(await this.authorizer.verifyPull(input))) throw new ProtocolValidationError('delivery pull is not authorised')
    await this.expire(now)
    const floor = await this.authorizer.deliveryFloor(input.identityId, input.recipientDeviceId)
    if (!floor) throw new ProtocolValidationError('device is not trusted for this identity')
    const latest = this.latest(input.identityId)
    const retainedFrom = this.retainedFrom(input.identityId, latest)
    const requested = BigInt(input.after)
    if (requested < BigInt(floor) - 1n) return restore(input.after, retainedFrom, latest, 'new-device')
    if (requested < BigInt(retainedFrom) - 1n) return restore(input.after, retainedFrom, latest, this.gapReason(input.identityId, deliverySeq(requested + 1n)))
    const rows = this.database.query<EntryRow, [string]>('SELECT * FROM vault_delivery_entries WHERE identity_id = ? AND state = \'pending\' ORDER BY length(seq), seq').all(input.identityId)
    const items = rows.filter(row => BigInt(row.seq) > requested && this.isRecipient(input.identityId, row.seq, input.recipientDeviceId) && !this.isAcknowledged(input.identityId, row.seq, input.recipientDeviceId)).map(item)
    return { kind: 'items', items, nextCursor: items.at(-1)?.seq ?? input.after, retainedFrom, latestSeq: latest }
  }

  async acknowledge(ack: VaultDeliveryAckV1, now = new Date()): Promise<void> {
    assertVaultDeliveryAck(ack)
    await this.expire(now)
    const row = this.database.query<EntryRow, [string, string]>('SELECT * FROM vault_delivery_entries WHERE identity_id = ? AND seq = ?').get(ack.identityId, ack.seq)
    if (!row) throw new ProtocolValidationError('unknown delivery sequence')
    if (!this.isRecipient(ack.identityId, ack.seq, ack.recipientDeviceId)) throw new ProtocolValidationError('ACK device is not in the recipient snapshot')
    if (!equalBytes(bytes(row.payload_hash), ack.payloadHash)) throw new ProtocolValidationError('ACK payload hash does not match delivery')
    if (!(await this.authorizer.verifyAck(ack, item(row)))) throw new ProtocolValidationError('ACK is not authorised')
    if (row.state === 'completed' && this.isAcknowledged(ack.identityId, ack.seq, ack.recipientDeviceId)) return
    if (row.state !== 'pending') throw new ProtocolValidationError(`delivery is already ${row.state}`)
    const transaction = this.database.transaction(() => {
      this.database.query('INSERT OR IGNORE INTO vault_delivery_acks (identity_id, seq, device_id) VALUES (?, ?, ?)').run(ack.identityId, ack.seq, ack.recipientDeviceId)
      const recipients = Number(this.database.query<{ count: number }, [string, string]>('SELECT count(*) AS count FROM vault_delivery_recipients WHERE identity_id = ? AND seq = ?').get(ack.identityId, ack.seq)?.count ?? 0)
      const acknowledgements = Number(this.database.query<{ count: number }, [string, string]>('SELECT count(*) AS count FROM vault_delivery_acks WHERE identity_id = ? AND seq = ?').get(ack.identityId, ack.seq)?.count ?? 0)
      if (acknowledgements === recipients) this.database.query("UPDATE vault_delivery_entries SET payload = x'', state = 'completed', gap_reason = 'delivery-confirmed' WHERE identity_id = ? AND seq = ?").run(ack.identityId, ack.seq)
    })
    transaction()
  }

  async expire(now = new Date()): Promise<void> {
    this.database.query("UPDATE vault_delivery_entries SET payload = x'', state = 'expired', gap_reason = 'ttl-expired' WHERE state = 'pending' AND expires_at <= ?").run(now.toISOString())
  }

  async status(identityId: IdentityId): Promise<VaultDeliveryStatus> {
    const latest = this.latest(identityId)
    const values = this.database.query<{ bytes: number; count: number }, [string]>("SELECT coalesce(sum(length(payload)), 0) AS bytes, count(*) AS count FROM vault_delivery_entries WHERE identity_id = ? AND state = 'pending'").get(identityId)
    return { identityId, latestSeq: latest, retainedFrom: this.retainedFrom(identityId, latest), payloadBytes: Number(values?.bytes ?? 0), pendingItems: Number(values?.count ?? 0) }
  }

  private latest(identityId: IdentityId): DeliverySeq {
    return this.database.query<{ latest_seq: string }, [string]>('SELECT latest_seq FROM vault_delivery_identities WHERE identity_id = ?').get(identityId)?.latest_seq ?? '0'
  }

  private retainedFrom(identityId: IdentityId, latest: DeliverySeq): DeliverySeq {
    return this.database.query<{ seq: string }, [string]>("SELECT seq FROM vault_delivery_entries WHERE identity_id = ? AND state = 'pending' ORDER BY length(seq), seq LIMIT 1").get(identityId)?.seq ?? deliverySeq(BigInt(latest) + 1n)
  }

  private gapReason(identityId: IdentityId, seq: DeliverySeq): RestoreRequiredReason {
    return this.database.query<{ gap_reason: RestoreRequiredReason | null }, [string, string]>('SELECT gap_reason FROM vault_delivery_entries WHERE identity_id = ? AND seq = ?').get(identityId, seq)?.gap_reason ?? 'ttl-expired'
  }

  private isRecipient(identityId: IdentityId, seq: DeliverySeq, deviceId: DeviceId): boolean {
    return this.database.query<{ present: number }, [string, string, string]>('SELECT 1 AS present FROM vault_delivery_recipients WHERE identity_id = ? AND seq = ? AND device_id = ?').get(identityId, seq, deviceId)?.present === 1
  }

  private isAcknowledged(identityId: IdentityId, seq: DeliverySeq, deviceId: DeviceId): boolean {
    return this.database.query<{ present: number }, [string, string, string]>('SELECT 1 AS present FROM vault_delivery_acks WHERE identity_id = ? AND seq = ? AND device_id = ?').get(identityId, seq, deviceId)?.present === 1
  }

  private enforceQuota(identityId: IdentityId): void {
    while (true) {
      const values = this.database.query<{ bytes: number; count: number }, [string]>("SELECT coalesce(sum(length(payload)), 0) AS bytes, count(*) AS count FROM vault_delivery_entries WHERE identity_id = ? AND state = 'pending'").get(identityId)
      if (Number(values?.bytes ?? 0) <= this.limits.maxIdentityPayloadBytes && Number(values?.count ?? 0) <= this.limits.maxIdentityPendingItems) return
      const oldest = this.database.query<{ seq: string }, [string]>("SELECT seq FROM vault_delivery_entries WHERE identity_id = ? AND state = 'pending' ORDER BY length(seq), seq LIMIT 1").get(identityId)
      if (!oldest) throw new ProtocolValidationError('cannot enforce delivery quota')
      this.database.query("UPDATE vault_delivery_entries SET payload = x'', state = 'expired', gap_reason = 'retention-quota' WHERE identity_id = ? AND seq = ?").run(identityId, oldest.seq)
    }
  }
}

function installSchema(database: Database): void {
  database.exec(`
    PRAGMA journal_mode = WAL;
    CREATE TABLE IF NOT EXISTS vault_delivery_identities (identity_id TEXT PRIMARY KEY, latest_seq TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS vault_delivery_entries (
      identity_id TEXT NOT NULL, seq TEXT NOT NULL, append_id TEXT NOT NULL, payload BLOB NOT NULL, payload_hash BLOB NOT NULL,
      created_at TEXT NOT NULL, expires_at TEXT NOT NULL, state TEXT NOT NULL, gap_reason TEXT,
      PRIMARY KEY (identity_id, seq), UNIQUE (identity_id, append_id)
    );
    CREATE TABLE IF NOT EXISTS vault_delivery_recipients (identity_id TEXT NOT NULL, seq TEXT NOT NULL, device_id TEXT NOT NULL, PRIMARY KEY (identity_id, seq, device_id));
    CREATE TABLE IF NOT EXISTS vault_delivery_acks (identity_id TEXT NOT NULL, seq TEXT NOT NULL, device_id TEXT NOT NULL, PRIMARY KEY (identity_id, seq, device_id));
    CREATE INDEX IF NOT EXISTS vault_delivery_pending ON vault_delivery_entries (identity_id, state, seq);
  `)
}

function item(row: EntryRow): VaultDeliveryItemV1 {
  return { version: 1, identityId: row.identity_id, seq: row.seq, payload: bytes(row.payload), payloadHash: bytes(row.payload_hash), createdAt: row.created_at, expiresAt: row.expires_at }
}

function bytes(value: Uint8Array): Uint8Array { return new Uint8Array(value) }

function restore(requestedCursor: DeliverySeq, retainedFrom: DeliverySeq, latestSeq: DeliverySeq, reason: RestoreRequiredReason): DeliveryPullResult {
  return { kind: 'restoreRequired', requestedCursor, retainedFrom, latestSeq, reason }
}
