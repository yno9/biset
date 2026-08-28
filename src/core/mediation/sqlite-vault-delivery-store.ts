import { Database } from 'bun:sqlite'
import { equalBytes, sha256Bytes } from '../../protocol/canonical.ts'
import { assertDeliverySeq, deliverySeq, type DeliverySeq, type DeviceId, type IdentityId } from '../../protocol/ids.ts'
import type { DeliveryPullResult, RestoreRequiredReason, VaultDeliveryAckV1, VaultDeliveryAppendV1, VaultDeliveryItemV1, VaultDeliveryPullV1 } from '../../protocol/vault.ts'
import { assertVaultDeliveryAck, assertVaultDeliveryAppend, assertVaultDeliveryPull, ProtocolValidationError } from '../../protocol/validate.ts'
import type { VaultDeliveryAuthorizer, VaultDeliveryStatus, VaultDeliveryStore, VaultDeliveryStoreLimits } from './vault-delivery-store.ts'
import { stableIdKey } from '../../identity/idkey.ts'

/** Kept identical to vault-delivery-store.ts's own DEFAULT_LIMITS (see its comment for the retention rationale). */
const DEFAULT_LIMITS: VaultDeliveryStoreLimits = {
  maxPayloadBytes: 25 * 1024 * 1024,
  maxIdentityPayloadBytes: 100 * 1024 * 1024,
  maxIdentityPendingItems: 128,
  deliveryTtlMs: 30 * 24 * 60 * 60 * 1000,
}

type State = 'pending' | 'completed' | 'expired'
interface EntryRow { identity_id: string; seq: string; append_id: string; payload: Uint8Array; payload_hash: Uint8Array; created_at: string; expires_at: string; state: State; gap_reason: RestoreRequiredReason | null }

/**
 * Crash-safe bounded mediator persistence. This schema deliberately contains
 * no plaintext, mailbox projection, query index, or historical blob archive:
 * only unacknowledged ciphertext, frozen recipients, ACKs, and gap metadata.
 *
 * Every table is actually PARTITIONED by `identity_key`
 * (`stableIdKey(identityId)`, the SCID), not the `identity_id` column --
 * same reasoning as device-roster.ts's own MemoryTrustedDeviceRoster and
 * sqlite-device-roster.ts: a did:webvh domain move changes the DID string
 * one device at a time, and partitioning by the mutable string would
 * silently split one identity's pending delivery queue into two the moment
 * one device's calls started using the new string, orphaning any device
 * still using the old one. `identity_id` itself stays a plain, unindexed
 * column recording whatever string the device that WROTE a given row
 * happened to use at the time -- still a real DID, just not necessarily
 * the same string a caller reading it back today uses internally; that
 * reconciliation is the CLIENT's job (its own local vault storage), not
 * this bounded relay's.
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

    const key = stableIdKey(input.identityId)
    const existing = this.database.query<EntryRow, [string, string]>('SELECT * FROM vault_delivery_entries WHERE identity_key = ? AND append_id = ?').get(key, input.appendId)
    if (existing) {
      if (!equalBytes(bytes(existing.payload_hash), input.payloadHash)) throw new ProtocolValidationError('appendId is already bound to a different payload')
      return item(existing)
    }
    const recipients = await this.authorizer.recipientsAtAppend(input.identityId)
    if (recipients.length === 0 || new Set(recipients).size !== recipients.length || recipients.some(value => !value)) throw new ProtocolValidationError('core returned an invalid recipient snapshot')

    const createdAt = now.toISOString()
    const expiresAt = new Date(now.getTime() + this.limits.deliveryTtlMs).toISOString()
    const append = this.database.transaction(() => {
      const current = this.database.query<{ latest_seq: string } | null, [string]>('SELECT latest_seq FROM vault_delivery_identities WHERE identity_key = ?').get(key)
      const seq = deliverySeq((current ? BigInt(current.latest_seq) : 0n) + 1n)
      this.database.query('INSERT INTO vault_delivery_identities (identity_key, latest_seq) VALUES (?, ?) ON CONFLICT(identity_key) DO UPDATE SET latest_seq = excluded.latest_seq').run(key, seq)
      this.database.query('INSERT INTO vault_delivery_entries (identity_key, identity_id, seq, append_id, payload, payload_hash, created_at, expires_at, state, gap_reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)').run(key, input.identityId, seq, input.appendId, input.payload, input.payloadHash, createdAt, expiresAt, 'pending')
      for (const deviceId of recipients) this.database.query('INSERT INTO vault_delivery_recipients (identity_key, seq, device_id) VALUES (?, ?, ?)').run(key, seq, deviceId)
      return seq
    })
    const seq = append()
    this.enforceQuota(key)
    return { version: 1, identityId: input.identityId, seq, payload: input.payload.slice(), payloadHash: input.payloadHash.slice(), createdAt, expiresAt }
  }

  async pull(input: VaultDeliveryPullV1, now = new Date()): Promise<DeliveryPullResult> {
    assertVaultDeliveryPull(input)
    if (!(await this.authorizer.verifyPull(input))) throw new ProtocolValidationError('delivery pull is not authorised')
    await this.expire(now)
    const floor = await this.authorizer.deliveryFloor(input.identityId, input.recipientDeviceId)
    if (!floor) throw new ProtocolValidationError('device is not trusted for this identity')
    const key = stableIdKey(input.identityId)
    const latest = this.latest(key)
    const retainedFrom = this.retainedFrom(key, latest)
    const requested = BigInt(input.after)
    if (requested < BigInt(floor) - 1n) return restore(input.after, retainedFrom, latest, 'new-device')
    if (requested < BigInt(retainedFrom) - 1n) return restore(input.after, retainedFrom, latest, this.gapReason(key, deliverySeq(requested + 1n)))
    const rows = this.database.query<EntryRow, [string]>('SELECT * FROM vault_delivery_entries WHERE identity_key = ? AND state = \'pending\' ORDER BY length(seq), seq').all(key)
    const items = rows.filter(row => BigInt(row.seq) > requested && this.isRecipient(key, row.seq, input.recipientDeviceId) && !this.isAcknowledged(key, row.seq, input.recipientDeviceId)).map(item)
    return { kind: 'items', items, nextCursor: items.at(-1)?.seq ?? input.after, retainedFrom, latestSeq: latest }
  }

  async acknowledge(ack: VaultDeliveryAckV1, now = new Date()): Promise<void> {
    assertVaultDeliveryAck(ack)
    await this.expire(now)
    const key = stableIdKey(ack.identityId)
    const row = this.database.query<EntryRow, [string, string]>('SELECT * FROM vault_delivery_entries WHERE identity_key = ? AND seq = ?').get(key, ack.seq)
    if (!row) throw new ProtocolValidationError('unknown delivery sequence')
    if (!this.isRecipient(key, ack.seq, ack.recipientDeviceId)) throw new ProtocolValidationError('ACK device is not in the recipient snapshot')
    if (!equalBytes(bytes(row.payload_hash), ack.payloadHash)) throw new ProtocolValidationError('ACK payload hash does not match delivery')
    if (!(await this.authorizer.verifyAck(ack, item(row)))) throw new ProtocolValidationError('ACK is not authorised')
    // `row` was read before the `authorizer.verifyAck` await above, so its
    // `state` can be stale by the time we get here: a concurrent expire()
    // (or another device's acknowledge()) may have completed/expired this
    // same row while this call was suspended. Re-check and write inside ONE
    // synchronous transaction so the decision is made against a fresh read,
    // not the pre-await snapshot -- otherwise a completing ACK could
    // resurrect an already-expired row as 'completed'.
    const transaction = this.database.transaction((): void => {
      const current = this.database.query<{ state: State }, [string, string]>('SELECT state FROM vault_delivery_entries WHERE identity_key = ? AND seq = ?').get(key, ack.seq)
      if (!current) throw new ProtocolValidationError('unknown delivery sequence')
      if (current.state === 'completed') {
        if (this.isAcknowledged(key, ack.seq, ack.recipientDeviceId)) return
        throw new ProtocolValidationError(`delivery is already ${current.state}`)
      }
      if (current.state !== 'pending') throw new ProtocolValidationError(`delivery is already ${current.state}`)
      this.database.query('INSERT OR IGNORE INTO vault_delivery_acks (identity_key, seq, device_id) VALUES (?, ?, ?)').run(key, ack.seq, ack.recipientDeviceId)
      const recipients = Number(this.database.query<{ count: number }, [string, string]>('SELECT count(*) AS count FROM vault_delivery_recipients WHERE identity_key = ? AND seq = ?').get(key, ack.seq)?.count ?? 0)
      const acknowledgements = Number(this.database.query<{ count: number }, [string, string]>('SELECT count(*) AS count FROM vault_delivery_acks WHERE identity_key = ? AND seq = ?').get(key, ack.seq)?.count ?? 0)
      if (acknowledgements === recipients) this.database.query("UPDATE vault_delivery_entries SET payload = x'', state = 'completed', gap_reason = 'delivery-confirmed' WHERE identity_key = ? AND seq = ?").run(key, ack.seq)
    })
    transaction()
  }

  async expire(now = new Date()): Promise<void> {
    this.database.query("UPDATE vault_delivery_entries SET payload = x'', state = 'expired', gap_reason = 'ttl-expired' WHERE state = 'pending' AND expires_at <= ?").run(now.toISOString())
  }

  async status(identityId: IdentityId): Promise<VaultDeliveryStatus> {
    const key = stableIdKey(identityId)
    const latest = this.latest(key)
    const values = this.database.query<{ bytes: number; count: number }, [string]>("SELECT coalesce(sum(length(payload)), 0) AS bytes, count(*) AS count FROM vault_delivery_entries WHERE identity_key = ? AND state = 'pending'").get(key)
    return { identityId, latestSeq: latest, retainedFrom: this.retainedFrom(key, latest), payloadBytes: Number(values?.bytes ?? 0), pendingItems: Number(values?.count ?? 0) }
  }

  private latest(key: string): DeliverySeq {
    return this.database.query<{ latest_seq: string }, [string]>('SELECT latest_seq FROM vault_delivery_identities WHERE identity_key = ?').get(key)?.latest_seq ?? '0'
  }

  private retainedFrom(key: string, latest: DeliverySeq): DeliverySeq {
    return this.database.query<{ seq: string }, [string]>("SELECT seq FROM vault_delivery_entries WHERE identity_key = ? AND state = 'pending' ORDER BY length(seq), seq LIMIT 1").get(key)?.seq ?? deliverySeq(BigInt(latest) + 1n)
  }

  private gapReason(key: string, seq: DeliverySeq): RestoreRequiredReason {
    return this.database.query<{ gap_reason: RestoreRequiredReason | null }, [string, string]>('SELECT gap_reason FROM vault_delivery_entries WHERE identity_key = ? AND seq = ?').get(key, seq)?.gap_reason ?? 'ttl-expired'
  }

  private isRecipient(key: string, seq: DeliverySeq, deviceId: DeviceId): boolean {
    return this.database.query<{ present: number }, [string, string, string]>('SELECT 1 AS present FROM vault_delivery_recipients WHERE identity_key = ? AND seq = ? AND device_id = ?').get(key, seq, deviceId)?.present === 1
  }

  private isAcknowledged(key: string, seq: DeliverySeq, deviceId: DeviceId): boolean {
    return this.database.query<{ present: number }, [string, string, string]>('SELECT 1 AS present FROM vault_delivery_acks WHERE identity_key = ? AND seq = ? AND device_id = ?').get(key, seq, deviceId)?.present === 1
  }

  private enforceQuota(key: string): void {
    while (true) {
      const values = this.database.query<{ bytes: number; count: number }, [string]>("SELECT coalesce(sum(length(payload)), 0) AS bytes, count(*) AS count FROM vault_delivery_entries WHERE identity_key = ? AND state = 'pending'").get(key)
      if (Number(values?.bytes ?? 0) <= this.limits.maxIdentityPayloadBytes && Number(values?.count ?? 0) <= this.limits.maxIdentityPendingItems) return
      const oldest = this.database.query<{ seq: string }, [string]>("SELECT seq FROM vault_delivery_entries WHERE identity_key = ? AND state = 'pending' ORDER BY length(seq), seq LIMIT 1").get(key)
      if (!oldest) throw new ProtocolValidationError('cannot enforce delivery quota')
      this.database.query("UPDATE vault_delivery_entries SET payload = x'', state = 'expired', gap_reason = 'retention-quota' WHERE identity_key = ? AND seq = ?").run(key, oldest.seq)
    }
  }
}

function installSchema(database: Database): void {
  migrateLegacySchema(database)
  database.exec(`
    PRAGMA journal_mode = WAL;
    CREATE TABLE IF NOT EXISTS vault_delivery_identities (identity_key TEXT PRIMARY KEY, latest_seq TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS vault_delivery_entries (
      identity_key TEXT NOT NULL, identity_id TEXT NOT NULL, seq TEXT NOT NULL, append_id TEXT NOT NULL, payload BLOB NOT NULL, payload_hash BLOB NOT NULL,
      created_at TEXT NOT NULL, expires_at TEXT NOT NULL, state TEXT NOT NULL, gap_reason TEXT,
      PRIMARY KEY (identity_key, seq), UNIQUE (identity_key, append_id)
    );
    CREATE TABLE IF NOT EXISTS vault_delivery_recipients (identity_key TEXT NOT NULL, seq TEXT NOT NULL, device_id TEXT NOT NULL, PRIMARY KEY (identity_key, seq, device_id));
    CREATE TABLE IF NOT EXISTS vault_delivery_acks (identity_key TEXT NOT NULL, seq TEXT NOT NULL, device_id TEXT NOT NULL, PRIMARY KEY (identity_key, seq, device_id));
    CREATE INDEX IF NOT EXISTS vault_delivery_pending ON vault_delivery_entries (identity_key, state, seq);
  `)
}

/** Migrates the pre-domain-move schema, whose four tables were partitioned
 * by the mutable DID (`identity_id`), to the stable SCID-derived key. The
 * whole family moves in one transaction so entries can never become
 * detached from their identity cursor or recipient/ACK rows. */
function migrateLegacySchema(database: Database): void {
  const tables = ['vault_delivery_identities', 'vault_delivery_entries', 'vault_delivery_recipients', 'vault_delivery_acks'] as const
  const columns = tables.map(table => tableColumns(database, table))
  if (columns.every(value => value.length === 0)) return
  const legacy = columns.map(value => value.includes('identity_id') && !value.includes('identity_key'))
  if (legacy.every(value => !value)) return
  if (!legacy.every(Boolean)) throw new TypeError('vault delivery SQLite schema is inconsistent')

  type LegacyIdentity = { identity_id: string; latest_seq: string }
  type LegacyEntry = EntryRow & { identity_id: string }
  type LegacyDeviceRow = { seq: string; device_id: string }
  const identities = database.query<LegacyIdentity, []>('SELECT identity_id, latest_seq FROM vault_delivery_identities').all()
  const seen = new Set<string>()

  database.transaction(() => {
    database.exec(`
      CREATE TABLE vault_delivery_identities_v2 (identity_key TEXT PRIMARY KEY, latest_seq TEXT NOT NULL);
      CREATE TABLE vault_delivery_entries_v2 (
        identity_key TEXT NOT NULL, identity_id TEXT NOT NULL, seq TEXT NOT NULL, append_id TEXT NOT NULL, payload BLOB NOT NULL, payload_hash BLOB NOT NULL,
        created_at TEXT NOT NULL, expires_at TEXT NOT NULL, state TEXT NOT NULL, gap_reason TEXT,
        PRIMARY KEY (identity_key, seq), UNIQUE (identity_key, append_id)
      );
      CREATE TABLE vault_delivery_recipients_v2 (identity_key TEXT NOT NULL, seq TEXT NOT NULL, device_id TEXT NOT NULL, PRIMARY KEY (identity_key, seq, device_id));
      CREATE TABLE vault_delivery_acks_v2 (identity_key TEXT NOT NULL, seq TEXT NOT NULL, device_id TEXT NOT NULL, PRIMARY KEY (identity_key, seq, device_id));
    `)
    for (const identity of identities) {
      const key = stableIdKey(identity.identity_id)
      if (seen.has(key)) throw new TypeError('legacy vault delivery rows collide after stable identity normalization')
      seen.add(key)
      database.query('INSERT INTO vault_delivery_identities_v2 VALUES (?, ?)').run(key, identity.latest_seq)
      const entries = database.query<LegacyEntry, [string]>('SELECT * FROM vault_delivery_entries WHERE identity_id = ?').all(identity.identity_id)
      for (const entry of entries) {
        database.query('INSERT INTO vault_delivery_entries_v2 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').run(key, entry.identity_id, entry.seq, entry.append_id, entry.payload, entry.payload_hash, entry.created_at, entry.expires_at, entry.state, entry.gap_reason)
      }
      const recipients = database.query<LegacyDeviceRow, [string]>('SELECT seq, device_id FROM vault_delivery_recipients WHERE identity_id = ?').all(identity.identity_id)
      for (const row of recipients) database.query('INSERT INTO vault_delivery_recipients_v2 VALUES (?, ?, ?)').run(key, row.seq, row.device_id)
      const acknowledgements = database.query<LegacyDeviceRow, [string]>('SELECT seq, device_id FROM vault_delivery_acks WHERE identity_id = ?').all(identity.identity_id)
      for (const row of acknowledgements) database.query('INSERT INTO vault_delivery_acks_v2 VALUES (?, ?, ?)').run(key, row.seq, row.device_id)
    }
    database.exec(`
      DROP TABLE vault_delivery_acks;
      DROP TABLE vault_delivery_recipients;
      DROP TABLE vault_delivery_entries;
      DROP TABLE vault_delivery_identities;
      ALTER TABLE vault_delivery_identities_v2 RENAME TO vault_delivery_identities;
      ALTER TABLE vault_delivery_entries_v2 RENAME TO vault_delivery_entries;
      ALTER TABLE vault_delivery_recipients_v2 RENAME TO vault_delivery_recipients;
      ALTER TABLE vault_delivery_acks_v2 RENAME TO vault_delivery_acks;
    `)
  })()
}

function tableColumns(database: Database, table: string): string[] {
  return database.query<{ name: string }, []>(`PRAGMA table_info(${table})`).all().map(column => column.name)
}

function item(row: EntryRow): VaultDeliveryItemV1 {
  return { version: 1, identityId: row.identity_id, seq: row.seq, payload: bytes(row.payload), payloadHash: bytes(row.payload_hash), createdAt: row.created_at, expiresAt: row.expires_at }
}

function bytes(value: Uint8Array): Uint8Array { return new Uint8Array(value) }

function restore(requestedCursor: DeliverySeq, retainedFrom: DeliverySeq, latestSeq: DeliverySeq, reason: RestoreRequiredReason): DeliveryPullResult {
  return { kind: 'restoreRequired', requestedCursor, retainedFrom, latestSeq, reason }
}
