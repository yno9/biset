import { Database } from 'bun:sqlite'
import { equalBytes, sha256Bytes } from '../../protocol/canonical.ts'
import type { IngressAckV1, IngressEnvelopeV1, IngressPullV1 } from '../../protocol/ingress.ts'
import type { IngressId } from '../../protocol/ids.ts'
import { assertIngressAck, assertIngressEnvelope, assertIngressPull, ProtocolValidationError } from '../../protocol/validate.ts'
import type { IngressAuthorizer, IngressStatus, IngressStatusRecord, IngressStore, IngressStoreLimits } from './ingress-store.ts'

const DEFAULT_LIMITS: IngressStoreLimits = {
  maxPayloadBytes: 25 * 1024 * 1024,
  maxIdentityPayloadBytes: 100 * 1024 * 1024,
  maxIdentityPendingItems: 128,
  claimLeaseMs: 60_000,
}

interface Row {
  ingress_id: string
  identity_id: string
  protocol: IngressEnvelopeV1['protocol']
  recipients_json: string
  created_at: string
  expires_at: string
  metadata_json: string
  source_evidence: Uint8Array
  protected_payload: Uint8Array
  payload_hash: Uint8Array
  status: IngressStatus
  claim_device_id: string | null
  claim_expires_at: string | null
}

/**
 * Crash-safe bounded external ingress. Its tombstones retain only routing
 * status, never an external body, source evidence, or transport metadata.
 */
export class SqliteIngressStore implements IngressStore {
  private readonly limits: IngressStoreLimits

  constructor(private readonly database: Database, private readonly authorizer: IngressAuthorizer, limits: IngressStoreLimits = DEFAULT_LIMITS) {
    assertLimits(limits)
    this.limits = limits
    installSchema(database)
  }

  static open(path: string, authorizer: IngressAuthorizer, limits?: IngressStoreLimits): SqliteIngressStore {
    if (!path) throw new TypeError('SQLite ingress store path is required')
    return new SqliteIngressStore(new Database(path), authorizer, limits)
  }

  close(): void { this.database.close() }

  async offer(envelope: IngressEnvelopeV1): Promise<void> {
    assertIngressEnvelope(envelope)
    if (!equalBytes(sha256Bytes(envelope.protectedPayload), envelope.protectedPayloadHash)) throw new ProtocolValidationError('ingress protectedPayloadHash does not match payload')
    if (envelope.protectedPayload.length > this.limits.maxPayloadBytes) throw new ProtocolValidationError('ingress payload exceeds maxPayloadBytes')
    const existing = this.row(envelope.ingressId)
    if (existing) {
      if (equalBytes(bytes(existing.payload_hash), envelope.protectedPayloadHash)) return
      throw new ProtocolValidationError('ingressId already exists with a different payload')
    }
    const values = this.database.query<{ bytes: number; count: number }, [string]>("SELECT coalesce(sum(length(protected_payload)), 0) AS bytes, count(*) AS count FROM ingress_entries WHERE identity_id = ? AND status = 'pending'").get(envelope.recipientIdentityId)
    if (Number(values?.count ?? 0) >= this.limits.maxIdentityPendingItems) throw new ProtocolValidationError('identity pending ingress item limit exceeded')
    if (Number(values?.bytes ?? 0) + envelope.protectedPayload.length > this.limits.maxIdentityPayloadBytes) throw new ProtocolValidationError('identity pending ingress byte limit exceeded')
    this.database.query('INSERT INTO ingress_entries (ingress_id, identity_id, protocol, recipients_json, created_at, expires_at, metadata_json, source_evidence, protected_payload, payload_hash, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
      .run(envelope.ingressId, envelope.recipientIdentityId, envelope.protocol, JSON.stringify(envelope.recipientDeviceSnapshot), envelope.createdAt, envelope.expiresAt, JSON.stringify(envelope.transportMetadata), envelope.sourceEvidence, envelope.protectedPayload, envelope.protectedPayloadHash, 'pending')
  }

  async pull(pull: IngressPullV1, now = new Date()): Promise<IngressEnvelopeV1[]> {
    assertIngressPull(pull)
    await this.expire(now)
    if (!(await this.authorizer.verifyPull(pull))) throw new ProtocolValidationError('ingress pull is not authorised')
    const claimExpiresAt = leaseExpiry(now, this.limits)
    const select = this.database.query<Row, [string, string, string]>("SELECT * FROM ingress_entries WHERE identity_id = ? AND status = 'pending' AND (claim_device_id IS NULL OR claim_expires_at <= ? OR claim_device_id = ?) ORDER BY created_at, ingress_id")
    const claim = this.database.query('UPDATE ingress_entries SET claim_device_id = ?, claim_expires_at = ? WHERE ingress_id = ? AND status = \'pending\' AND (claim_device_id IS NULL OR claim_expires_at <= ? OR claim_device_id = ?)')
    const claimed = this.database.transaction(() => select.all(pull.identityId, now.toISOString(), pull.recipientDeviceId)
      .filter(row => envelope(row).recipientDeviceSnapshot.includes(pull.recipientDeviceId))
      .flatMap((row) => {
        const result = claim.run(pull.recipientDeviceId, earliestExpiry(claimExpiresAt, row.expires_at), row.ingress_id, now.toISOString(), pull.recipientDeviceId)
        return result.changes === 1 ? [row] : []
      }))()
    return claimed.map(envelope)
  }

  async acknowledge(ack: IngressAckV1, now = new Date()): Promise<IngressStatusRecord> {
    assertIngressAck(ack)
    await this.expire(now)
    const row = this.row(ack.ingressId)
    if (!row) throw new ProtocolValidationError('unknown ingressId')
    if (row.status !== 'pending') throw new ProtocolValidationError(`ingress is already ${row.status}`)
    const value = envelope(row)
    if (!value.recipientDeviceSnapshot.includes(ack.recipientDeviceId)) throw new ProtocolValidationError('ACK device is not in the recipient snapshot')
    if (row.claim_device_id !== ack.recipientDeviceId || !row.claim_expires_at || row.claim_expires_at <= now.toISOString()) {
      throw new ProtocolValidationError('ACK device does not hold the active ingress claim')
    }
    if (!equalBytes(ack.protectedPayloadHash, value.protectedPayloadHash)) throw new ProtocolValidationError('ACK payload hash does not match ingress')
    if (!(await this.authorizer.verify(ack, value))) throw new ProtocolValidationError('ACK is not authorised')
    // `row` was read before the `authorizer.verify` await above, so its
    // `status`/claim can be stale by now: a concurrent expire() may have
    // tombstoned this same entry while this call was suspended. Re-check and
    // write inside one synchronous transaction against a fresh read, rather
    // than trusting the pre-await snapshot -- clearBody's own UPDATE has no
    // status guard, so an unconditional call here would silently resurrect
    // an already-expired row as 'vault-ingested'.
    const transaction = this.database.transaction((): IngressStatusRecord => {
      const current = this.row(ack.ingressId)
      if (!current) throw new ProtocolValidationError('unknown ingressId')
      if (current.status !== 'pending') throw new ProtocolValidationError(`ingress is already ${current.status}`)
      if (current.claim_device_id !== ack.recipientDeviceId || !current.claim_expires_at || current.claim_expires_at <= now.toISOString()) {
        throw new ProtocolValidationError('ACK device does not hold the active ingress claim')
      }
      this.clearBody(ack.ingressId, 'vault-ingested')
      return status(this.row(ack.ingressId)!)
    })
    return transaction()
  }

  async expire(now = new Date()): Promise<IngressStatusRecord[]> {
    const rows = this.database.query<Row, [string]>("SELECT * FROM ingress_entries WHERE status = 'pending' AND expires_at <= ?").all(now.toISOString())
    if (rows.length === 0) return []
    const transaction = this.database.transaction(() => rows.forEach(row => this.clearBody(row.ingress_id, 'expired')))
    transaction()
    return rows.map(row => ({ ingressId: row.ingress_id, identityId: row.identity_id, status: 'expired' as const, expiresAt: row.expires_at, payloadRetained: false }))
  }

  async status(ingressId: IngressId): Promise<IngressStatusRecord | undefined> {
    const row = this.row(ingressId)
    return row && status(row)
  }

  private row(ingressId: IngressId): Row | undefined {
    return this.database.query<Row, [string]>('SELECT * FROM ingress_entries WHERE ingress_id = ?').get(ingressId) ?? undefined
  }

  private clearBody(ingressId: IngressId, state: Extract<IngressStatus, 'vault-ingested' | 'expired'>): void {
    this.database.query("UPDATE ingress_entries SET source_evidence = x'', protected_payload = x'', payload_hash = x'', metadata_json = '{}', recipients_json = '[]', claim_device_id = NULL, claim_expires_at = NULL, status = ? WHERE ingress_id = ?").run(state, ingressId)
  }
}

function installSchema(database: Database): void {
  database.exec(`
    CREATE TABLE IF NOT EXISTS ingress_entries (
      ingress_id TEXT PRIMARY KEY, identity_id TEXT NOT NULL, protocol TEXT NOT NULL, recipients_json TEXT NOT NULL,
      created_at TEXT NOT NULL, expires_at TEXT NOT NULL, metadata_json TEXT NOT NULL,
      source_evidence BLOB NOT NULL, protected_payload BLOB NOT NULL, payload_hash BLOB NOT NULL, status TEXT NOT NULL,
      claim_device_id TEXT, claim_expires_at TEXT
    );
    CREATE INDEX IF NOT EXISTS ingress_pending_by_identity ON ingress_entries (identity_id, status, created_at);
  `)
  const columns = database.query<{ name: string }, []>('PRAGMA table_info(ingress_entries)').all().map(column => column.name)
  if (!columns.includes('claim_device_id')) database.exec('ALTER TABLE ingress_entries ADD COLUMN claim_device_id TEXT')
  if (!columns.includes('claim_expires_at')) database.exec('ALTER TABLE ingress_entries ADD COLUMN claim_expires_at TEXT')
}

function envelope(row: Row): IngressEnvelopeV1 {
  const recipients = parseRecipients(row.recipients_json)
  const metadata = parseMetadata(row.metadata_json)
  const value: IngressEnvelopeV1 = { version: 1, ingressId: row.ingress_id, protocol: row.protocol, recipientIdentityId: row.identity_id, recipientDeviceSnapshot: recipients, createdAt: row.created_at, expiresAt: row.expires_at, transportMetadata: metadata, sourceEvidence: bytes(row.source_evidence), protectedPayload: bytes(row.protected_payload), protectedPayloadHash: bytes(row.payload_hash) }
  assertIngressEnvelope(value)
  return value
}

function status(row: Row): IngressStatusRecord {
  return { ingressId: row.ingress_id, identityId: row.identity_id, status: row.status, expiresAt: row.expires_at, payloadRetained: row.status === 'pending' && row.protected_payload.length > 0 }
}

function parseRecipients(value: string): string[] {
  let parsed: unknown
  try { parsed = JSON.parse(value) } catch { throw new TypeError('stored ingress recipients are invalid') }
  if (!Array.isArray(parsed) || parsed.some(item => typeof item !== 'string' || item.length === 0)) throw new TypeError('stored ingress recipients are invalid')
  return [...parsed]
}

function parseMetadata(value: string): Record<string, string> {
  let parsed: unknown
  try { parsed = JSON.parse(value) } catch { throw new TypeError('stored ingress metadata is invalid') }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed) || Object.values(parsed).some(item => typeof item !== 'string')) throw new TypeError('stored ingress metadata is invalid')
  return { ...(parsed as Record<string, string>) }
}

function bytes(value: Uint8Array): Uint8Array { return new Uint8Array(value) }

function assertLimits(limits: IngressStoreLimits): void {
  for (const value of [limits.maxPayloadBytes, limits.maxIdentityPayloadBytes, limits.maxIdentityPendingItems]) {
    if (!Number.isSafeInteger(value) || value < 1) throw new TypeError('ingress limits must be positive safe integers')
  }
  if (limits.claimLeaseMs !== undefined && (!Number.isSafeInteger(limits.claimLeaseMs) || limits.claimLeaseMs < 1)) {
    throw new TypeError('ingress claimLeaseMs must be a positive safe integer')
  }
}

function leaseExpiry(now: Date, limits: IngressStoreLimits): string {
  const duration = limits.claimLeaseMs ?? DEFAULT_LIMITS.claimLeaseMs!
  return new Date(now.getTime() + duration).toISOString()
}
function earliestExpiry(one: string, two: string): string { return one <= two ? one : two }
