// Single-writer production persistence for the Mail Mediator: route
// bindings, the encrypted spool, submission idempotency, and replay ids
// all in one SQLite database, same "one connection, one transaction
// domain" shape as src/mediator/sqlite-store.ts. No identity, MLS, or
// Vault data enters this database (PLAN_biset-mail-mediator.md section 2).
import { Database } from 'bun:sqlite'
import { mkdirSync } from 'node:fs'
import { dirname } from 'node:path'
import { x25519, ed25519 } from '@noble/curves/ed25519.js'
import { b64url, b64urlDecodeToBytes, identityFromKeys, type PeerIdentity, type PeerService } from '../didcomm/peer.ts'
import type { ReplayGuard } from '../mediator/replay.ts'
import { RouteStoreFullError, type MailRouteStore, type MailRoute, type RouteHolder } from './route-store.ts'
import { SpoolFullError, type MailSpoolStore, type SpoolRecord, type EnqueueInput } from './spool-store.ts'
import { SubmissionStoreFullError, type MailSubmissionStore, type SubmissionRecord, type RecipientResult } from './submission-store.ts'

export interface SqliteMailMediatorLimits {
  maxAddresses: number
  maxHoldersPerAddress: number
  maxPendingPerAddress: number
  maxSubmissionRecords: number
  replayTtlMs: number
  maxReplayIds: number
}

export const DEFAULT_SQLITE_MAIL_MEDIATOR_LIMITS: SqliteMailMediatorLimits = {
  maxAddresses: 100_000,
  maxHoldersPerAddress: 8,
  maxPendingPerAddress: 10_000,
  maxSubmissionRecords: 100_000,
  replayTtlMs: 10 * 60 * 1000,
  maxReplayIds: 50_000,
}

interface IdentityRow { public_url: string; x_priv: string; ed_priv: string }
interface RouteRow { address: string; route_generation: string; updated_at: string }
interface HolderRow { relationship_kid: string; address: string; pickup_public_key: string; expires_at: string }
interface SpoolRow {
  spool_id: string; address: string; semantic_ingress_id: string; mail_from: string
  encrypted_body: Uint8Array; body_hash: Uint8Array; state: string
  claim_holder_id: string | null; claim_expires_at: string | null; created_at: string; expires_at: string
}
interface SubmissionRow {
  idempotency_key: string; mail_from: string; rcpt_to: string; raw_rfc5322: Uint8Array
  state: string; results: string | null; created_at: string
}

export class SqliteMailMediatorStore implements MailRouteStore, MailSpoolStore, MailSubmissionStore, ReplayGuard {
  readonly limits: SqliteMailMediatorLimits

  constructor(private readonly database: Database, limits: Partial<SqliteMailMediatorLimits> = {}) {
    this.limits = { ...DEFAULT_SQLITE_MAIL_MEDIATOR_LIMITS, ...limits }
    assertLimits(this.limits)
    installSchema(database)
  }

  static open(path: string, limits?: Partial<SqliteMailMediatorLimits>): SqliteMailMediatorStore {
    if (!path) throw new TypeError('mail mediator SQLite path is required')
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
    return new SqliteMailMediatorStore(new Database(path, { create: true }), limits)
  }

  close(): void { this.database.close() }

  transaction = <T>(operation: () => T): T => this.database.transaction(operation)()

  /** Creates the mediator's own did:peer key once, mirroring
   * mediator/sqlite-store.ts's loadIdentity -- a URL change would alter
   * did:peer:2's service segment (and therefore its DID), so this fails
   * loudly instead of silently orphaning every bound route. */
  loadIdentity(publicUrl: string): PeerIdentity {
    const normalized = validPublicUrl(publicUrl)
    let row = this.database.query<IdentityRow, []>('SELECT public_url, x_priv, ed_priv FROM mail_mediator_identity WHERE singleton = 1').get()
    if (!row) {
      const xPriv = x25519.utils.randomSecretKey()
      const edPriv = ed25519.utils.randomSecretKey()
      this.database.query('INSERT INTO mail_mediator_identity (singleton, public_url, x_priv, ed_priv) VALUES (1, ?, ?, ?)')
        .run(normalized, b64url(xPriv), b64url(edPriv))
      row = { public_url: normalized, x_priv: b64url(xPriv), ed_priv: b64url(edPriv) }
    }
    if (row.public_url !== normalized) {
      throw new Error(`MAIL_MEDIATOR_PUBLIC_URL differs from the persisted mediator identity (${row.public_url})`)
    }
    const service: PeerService = { uri: row.public_url, accept: ['didcomm/v2'] }
    return identityFromKeys(b64urlDecodeToBytes(row.x_priv), b64urlDecodeToBytes(row.ed_priv), service)
  }

  ready(): boolean {
    return this.database.query<{ quick_check: string }, []>('PRAGMA quick_check').get()?.quick_check === 'ok'
  }

  stats(): { addresses: number; holders: number; pendingSpool: number; oldestPendingCreatedAt?: string } {
    const addresses = this.scalar('SELECT count(*) AS value FROM mail_routes')
    const holders = this.scalar('SELECT count(*) AS value FROM mail_route_holders')
    const pendingSpool = this.scalar("SELECT count(*) AS value FROM mail_spool WHERE state != 'acknowledged'")
    const oldest = this.database.query<{ oldest: string | null }, []>(
      "SELECT min(created_at) AS oldest FROM mail_spool WHERE state != 'acknowledged'",
    ).get()?.oldest
    return { addresses, holders, pendingSpool, ...(oldest === null || oldest === undefined ? {} : { oldestPendingCreatedAt: oldest }) }
  }

  // ---- MailRouteStore ----

  bind(address: string, holder: RouteHolder, routeGeneration: string, nowIso: string): MailRoute {
    return this.transaction(() => {
      const existing = this.database.query<RouteRow, [string]>('SELECT address, route_generation, updated_at FROM mail_routes WHERE address = ?').get(address)
      if (!existing || existing.route_generation !== routeGeneration) {
        if (existing) this.database.query('DELETE FROM mail_route_holders WHERE address = ?').run(address)
        else if (this.scalar('SELECT count(*) AS value FROM mail_routes') >= this.limits.maxAddresses) {
          throw new RouteStoreFullError('mail-mediator: too many routed addresses')
        }
        this.database.query('INSERT INTO mail_routes (address, route_generation, updated_at) VALUES (?, ?, ?) ON CONFLICT(address) DO UPDATE SET route_generation = excluded.route_generation, updated_at = excluded.updated_at')
          .run(address, routeGeneration, nowIso)
        this.insertHolder(address, holder)
        return this.routeFor(address)!
      }
      const already = this.database.query<{ present: number }, [string]>('SELECT 1 AS present FROM mail_route_holders WHERE relationship_kid = ?').get(holder.relationshipKid)
      if (!already) {
        const count = this.scalar('SELECT count(*) AS value FROM mail_route_holders WHERE address = ?', address)
        if (count >= this.limits.maxHoldersPerAddress) throw new RouteStoreFullError(`mail-mediator: too many holders for ${address}`)
      }
      this.insertHolder(address, holder)
      this.database.query('UPDATE mail_routes SET updated_at = ? WHERE address = ?').run(nowIso, address)
      return this.routeFor(address)!
    })
  }

  private insertHolder(address: string, holder: RouteHolder): void {
    this.database.query(
      'INSERT INTO mail_route_holders (relationship_kid, address, pickup_public_key, expires_at) VALUES (?, ?, ?, ?) ' +
      'ON CONFLICT(relationship_kid) DO UPDATE SET pickup_public_key = excluded.pickup_public_key, expires_at = excluded.expires_at',
    ).run(holder.relationshipKid, address, b64url(holder.pickupPublicKey), holder.expiresAt)
  }

  routeFor(address: string): MailRoute | undefined {
    const row = this.database.query<RouteRow, [string]>('SELECT address, route_generation, updated_at FROM mail_routes WHERE address = ?').get(address)
    if (!row) return undefined
    const holders = this.database.query<HolderRow, [string]>(
      'SELECT relationship_kid, address, pickup_public_key, expires_at FROM mail_route_holders WHERE address = ? ORDER BY relationship_kid',
    ).all(address).map(rowToHolder)
    return { address: row.address, routeGeneration: row.route_generation, holders, updatedAt: row.updated_at }
  }

  holderFor(address: string, relationshipKid: string): RouteHolder | undefined {
    const row = this.database.query<HolderRow, [string, string]>(
      'SELECT relationship_kid, address, pickup_public_key, expires_at FROM mail_route_holders WHERE address = ? AND relationship_kid = ?',
    ).get(address, relationshipKid)
    return row ? rowToHolder(row) : undefined
  }

  addressForRelationshipKid(relationshipKid: string): string | undefined {
    return this.database.query<{ address: string }, [string]>('SELECT address FROM mail_route_holders WHERE relationship_kid = ?').get(relationshipKid)?.address
  }

  unbind(address: string, relationshipKid: string): boolean {
    return this.transaction(() => {
      const result = this.database.query('DELETE FROM mail_route_holders WHERE address = ? AND relationship_kid = ?').run(address, relationshipKid)
      if (result.changes === 0) return false
      if (this.scalar('SELECT count(*) AS value FROM mail_route_holders WHERE address = ?', address) === 0) {
        this.database.query('DELETE FROM mail_routes WHERE address = ?').run(address)
      }
      return true
    })
  }

  expireHolders(nowIso: string): void {
    this.transaction(() => {
      this.database.query('DELETE FROM mail_route_holders WHERE expires_at <= ?').run(nowIso)
      this.database.query(
        'DELETE FROM mail_routes WHERE address NOT IN (SELECT DISTINCT address FROM mail_route_holders)',
      ).run()
    })
  }

  // ---- MailSpoolStore ----

  enqueue(input: EnqueueInput): SpoolRecord {
    return this.transaction(() => {
      const existingId = this.database.query<{ spool_id: string }, [string, string]>(
        'SELECT spool_id FROM mail_spool WHERE address = ? AND semantic_ingress_id = ?',
      ).get(input.address, input.semanticIngressId)?.spool_id
      if (existingId) {
        const existing = this.spoolById(existingId)
        if (existing) return existing
      }
      const pendingCount = this.scalar(
        "SELECT count(*) AS value FROM mail_spool WHERE address = ? AND state != 'acknowledged'", input.address,
      )
      if (pendingCount >= this.limits.maxPendingPerAddress) throw new SpoolFullError(`mail-mediator: spool full for ${input.address}`)
      const spoolId = crypto.randomUUID()
      this.database.query(
        'INSERT INTO mail_spool (spool_id, address, semantic_ingress_id, mail_from, encrypted_body, body_hash, state, created_at, expires_at) ' +
        "VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)",
      ).run(spoolId, input.address, input.semanticIngressId, input.mailFrom, input.encryptedBody, input.bodyHash, input.createdAt, input.expiresAt)
      return this.spoolById(spoolId)!
    })
  }

  claim(address: string, holderId: string, leaseMs: number, limit: number, nowIso: string): SpoolRecord[] {
    return this.transaction(() => {
      this.expireLeases(nowIso)
      const claimExpiresAt = new Date(Date.parse(nowIso) + leaseMs).toISOString()
      const rows = this.database.query<SpoolRow, [string, number]>(
        "SELECT * FROM mail_spool WHERE address = ? AND state = 'pending' ORDER BY created_at, spool_id LIMIT ?",
      ).all(address, Math.max(0, Math.trunc(limit)))
      const update = this.database.query("UPDATE mail_spool SET state = 'claimed', claim_holder_id = ?, claim_expires_at = ? WHERE spool_id = ?")
      for (const row of rows) update.run(holderId, claimExpiresAt, row.spool_id)
      return rows.map(row => rowToSpoolRecord({ ...row, state: 'claimed', claim_holder_id: holderId, claim_expires_at: claimExpiresAt }))
    })
  }

  acknowledge(address: string, holderId: string, spoolIds: string[]): number {
    if (spoolIds.length === 0) return 0
    return this.transaction(() => {
      let count = 0
      const del = this.database.query("DELETE FROM mail_spool WHERE spool_id = ? AND address = ? AND state = 'claimed' AND claim_holder_id = ?")
      for (const spoolId of new Set(spoolIds)) {
        const result = del.run(spoolId, address, holderId)
        if (result.changes > 0) count++
      }
      return count
    })
  }

  expireLeases(nowIso: string): void {
    this.database.query("UPDATE mail_spool SET state = 'pending', claim_holder_id = NULL, claim_expires_at = NULL WHERE state = 'claimed' AND claim_expires_at <= ?").run(nowIso)
  }

  expireRecords(nowIso: string): number {
    return this.database.query('DELETE FROM mail_spool WHERE expires_at <= ?').run(nowIso).changes
  }

  pendingCount(address: string): number {
    return this.scalar("SELECT count(*) AS value FROM mail_spool WHERE address = ? AND state = 'pending'", address)
  }

  private spoolById(spoolId: string): SpoolRecord | undefined {
    const row = this.database.query<SpoolRow, [string]>('SELECT * FROM mail_spool WHERE spool_id = ?').get(spoolId)
    return row ? rowToSpoolRecord(row) : undefined
  }

  // ---- MailSubmissionStore ----

  acquire(
    idempotencyKey: string, mailFrom: string, rcptTo: string[], rawRfc5322: Uint8Array, nowIso: string,
  ): { started: true; record: SubmissionRecord } | { started: false; record: SubmissionRecord } {
    return this.transaction(() => {
      const existing = this.submissionByKey(idempotencyKey)
      if (existing) return { started: false, record: existing }
      if (this.scalar('SELECT count(*) AS value FROM mail_submissions') >= this.limits.maxSubmissionRecords) {
        throw new SubmissionStoreFullError('mail-mediator: too many pending submissions')
      }
      this.database.query(
        "INSERT INTO mail_submissions (idempotency_key, mail_from, rcpt_to, raw_rfc5322, state, created_at) VALUES (?, ?, ?, ?, 'in-flight', ?)",
      ).run(idempotencyKey, mailFrom, JSON.stringify(rcptTo), rawRfc5322, nowIso)
      return { started: true, record: this.submissionByKey(idempotencyKey)! }
    })
  }

  complete(idempotencyKey: string, results: RecipientResult[]): SubmissionRecord | undefined {
    return this.transaction(() => {
      const result = this.database.query("UPDATE mail_submissions SET state = 'completed', results = ? WHERE idempotency_key = ?")
        .run(JSON.stringify(results), idempotencyKey)
      if (result.changes === 0) return undefined
      return this.submissionByKey(idempotencyKey)
    })
  }

  recordFor(idempotencyKey: string): SubmissionRecord | undefined {
    return this.submissionByKey(idempotencyKey)
  }

  private submissionByKey(idempotencyKey: string): SubmissionRecord | undefined {
    const row = this.database.query<SubmissionRow, [string]>('SELECT * FROM mail_submissions WHERE idempotency_key = ?').get(idempotencyKey)
    return row ? rowToSubmissionRecord(row) : undefined
  }

  // ---- ReplayGuard ----

  check(id: string): boolean {
    return this.transaction(() => {
      const now = Date.now()
      const key = id.toLowerCase()
      const existing = this.database.query<{ expires_at: number }, [string]>('SELECT expires_at FROM mail_mediator_replay_ids WHERE message_id = ?').get(key)
      if (existing && Number(existing.expires_at) > now) return false
      this.database.query(
        'INSERT INTO mail_mediator_replay_ids (message_id, expires_at, recorded_at) VALUES (?, ?, ?) ' +
        'ON CONFLICT(message_id) DO UPDATE SET expires_at = excluded.expires_at, recorded_at = excluded.recorded_at',
      ).run(key, now + this.limits.replayTtlMs, now)
      const overflow = this.scalar('SELECT count(*) AS value FROM mail_mediator_replay_ids') - this.limits.maxReplayIds
      if (overflow > 0) {
        this.database.query('DELETE FROM mail_mediator_replay_ids WHERE message_id IN (SELECT message_id FROM mail_mediator_replay_ids ORDER BY recorded_at, message_id LIMIT ?)').run(overflow)
      }
      return true
    })
  }

  expireReplay(now = Date.now()): void {
    this.database.query('DELETE FROM mail_mediator_replay_ids WHERE expires_at <= ?').run(now)
  }

  private scalar(sql: string, parameter?: string): number {
    const query = this.database.query<{ value: number }, [] | [string]>(sql)
    const row = parameter === undefined ? query.get() : query.get(parameter)
    return Number(row?.value ?? 0)
  }
}

function rowToHolder(row: HolderRow): RouteHolder {
  return { relationshipKid: row.relationship_kid, pickupPublicKey: b64urlDecodeToBytes(row.pickup_public_key), expiresAt: row.expires_at }
}

function rowToSpoolRecord(row: SpoolRow): SpoolRecord {
  return {
    address: row.address, spoolId: row.spool_id, semanticIngressId: row.semantic_ingress_id, mailFrom: row.mail_from,
    encryptedBody: row.encrypted_body, bodyHash: row.body_hash, state: row.state as SpoolRecord['state'],
    ...(row.claim_holder_id === null ? {} : { claimHolderId: row.claim_holder_id }),
    ...(row.claim_expires_at === null ? {} : { claimExpiresAt: row.claim_expires_at }),
    createdAt: row.created_at, expiresAt: row.expires_at,
  }
}

function rowToSubmissionRecord(row: SubmissionRow): SubmissionRecord {
  return {
    idempotencyKey: row.idempotency_key, mailFrom: row.mail_from, rcptTo: JSON.parse(row.rcpt_to),
    rawRfc5322: row.raw_rfc5322, state: row.state as SubmissionRecord['state'],
    ...(row.results === null ? {} : { results: JSON.parse(row.results) }),
    createdAt: row.created_at,
  }
}

function validPublicUrl(value: string): string {
  const url = new URL(value)
  if (url.protocol !== 'https:' && url.hostname !== 'localhost' && url.hostname !== '127.0.0.1') {
    throw new TypeError('MAIL_MEDIATOR_PUBLIC_URL must use https')
  }
  url.hash = ''
  url.search = ''
  return url.toString().replace(/\/$/, '')
}

function assertLimits(limits: SqliteMailMediatorLimits): void {
  for (const [name, value] of Object.entries(limits)) {
    if (!Number.isSafeInteger(value) || value <= 0) throw new TypeError(`${name} must be a positive safe integer`)
  }
}

function installSchema(database: Database): void {
  database.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = FULL;
    PRAGMA foreign_keys = ON;
    PRAGMA busy_timeout = 5000;
    CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL);
    INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (1, unixepoch() * 1000);
    CREATE TABLE IF NOT EXISTS mail_mediator_identity (
      singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
      public_url TEXT NOT NULL,
      x_priv TEXT NOT NULL,
      ed_priv TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS mail_routes (
      address TEXT PRIMARY KEY,
      route_generation TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS mail_route_holders (
      relationship_kid TEXT PRIMARY KEY,
      address TEXT NOT NULL REFERENCES mail_routes(address) ON DELETE CASCADE,
      pickup_public_key TEXT NOT NULL,
      expires_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS mail_route_holders_address ON mail_route_holders(address);
    CREATE INDEX IF NOT EXISTS mail_route_holders_expiry ON mail_route_holders(expires_at);
    CREATE TABLE IF NOT EXISTS mail_spool (
      spool_id TEXT PRIMARY KEY,
      address TEXT NOT NULL,
      semantic_ingress_id TEXT NOT NULL,
      mail_from TEXT NOT NULL,
      encrypted_body BLOB NOT NULL,
      body_hash BLOB NOT NULL,
      state TEXT NOT NULL CHECK (state IN ('pending', 'claimed', 'acknowledged')),
      claim_holder_id TEXT,
      claim_expires_at TEXT,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      UNIQUE (address, semantic_ingress_id)
    );
    CREATE INDEX IF NOT EXISTS mail_spool_address_state ON mail_spool(address, state, created_at);
    CREATE INDEX IF NOT EXISTS mail_spool_expiry ON mail_spool(expires_at);
    CREATE TABLE IF NOT EXISTS mail_submissions (
      idempotency_key TEXT PRIMARY KEY,
      mail_from TEXT NOT NULL,
      rcpt_to TEXT NOT NULL,
      raw_rfc5322 BLOB NOT NULL,
      state TEXT NOT NULL CHECK (state IN ('in-flight', 'completed')),
      results TEXT,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS mail_mediator_replay_ids (
      message_id TEXT PRIMARY KEY COLLATE NOCASE,
      expires_at INTEGER NOT NULL,
      recorded_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS mail_mediator_replay_ids_expiry ON mail_mediator_replay_ids(expires_at);
  `)
}
