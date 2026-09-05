import { Database } from 'bun:sqlite'
import { mkdirSync } from 'node:fs'
import { dirname } from 'node:path'
import { x25519, ed25519 } from '@noble/curves/ed25519.js'
import { b64url, b64urlDecodeToBytes, identityFromKeys, type PeerIdentity, type PeerService } from '../../didcomm/peer.ts'
import { ConnectionFullError, type MediatorConnectionStore } from './connections.ts'
import { QueueFullError, type MediatorMessageQueue, type QueuedMessage } from './queue.ts'
import type { ReplayGuard } from './replay.ts'

export interface SqliteMediatorLimits {
  maxConnections: number
  maxKeysPerConnection: number
  maxQueueItemsPerRecipient: number
  maxQueueBytesPerRecipient: number
  maxMessageBytes: number
  queueTtlMs: number
  replayTtlMs: number
  maxReplayIds: number
}

const DEFAULT_SQLITE_MEDIATOR_LIMITS: SqliteMediatorLimits = {
  maxConnections: 10_000,
  maxKeysPerConnection: 32,
  maxQueueItemsPerRecipient: 256,
  maxQueueBytesPerRecipient: 16 * 1024 * 1024,
  maxMessageBytes: 1024 * 1024,
  queueTtlMs: 30 * 24 * 60 * 60 * 1000,
  replayTtlMs: 10 * 60 * 1000,
  maxReplayIds: 50_000,
}

interface IdentityRow { public_url: string; x_priv: string; ed_priv: string }
interface RelayPollerIdentityRow { x_priv: string; ed_priv: string }
interface MailPluginIdentityRow { x_priv: string; ed_priv: string }
interface QueueRow { id: string; packed: string; queued_at: number; silent: number }

/** Single-writer production persistence for the blind mediator. The same
 * SQLite connection owns every table so Forward replay admission and queue
 * insertion can share one transaction. No identity, mail, MLS, or Vault data
 * enters this database. */
export class SqliteMediatorStore implements MediatorConnectionStore, MediatorMessageQueue, ReplayGuard {
  readonly limits: SqliteMediatorLimits
  // In-process pub/sub for `GET /stream` (server.ts) -- same shape and same
  // "never persisted, never crosses a process boundary" scope as
  // mls-ds/store.ts's own `watchers`. SQLite backs durability; this is
  // purely the live-tail notification on top of it.
  private readonly watchers = new Map<string, Set<(messages: QueuedMessage[]) => void>>()

  constructor(private readonly database: Database, limits: Partial<SqliteMediatorLimits> = {}) {
    this.limits = { ...DEFAULT_SQLITE_MEDIATOR_LIMITS, ...limits }
    assertLimits(this.limits)
    installSchema(database)
  }

  static open(path: string, limits?: Partial<SqliteMediatorLimits>): SqliteMediatorStore {
    if (!path) throw new TypeError('mediator SQLite path is required')
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
    return new SqliteMediatorStore(new Database(path, { create: true }), limits)
  }

  close(): void { this.database.close() }

  transaction = <T>(operation: () => T): T => this.database.transaction(operation)()

  /** Creates the mediator key once. A URL change would alter did:peer:2's
   * service segment and therefore its DID, so fail instead of orphaning every
   * existing registration silently. */
  loadIdentity(publicUrl: string): PeerIdentity {
    const normalized = validPublicUrl(publicUrl)
    let row = this.database.query<IdentityRow, []>('SELECT public_url, x_priv, ed_priv FROM mediator_identity WHERE singleton = 1').get()
    if (!row) {
      const xPriv = x25519.utils.randomSecretKey()
      const edPriv = ed25519.utils.randomSecretKey()
      this.database.query('INSERT INTO mediator_identity (singleton, public_url, x_priv, ed_priv) VALUES (1, ?, ?, ?)')
        .run(normalized, b64url(xPriv), b64url(edPriv))
      row = { public_url: normalized, x_priv: b64url(xPriv), ed_priv: b64url(edPriv) }
    }
    if (row.public_url !== normalized) {
      throw new Error(`MEDIATOR_PUBLIC_URL differs from the persisted mediator identity (${row.public_url})`)
    }
    const service: PeerService = { uri: row.public_url, accept: ['didcomm/v2'] }
    return identityFromKeys(b64urlDecodeToBytes(row.x_priv), b64urlDecodeToBytes(row.ed_priv), service)
  }

  /** The relay poller's own did:peer key (mediator/relay-poller.ts) --
   * persisted separately from `loadIdentity`'s own key because it is a
   * downstream CLIENT identity registered with an upstream mediator for
   * hop-chaining, not this mediator's own published/dereferenced one. No
   * `publicUrl` to pin: unlike this mediator's own did.json, nobody ever
   * dereferences the poller's DID over HTTP -- an upstream mediator only
   * ever anoncrypts TO its self-certifying kid, never resolves it. */
  loadRelayPollerIdentity(): PeerIdentity {
    let row = this.database.query<RelayPollerIdentityRow, []>('SELECT x_priv, ed_priv FROM relay_poller_identity WHERE singleton = 1').get()
    if (!row) {
      const xPriv = x25519.utils.randomSecretKey()
      const edPriv = ed25519.utils.randomSecretKey()
      this.database.query('INSERT INTO relay_poller_identity (singleton, x_priv, ed_priv) VALUES (1, ?, ?)')
        .run(b64url(xPriv), b64url(edPriv))
      row = { x_priv: b64url(xPriv), ed_priv: b64url(edPriv) }
    }
    return identityFromKeys(b64urlDecodeToBytes(row.x_priv), b64urlDecodeToBytes(row.ed_priv))
  }

  /** The mail plugin's own did:peer key (mediator/mail-plugin/bridge.ts) --
   * the `sender` an inbound-mail Forward is authcrypt'd from. Kept separate
   * from both this mediator's own identity and the relay poller's: unlike
   * the poller it never registers a keylist with anyone, and unlike the
   * mediator's own identity it is never dereferenced as a did.json -- a
   * recipient only ever learns it from the `from` field of an already-
   * authcrypt'd message it could decrypt. Authcrypt (not anoncrypt) purely
   * because the client's mediator-polling pipeline
   * (didcomm/mediator-pickup.ts's `pickupDeliver`) only ever tries to
   * unpack a queued item as authcrypt -- there is no DIDComm-level
   * authentication claim actually being made about the ORIGINAL SMTP
   * sender here, who has no DIDComm identity at all. */
  loadMailPluginIdentity(): PeerIdentity {
    let row = this.database.query<MailPluginIdentityRow, []>('SELECT x_priv, ed_priv FROM mail_plugin_identity WHERE singleton = 1').get()
    if (!row) {
      const xPriv = x25519.utils.randomSecretKey()
      const edPriv = ed25519.utils.randomSecretKey()
      this.database.query('INSERT INTO mail_plugin_identity (singleton, x_priv, ed_priv) VALUES (1, ?, ?)')
        .run(b64url(xPriv), b64url(edPriv))
      row = { x_priv: b64url(xPriv), ed_priv: b64url(edPriv) }
    }
    return identityFromKeys(b64urlDecodeToBytes(row.x_priv), b64urlDecodeToBytes(row.ed_priv))
  }

  ready(): boolean {
    return this.database.query<{ quick_check: string }, []>('PRAGMA quick_check').get()?.quick_check === 'ok'
  }

  stats(): { connections: number; keys: number; queuedMessages: number; queuedBytes: number; oldestQueuedAt?: number } {
    const connections = this.scalar('SELECT count(*) AS value FROM connections')
    const keys = this.scalar('SELECT count(*) AS value FROM connection_keys')
    const queue = this.database.query<{ count: number; bytes: number; oldest: number | null }, []>(
      'SELECT count(*) AS count, coalesce(sum(size_bytes), 0) AS bytes, min(queued_at) AS oldest FROM queued_messages',
    ).get()!
    return {
      connections,
      keys,
      queuedMessages: Number(queue.count),
      queuedBytes: Number(queue.bytes),
      ...(queue.oldest === null ? {} : { oldestQueuedAt: Number(queue.oldest) }),
    }
  }

  register(clientDid: string): void {
    if (this.database.query<{ present: number }, [string]>('SELECT 1 AS present FROM connections WHERE client_did = ?').get(clientDid)) return
    if (this.scalar('SELECT count(*) AS value FROM connections') >= this.limits.maxConnections) {
      throw new ConnectionFullError('mediator: too many registered clients')
    }
    this.database.query('INSERT INTO connections (client_did, created_at) VALUES (?, ?)').run(clientDid, Date.now())
  }

  touch(recipientKid: string): void {
    const now = Date.now()
    this.database.query('UPDATE connection_keys SET last_seen = ? WHERE recipient_kid = ? AND (last_seen IS NULL OR last_seen <= ?)')
      .run(now, recipientKid, now - 60 * 60 * 1000)
  }

  addKey(clientDid: string, recipientKid: string, asGiven = recipientKid, publicKeyHex?: string): boolean {
    return this.transaction(() => {
      this.register(clientDid)
      const existing = this.database.query<{ client_did: string }, [string]>('SELECT client_did FROM connection_keys WHERE recipient_kid = ?').get(recipientKid)
      if (existing) {
        if (existing.client_did !== clientDid) throw new Error('mediator: recipient kid is already owned by another connection')
        return false
      }
      const count = this.scalar('SELECT count(*) AS value FROM connection_keys WHERE client_did = ?', clientDid)
      if (count >= this.limits.maxKeysPerConnection) throw new ConnectionFullError('mediator: too many keys for this connection')
      this.database.query('INSERT INTO connection_keys (recipient_kid, client_did, as_given, public_key_hex, created_at) VALUES (?, ?, ?, ?, ?)')
        .run(recipientKid, clientDid, asGiven, publicKeyHex ?? null, Date.now())
      return true
    })
  }

  keyFor(recipientKid: string): string | undefined {
    return this.database.query<{ public_key_hex: string | null }, [string]>('SELECT public_key_hex FROM connection_keys WHERE recipient_kid = ?').get(recipientKid)?.public_key_hex ?? undefined
  }

  removeKey(clientDid: string, recipientKid: string): boolean {
    return this.transaction(() => {
      const result = this.database.query('DELETE FROM connection_keys WHERE client_did = ? AND recipient_kid = ?').run(clientDid, recipientKid)
      if (result.changes === 0) return false
      if (this.scalar('SELECT count(*) AS value FROM connection_keys WHERE client_did = ?', clientDid) === 0) {
        this.database.query('DELETE FROM connections WHERE client_did = ?').run(clientDid)
      }
      return true
    })
  }

  ownsKey(clientDid: string, recipientKid: string): boolean {
    return !!this.database.query<{ present: number }, [string, string]>('SELECT 1 AS present FROM connection_keys WHERE client_did = ? AND recipient_kid = ?').get(clientDid, recipientKid)
  }

  isAuthorized(recipientKid: string): boolean {
    return !!this.database.query<{ present: number }, [string]>('SELECT 1 AS present FROM connection_keys WHERE recipient_kid = ?').get(recipientKid)
  }

  listKeys(clientDid: string): string[] {
    return this.database.query<{ recipient_kid: string }, [string]>('SELECT recipient_kid FROM connection_keys WHERE client_did = ? ORDER BY created_at, recipient_kid').all(clientDid).map(row => row.recipient_kid)
  }

  listKeysWithActivity(clientDid: string): Array<{ kid: string; asGiven: string; lastSeen?: number }> {
    return this.database.query<{ recipient_kid: string; as_given: string; last_seen: number | null }, [string]>(
      'SELECT recipient_kid, as_given, last_seen FROM connection_keys WHERE client_did = ? ORDER BY created_at, recipient_kid',
    ).all(clientDid).map(row => row.last_seen === null
      ? { kid: row.recipient_kid, asGiven: row.as_given }
      : { kid: row.recipient_kid, asGiven: row.as_given, lastSeen: Number(row.last_seen) })
  }

  push(recipientKid: string, packedMessage: string, opts: { silent?: boolean } = {}): string {
    this.expire()
    const size = new TextEncoder().encode(packedMessage).byteLength
    if (size > this.limits.maxMessageBytes) throw new QueueFullError(recipientKid, 'message exceeds byte limit')
    const usage = this.database.query<{ count: number; bytes: number }, [string]>(
      'SELECT count(*) AS count, coalesce(sum(size_bytes), 0) AS bytes FROM queued_messages WHERE recipient_kid = ?',
    ).get(recipientKid)!
    if (Number(usage.count) >= this.limits.maxQueueItemsPerRecipient) throw new QueueFullError(recipientKid, 'item quota exceeded')
    if (Number(usage.bytes) + size > this.limits.maxQueueBytesPerRecipient) throw new QueueFullError(recipientKid, 'byte quota exceeded')
    const id = crypto.randomUUID()
    const queuedAt = Date.now()
    this.database.query('INSERT INTO queued_messages (id, recipient_kid, packed, size_bytes, queued_at, silent) VALUES (?, ?, ?, ?, ?, ?)')
      .run(id, recipientKid, packedMessage, size, queuedAt, opts.silent ? 1 : 0)
    this.notify(recipientKid, [{ id, packed: packedMessage, queuedAt, ...(opts.silent ? { silent: true } : {}) }])
    return id
  }

  subscribe(recipientKid: string, listener: (messages: QueuedMessage[]) => void): () => void {
    let set = this.watchers.get(recipientKid)
    if (!set) { set = new Set(); this.watchers.set(recipientKid, set) }
    set.add(listener)
    return () => {
      set!.delete(listener)
      if (set!.size === 0) this.watchers.delete(recipientKid)
    }
  }

  private notify(recipientKid: string, messages: QueuedMessage[]): void {
    for (const listener of this.watchers.get(recipientKid) ?? []) listener(messages)
  }

  count(recipientKid: string): number {
    this.expire()
    return this.scalar('SELECT count(*) AS value FROM queued_messages WHERE recipient_kid = ?', recipientKid)
  }

  loudCount(recipientKid: string): number {
    this.expire()
    return this.scalar('SELECT count(*) AS value FROM queued_messages WHERE recipient_kid = ? AND silent = 0', recipientKid)
  }

  clear(recipientKid: string): void {
    this.database.query('DELETE FROM queued_messages WHERE recipient_kid = ?').run(recipientKid)
  }

  peek(recipientKid: string, limit: number): QueuedMessage[] {
    this.expire()
    const bounded = Math.max(0, Math.min(Math.trunc(limit), this.limits.maxQueueItemsPerRecipient))
    return this.database.query<QueueRow, [string, number]>(
      'SELECT id, packed, queued_at, silent FROM queued_messages WHERE recipient_kid = ? ORDER BY queued_at, id LIMIT ?',
    ).all(recipientKid, bounded).map(row => ({
      id: row.id,
      packed: row.packed,
      queuedAt: Number(row.queued_at),
      ...(row.silent ? { silent: true } : {}),
    }))
  }

  remove(recipientKid: string, ids: string[]): number {
    if (ids.length === 0) return this.count(recipientKid)
    return this.transaction(() => {
      const now = Date.now()
      const insertAck = this.database.query(
        'INSERT OR IGNORE INTO received_acks (message_id, recipient_kid, acked_at, expires_at) SELECT id, recipient_kid, ?, ? FROM queued_messages WHERE id = ? AND recipient_kid = ?',
      )
      const remove = this.database.query('DELETE FROM queued_messages WHERE id = ? AND recipient_kid = ?')
      for (const id of new Set(ids)) {
        insertAck.run(now, now + this.limits.queueTtlMs, id, recipientKid)
        remove.run(id, recipientKid)
      }
      return this.scalar('SELECT count(*) AS value FROM queued_messages WHERE recipient_kid = ?', recipientKid)
    })
  }

  check(id: string): boolean {
    return this.transaction(() => {
      const now = Date.now()
      const key = id.toLowerCase()
      const existing = this.database.query<{ expires_at: number }, [string]>('SELECT expires_at FROM replay_ids WHERE message_id = ?').get(key)
      if (existing && Number(existing.expires_at) > now) return false
      this.database.query('INSERT INTO replay_ids (message_id, expires_at, recorded_at) VALUES (?, ?, ?) ON CONFLICT(message_id) DO UPDATE SET expires_at = excluded.expires_at, recorded_at = excluded.recorded_at')
        .run(key, now + this.limits.replayTtlMs, now)
      const overflow = this.scalar('SELECT count(*) AS value FROM replay_ids') - this.limits.maxReplayIds
      if (overflow > 0) {
        this.database.query('DELETE FROM replay_ids WHERE message_id IN (SELECT message_id FROM replay_ids ORDER BY recorded_at, message_id LIMIT ?)').run(overflow)
      }
      return true
    })
  }

  expire(now = Date.now()): void {
    const queueCutoff = now - this.limits.queueTtlMs
    this.transaction(() => {
      this.database.query('DELETE FROM queued_messages WHERE queued_at < ?').run(queueCutoff)
      this.database.query('DELETE FROM received_acks WHERE expires_at <= ?').run(now)
      this.database.query('DELETE FROM replay_ids WHERE expires_at <= ?').run(now)
    })
  }

  private scalar(sql: string, parameter?: string): number {
    const query = this.database.query<{ value: number }, [] | [string]>(sql)
    const row = parameter === undefined ? query.get() : query.get(parameter)
    return Number(row?.value ?? 0)
  }
}

function validPublicUrl(value: string): string {
  const url = new URL(value)
  if (url.protocol !== 'https:' && url.hostname !== 'localhost' && url.hostname !== '127.0.0.1') {
    throw new TypeError('MEDIATOR_PUBLIC_URL must use https')
  }
  url.hash = ''
  url.search = ''
  return url.toString().replace(/\/$/, '')
}

function assertLimits(limits: SqliteMediatorLimits): void {
  for (const [name, value] of Object.entries(limits)) {
    if (!Number.isSafeInteger(value) || value <= 0) throw new TypeError(`${name} must be a positive safe integer`)
  }
  if (limits.maxMessageBytes > limits.maxQueueBytesPerRecipient) {
    throw new TypeError('maxMessageBytes must not exceed maxQueueBytesPerRecipient')
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
    CREATE TABLE IF NOT EXISTS mediator_identity (
      singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
      public_url TEXT NOT NULL,
      x_priv TEXT NOT NULL,
      ed_priv TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS relay_poller_identity (
      singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
      x_priv TEXT NOT NULL,
      ed_priv TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS mail_plugin_identity (
      singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
      x_priv TEXT NOT NULL,
      ed_priv TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS connections (
      client_did TEXT PRIMARY KEY,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS connection_keys (
      recipient_kid TEXT PRIMARY KEY,
      client_did TEXT NOT NULL REFERENCES connections(client_did) ON DELETE CASCADE,
      as_given TEXT NOT NULL,
      public_key_hex TEXT,
      last_seen INTEGER,
      created_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS connection_keys_client ON connection_keys(client_did, created_at);
    CREATE TABLE IF NOT EXISTS queued_messages (
      id TEXT PRIMARY KEY,
      recipient_kid TEXT NOT NULL REFERENCES connection_keys(recipient_kid) ON DELETE CASCADE,
      packed TEXT NOT NULL,
      size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
      queued_at INTEGER NOT NULL,
      silent INTEGER NOT NULL DEFAULT 0 CHECK (silent IN (0, 1))
    );
    CREATE INDEX IF NOT EXISTS queued_messages_recipient ON queued_messages(recipient_kid, queued_at, id);
    CREATE TABLE IF NOT EXISTS received_acks (
      message_id TEXT PRIMARY KEY,
      recipient_kid TEXT NOT NULL,
      acked_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS replay_ids (
      message_id TEXT PRIMARY KEY COLLATE NOCASE,
      expires_at INTEGER NOT NULL,
      recorded_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS replay_ids_expiry ON replay_ids(expires_at);
  `)
}
