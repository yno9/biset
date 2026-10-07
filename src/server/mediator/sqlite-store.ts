import { Database } from 'bun:sqlite'
import { mkdirSync } from 'node:fs'
import { dirname } from 'node:path'
import { x25519, ed25519 } from '@noble/curves/ed25519.js'
import { b64url, b64urlDecodeToBytes, identityFromKeys, type PeerIdentity, type PeerService } from '../../protocol/didcomm/peer.ts'

export interface SqliteMediatorLimits {
  /** Inboxes across the whole mediator -- registering is open, so this is
   * the floor under how much any number of strangers can allocate. */
  maxInboxes: number
  /** Devices (inboxes) one recipient DID may hold. */
  maxDevicesPerDid: number
  maxQueueItemsPerInbox: number
  maxQueueBytesPerInbox: number
  maxMessageBytes: number
  queueTtlMs: number
  /** An inbox whose device has not picked anything up for this long gets no
   * new copies and loses what it had (its device catches up from a sibling
   * via Vault Sync instead) -- unless it is its DID's most recently active
   * inbox, which keeps collecting so a user away from every device still
   * finds their messages. */
  dormantAfterMs: number
  replayTtlMs: number
  maxReplayIds: number
}

const DEFAULT_SQLITE_MEDIATOR_LIMITS: SqliteMediatorLimits = {
  maxInboxes: 30_000,
  maxDevicesPerDid: 3,
  // One inbox per device carries all of its traffic -- every conversation
  // and Vault Sync alike (PLAN-refactor.md §9.3).
  maxQueueItemsPerInbox: 1024,
  maxQueueBytesPerInbox: 64 * 1024 * 1024,
  maxMessageBytes: 1024 * 1024,
  queueTtlMs: 30 * 24 * 60 * 60 * 1000,
  dormantAfterMs: 14 * 24 * 60 * 60 * 1000,
  replayTtlMs: 10 * 60 * 1000,
  maxReplayIds: 50_000,
}

/** A queued message as one inbox sees it. `id` is the mediator's own id for
 * the stored body -- the value a device names back in `messages-received`.
 * The same body copied to several inboxes keeps one id; an ack only ever
 * removes it from the acking inbox. */
export interface QueuedMessage { id: string; packed: string; queuedAt: number }

export interface InboxSummary { device: string; lastSeen: number }

export class TooManyDevicesError extends Error {
  constructor(readonly limit: number, readonly devices: InboxSummary[]) {
    super(`mediator: this DID already has ${devices.length} devices registered (limit ${limit})`)
  }
}

export class MediatorFullError extends Error {}

export class QueueFullError extends Error {}
/** One message larger than `maxMessageBytes` -- never queueable, unlike a full inbox. */
export class MessageTooBigError extends Error {}

export type InboxAddResult = 'added' | 'updated' | 'unchanged'

interface IdentityRow { public_url: string; x_priv: string; ed_priv: string }
interface RelayPollerIdentityRow { x_priv: string; ed_priv: string }
interface MailPluginIdentityRow { x_priv: string; ed_priv: string }
interface InboxRow { device: string; registered_kid: string; last_seen: number }

const DEVICE_LABEL = /^[A-Za-z0-9_-]{8,64}$/

export function isDeviceLabel(value: unknown): value is string {
  return typeof value === 'string' && DEVICE_LABEL.test(value)
}

/** The blind mediator's whole durable state, one SQLite connection.
 *
 * An INBOX is one device's queue for one recipient DID: (recipient_did,
 * device). A recipient DID has up to `maxDevicesPerDid` of them, and a
 * Forward for that DID is copied to each (the spec allows a mediator to
 * multiplex to a recipient's several physical devices -- routing.md). The
 * body is stored once in `messages`; `deliveries` holds one small row per
 * inbox that still owes it, so N devices cost one body plus N rows.
 *
 * `did_states` is the latest verified did:webvh log state this mediator has
 * seen per DID -- the only source it authenticates a did:webvh device key
 * against, and the record that revokes a device the moment a newer log
 * drops its key. Nothing here can decrypt a byte of what it queues.
 *
 * Tests use `new SqliteMediatorStore(new Database(':memory:'))`: one store,
 * one implementation of every rule, in production and under test alike. */
export class SqliteMediatorStore {
  readonly limits: SqliteMediatorLimits
  // In-process pub/sub for `GET /stream` (server.ts): durability is SQLite's,
  // this is only the live-tail notification on top of it.
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

  static memory(limits?: Partial<SqliteMediatorLimits>): SqliteMediatorStore {
    return new SqliteMediatorStore(new Database(':memory:'), limits)
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
   * the poller it never registers an inbox with anyone, and unlike the
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

  stats(): { inboxes: number; recipients: number; queuedMessages: number; queuedBytes: number; pendingDeliveries: number; oldestQueuedAt?: number } {
    const queue = this.database.query<{ count: number; bytes: number; oldest: number | null }, []>(
      'SELECT count(*) AS count, coalesce(sum(size_bytes), 0) AS bytes, min(queued_at) AS oldest FROM messages',
    ).get()!
    return {
      inboxes: this.scalar('SELECT count(*) AS value FROM inboxes'),
      recipients: this.scalar('SELECT count(DISTINCT recipient_did) AS value FROM inboxes'),
      queuedMessages: Number(queue.count),
      queuedBytes: Number(queue.bytes),
      pendingDeliveries: this.scalar('SELECT count(*) AS value FROM deliveries'),
      ...(queue.oldest === null ? {} : { oldestQueuedAt: Number(queue.oldest) }),
    }
  }

  // ── did:webvh state ───────────────────────────────────────────────────────

  /** Records a verified did:webvh state if it is newer than what is held.
   * `keys` maps every keyAgreement kid (absolute DID URL) to its X25519 key,
   * hex. A newer state revokes: every inbox of that DID registered with a kid
   * the new state no longer lists is dropped with what it held. */
  recordWebvhState(did: string, versionNumber: number, keys: Record<string, string>): 'stored' | 'stale' {
    return this.transaction(() => {
      const held = this.database.query<{ version_number: number }, [string]>('SELECT version_number FROM did_states WHERE did = ?').get(did)
      if (held && Number(held.version_number) >= versionNumber) return 'stale'
      this.database.query('INSERT INTO did_states (did, version_number, keys_json, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(did) DO UPDATE SET version_number = excluded.version_number, keys_json = excluded.keys_json, updated_at = excluded.updated_at')
        .run(did, versionNumber, JSON.stringify(keys), Date.now())
      const removeInbox = this.database.query('DELETE FROM inboxes WHERE recipient_did = ? AND device = ?')
      for (const row of this.database.query<InboxRow, [string]>('SELECT device, registered_kid, last_seen FROM inboxes WHERE recipient_did = ?').all(did)) {
        if (!Object.hasOwn(keys, row.registered_kid)) removeInbox.run(did, row.device)
      }
      this.dropOrphanMessages()
      return 'stored'
    })
  }

  /** When the held state of `did` was last recorded (a new version). */
  webvhStateRecordedAt(did: string): number | undefined {
    const row = this.database.query<{ updated_at: number }, [string]>('SELECT updated_at FROM did_states WHERE did = ?').get(did)
    return row ? Number(row.updated_at) : undefined
  }

  /** The did:webvh DIDs that hold at least one inbox -- the ones whose keys
   * have to be checked again from time to time, so a device removed from its
   * DID loses its inbox. */
  webvhRecipientDids(): string[] {
    return this.database.query<{ recipient_did: string }, []>("SELECT DISTINCT recipient_did FROM inboxes WHERE recipient_did LIKE 'did:webvh:%'").all().map(row => row.recipient_did)
  }

  /** The X25519 key (hex) the latest held state lists for this kid. */
  webvhKey(did: string, kid: string): string | undefined {
    const row = this.database.query<{ keys_json: string }, [string]>('SELECT keys_json FROM did_states WHERE did = ?').get(did)
    if (!row) return undefined
    const keys = JSON.parse(row.keys_json) as Record<string, string>
    return Object.hasOwn(keys, kid) ? keys[kid] : undefined
  }

  // ── inboxes ───────────────────────────────────────────────────────────────

  /** Opens (or re-keys) one device's inbox for `did`. The caller has already
   * proven `registeredKid` is a key of `did` -- that proof is the whole
   * authorization; this only enforces capacity. */
  addInbox(did: string, device: string, registeredKid: string, now = Date.now()): InboxAddResult {
    return this.transaction(() => {
      const existing = this.database.query<InboxRow, [string, string]>('SELECT device, registered_kid, last_seen FROM inboxes WHERE recipient_did = ? AND device = ?').get(did, device)
      if (existing) {
        if (existing.registered_kid === registeredKid) return 'unchanged'
        this.database.query('UPDATE inboxes SET registered_kid = ? WHERE recipient_did = ? AND device = ?').run(registeredKid, did, device)
        return 'updated'
      }
      const devices = this.listInboxes(did)
      if (devices.length >= this.limits.maxDevicesPerDid) throw new TooManyDevicesError(this.limits.maxDevicesPerDid, devices)
      if (this.scalar('SELECT count(*) AS value FROM inboxes') >= this.limits.maxInboxes) throw new MediatorFullError('mediator: too many inboxes')
      this.database.query('INSERT INTO inboxes (recipient_did, device, registered_kid, created_at, last_seen, missed) VALUES (?, ?, ?, ?, ?, 0)')
        .run(did, device, registeredKid, now, now)
      return 'added'
    })
  }

  /** Drops one inbox and everything it still owed. */
  removeInbox(did: string, device: string): boolean {
    return this.transaction(() => {
      const removed = this.database.query('DELETE FROM inboxes WHERE recipient_did = ? AND device = ?').run(did, device).changes > 0
      if (removed) this.dropOrphanMessages()
      return removed
    })
  }

  hasInbox(did: string, device: string): boolean {
    return !!this.database.query<{ present: number }, [string, string]>('SELECT 1 AS present FROM inboxes WHERE recipient_did = ? AND device = ?').get(did, device)
  }

  listInboxes(did: string): InboxSummary[] {
    return this.database.query<{ device: string; last_seen: number }, [string]>('SELECT device, last_seen FROM inboxes WHERE recipient_did = ? ORDER BY created_at, device')
      .all(did).map(row => ({ device: row.device, lastSeen: Number(row.last_seen) }))
  }

  /** Proof of life for one inbox: any authenticated pickup-family request. */
  touch(did: string, device: string, now = Date.now()): void {
    this.database.query('UPDATE inboxes SET last_seen = ? WHERE recipient_did = ? AND device = ? AND last_seen < ?').run(now, did, device, now)
  }

  /** Reads and clears whether this inbox lost messages (dormancy or a full
   * queue) since it last asked. */
  takeMissed(did: string, device: string): boolean {
    return this.transaction(() => {
      const row = this.database.query<{ missed: number }, [string, string]>('SELECT missed FROM inboxes WHERE recipient_did = ? AND device = ?').get(did, device)
      if (!row?.missed) return false
      this.database.query('UPDATE inboxes SET missed = 0 WHERE recipient_did = ? AND device = ?').run(did, device)
      return true
    })
  }

  // ── queue ─────────────────────────────────────────────────────────────────

  /** Copies one Forward payload to every live inbox of `did` and returns how
   * many accepted it -- 0 means `did` has no inbox here at all. Dormant
   * inboxes are skipped (and marked as having missed something); when every
   * inbox is dormant, the most recently active one still collects. A full
   * inbox is skipped and marked the same way, so one abandoned device can
   * never block the others; the sender is refused only when no inbox could
   * take it. */
  enqueue(did: string, packed: string, now = Date.now()): number {
    const size = new TextEncoder().encode(packed).byteLength
    if (size > this.limits.maxMessageBytes) throw new MessageTooBigError(`mediator: message exceeds ${this.limits.maxMessageBytes} bytes`)
    return this.transaction(() => {
      const inboxes = this.database.query<InboxRow, [string]>('SELECT device, registered_kid, last_seen FROM inboxes WHERE recipient_did = ? ORDER BY last_seen DESC, device').all(did)
      if (inboxes.length === 0) return 0
      const liveSince = now - this.limits.dormantAfterMs
      const live = inboxes.filter(row => Number(row.last_seen) >= liveSince)
      const targets = live.length > 0 ? live : [inboxes[0]!]
      const markMissed = this.database.query('UPDATE inboxes SET missed = 1 WHERE recipient_did = ? AND device = ?')
      for (const row of inboxes) if (!targets.includes(row)) markMissed.run(did, row.device)
      const usage = this.database.query<{ count: number; bytes: number }, [string, string]>(
        'SELECT count(*) AS count, coalesce(sum(m.size_bytes), 0) AS bytes FROM deliveries d JOIN messages m ON m.id = d.message_id WHERE d.recipient_did = ? AND d.device = ?',
      )
      const accepting = targets.filter(row => {
        const used = usage.get(did, row.device)!
        const fits = Number(used.count) < this.limits.maxQueueItemsPerInbox && Number(used.bytes) + size <= this.limits.maxQueueBytesPerInbox
        if (!fits) markMissed.run(did, row.device)
        return fits
      })
      if (accepting.length === 0) throw new QueueFullError(`mediator: every inbox of ${did} is full`)
      const id = crypto.randomUUID()
      this.database.query('INSERT INTO messages (id, packed, size_bytes, queued_at) VALUES (?, ?, ?, ?)').run(id, packed, size, now)
      const deliver = this.database.query('INSERT INTO deliveries (recipient_did, device, message_id) VALUES (?, ?, ?)')
      for (const row of accepting) deliver.run(did, row.device, id)
      const message: QueuedMessage = { id, packed, queuedAt: now }
      for (const row of accepting) this.notify(did, row.device, [message])
      return accepting.length
    })
  }

  subscribe(did: string, device: string, listener: (messages: QueuedMessage[]) => void): () => void {
    const key = inboxKey(did, device)
    let set = this.watchers.get(key)
    if (!set) { set = new Set(); this.watchers.set(key, set) }
    set.add(listener)
    return () => {
      set!.delete(listener)
      if (set!.size === 0) this.watchers.delete(key)
    }
  }

  private notify(did: string, device: string, messages: QueuedMessage[]): void {
    for (const listener of this.watchers.get(inboxKey(did, device)) ?? []) listener(messages)
  }

  count(did: string, device: string): number {
    return this.scalar2('SELECT count(*) AS value FROM deliveries WHERE recipient_did = ? AND device = ?', did, device)
  }

  /** Non-destructive (Pickup 3.0): removal waits for `messages-received`. */
  peek(did: string, device: string, limit: number): QueuedMessage[] {
    const bounded = Math.max(0, Math.min(Math.trunc(limit), this.limits.maxQueueItemsPerInbox))
    return this.database.query<{ id: string; packed: string; queued_at: number }, [string, string, number]>(
      'SELECT m.id, m.packed, m.queued_at FROM deliveries d JOIN messages m ON m.id = d.message_id WHERE d.recipient_did = ? AND d.device = ? ORDER BY m.queued_at, m.id LIMIT ?',
    ).all(did, device, bounded).map(row => ({ id: row.id, packed: row.packed, queuedAt: Number(row.queued_at) }))
  }

  /** Removes the named messages from THIS inbox only and returns how many it
   * still holds. A body no inbox owes any more is dropped with it. Unknown
   * ids are ignored -- an ack is idempotent. */
  acknowledge(did: string, device: string, ids: readonly string[]): number {
    return this.transaction(() => {
      const remove = this.database.query('DELETE FROM deliveries WHERE recipient_did = ? AND device = ? AND message_id = ?')
      for (const id of new Set(ids)) remove.run(did, device, id)
      this.dropOrphanMessages()
      return this.count(did, device)
    })
  }

  // ── replay ────────────────────────────────────────────────────────────────

  /** Records a DIDComm message `id` and returns true if it is new (not seen
   * within `replayTtlMs`). Bounded by `maxReplayIds`, oldest first. */
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

  // ── retention ─────────────────────────────────────────────────────────────

  /** Ages out messages past `queueTtlMs`, and empties dormant inboxes that
   * are not their DID's most recently active one (marking them as having
   * missed what was dropped). Runs on a timer (deployment.ts). */
  expire(now = Date.now()): void {
    this.transaction(() => {
      this.database.query('DELETE FROM messages WHERE queued_at < ?').run(now - this.limits.queueTtlMs)
      const dormant = this.database.query<{ recipient_did: string; device: string }, [number]>(`
        SELECT i.recipient_did, i.device FROM inboxes i
        WHERE i.last_seen < ?
          AND EXISTS (SELECT 1 FROM inboxes o WHERE o.recipient_did = i.recipient_did AND (o.last_seen > i.last_seen OR (o.last_seen = i.last_seen AND o.device < i.device)))
          AND EXISTS (SELECT 1 FROM deliveries d WHERE d.recipient_did = i.recipient_did AND d.device = i.device)
      `).all(now - this.limits.dormantAfterMs)
      const empty = this.database.query('DELETE FROM deliveries WHERE recipient_did = ? AND device = ?')
      const markMissed = this.database.query('UPDATE inboxes SET missed = 1 WHERE recipient_did = ? AND device = ?')
      for (const row of dormant) { empty.run(row.recipient_did, row.device); markMissed.run(row.recipient_did, row.device) }
      this.dropOrphanMessages()
      this.database.query('DELETE FROM replay_ids WHERE expires_at <= ?').run(now)
    })
  }

  private dropOrphanMessages(): void {
    this.database.query('DELETE FROM messages WHERE NOT EXISTS (SELECT 1 FROM deliveries d WHERE d.message_id = messages.id)').run()
  }

  private scalar(sql: string, parameter?: string): number {
    const query = this.database.query<{ value: number }, [] | [string]>(sql)
    const row = parameter === undefined ? query.get() : query.get(parameter)
    return Number(row?.value ?? 0)
  }

  private scalar2(sql: string, a: string, b: string): number {
    return Number(this.database.query<{ value: number }, [string, string]>(sql).get(a, b)?.value ?? 0)
  }
}

function inboxKey(did: string, device: string): string { return `${did}\n${device}` }

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
  if (limits.maxMessageBytes > limits.maxQueueBytesPerInbox) {
    throw new TypeError('maxMessageBytes must not exceed maxQueueBytesPerInbox')
  }
}

function installSchema(database: Database): void {
  database.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = FULL;
    PRAGMA foreign_keys = ON;
    PRAGMA busy_timeout = 5000;
    CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL);
    INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (2, unixepoch() * 1000);
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
    CREATE TABLE IF NOT EXISTS did_states (
      did TEXT PRIMARY KEY,
      version_number INTEGER NOT NULL,
      keys_json TEXT NOT NULL,
      updated_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS inboxes (
      recipient_did TEXT NOT NULL,
      device TEXT NOT NULL,
      registered_kid TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      last_seen INTEGER NOT NULL,
      missed INTEGER NOT NULL DEFAULT 0 CHECK (missed IN (0, 1)),
      PRIMARY KEY (recipient_did, device)
    );
    CREATE TABLE IF NOT EXISTS messages (
      id TEXT PRIMARY KEY,
      packed TEXT NOT NULL,
      size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
      queued_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS messages_queued_at ON messages(queued_at);
    CREATE TABLE IF NOT EXISTS deliveries (
      recipient_did TEXT NOT NULL,
      device TEXT NOT NULL,
      message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
      PRIMARY KEY (recipient_did, device, message_id),
      FOREIGN KEY (recipient_did, device) REFERENCES inboxes(recipient_did, device) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS deliveries_message ON deliveries(message_id);
    CREATE TABLE IF NOT EXISTS replay_ids (
      message_id TEXT PRIMARY KEY COLLATE NOCASE,
      expires_at INTEGER NOT NULL,
      recorded_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS replay_ids_expiry ON replay_ids(expires_at);
  `)
}
