// The Conversation Group MLS Delivery Service (RFC 9750 §5,
// docs/protocols/mls-ds-1.0.md), ported from
// coordinator/mls-delivery-store.ts's Self Group DS with `identityId`
// dropped throughout (PLAN_biset-mls-ds.md §7, decided 2026-08-31: `(groupId,
// senderKid)` is the whole membership model, no single-owner identity
// concept). This is a NEW module, not a modification of the Self Group one
// -- that file is untouched.
//
// Consequences of dropping identityId, all making this simpler than the
// Self Group version rather than just different:
//   - `groupInfoFor`/`submitExternalCommit` no longer gate on "does this
//     requester belong to the group's owner identity" (there is no owner
//     identity). The gate becomes: knowing `groupId` is itself the
//     invitation (PLAN_biset-mls-ds.md §11-2's bootstrap/invitation
//     protocol is what's expected to keep groupId non-guessable; this store
//     doesn't invent a second gate on top of that). GroupInfo itself carries
//     no group secret (RFC 9420) -- this mirrors MLS's own external-join
//     design, where GroupInfo is meant to be shared with a prospective joiner.
//   - KeyPackage take has no "every live device of this identity" fan-out
//     (there is no identity to enumerate devices of) -- a Conversation
//     Group take always names one `targetKid` (conversation-mls-ds.ts's own
//     ConversationKeyPackageTakeV1), so it's a single take-one-and-consume,
//     no async liveness check needed.
//
// A new application-message log entry kind and submitMessage() operation
// exist here with no Self Group equivalent -- PLAN-mimi.md's finding that
// Self Group's DS never carries application data (Vault sync uses a
// separate ordered log) but a Conversation Group's does, since fanning
// that out IS this DS's job.
import { Database } from 'bun:sqlite'
import type { ConversationGroupInfoAnswer, ConversationLogEntry, ConversationLogEntryKind } from '../protocol/conversation-mls-ds.ts'

export type { ConversationGroupInfoAnswer, ConversationLogEntry } from '../protocol/conversation-mls-ds.ts'

const MAX_GROUPS = 10_000
const MAX_ROSTER = 512
const MAX_KEY_PACKAGES_PER_KID = 32
const MAX_LOG_PER_GROUP = 256
const MAX_EVER_MEMBERS = 2048
const MAX_DELIVERIES_PER_PULL = 32
const MAX_PENDING_REMOVALS = 64

export class ConversationDsCapacityError extends Error {}

interface ConversationDeliveryTables {
  groups: string
  log: string
  keyPackages: string
  keyPackagesByKid: string
}

const CONVERSATION_DELIVERY_TABLES: ConversationDeliveryTables = {
  groups: 'conversation_ds_groups', log: 'conversation_ds_log',
  keyPackages: 'conversation_ds_key_packages', keyPackagesByKid: 'conversation_ds_key_packages_by_kid',
}

export interface ConversationCommitAccepted { ok: true; entries: ConversationLogEntry[]; roster: string[] }
export interface ConversationCommitRejected { ok: false; reason: 'epoch-conflict' | 'not-a-member' | 'no-such-group' | 'no-group-info' | 'unauthorized'; epoch: string }
export type ConversationCommitResult = ConversationCommitAccepted | ConversationCommitRejected

interface GroupRow {
  group_id: string
  roster_json: string
  ever_members_json: string
  epoch: string
  next_seq: number
  group_info: Uint8Array | null
  pending_removals_json: string
  last_committer: string | null
  created_at: string
}

interface Group {
  groupId: string
  roster: Set<string>
  everMembers: Set<string>
  epoch: bigint
  nextSeq: number
  groupInfo?: Uint8Array
  pendingRemovals: string[]
  lastCommitter?: string
}

/**
 * The Conversation Group DS role and KeyPackage store. Never parses an MLS
 * object, holds no group key, cannot read a message or an application
 * PrivateMessage. Its whole job: admit one commit (or application message)
 * per epoch (first arrival wins for commits), number what it accepts, and
 * hand back what a member asks for.
 */
export class SqliteConversationDeliveryService {
  private readonly tables: ConversationDeliveryTables

  constructor(private readonly database: Database) {
    this.tables = CONVERSATION_DELIVERY_TABLES
    installSchema(database, this.tables)
  }

  static open(path: string): SqliteConversationDeliveryService {
    if (!path) throw new TypeError('SQLite Conversation DS path is required')
    return new SqliteConversationDeliveryService(new Database(path))
  }

  close(): void { this.database.close() }

  // ------------------------------------------------------------------ groups

  /** Take on the DS role for a group. Idempotent for the same creator. */
  createGroup(groupId: string, creatorKid: string, roster: string[]): { roster: string[] } {
    const existing = this.loadGroup(groupId)
    if (existing) {
      if (!existing.roster.has(creatorKid)) throw new ConversationDsCapacityError(`group ${groupId} already exists and ${creatorKid} is not in it`)
      return { roster: [...existing.roster] }
    }
    if (this.groupCount() >= MAX_GROUPS) throw new ConversationDsCapacityError('DS is at capacity for Conversation Groups')
    if (roster.length > MAX_ROSTER) throw new ConversationDsCapacityError(`roster of ${roster.length} exceeds the maximum of ${MAX_ROSTER}`)
    const rosterSet = new Set([creatorKid, ...roster])
    this.insertGroup({ groupId, roster: rosterSet, everMembers: new Set(rosterSet), epoch: 0n, nextSeq: 1, pendingRemovals: [] })
    return { roster: [...rosterSet] }
  }

  /** Every group kid `deviceKid` has ever been a member of. */
  groupsFor(deviceKid: string, limit = 256): Array<{ groupId: string; epoch: bigint }> {
    const rows = this.database.query<GroupRow, []>(`SELECT * FROM ${this.tables.groups}`).all()
    const found: Array<{ groupId: string; epoch: bigint }> = []
    for (const row of rows) {
      if (!parseStringArray(row.ever_members_json).includes(deviceKid)) continue
      found.push({ groupId: row.group_id, epoch: BigInt(row.epoch) })
      if (found.length >= limit) break
    }
    return found
  }

  roster(groupId: string): string[] { return [...(this.loadGroup(groupId)?.roster ?? [])] }

  /** Admit (or refuse) a commit -- the one place the DS is authoritative. */
  submitCommit(groupId: string, sender: string, epoch: string, commit: Uint8Array, roster: string[], welcome?: Uint8Array, welcomeTo?: string[], groupInfo?: Uint8Array): ConversationCommitResult {
    const group = this.loadGroup(groupId)
    if (!group) return { ok: false, reason: 'no-such-group', epoch: '0' }
    if (!group.roster.has(sender)) return { ok: false, reason: 'not-a-member', epoch: group.epoch.toString() }
    if (BigInt(epoch) !== group.epoch) return { ok: false, reason: 'epoch-conflict', epoch: group.epoch.toString() }
    if (roster.length > MAX_ROSTER) return { ok: false, reason: 'not-a-member', epoch: group.epoch.toString() }

    return this.database.transaction((): ConversationCommitAccepted => {
      const entries: ConversationLogEntry[] = []
      if (welcome) entries.push(this.append(group, 'welcome', welcome, epoch))
      entries.push(this.append(group, 'commit', commit, epoch))
      group.epoch = group.epoch + 1n
      group.lastCommitter = sender
      group.roster = new Set([...roster, ...(welcomeTo ?? [])])
      for (const kid of group.roster) group.everMembers.add(kid)
      this.trimEverMembers(group)
      group.groupInfo = groupInfo
      this.saveGroup(group)
      return { ok: true, entries, roster: [...group.roster] }
    })()
  }

  /** Fan out an application message -- no epoch/roster change, just a log
   * entry the recipient side (message-notify, mls-ds-1.0.md §5.2) delivers.
   * The one operation with no Self Group DS equivalent (PLAN-mimi.md). */
  submitMessage(groupId: string, sender: string, epoch: string, privateMessage: Uint8Array): ConversationCommitResult {
    const group = this.loadGroup(groupId)
    if (!group) return { ok: false, reason: 'no-such-group', epoch: '0' }
    if (!group.roster.has(sender)) return { ok: false, reason: 'not-a-member', epoch: group.epoch.toString() }
    if (BigInt(epoch) !== group.epoch) return { ok: false, reason: 'epoch-conflict', epoch: group.epoch.toString() }
    return this.database.transaction((): ConversationCommitAccepted => {
      const entry = this.append(group, 'application', privateMessage, epoch)
      this.saveGroup(group)
      return { ok: true, entries: [entry], roster: [...group.roster] }
    })()
  }

  /**
   * The GroupInfo a prospective member may use to join via external commit,
   * plus outstanding self-removals. Gated on nothing but `groupId` existing
   * -- unlike Self Group's `groupInfoFor`, there is no owner identity to
   * check membership of. Knowing `groupId` (expected to come from an
   * out-of-band invitation, PLAN_biset-mls-ds.md §11-2, not yet designed)
   * IS the authorization here; GroupInfo itself carries no group secret
   * (RFC 9420 designs it to be shareable with a joiner).
   */
  groupInfoFor(groupId: string): ConversationGroupInfoAnswer | undefined {
    const group = this.loadGroup(groupId)
    if (!group) return undefined
    return { ...(group.groupInfo ? { groupInfo: group.groupInfo } : {}), pendingRemovals: [...group.pendingRemovals] }
  }

  /** Record a device's declaration that it is removing itself. */
  submitSelfRemove(groupId: string, sender: string, epoch: string, proposal: Uint8Array, kid: string): ConversationCommitResult {
    const group = this.loadGroup(groupId)
    if (!group) return { ok: false, reason: 'no-such-group', epoch: '0' }
    if (!group.everMembers.has(sender)) return { ok: false, reason: 'not-a-member', epoch: group.epoch.toString() }
    return this.database.transaction((): ConversationCommitAccepted => {
      if (!group.pendingRemovals.includes(kid) && group.pendingRemovals.length < MAX_PENDING_REMOVALS) group.pendingRemovals.push(kid)
      const entry = this.append(group, 'proposal', proposal, epoch)
      this.saveGroup(group)
      return { ok: true, entries: [entry], roster: [...group.roster] }
    })()
  }

  /** Forget self-removal declarations that were carried out by the last accepted commit. */
  clearPendingRemovals(groupId: string, requester: string, kids: string[]): void {
    const group = this.loadGroup(groupId)
    if (!group || group.lastCommitter !== requester) return
    group.pendingRemovals = group.pendingRemovals.filter(k => !kids.includes(k))
    this.saveGroup(group)
  }

  /**
   * Admit an external commit: a device committing itself in, without an
   * existing member adding it. Safety comes from the signature (the caller
   * verified `senderKid` really controls that key) plus MLS itself (the
   * joiner's credential still has to name something this Conversation
   * Group's Authentication Service accepts) -- never from `roster.has`,
   * which by definition excludes a joiner who isn't a member yet.
   */
  submitExternalCommit(groupId: string, senderKid: string, epoch: string, commit: Uint8Array, groupInfo?: Uint8Array): ConversationCommitResult {
    const group = this.loadGroup(groupId)
    if (!group) return { ok: false, reason: 'no-such-group', epoch: '0' }
    if (group.groupInfo === undefined) return { ok: false, reason: 'no-group-info', epoch: group.epoch.toString() }
    if (BigInt(epoch) !== group.epoch) return { ok: false, reason: 'epoch-conflict', epoch: group.epoch.toString() }
    return this.database.transaction((): ConversationCommitAccepted => {
      const entry = this.append(group, 'commit', commit, epoch)
      group.epoch = group.epoch + 1n
      group.lastCommitter = senderKid
      group.groupInfo = groupInfo
      group.roster.add(senderKid)
      group.everMembers.add(senderKid)
      this.saveGroup(group)
      return { ok: true, entries: [entry], roster: [...group.roster] }
    })()
  }

  /** Deliveries after `afterSeq`. Empty when the gap is older than the retained log. */
  since(groupId: string, afterSeq: number): ConversationLogEntry[] {
    return this.database.query<{ seq: number; kind: ConversationLogEntry['kind']; payload: Uint8Array; epoch: string; at: string }, [string, number]>(
      `SELECT seq, kind, payload, epoch, at FROM ${this.tables.log} WHERE group_id = ? AND seq > ? ORDER BY seq`,
    ).all(groupId, afterSeq).map(row => ({ seq: row.seq, kind: row.kind, payload: new Uint8Array(row.payload), epoch: row.epoch, at: row.at }))
  }

  /** The authorised form: gated on ever-membership, bounded per pull. Undefined means "not yours". */
  deliveriesSince(groupId: string, requester: string, afterSeq: number, limit = MAX_DELIVERIES_PER_PULL): ConversationLogEntry[] | undefined {
    const group = this.loadGroup(groupId)
    if (!group || !group.everMembers.has(requester)) return undefined
    return this.since(groupId, afterSeq).slice(0, limit)
  }

  private append(group: Group, kind: ConversationLogEntryKind, payload: Uint8Array, epoch: string): ConversationLogEntry {
    const entry: ConversationLogEntry = { seq: group.nextSeq++, kind, payload, epoch, at: new Date().toISOString() }
    this.database.query(`INSERT INTO ${this.tables.log} (group_id, seq, kind, payload, epoch, at) VALUES (?, ?, ?, ?, ?, ?)`)
      .run(group.groupId, entry.seq, entry.kind, entry.payload, entry.epoch, entry.at)
    this.database.query(`DELETE FROM ${this.tables.log} WHERE group_id = ? AND seq <= (SELECT max(seq) FROM ${this.tables.log} WHERE group_id = ?) - ?`)
      .run(group.groupId, group.groupId, MAX_LOG_PER_GROUP)
    return entry
  }

  private trimEverMembers(group: Group): void {
    if (group.everMembers.size <= MAX_EVER_MEMBERS) return
    for (const kid of [...group.everMembers]) {
      if (group.everMembers.size <= MAX_EVER_MEMBERS) break
      if (!group.roster.has(kid)) group.everMembers.delete(kid)
    }
  }

  private groupCount(): number {
    return this.database.query<{ count: number }, []>(`SELECT count(*) AS count FROM ${this.tables.groups}`).get()!.count
  }

  private loadGroup(groupId: string): Group | undefined {
    const row = this.database.query<GroupRow, [string]>(`SELECT * FROM ${this.tables.groups} WHERE group_id = ?`).get(groupId) ?? undefined
    if (!row) return undefined
    return {
      groupId: row.group_id,
      roster: new Set(parseStringArray(row.roster_json)),
      everMembers: new Set(parseStringArray(row.ever_members_json)),
      epoch: BigInt(row.epoch),
      nextSeq: row.next_seq,
      groupInfo: row.group_info === null ? undefined : new Uint8Array(row.group_info),
      pendingRemovals: parseStringArray(row.pending_removals_json),
      lastCommitter: row.last_committer ?? undefined,
    }
  }

  private insertGroup(group: Omit<Group, 'lastCommitter' | 'groupInfo'>): void {
    this.database.query(`INSERT INTO ${this.tables.groups}
      (group_id, roster_json, ever_members_json, epoch, next_seq, group_info, pending_removals_json, last_committer, created_at)
      VALUES (?, ?, ?, ?, ?, NULL, ?, NULL, ?)`)
      .run(group.groupId, JSON.stringify([...group.roster]), JSON.stringify([...group.everMembers]), group.epoch.toString(), group.nextSeq, JSON.stringify(group.pendingRemovals), new Date().toISOString())
  }

  private saveGroup(group: Group): void {
    this.database.query(`UPDATE ${this.tables.groups} SET
      roster_json = ?, ever_members_json = ?, epoch = ?, next_seq = ?, group_info = ?, pending_removals_json = ?, last_committer = ?
      WHERE group_id = ?`)
      .run(JSON.stringify([...group.roster]), JSON.stringify([...group.everMembers]), group.epoch.toString(), group.nextSeq, group.groupInfo ?? null, JSON.stringify(group.pendingRemovals), group.lastCommitter ?? null, group.groupId)
  }

  // ------------------------------------------------------------ key packages

  /** Add to a device's published key packages (single-use; the DS deletes each as it hands it out). */
  publishKeyPackages(kid: string, packages: Uint8Array[]): number {
    const existing = this.database.query<{ count: number }, [string]>(`SELECT count(*) AS count FROM ${this.tables.keyPackages} WHERE kid = ?`).get(kid)!.count
    const room = Math.max(0, MAX_KEY_PACKAGES_PER_KID - existing)
    const toInsert = packages.slice(0, room)
    if (toInsert.length > 0) {
      const insert = this.database.query(`INSERT INTO ${this.tables.keyPackages} (kid, package, created_at) VALUES (?, ?, ?)`)
      this.database.transaction(() => { for (const kp of toInsert) insert.run(kid, kp, new Date().toISOString()) })()
    }
    return this.database.query<{ count: number }, [string]>(`SELECT count(*) AS count FROM ${this.tables.keyPackages} WHERE kid = ?`).get(kid)!.count
  }

  /** Forget a device's published key packages (deregistration). */
  dropKeyPackages(kid: string): void {
    this.database.query(`DELETE FROM ${this.tables.keyPackages} WHERE kid = ?`).run(kid)
  }

  /** Take (consume) one key package for `targetKid` -- no liveness fan-out
   * needed (unlike Self Group's takeKeyPackages), a Conversation Group take
   * always names exactly one target. */
  takeKeyPackage(targetKid: string): { keyPackage: Uint8Array } | undefined {
    const row = this.database.query<{ id: number; package: Uint8Array }, [string]>(
      `SELECT id, package FROM ${this.tables.keyPackages} WHERE kid = ? ORDER BY id LIMIT 1`,
    ).get(targetKid)
    if (!row) return undefined
    this.database.query(`DELETE FROM ${this.tables.keyPackages} WHERE id = ?`).run(row.id)
    return { keyPackage: new Uint8Array(row.package) }
  }

  /** How many unused key packages a device has left. */
  keyPackageCount(kid: string): number {
    return this.database.query<{ count: number }, [string]>(`SELECT count(*) AS count FROM ${this.tables.keyPackages} WHERE kid = ?`).get(kid)!.count
  }
}

function installSchema(database: Database, tables: ConversationDeliveryTables): void {
  database.exec(`
    CREATE TABLE IF NOT EXISTS ${tables.groups} (
      group_id TEXT PRIMARY KEY, roster_json TEXT NOT NULL, ever_members_json TEXT NOT NULL,
      epoch TEXT NOT NULL, next_seq INTEGER NOT NULL, group_info BLOB, pending_removals_json TEXT NOT NULL,
      last_committer TEXT, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS ${tables.log} (
      group_id TEXT NOT NULL, seq INTEGER NOT NULL, kind TEXT NOT NULL, payload BLOB NOT NULL, epoch TEXT NOT NULL, at TEXT NOT NULL,
      PRIMARY KEY (group_id, seq)
    );
    CREATE TABLE IF NOT EXISTS ${tables.keyPackages} (
      id INTEGER PRIMARY KEY AUTOINCREMENT, kid TEXT NOT NULL, package BLOB NOT NULL, created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS ${tables.keyPackagesByKid} ON ${tables.keyPackages} (kid, id);
  `)
}

function parseStringArray(value: string): string[] {
  let parsed: unknown
  try { parsed = JSON.parse(value) } catch { throw new TypeError('stored Conversation DS field is invalid') }
  if (!Array.isArray(parsed) || parsed.some(item => typeof item !== 'string')) throw new TypeError('stored Conversation DS field is invalid')
  return [...parsed]
}
