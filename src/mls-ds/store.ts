// The Conversation Group MLS Delivery Service (RFC 9750 §5,
// docs/protocols/mls-ds-1.0.md), ported from
// coordinator/mls-delivery-store.ts's Self Group DS with `identityId`
// dropped throughout (PLAN_biset-mls-ds.md §7, decided 2026-08-31: `(groupId,
// senderId)` is the whole membership model, no single-owner identity
// concept). This is a NEW module, not a modification of the Self Group one
// -- that file is untouched.
//
// **Revision (identity-blind DS)**: `senderId`/`creatorId`/etc. are now
// `GroupLocalId`s (conversation-mls-ds.ts's own note) rather than DID kids.
// This store never sees, stores, or could reconstruct a real DID from
// anything it's handed -- there is no `group_info` column and no
// `groupInfoFor`/`submitExternalCommit` methods any more (GroupInfo's
// ratchet tree is what leaked every member's real MLS credential, RFC 9420
// requiring it to be plaintext-readable for external join; joining is
// Welcome-only now, and Welcome is HPKE-opaque to this store). `roster` is
// a delta (`addedIds`/`removedIds`) rather than a submitter-declared full
// snapshot -- the store already owns the authoritative Set, so it no
// longer needs to trust (or even receive) the whole thing on every commit.
// `groupsFor` is gone too: "every group this id belongs to" is meaningless
// once an id is single-group and throwaway by construction.
//
// Consequences of dropping identityId, all making this simpler than the
// Self Group version rather than just different:
//   - KeyPackage take has no "every live device of this identity" fan-out
//     (there is no identity to enumerate devices of) -- a Conversation
//     Group take always names one `targetId` (conversation-mls-ds.ts's own
//     ConversationKeyPackageTakeV1), so it's a single take-one-and-consume,
//     no async liveness check needed.
//
// A new application-message log entry kind and submitMessage() operation
// exist here with no Self Group equivalent -- PLAN-mimi.md's finding that
// Self Group's DS never carries application data (Vault sync uses a
// separate ordered log) but a Conversation Group's does, since fanning
// that out IS this DS's job here (delivered by pull only now -- see
// conversation-mls-ds.ts's header for why push/DIDComm binding is gone).
import { Database } from 'bun:sqlite'
import type { ConversationLogEntry, ConversationLogEntryKind, GroupLocalId } from '../protocol/conversation-mls-ds.ts'

export type { ConversationLogEntry } from '../protocol/conversation-mls-ds.ts'

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
export interface ConversationCommitRejected { ok: false; reason: 'epoch-conflict' | 'not-a-member' | 'no-such-group' | 'unauthorized'; epoch: string }
export type ConversationCommitResult = ConversationCommitAccepted | ConversationCommitRejected

interface GroupRow {
  group_id: string
  roster_json: string
  ever_members_json: string
  epoch: string
  next_seq: number
  pending_removals_json: string
  last_committer: string | null
  created_at: string
}

interface Group {
  groupId: string
  roster: Set<GroupLocalId>
  everMembers: Set<GroupLocalId>
  epoch: bigint
  nextSeq: number
  pendingRemovals: string[]
  lastCommitter?: string
}

/**
 * The Conversation Group DS role and KeyPackage store. Never parses an MLS
 * object, holds no group key, cannot read a message or an application
 * PrivateMessage -- and, since the revision above, never sees anything
 * shaped like a real identity either: every id it stores is a group-local
 * public key with no path back to a DID. Its whole job: admit one commit
 * (or application message) per epoch (first arrival wins for commits),
 * number what it accepts, and hand back what a member asks for.
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

  /** Take on the DS role for a group. Idempotent for the same creator. No
   * prior roster to check membership against -- `creatorId` needs no proof
   * beyond its own signature (conversation-mls-ds.ts's own note on why
   * group-create can be entirely self-authorized). */
  createGroup(groupId: string, creatorId: GroupLocalId): { roster: string[] } {
    const existing = this.loadGroup(groupId)
    if (existing) {
      if (!existing.roster.has(creatorId)) throw new ConversationDsCapacityError(`group ${groupId} already exists and ${creatorId} is not in it`)
      return { roster: [...existing.roster] }
    }
    if (this.groupCount() >= MAX_GROUPS) throw new ConversationDsCapacityError('DS is at capacity for Conversation Groups')
    const rosterSet = new Set([creatorId])
    this.insertGroup({ groupId, roster: rosterSet, everMembers: new Set(rosterSet), epoch: 0n, nextSeq: 1, pendingRemovals: [] })
    return { roster: [...rosterSet] }
  }

  roster(groupId: string): string[] { return [...(this.loadGroup(groupId)?.roster ?? [])] }

  /** Admit (or refuse) a commit -- the one place the DS is authoritative.
   * `addedIds`/`removedIds` are a DELTA against the roster THIS STORE
   * already owns, not a submitter-declared snapshot -- the submitter only
   * needs to know who they're adding or removing, never the whole current
   * membership (a second reason this is simpler than the first version,
   * independent of the privacy motivation). */
  submitCommit(groupId: string, sender: GroupLocalId, epoch: string, commit: Uint8Array, addedIds: GroupLocalId[] = [], removedIds: GroupLocalId[] = [], welcome?: Uint8Array): ConversationCommitResult {
    const group = this.loadGroup(groupId)
    if (!group) return { ok: false, reason: 'no-such-group', epoch: '0' }
    if (!group.roster.has(sender)) return { ok: false, reason: 'not-a-member', epoch: group.epoch.toString() }
    if (BigInt(epoch) !== group.epoch) return { ok: false, reason: 'epoch-conflict', epoch: group.epoch.toString() }
    if (group.roster.size + addedIds.length > MAX_ROSTER) return { ok: false, reason: 'not-a-member', epoch: group.epoch.toString() }

    return this.database.transaction((): ConversationCommitAccepted => {
      const entries: ConversationLogEntry[] = []
      if (welcome) entries.push(this.append(group, 'welcome', welcome, epoch))
      entries.push(this.append(group, 'commit', commit, epoch))
      group.epoch = group.epoch + 1n
      group.lastCommitter = sender
      const next = new Set(group.roster)
      for (const id of addedIds) next.add(id)
      for (const id of removedIds) next.delete(id)
      group.roster = next
      for (const id of group.roster) group.everMembers.add(id)
      this.trimEverMembers(group)
      this.saveGroup(group)
      return { ok: true, entries, roster: [...group.roster] }
    })()
  }

  /** Fan out an application message -- no epoch/roster change, just a log
   * entry a puller sees via `deliveries-pull` (no push any more, see
   * conversation-mls-ds.ts's header). The one operation with no Self Group
   * DS equivalent (PLAN-mimi.md). */
  submitMessage(groupId: string, sender: GroupLocalId, epoch: string, privateMessage: Uint8Array): ConversationCommitResult {
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

  /** Record a device's declaration that it is removing itself. */
  submitSelfRemove(groupId: string, sender: GroupLocalId, epoch: string, proposal: Uint8Array, id: GroupLocalId): ConversationCommitResult {
    const group = this.loadGroup(groupId)
    if (!group) return { ok: false, reason: 'no-such-group', epoch: '0' }
    if (!group.everMembers.has(sender)) return { ok: false, reason: 'not-a-member', epoch: group.epoch.toString() }
    return this.database.transaction((): ConversationCommitAccepted => {
      if (!group.pendingRemovals.includes(id) && group.pendingRemovals.length < MAX_PENDING_REMOVALS) group.pendingRemovals.push(id)
      const entry = this.append(group, 'proposal', proposal, epoch)
      this.saveGroup(group)
      return { ok: true, entries: [entry], roster: [...group.roster] }
    })()
  }

  /** Forget self-removal declarations that were carried out by the last accepted commit. */
  clearPendingRemovals(groupId: string, requester: GroupLocalId, ids: string[]): void {
    const group = this.loadGroup(groupId)
    if (!group || group.lastCommitter !== requester) return
    group.pendingRemovals = group.pendingRemovals.filter(id => !ids.includes(id))
    this.saveGroup(group)
  }

  /** Deliveries after `afterSeq`. Empty when the gap is older than the retained log. */
  since(groupId: string, afterSeq: number): ConversationLogEntry[] {
    return this.database.query<{ seq: number; kind: ConversationLogEntry['kind']; payload: Uint8Array; epoch: string; at: string }, [string, number]>(
      `SELECT seq, kind, payload, epoch, at FROM ${this.tables.log} WHERE group_id = ? AND seq > ? ORDER BY seq`,
    ).all(groupId, afterSeq).map(row => ({ seq: row.seq, kind: row.kind, payload: new Uint8Array(row.payload), epoch: row.epoch, at: row.at }))
  }

  /** The authorised form: gated on ever-membership, bounded per pull. Undefined means "not yours". */
  deliveriesSince(groupId: string, requester: GroupLocalId, afterSeq: number, limit = MAX_DELIVERIES_PER_PULL): ConversationLogEntry[] | undefined {
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
    for (const id of [...group.everMembers]) {
      if (group.everMembers.size <= MAX_EVER_MEMBERS) break
      if (!group.roster.has(id)) group.everMembers.delete(id)
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
      pendingRemovals: parseStringArray(row.pending_removals_json),
      lastCommitter: row.last_committer ?? undefined,
    }
  }

  private insertGroup(group: Omit<Group, 'lastCommitter'>): void {
    this.database.query(`INSERT INTO ${this.tables.groups}
      (group_id, roster_json, ever_members_json, epoch, next_seq, pending_removals_json, last_committer, created_at)
      VALUES (?, ?, ?, ?, ?, ?, NULL, ?)`)
      .run(group.groupId, JSON.stringify([...group.roster]), JSON.stringify([...group.everMembers]), group.epoch.toString(), group.nextSeq, JSON.stringify(group.pendingRemovals), new Date().toISOString())
  }

  private saveGroup(group: Group): void {
    this.database.query(`UPDATE ${this.tables.groups} SET
      roster_json = ?, ever_members_json = ?, epoch = ?, next_seq = ?, pending_removals_json = ?, last_committer = ?
      WHERE group_id = ?`)
      .run(JSON.stringify([...group.roster]), JSON.stringify([...group.everMembers]), group.epoch.toString(), group.nextSeq, JSON.stringify(group.pendingRemovals), group.lastCommitter ?? null, group.groupId)
  }

  // ------------------------------------------------------------ key packages

  /** Add to a device's published key packages (single-use; the DS deletes each as it hands it out). */
  publishKeyPackages(id: GroupLocalId, packages: Uint8Array[]): number {
    const existing = this.database.query<{ count: number }, [string]>(`SELECT count(*) AS count FROM ${this.tables.keyPackages} WHERE kid = ?`).get(id)!.count
    const room = Math.max(0, MAX_KEY_PACKAGES_PER_KID - existing)
    const toInsert = packages.slice(0, room)
    if (toInsert.length > 0) {
      const insert = this.database.query(`INSERT INTO ${this.tables.keyPackages} (kid, package, created_at) VALUES (?, ?, ?)`)
      this.database.transaction(() => { for (const kp of toInsert) insert.run(id, kp, new Date().toISOString()) })()
    }
    return this.database.query<{ count: number }, [string]>(`SELECT count(*) AS count FROM ${this.tables.keyPackages} WHERE kid = ?`).get(id)!.count
  }

  /** Forget a device's published key packages (deregistration). */
  dropKeyPackages(id: GroupLocalId): void {
    this.database.query(`DELETE FROM ${this.tables.keyPackages} WHERE kid = ?`).run(id)
  }

  /** Take (consume) one key package for `targetId` -- no liveness fan-out
   * needed (unlike Self Group's takeKeyPackages), a Conversation Group take
   * always names exactly one target. */
  takeKeyPackage(targetId: GroupLocalId): { keyPackage: Uint8Array } | undefined {
    const row = this.database.query<{ id: number; package: Uint8Array }, [string]>(
      `SELECT id, package FROM ${this.tables.keyPackages} WHERE kid = ? ORDER BY id LIMIT 1`,
    ).get(targetId)
    if (!row) return undefined
    this.database.query(`DELETE FROM ${this.tables.keyPackages} WHERE id = ?`).run(row.id)
    return { keyPackage: new Uint8Array(row.package) }
  }

  /** How many unused key packages a device has left. */
  keyPackageCount(id: GroupLocalId): number {
    return this.database.query<{ count: number }, [string]>(`SELECT count(*) AS count FROM ${this.tables.keyPackages} WHERE kid = ?`).get(id)!.count
  }
}

function installSchema(database: Database, tables: ConversationDeliveryTables): void {
  database.exec(`
    CREATE TABLE IF NOT EXISTS ${tables.groups} (
      group_id TEXT PRIMARY KEY, roster_json TEXT NOT NULL, ever_members_json TEXT NOT NULL,
      epoch TEXT NOT NULL, next_seq INTEGER NOT NULL, pending_removals_json TEXT NOT NULL,
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
