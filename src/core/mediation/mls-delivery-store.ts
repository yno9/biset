// The MLS self-group Delivery Service (RFC 9750 §5), ported from the
// pre-rewrite `src.bak/anchor/mediator/mls-ds.ts`. Persistence moves from a
// single JSON file to SQLite (this codebase's core-deployment pattern); the
// state machine itself — what gets accepted, what gets rejected, what a
// pull returns — is unchanged, because it already follows RFC 9750 to the
// letter (see the module header this file's functions still reference).
//
// The one scope change from the pre-rewrite version: that DS was generic
// over any MLS group (a conversation between several identities), so its
// `roster`/`everMembers` held IDENTITIES. Vault Core's MLS groups are
// self-groups only (PLANIMPLEMENTATION.md §4.1 — one identity's own
// devices; conversation groups are out of scope), so here `roster` and
// `everMembers` hold DEVICE KIDS instead. The ordering/tie-break/pull
// semantics are identical either way; only what the strings name changes.
//
// This is DELIBERATELY separate from `TrustedDeviceRoster`
// (core/identity/device-roster.ts). That roster is the confirmed, signed
// result of an accepted commit (installed via RosterInstallV1 by the
// producer in src/mls/roster-projection.ts, asynchronously, after this
// service has already accepted the commit that produced it). This service's
// own roster is the DS's necessarily-unverified bookkeeping of what the
// last accepted commit's sender CLAIMED the new roster to be — the same
// distinction the ported header draws ("the roster decides where copies are
// PUSHED... this decides who may PULL"). Conflating the two would make
// commit ordering depend on a roster update that hasn't happened yet.
import { Database } from 'bun:sqlite'
import type { MlsGroupInfoAnswer, MlsLogEntry } from '../../protocol/mls-ds.ts'

export type { MlsGroupInfoAnswer, MlsLogEntry } from '../../protocol/mls-ds.ts'

const MAX_GROUPS = 10_000
const MAX_ROSTER = 512
const MAX_KEY_PACKAGES_PER_KID = 32
const MAX_LOG_PER_GROUP = 256
const MAX_EVER_MEMBERS = 2048
const MAX_DELIVERIES_PER_PULL = 32
const MAX_PENDING_REMOVALS = 64

export class MlsDsCapacityError extends Error {}

export interface MlsCommitAccepted { ok: true; entries: MlsLogEntry[]; roster: string[] }
export interface MlsCommitRejected { ok: false; reason: 'epoch-conflict' | 'not-a-member' | 'no-such-group' | 'no-group-info' | 'unauthorized'; epoch: string }
export type MlsCommitResult = MlsCommitAccepted | MlsCommitRejected

interface GroupRow {
  group_id: string
  identity_id: string
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
  identityId: string
  roster: Set<string>
  everMembers: Set<string>
  epoch: bigint
  nextSeq: number
  groupInfo?: Uint8Array
  pendingRemovals: string[]
  lastCommitter?: string
}

/**
 * The MLS self-group DS role and KeyPackage store (RFC 9750 §5). Never
 * parses an MLS object, holds no group key, cannot read a message. Its whole
 * job: admit one commit per epoch (first arrival wins), number what it
 * accepts, and hand back what a device asks for.
 */
export class SqliteMlsDeliveryService {
  constructor(private readonly database: Database) {
    installSchema(database)
  }

  static open(path: string): SqliteMlsDeliveryService {
    if (!path) throw new TypeError('SQLite MLS delivery service path is required')
    return new SqliteMlsDeliveryService(new Database(path))
  }

  close(): void { this.database.close() }

  // ------------------------------------------------------------------ groups

  /** Take on the DS role for a group. Idempotent for the same creator. */
  createGroup(groupId: string, identityId: string, creatorKid: string, roster: string[]): { roster: string[] } {
    const existing = this.loadGroup(groupId)
    if (existing) {
      if (!existing.roster.has(creatorKid)) throw new MlsDsCapacityError(`group ${groupId} already exists and ${creatorKid} is not in it`)
      return { roster: [...existing.roster] }
    }
    if (this.groupCount() >= MAX_GROUPS) throw new MlsDsCapacityError('mediator is at capacity for MLS groups')
    if (roster.length > MAX_ROSTER) throw new MlsDsCapacityError(`roster of ${roster.length} exceeds the maximum of ${MAX_ROSTER}`)
    const rosterSet = new Set([creatorKid, ...roster])
    this.insertGroup({
      groupId, identityId, roster: rosterSet, everMembers: new Set(rosterSet),
      epoch: 0n, nextSeq: 1, pendingRemovals: [],
    })
    return { roster: [...rosterSet] }
  }

  /** Every group kid `deviceKid` has ever been a member of. */
  groupsFor(deviceKid: string, limit = 256): Array<{ groupId: string; epoch: bigint }> {
    const rows = this.database.query<GroupRow, []>('SELECT * FROM mls_groups').all()
    const found: Array<{ groupId: string; epoch: bigint }> = []
    for (const row of rows) {
      if (!parseStringArray(row.ever_members_json).includes(deviceKid)) continue
      found.push({ groupId: row.group_id, epoch: BigInt(row.epoch) })
      if (found.length >= limit) break
    }
    return found
  }

  roster(groupId: string): string[] { return [...(this.loadGroup(groupId)?.roster ?? [])] }

  /** Admit (or refuse) a commit — the one place the DS is authoritative. */
  submitCommit(groupId: string, sender: string, epoch: string, commit: Uint8Array, roster: string[], welcome?: Uint8Array, welcomeTo?: string[], groupInfo?: Uint8Array): MlsCommitResult {
    const group = this.loadGroup(groupId)
    if (!group) return { ok: false, reason: 'no-such-group', epoch: '0' }
    if (!group.roster.has(sender)) return { ok: false, reason: 'not-a-member', epoch: group.epoch.toString() }
    if (BigInt(epoch) !== group.epoch) return { ok: false, reason: 'epoch-conflict', epoch: group.epoch.toString() }
    if (roster.length > MAX_ROSTER) return { ok: false, reason: 'not-a-member', epoch: group.epoch.toString() }

    return this.database.transaction((): MlsCommitAccepted => {
      const entries: MlsLogEntry[] = []
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

  /**
   * The GroupInfo a member may use to add its own device, plus outstanding
   * self-removals. Gated on `identityId`, not device membership — a device
   * asking for this specific group's GroupInfo, in order to join it via
   * external commit, is BY DEFINITION not yet a member (that is the whole
   * point of external join). The only thing worth checking here is that the
   * requester belongs to the identity this self-group actually is.
   */
  groupInfoFor(groupId: string, identityId: string): MlsGroupInfoAnswer | undefined {
    const group = this.loadGroup(groupId)
    if (!group || group.identityId !== identityId) return undefined
    return { ...(group.groupInfo ? { groupInfo: group.groupInfo } : {}), pendingRemovals: [...group.pendingRemovals] }
  }

  /** Record a device's declaration that it is removing itself. */
  submitSelfRemove(groupId: string, sender: string, epoch: string, proposal: Uint8Array, kid: string): MlsCommitResult {
    const group = this.loadGroup(groupId)
    if (!group) return { ok: false, reason: 'no-such-group', epoch: '0' }
    if (!group.everMembers.has(sender)) return { ok: false, reason: 'not-a-member', epoch: group.epoch.toString() }
    return this.database.transaction((): MlsCommitAccepted => {
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
   * existing member adding it. Gated on `identityId` matching this
   * self-group, the same reasoning as `groupInfoFor` — the whole purpose of
   * external join is to let a device that is not yet in `roster` become a
   * member, so `roster.has(senderKid)` cannot be the gate here. Safety comes
   * from the signature (the caller verified `senderKid` really is a device
   * of `identityId` before calling this) plus MLS itself (the joiner's
   * credential still has to name a DID the group's Authentication Service
   * accepts) — never from a stranger being able to name someone else's
   * `identityId` and a self-generated `senderKid`, which buys them nothing:
   * MLS validation of the actual commit rejects a credential that does not
   * belong to this self-group's DID.
   */
  submitExternalCommit(groupId: string, identityId: string, senderKid: string, epoch: string, commit: Uint8Array, groupInfo?: Uint8Array): MlsCommitResult {
    const group = this.loadGroup(groupId)
    if (!group) return { ok: false, reason: 'no-such-group', epoch: '0' }
    if (group.identityId !== identityId) return { ok: false, reason: 'not-a-member', epoch: group.epoch.toString() }
    if (group.groupInfo === undefined) return { ok: false, reason: 'no-group-info', epoch: group.epoch.toString() }
    if (BigInt(epoch) !== group.epoch) return { ok: false, reason: 'epoch-conflict', epoch: group.epoch.toString() }
    return this.database.transaction((): MlsCommitAccepted => {
      const entry = this.append(group, 'commit', commit, epoch)
      group.epoch = group.epoch + 1n
      group.lastCommitter = senderKid
      group.groupInfo = groupInfo
      // The joining device becomes a member as of exactly this commit.
      group.roster.add(senderKid)
      group.everMembers.add(senderKid)
      this.saveGroup(group)
      return { ok: true, entries: [entry], roster: [...group.roster] }
    })()
  }

  /** Deliveries after `afterSeq`. Empty when the gap is older than the retained log. */
  since(groupId: string, afterSeq: number): MlsLogEntry[] {
    return this.database.query<{ seq: number; kind: MlsLogEntry['kind']; payload: Uint8Array; epoch: string; at: string }, [string, number]>(
      'SELECT seq, kind, payload, epoch, at FROM mls_log WHERE group_id = ? AND seq > ? ORDER BY seq',
    ).all(groupId, afterSeq).map(row => ({ seq: row.seq, kind: row.kind, payload: new Uint8Array(row.payload), epoch: row.epoch, at: row.at }))
  }

  /** The authorised form: gated on ever-membership, bounded per pull. Undefined means "not yours". */
  deliveriesSince(groupId: string, requester: string, afterSeq: number, limit = MAX_DELIVERIES_PER_PULL): MlsLogEntry[] | undefined {
    const group = this.loadGroup(groupId)
    if (!group || !group.everMembers.has(requester)) return undefined
    return this.since(groupId, afterSeq).slice(0, limit)
  }

  private append(group: Group, kind: MlsLogEntry['kind'], payload: Uint8Array, epoch: string): MlsLogEntry {
    const entry: MlsLogEntry = { seq: group.nextSeq++, kind, payload, epoch, at: new Date().toISOString() }
    this.database.query('INSERT INTO mls_log (group_id, seq, kind, payload, epoch, at) VALUES (?, ?, ?, ?, ?, ?)')
      .run(group.groupId, entry.seq, entry.kind, entry.payload, entry.epoch, entry.at)
    this.database.query('DELETE FROM mls_log WHERE group_id = ? AND seq <= (SELECT max(seq) FROM mls_log WHERE group_id = ?) - ?')
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
    return this.database.query<{ count: number }, []>('SELECT count(*) AS count FROM mls_groups').get()!.count
  }

  private loadGroup(groupId: string): Group | undefined {
    const row = this.database.query<GroupRow, [string]>('SELECT * FROM mls_groups WHERE group_id = ?').get(groupId) ?? undefined
    if (!row) return undefined
    return {
      groupId: row.group_id,
      identityId: row.identity_id,
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
    this.database.query(`INSERT INTO mls_groups
      (group_id, identity_id, roster_json, ever_members_json, epoch, next_seq, group_info, pending_removals_json, last_committer, created_at)
      VALUES (?, ?, ?, ?, ?, ?, NULL, ?, NULL, ?)`)
      .run(group.groupId, group.identityId, JSON.stringify([...group.roster]), JSON.stringify([...group.everMembers]), group.epoch.toString(), group.nextSeq, JSON.stringify(group.pendingRemovals), new Date().toISOString())
  }

  private saveGroup(group: Group): void {
    this.database.query(`UPDATE mls_groups SET
      roster_json = ?, ever_members_json = ?, epoch = ?, next_seq = ?, group_info = ?, pending_removals_json = ?, last_committer = ?
      WHERE group_id = ?`)
      .run(JSON.stringify([...group.roster]), JSON.stringify([...group.everMembers]), group.epoch.toString(), group.nextSeq, group.groupInfo ?? null, JSON.stringify(group.pendingRemovals), group.lastCommitter ?? null, group.groupId)
  }

  // ------------------------------------------------------------ key packages

  /** Add to a device's published key packages (single-use; the DS deletes each as it hands it out). */
  publishKeyPackages(kid: string, identityId: string, packages: Uint8Array[]): number {
    const existing = this.database.query<{ count: number }, [string]>('SELECT count(*) AS count FROM mls_key_packages WHERE kid = ?').get(kid)!.count
    const room = Math.max(0, MAX_KEY_PACKAGES_PER_KID - existing)
    const toInsert = packages.slice(0, room)
    if (toInsert.length > 0) {
      const insert = this.database.query('INSERT INTO mls_key_packages (kid, identity_id, package, created_at) VALUES (?, ?, ?, ?)')
      this.database.transaction(() => { for (const kp of toInsert) insert.run(kid, identityId, kp, new Date().toISOString()) })()
    }
    return this.database.query<{ count: number }, [string]>('SELECT count(*) AS count FROM mls_key_packages WHERE kid = ?').get(kid)!.count
  }

  /** Forget a device's published key packages (deregistration). */
  dropKeyPackages(kid: string): void {
    this.database.query('DELETE FROM mls_key_packages WHERE kid = ?').run(kid)
  }

  /**
   * Take one key package per live device of `identityId`, consuming each.
   * `isLive` is resolved for every candidate kid BEFORE the transaction
   * starts — bun:sqlite's `transaction()` callback runs synchronously (SQLite
   * commits are not interleaved with awaits), so an async liveness check
   * (typically `TrustedDeviceRoster.isTrustedDevice`) cannot be called from
   * inside it.
   */
  async takeKeyPackages(identityId: string, isLive: (kid: string) => Promise<boolean>): Promise<Array<{ kid: string; keyPackage: Uint8Array }>> {
    const kids = this.database.query<{ kid: string }, [string]>('SELECT DISTINCT kid FROM mls_key_packages WHERE identity_id = ?').all(identityId)
    const liveness = new Map<string, boolean>()
    for (const { kid } of kids) liveness.set(kid, await isLive(kid))
    const taken: Array<{ kid: string; keyPackage: Uint8Array }> = []
    this.database.transaction(() => {
      for (const { kid } of kids) {
        if (!liveness.get(kid)) {
          this.database.query('DELETE FROM mls_key_packages WHERE kid = ?').run(kid)
          continue
        }
        const row = this.database.query<{ id: number; package: Uint8Array }, [string]>('SELECT id, package FROM mls_key_packages WHERE kid = ? ORDER BY id LIMIT 1').get(kid)
        if (!row) continue
        this.database.query('DELETE FROM mls_key_packages WHERE id = ?').run(row.id)
        taken.push({ kid, keyPackage: new Uint8Array(row.package) })
      }
    })()
    return taken
  }

  /** How many unused key packages a device has left. */
  keyPackageCount(kid: string): number {
    return this.database.query<{ count: number }, [string]>('SELECT count(*) AS count FROM mls_key_packages WHERE kid = ?').get(kid)!.count
  }
}

function installSchema(database: Database): void {
  database.exec(`
    CREATE TABLE IF NOT EXISTS mls_groups (
      group_id TEXT PRIMARY KEY, identity_id TEXT NOT NULL, roster_json TEXT NOT NULL, ever_members_json TEXT NOT NULL,
      epoch TEXT NOT NULL, next_seq INTEGER NOT NULL, group_info BLOB, pending_removals_json TEXT NOT NULL,
      last_committer TEXT, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS mls_log (
      group_id TEXT NOT NULL, seq INTEGER NOT NULL, kind TEXT NOT NULL, payload BLOB NOT NULL, epoch TEXT NOT NULL, at TEXT NOT NULL,
      PRIMARY KEY (group_id, seq)
    );
    CREATE TABLE IF NOT EXISTS mls_key_packages (
      id INTEGER PRIMARY KEY AUTOINCREMENT, kid TEXT NOT NULL, identity_id TEXT NOT NULL, package BLOB NOT NULL, created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS mls_key_packages_by_kid ON mls_key_packages (kid, id);
    CREATE INDEX IF NOT EXISTS mls_key_packages_by_identity ON mls_key_packages (identity_id);
  `)
}

function parseStringArray(value: string): string[] {
  let parsed: unknown
  try { parsed = JSON.parse(value) } catch { throw new TypeError('stored MLS DS field is invalid') }
  if (!Array.isArray(parsed) || parsed.some(item => typeof item !== 'string')) throw new TypeError('stored MLS DS field is invalid')
  return [...parsed]
}
