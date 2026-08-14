// The mediator's two MLS roles: **Delivery Service** (ordering authority for a
// group) and **key package store** (a place to leave key packages for an
// offline device). PLANMLS.md §2 and Phase 1.
//
// The DS is deliberately dumb. It never parses an MLS object, holds no group
// key and cannot read a message. Its whole job is:
//
//   1. **Admit one commit per epoch.** Two members who commit from epoch 5 both
//      produce a valid epoch-6 commit, but only one may become the group's
//      history or members diverge irrecoverably. First arrival wins; the loser
//      is told so and retries from the new epoch (MLS's own remedy). That
//      single decision is what "server fanout" buys, and it is the entirety of
//      the centralization this design accepts.
//   2. **Number what it accepts**, per group, from 1 and gapless, so a client
//      can tell "I am missing one" from "this is next".
//   3. **Fan out** to every member's home mediator.
//
// Fan-out itself (packing a copy per recipient, Forwarding each) is
// server.ts's job — it owns the crypto and the routing. This module owns the
// state and the decisions.
//
// Persisted for the same reason connections.ts is: a restart that forgot which
// mediator was a group's DS, or reset a group's sequence numbers, would break
// every group on the anchor at once, and nothing in MLS lets a client repair
// that on its own.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'

/** Bounds, not rationing — a mediator that will act as DS for anyone needs a
 * ceiling, and these sit far above any real group. */
const MAX_GROUPS = 10_000
const MAX_ROSTER = 512
const MAX_KEY_PACKAGES_PER_KID = 32
/** How far back the delivery log goes, per group. It exists so a client that
 * missed a delivery can ask for a resend; it is not the group's history (MLS
 * has no such thing on the server) and the ciphertext in it is unreadable to
 * the mediator. */
const MAX_LOG_PER_GROUP = 256
/** How many past members a group remembers as allowed to pull. Well above any
 * real group's churn; see DsGroup.everMembers. */
const MAX_EVER_MEMBERS = 2048
/** How many log entries one pull returns. A client that is further behind
 * asks again from the seq it reached — bounded work per envelope, and the
 * envelope has to fit in one authcrypt'd reply. */
const MAX_DELIVERIES_PER_PULL = 32

export class DsFullError extends Error {}

/** One delivered object, as the DS holds it: opaque payload plus the ordering
 * it was given. */
export interface DsLogEntry {
  seq: number
  kind: 'commit' | 'welcome' | 'application' | 'proposal'
  /** base64url MLS bytes, exactly as submitted. */
  payload: string
  epoch?: string
  at: number
}

interface DsGroup {
  groupId: string
  /** Who may submit — the roster, as the last accepted commit declared it.
   * IDENTITIES, not devices: an identity's devices are separate MLS leaves but
   * one entry here, which is what makes "a new device of an existing member"
   * expressible as a rule (see submitExternalCommit). */
  roster: Set<string>
  /** Everyone who has EVER been in the roster, and the reason this is separate
   * from it.
   *
   * The DS cannot verify the roster. A commit is a PrivateMessage, so the
   * Add/Remove inside it is unreadable here — by design; a DS that could read
   * membership changes could read the group. So the roster is whatever the
   * committer SAID it is, and a malicious member could shrink it to cut
   * someone out of fan-out. MLS would keep protecting that victim's content,
   * and say nothing about their delivery.
   *
   * So the roster decides where copies are PUSHED, and this decides who may
   * PULL. Once in, a DID may always ask the DS for the deliveries it is
   * missing, whatever a later roster claims — a censored member catches up on
   * its own, and a genuinely removed one only ever retrieves ciphertext its
   * epoch's keys cannot open.
   *
   * The cost, stated plainly: a removed member can keep observing that a group
   * is active, and the size and timing of its traffic. That is the same class
   * of metadata the DS itself holds (mls-transport.ts's boundary note), and a
   * smaller price than a member being able to silently cut another member off. */
  everMembers: Set<string>
  /** The epoch the group is in. A commit is admitted only if it names this
   * epoch; accepting it advances the counter. */
  epoch: bigint
  nextSeq: number
  log: DsLogEntry[]
  /** base64url GroupInfo (with external_pub + ratchet tree), as published by
   * whoever last committed. This is what a NEW DEVICE of an existing member
   * needs to commit itself in without any of that member's other devices
   * being online. Unreadable to the DS like everything else it holds; it
   * discloses the roster and tree shape, which the DS already knows.
   *
   * Absent until the first member publishes one — an external join then
   * simply isn't possible yet, which is honest rather than a failure. */
  groupInfo?: string
  /** Device kids that have declared their own removal and are still in the
   * group. MLS forbids a commit that removes its own committer, so a device
   * leaving can only PROPOSE it and needs someone else to commit — and if it
   * was the last device, there is nobody. The declaration outlives the
   * proposal's epoch here so that whoever joins next can act on it, which is
   * the only path by which a sole device's departure ever takes effect.
   *
   * The DS does not act on these itself and could not: it holds no group key
   * and cannot commit anything. It remembers, and hands the list to members. */
  pendingRemovals: string[]
  createdAt: number
}

interface StoredGroup {
  groupId: string
  roster: string[]
  everMembers?: string[]
  epoch: string
  nextSeq: number
  log: DsLogEntry[]
  groupInfo?: string
  pendingRemovals?: string[]
  createdAt: number
}

interface StoredKeyPackages { kid: string; did: string; packages: string[] }

export interface CommitAccepted { ok: true; entries: DsLogEntry[]; roster: string[] }
export interface CommitRejected { ok: false; reason: 'epoch-conflict' | 'not-a-member' | 'no-such-group' | 'no-group-info'; epoch: string }

export class MlsDeliveryService {
  private groups = new Map<string, DsGroup>()
  /** kid → its unused key packages (base64url wire). Kept per DEVICE, since
   * that is what a key package belongs to, and looked up per identity. */
  private keyPackages = new Map<string, { did: string; packages: string[] }>()
  private persistPath?: string

  /** `persistPath` behaves as in connections.ts: loaded once, rewritten after
   * every mutation, and a missing or corrupt file starts empty. */
  constructor(persistPath?: string) {
    this.persistPath = persistPath
    if (!persistPath || !existsSync(persistPath)) return
    try {
      const stored: { groups: StoredGroup[]; keyPackages: StoredKeyPackages[] } = JSON.parse(readFileSync(persistPath, 'utf-8'))
      for (const g of stored.groups ?? []) {
        this.groups.set(g.groupId, {
          ...g,
          roster: new Set(g.roster),
          // A group stored before pull existed has no record of who has left,
          // so its current roster is the most that can honestly be claimed.
          everMembers: new Set(g.everMembers ?? g.roster),
          epoch: BigInt(g.epoch),
          pendingRemovals: g.pendingRemovals ?? [],
        })
      }
      for (const k of stored.keyPackages ?? []) this.keyPackages.set(k.kid, { did: k.did, packages: k.packages })
    } catch {
      this.groups.clear()
      this.keyPackages.clear()
    }
  }

  private persist(): void {
    if (!this.persistPath) return
    const data = {
      // The epoch is a bigint (MLS counts to 2^64) and JSON.stringify throws on
      // one — it goes to disk as a decimal string and comes back through
      // BigInt() above.
      groups: [...this.groups.values()].map(g => ({ ...g, roster: [...g.roster], everMembers: [...g.everMembers], epoch: g.epoch.toString() })),
      keyPackages: [...this.keyPackages.entries()].map(([kid, v]) => ({ kid, did: v.did, packages: v.packages })),
    }
    try {
      mkdirSync(dirname(this.persistPath), { recursive: true })
      writeFileSync(this.persistPath, JSON.stringify(data))
    } catch (e) {
      console.error('[mediator] could not persist MLS DS state:', e)
    }
  }

  // ------------------------------------------------------------------ groups

  /** Take on the DS role for a group. Idempotent for the same creator — a
   * client that resends `group-create` (a lost response, a retry) must get the
   * same answer, not a conflict. */
  createGroup(groupId: string, creator: string, roster: string[]): DsGroup {
    const existing = this.groups.get(groupId)
    if (existing) {
      if (!existing.roster.has(creator)) throw new DsFullError(`group ${groupId} already exists and ${creator} is not in it`)
      return existing
    }
    if (this.groups.size >= MAX_GROUPS) throw new DsFullError('mediator is at capacity for MLS groups')
    if (roster.length > MAX_ROSTER) throw new DsFullError(`roster of ${roster.length} exceeds the maximum of ${MAX_ROSTER}`)
    const group: DsGroup = {
      groupId,
      roster: new Set([creator, ...roster]),
      everMembers: new Set([creator, ...roster]),
      epoch: 0n,
      nextSeq: 1,
      log: [],
      pendingRemovals: [],
      createdAt: Date.now(),
    }
    this.groups.set(groupId, group)
    this.persist()
    return group
  }

  group(groupId: string): DsGroup | undefined { return this.groups.get(groupId) }

  /** Everyone a delivery for this group goes to. */
  roster(groupId: string): string[] { return [...(this.groups.get(groupId)?.roster ?? [])] }

  /** Admit (or refuse) a commit. This is the ordering decision, and the only
   * place the DS is authoritative over anything.
   *
   * `epoch` is what the SENDER committed from. It must equal the group's
   * current epoch: if it is behind, someone else's commit got here first and
   * this one is refused (the sender applies the winner and retries); if it is
   * ahead, the sender is working from state this DS never issued, which is the
   * same refusal for the same reason.
   *
   * The Welcome rides along in the same accepted batch rather than as a
   * separate submission, so a joiner can never be welcomed into a commit that
   * lost its epoch. */
  submitCommit(groupId: string, sender: string, epoch: string, commit: string, roster: string[], welcome?: string, welcomeTo?: string[], groupInfo?: string): CommitAccepted | CommitRejected {
    const group = this.groups.get(groupId)
    if (!group) return { ok: false, reason: 'no-such-group', epoch: '0' }
    if (!group.roster.has(sender)) return { ok: false, reason: 'not-a-member', epoch: group.epoch.toString() }
    if (BigInt(epoch) !== group.epoch) return { ok: false, reason: 'epoch-conflict', epoch: group.epoch.toString() }
    if (roster.length > MAX_ROSTER) return { ok: false, reason: 'not-a-member', epoch: group.epoch.toString() }

    const entries: DsLogEntry[] = []
    // The Welcome is numbered first: a joiner must be able to build its state
    // before anything that follows in that state reaches it.
    if (welcome) entries.push(this.append(group, 'welcome', welcome, epoch))
    entries.push(this.append(group, 'commit', commit, epoch))
    group.epoch = group.epoch + 1n
    // The roster the commit results in — including anyone the Welcome is for,
    // who by definition isn't in the old roster.
    group.roster = new Set([...roster, ...(welcomeTo ?? [])])
    for (const did of group.roster) group.everMembers.add(did)
    this.trimEverMembers(group)
    // Kept only when it belongs to the epoch just reached — a GroupInfo from
    // an older epoch is worse than none, since an external joiner would
    // commit against it and be refused for a conflict it can't diagnose.
    if (groupInfo) group.groupInfo = groupInfo
    else delete group.groupInfo
    this.persist()
    return { ok: true, entries, roster: [...group.roster] }
  }

  /** The GroupInfo a member may use to add one of its OWN devices, plus any
   * self-removals still outstanding, or undefined when the requester is not in
   * the roster. */
  groupInfoFor(groupId: string, requester: string): { groupInfo?: string; pendingRemovals: string[] } | undefined {
    const group = this.groups.get(groupId)
    // Answered for anyone who has ever been in the roster, not only who is in
    // it now: this is how a member cut out of a shrunken roster still sees the
    // group's shape, and how a device removed while offline learns that it was
    // (self-group.ts's stillInGroupAccordingToDs asks exactly this). The
    // GroupInfo discloses the tree, which every member already has.
    if (!group || !group.everMembers.has(requester)) return undefined
    return { ...(group.groupInfo ? { groupInfo: group.groupInfo } : {}), pendingRemovals: [...group.pendingRemovals] }
  }

  /** Record a device's declaration that it is removing itself, and log the
   * proposal so live members can commit it in this epoch.
   *
   * Nothing here is ordered: a proposal does not advance the epoch, and two
   * of them do not conflict. The DS's only decisions are the same two it makes
   * everywhere else — is the sender in the roster, and does this group exist. */
  submitSelfRemove(groupId: string, sender: string, epoch: string, proposal: string, kid: string): CommitAccepted | CommitRejected {
    const group = this.groups.get(groupId)
    if (!group) return { ok: false, reason: 'no-such-group', epoch: '0' }
    if (!group.roster.has(sender)) return { ok: false, reason: 'not-a-member', epoch: group.epoch.toString() }
    if (!group.pendingRemovals.includes(kid)) group.pendingRemovals.push(kid)
    const entry = this.append(group, 'proposal', proposal, epoch)
    this.persist()
    return { ok: true, entries: [entry], roster: [...group.roster] }
  }

  /** Forget declarations that have been carried out. Called by the member that
   * committed the removal — the DS cannot tell on its own, since it never sees
   * the tree. */
  clearPendingRemovals(groupId: string, requester: string, kids: string[]): void {
    const group = this.groups.get(groupId)
    if (!group || !group.roster.has(requester)) return
    group.pendingRemovals = group.pendingRemovals.filter(k => !kids.includes(k))
    this.persist()
  }

  /** Admit an EXTERNAL commit — a device committing itself into the group
   * without being added by an existing member.
   *
   * The rule that makes this safe is one line: the submitter's DID must
   * ALREADY be in the roster. The submitter is authenticated by the authcrypt
   * envelope this request arrived in, so being able to do this is exactly
   * being able to prove control of a device key already listed in that
   * identity's DID document — i.e. it lets an identity add its own new device,
   * and lets nobody add themselves to a group they were not in.
   *
   * The roster is therefore UNCHANGED by an external commit: it names
   * identities, and this adds a device to one that is already there. */
  submitExternalCommit(groupId: string, sender: string, epoch: string, commit: string, groupInfo?: string): CommitAccepted | CommitRejected {
    const group = this.groups.get(groupId)
    if (!group) return { ok: false, reason: 'no-such-group', epoch: '0' }
    if (!group.roster.has(sender)) return { ok: false, reason: 'not-a-member', epoch: group.epoch.toString() }
    if (group.groupInfo === undefined) return { ok: false, reason: 'no-group-info', epoch: group.epoch.toString() }
    if (BigInt(epoch) !== group.epoch) return { ok: false, reason: 'epoch-conflict', epoch: group.epoch.toString() }
    const entry = this.append(group, 'commit', commit, epoch)
    group.epoch = group.epoch + 1n
    // The stored GroupInfo described the epoch this commit just left, so it is
    // replaced by the joiner's own (describing the epoch just reached) or
    // dropped. Dropping leaves the group unjoinable until someone commits
    // again — correct, but a poor default, which is why the joiner is expected
    // to attach one.
    if (groupInfo) group.groupInfo = groupInfo
    else delete group.groupInfo
    this.persist()
    return { ok: true, entries: [entry], roster: [...group.roster] }
  }

  /** Number and log an application message. No epoch check: application
   * messages don't advance the group, and MLS itself rejects one from an epoch
   * the receiver has left. */
  submitApplication(groupId: string, sender: string, message: string): CommitAccepted | CommitRejected {
    const group = this.groups.get(groupId)
    if (!group) return { ok: false, reason: 'no-such-group', epoch: '0' }
    if (!group.roster.has(sender)) return { ok: false, reason: 'not-a-member', epoch: group.epoch.toString() }
    const entry = this.append(group, 'application', message, group.epoch.toString())
    this.persist()
    return { ok: true, entries: [entry], roster: [...group.roster] }
  }

  private append(group: DsGroup, kind: DsLogEntry['kind'], payload: string, epoch: string): DsLogEntry {
    const entry: DsLogEntry = { seq: group.nextSeq++, kind, payload, epoch, at: Date.now() }
    group.log.push(entry)
    if (group.log.length > MAX_LOG_PER_GROUP) group.log.splice(0, group.log.length - MAX_LOG_PER_GROUP)
    return entry
  }

  /** Deliveries after `afterSeq`, for a client catching up on a gap. Empty when
   * the gap is older than the log — the client then has to be re-added to the
   * group, which is the honest answer: the DS has no way to reconstruct MLS
   * state it never held. */
  since(groupId: string, afterSeq: number): DsLogEntry[] {
    return (this.groups.get(groupId)?.log ?? []).filter(e => e.seq > afterSeq)
  }

  /** The same, for a client asking over the wire: authorized, and bounded so
   * one answer fits in one envelope.
   *
   * Undefined means "not yours" — a group that does not exist and one the
   * asker was never in are deliberately the same answer, as everywhere else
   * here.
   *
   * Authorization is `everMembers`, NOT the roster, and that is the whole
   * point: push is advisory, pull is the guarantee. A member whom someone
   * else's roster left out asks for its own missing deliveries and catches up
   * without needing anyone's cooperation. It also repairs an ordinary lost
   * fan-out, which nothing else could — the DS is the only party holding a
   * copy once the sender has moved on. */
  deliveriesSince(groupId: string, requester: string, afterSeq: number, limit = MAX_DELIVERIES_PER_PULL): DsLogEntry[] | undefined {
    const group = this.groups.get(groupId)
    if (!group || !group.everMembers.has(requester)) return undefined
    return this.since(groupId, afterSeq).slice(0, limit)
  }

  /** Keep `everMembers` from growing without bound in a long-lived group with
   * a lot of churn. Current members are never dropped; past ones go oldest
   * first, and a dropped one loses only the ability to pull ciphertext it
   * could not read anyway. */
  private trimEverMembers(group: DsGroup): void {
    if (group.everMembers.size <= MAX_EVER_MEMBERS) return
    for (const did of [...group.everMembers]) {
      if (group.everMembers.size <= MAX_EVER_MEMBERS) break
      if (!group.roster.has(did)) group.everMembers.delete(did)
    }
  }

  // ------------------------------------------------------------ key packages

  /** Replace a device's published key packages. Replace rather than append:
   * the client knows which of its key packages are still unused (it holds the
   * private halves), so its latest publish is the truth. */
  publishKeyPackages(kid: string, packages: string[]): void {
    const did = kid.includes('#') ? kid.slice(0, kid.indexOf('#')) : kid
    if (packages.length === 0) this.keyPackages.delete(kid)
    else this.keyPackages.set(kid, { did, packages: packages.slice(0, MAX_KEY_PACKAGES_PER_KID) })
    this.persist()
  }

  /** Forget a device's published key packages.
   *
   * Called when that device deregisters (server.ts's keylist-update remove),
   * which is the moment a device stops existing as far as this mediator is
   * concerned — logout and the Devices panel both go through it. Without this
   * a departed device's key packages sit in the store and get handed to the
   * next person who invites this identity, who then sends a Welcome nobody can
   * open: the invitation looks accepted and the device never appears. */
  dropKeyPackages(kid: string): void {
    if (!this.keyPackages.delete(kid)) return
    this.persist()
  }

  /** Take one key package per device of `did`, consuming each.
   *
   * Consuming is the point: an MLS key package is single-use, and handing the
   * same one to two inviters produces two groups whose Welcomes both name key
   * material the joiner can only use once. A device whose pool is empty is
   * simply omitted — inviting the rest of someone's devices now is better than
   * failing the invitation, and the missing device can be added later. */
  takeKeyPackages(did: string, isLive: (kid: string) => boolean): Array<{ kid: string; keyPackage: string }> {
    const taken: Array<{ kid: string; keyPackage: string }> = []
    let dropped = false
    for (const [kid, entry] of [...this.keyPackages]) {
      if (entry.did !== did) continue
      // A device that is no longer registered is gone; its key packages are
      // worse than useless, because handing one out produces a Welcome that
      // nobody will ever open. Dropped here as well as at deregistration,
      // which catches devices that departed before that existed — and any
      // whose deregistration never reached this mediator.
      if (!isLive(kid)) {
        this.keyPackages.delete(kid)
        dropped = true
        continue
      }
      const kp = entry.packages.shift()
      if (kp === undefined) continue
      taken.push({ kid, keyPackage: kp })
    }
    if (taken.length > 0 || dropped) this.persist()
    return taken
  }

  /** How many unused key packages a device has left — what a client checks to
   * decide whether to refill its pool. */
  keyPackageCount(kid: string): number {
    return this.keyPackages.get(kid)?.packages.length ?? 0
  }
}
