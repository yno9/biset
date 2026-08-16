// The client side of the MLS transport protocol (didcomm/mls-transport.ts):
// what a device says to a mediator acting as key package store or Delivery
// Service, and how it reads what comes back.
//
// Everything here is one authcrypt'd request/response over the channel
// `coordinate.ts` already established — no new authentication, no new endpoint.
// The MLS layer proper (mls/group.ts) never appears in a network call, and
// this module never touches group state; keeping the two apart is what lets
// the E2E test drive real MLS over a real mediator without a browser.
import { sendAndUnpack, type DidCommSender } from '../did/didcomm/message.ts'
import { DidCommProblemError } from '../did/didcomm/problems.ts'
import type { MediatorInfo } from '../did/didcomm/coordinate.ts'
import {
  KEY_PACKAGE_PUBLISH, KEY_PACKAGE_REQUEST, KEY_PACKAGE_RESPONSE,
  GROUP_CREATE, GROUP_CREATED, COMMIT, APPLICATION, DELIVER, EPOCH_CONFLICT,
  DELIVERIES_REQUEST, DELIVERIES, GROUPS_REQUEST, GROUPS,
  EXTERNAL_COMMIT, GROUP_INFO_REQUEST, GROUP_INFO, NO_GROUP_INFO, SELF_REMOVE, CLEAR_REMOVALS,
  encodeMlsField, decodeMlsField,
  type ExternalCommitBody, type GroupInfoRequestBody, type GroupInfoBody, type SelfRemoveBody, type ClearRemovalsBody,
  type ApplicationBody, type CommitBody, type DeliverBody,
  type DeliveriesRequestBody, type DeliveriesBody, type GroupsBody, type GroupCreateBody,
  type GroupCreatedBody, type KeyPackagePublishBody, type KeyPackageRequestBody,
  type KeyPackageResponseBody, type MlsObjectKind,
} from '../did/didcomm/mls-transport.ts'

/** Add key packages to this device's published pool, and learn how many it
 * has left unused. Publishing none is how a device ASKS, which is the normal
 * first step of a top-up: only the store knows the real count, because a key
 * package is consumed there and the private half stays here until a Welcome
 * arrives (mls/store.ts's topUpKeyPackages). */
export async function publishKeyPackages(store: MediatorInfo, own: DidCommSender, kid: string, packages: Uint8Array[]): Promise<number> {
  const body: KeyPackagePublishBody = { kid, key_packages: packages.map(encodeMlsField) }
  const reply = await sendAndUnpack(store, own, KEY_PACKAGE_PUBLISH, body)
  if (reply.type !== KEY_PACKAGE_RESPONSE) throw new Error(`publishKeyPackages: unexpected reply type ${reply.type}`)
  return (reply.body as KeyPackageResponseBody | undefined)?.remaining ?? 0
}

/** One key package per device of `did`, consumed from the store. Empty when
 * that identity has published none — the caller cannot add them to a group
 * yet, which is a real answer, not an error. */
export async function fetchKeyPackages(store: MediatorInfo, own: DidCommSender, did: string): Promise<Array<{ kid: string; keyPackage: Uint8Array }>> {
  const body: KeyPackageRequestBody = { did }
  const reply = await sendAndUnpack(store, own, KEY_PACKAGE_REQUEST, body)
  if (reply.type !== KEY_PACKAGE_RESPONSE) throw new Error(`fetchKeyPackages: unexpected reply type ${reply.type}`)
  const packages = (reply.body as KeyPackageResponseBody | undefined)?.packages ?? []
  return packages.map(p => ({ kid: p.kid, keyPackage: decodeMlsField(p.key_package, 'key_package') }))
}

/** Ask a mediator to be this group's DS. Returns the DID it will act as —
 * which the client stores with the group, since every later submission for
 * that group has to go to the same one (PLANMLS.md §2: one DS per group). */
export async function createGroupOnDs(ds: MediatorInfo, own: DidCommSender, groupId: string, roster: string[]): Promise<string> {
  const body: GroupCreateBody = { group_id: groupId, roster }
  const reply = await sendAndUnpack(ds, own, GROUP_CREATE, body)
  if (reply.type !== GROUP_CREATED) throw new Error(`createGroupOnDs: unexpected reply type ${reply.type}`)
  const dsDid = (reply.body as GroupCreatedBody | undefined)?.ds_did
  if (!dsDid) throw new Error('createGroupOnDs: group-created without ds_did')
  return dsDid
}

/** Someone else's commit won this epoch. Not a failure: the winning commit is
 * already on its way here, and the remedy is to apply it and commit again —
 * which is why this is a predicate rather than an error to surface. */
export function isEpochConflict(err: unknown): err is DidCommProblemError {
  return err instanceof DidCommProblemError && err.code === EPOCH_CONFLICT
}

/** The epoch the DS says the group is actually at, from a conflict report. */
export function conflictEpoch(err: DidCommProblemError): bigint | undefined {
  const raw = err.args[0]
  return raw === undefined ? undefined : BigInt(raw)
}

export interface CommitSubmission {
  groupId: string
  /** The epoch committed FROM — MLS's `epochOf(state)` before the commit. */
  epoch: bigint
  commit: Uint8Array
  welcome?: Uint8Array
  /** DIDs the Welcome is for. */
  welcomeTo?: string[]
  /** Member DIDs after this commit. */
  roster: string[]
  /** GroupInfo for the resulting epoch, so this identity's future devices can
   * join externally. Omitting it doesn't break the group — it only leaves it
   * unjoinable by a new device until someone commits again with one. */
  groupInfo?: Uint8Array
}

/** Submit a commit for ordering. Throws `isEpochConflict` when it lost the
 * race, and an ordinary error for anything else. */
export async function submitCommit(ds: MediatorInfo, own: DidCommSender, submission: CommitSubmission): Promise<void> {
  const body: CommitBody = {
    group_id: submission.groupId,
    epoch: submission.epoch.toString(),
    commit: encodeMlsField(submission.commit),
    roster: submission.roster,
    ...(submission.welcome ? { welcome: encodeMlsField(submission.welcome) } : {}),
    ...(submission.welcomeTo ? { welcome_to: submission.welcomeTo } : {}),
    ...(submission.groupInfo ? { group_info: encodeMlsField(submission.groupInfo) } : {}),
  }
  const reply = await sendAndUnpack(ds, own, COMMIT, body)
  if (reply.type !== DELIVER) throw new Error(`submitCommit: unexpected reply type ${reply.type}`)
}

/** No GroupInfo has been published for this group's current epoch, so there is
 * nothing to build an external commit against. Unlike an epoch conflict this
 * is not fixed by retrying: some member has to commit (with a GroupInfo) first. */
export function isNoGroupInfo(err: unknown): err is DidCommProblemError {
  return err instanceof DidCommProblemError && err.code === NO_GROUP_INFO
}

/** Fetch the GroupInfo an external join commits against. Undefined when none
 * has been published — or when we are not in the roster, which the DS
 * deliberately does not distinguish. */
export async function fetchGroupInfo(ds: MediatorInfo, own: DidCommSender, groupId: string): Promise<{ groupInfo?: Uint8Array; pendingRemovals: string[] }> {
  const body: GroupInfoRequestBody = { group_id: groupId }
  const reply = await sendAndUnpack(ds, own, GROUP_INFO_REQUEST, body)
  if (reply.type !== GROUP_INFO) throw new Error(`fetchGroupInfo: unexpected reply type ${reply.type}`)
  const answer = reply.body as GroupInfoBody | undefined
  return {
    ...(answer?.group_info ? { groupInfo: decodeMlsField(answer.group_info, 'group_info') } : {}),
    pendingRemovals: answer?.pending_removals ?? [],
  }
}

/** Submit an external commit — this device adding ITSELF to a group its
 * identity is already a member of (a new or restored device of our own). */
export async function submitExternalCommit(ds: MediatorInfo, own: DidCommSender, groupId: string, epoch: bigint, commit: Uint8Array, groupInfo?: Uint8Array): Promise<void> {
  const body: ExternalCommitBody = {
    group_id: groupId, epoch: epoch.toString(), commit: encodeMlsField(commit),
    ...(groupInfo ? { group_info: encodeMlsField(groupInfo) } : {}),
  }
  const reply = await sendAndUnpack(ds, own, EXTERNAL_COMMIT, body)
  if (reply.type !== DELIVER) throw new Error(`submitExternalCommit: unexpected reply type ${reply.type}`)
}

/** Tell the DS a declared departure has been carried out, so it stops handing
 * it to future joiners. Best-effort: a DS that still lists it only makes the
 * next member check a leaf that is already gone. */
export async function clearPendingRemovals(ds: MediatorInfo, own: DidCommSender, groupId: string, kids: string[]): Promise<void> {
  const body: ClearRemovalsBody = { group_id: groupId, kids }
  const reply = await sendAndUnpack(ds, own, CLEAR_REMOVALS, body)
  if (reply.type !== GROUP_INFO) throw new Error(`clearPendingRemovals: unexpected reply type ${reply.type}`)
}

/** Declare this device's own removal. The proposal rides to the DS, which
 * fans it out for a sibling to commit and remembers the declaration for
 * whoever joins next. */
export async function submitSelfRemove(ds: MediatorInfo, own: DidCommSender, groupId: string, epoch: bigint, proposal: Uint8Array, kid: string): Promise<void> {
  const body: SelfRemoveBody = { group_id: groupId, epoch: epoch.toString(), proposal: encodeMlsField(proposal), kid }
  const reply = await sendAndUnpack(ds, own, SELF_REMOVE, body)
  if (reply.type !== DELIVER) throw new Error(`submitSelfRemove: unexpected reply type ${reply.type}`)
}

/** Submit an application message for fan-out. */
export async function submitApplication(ds: MediatorInfo, own: DidCommSender, groupId: string, message: Uint8Array): Promise<void> {
  const body: ApplicationBody = { group_id: groupId, message: encodeMlsField(message) }
  const reply = await sendAndUnpack(ds, own, APPLICATION, body)
  if (reply.type !== DELIVER) throw new Error(`submitApplication: unexpected reply type ${reply.type}`)
}

/** A delivery as the receiving client wants it: the MLS bytes, plus the
 * ordering it arrived with. */
export interface Delivery { groupId: string; seq: number; kind: MlsObjectKind; payload: Uint8Array; epoch?: bigint }

/** Ask a DS which of its groups this device's identity is in.
 *
 * The recovery path for a lost Welcome: joining is pushed exactly once, so a
 * device that could not use the Welcome it was sent has no way to notice that
 * it is a member of a group it has never seen. Everyone else already thinks
 * it is one. */
export async function fetchGroups(ds: MediatorInfo, own: DidCommSender): Promise<Array<{ groupId: string; epoch: bigint }>> {
  const reply = await sendAndUnpack(ds, own, GROUPS_REQUEST, {})
  if (reply.type !== GROUPS) throw new Error(`fetchGroups: unexpected reply type ${reply.type}`)
  return ((reply.body as GroupsBody | undefined)?.groups ?? []).map(g => ({ groupId: g.group_id, epoch: BigInt(g.epoch) }))
}

/** Ask the DS for everything this device is missing in a group, after the last
 * seq it managed to APPLY.
 *
 * The pull half of delivery, and the reason it exists is that the push half
 * cannot be verified. The DS fans out to the roster the last committer
 * declared, and it has no way to check that declaration — the commit is
 * encrypted. So a member could shrink the roster and quietly cut someone out.
 * Pulling makes that a nuisance instead of an attack: what a device is owed is
 * defined by the group's own gapless sequence, not by whether anyone chose to
 * send it. It repairs an ordinary lost delivery by exactly the same mechanism.
 *
 * Empty means nothing is outstanding — or that the gap has aged out of the
 * DS's log, which is indistinguishable here and equally means "there is
 * nothing to fetch". */
export async function fetchDeliveries(ds: MediatorInfo, own: DidCommSender, groupId: string, afterSeq: number): Promise<Delivery[]> {
  const body: DeliveriesRequestBody = { group_id: groupId, after_seq: afterSeq }
  const reply = await sendAndUnpack(ds, own, DELIVERIES_REQUEST, body)
  if (reply.type !== DELIVERIES) throw new Error(`fetchDeliveries: unexpected reply type ${reply.type}`)
  const list = (reply.body as DeliveriesBody | undefined)?.deliveries ?? []
  return list.map(readDelivery).sort((a, b) => a.seq - b.seq)
}

/** Read a `deliver` message's body. Throws on a malformed one rather than
 * returning a partial delivery — an MLS object with the wrong `kind` would be
 * handed to the wrong entry point and fail obscurely deep inside ts-mls. */
export function readDelivery(body: unknown): Delivery {
  const b = body as DeliverBody | undefined
  if (typeof b?.group_id !== 'string' || typeof b.seq !== 'number') throw new Error('readDelivery: deliver body needs `group_id` and `seq`')
  if (b.kind !== 'commit' && b.kind !== 'welcome' && b.kind !== 'application' && b.kind !== 'proposal') {
    throw new Error(`readDelivery: unknown delivery kind ${String(b.kind)}`)
  }
  return {
    groupId: b.group_id,
    seq: b.seq,
    kind: b.kind,
    payload: decodeMlsField(b.payload, 'payload'),
    ...(b.epoch === undefined ? {} : { epoch: BigInt(b.epoch) }),
  }
}
