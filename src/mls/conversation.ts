// Group conversations: an MLS group whose members are OTHER PEOPLE.
//
// The sibling of self-group.ts, and deliberately built from the same parts.
// The self group proved the machinery on the easy case — every member is one
// user's own device, so the roster is one DID and nobody in it is hostile.
// A conversation changes three things and nothing else:
//
//   - the group id is RANDOM rather than derived from a DID. A conversation
//     has no natural name to derive from, and one that encoded its membership
//     would either go stale or tell anyone who saw it who is in the group.
//   - members are strangers, so a message has to be attributed to the LEAF
//     that sent it (group.ts's `sender`), never to a name inside the
//     plaintext, which any member could fill in with someone else's.
//   - the Delivery Service is whoever's mediator created the group, so it may
//     not be this identity's own — its URL is carried with the group state.
//
// Everything else — ordering, the pull cursor, catch-up, what "cannot apply
// this" means — is delivery.ts, shared with the self group so there is one
// answer to "am I missing a delivery" rather than two that drift.
import type { ClientState } from './vendor/index.ts'
import type { DidCommSender } from '../did/didcomm/message.ts'
import { fetchMediatorInfo, type MediatorInfo } from '../did/didcomm/coordinate.ts'
import { resolveDidCommDoc } from '../did/didcomm/resolve.ts'
import {
  createMlsGroup, addMembers, removeMembers, rekey, confirmCommit, encryptApplication,
  joinMlsGroup, groupInfoForExternalJoin, proposeSelfRemoval, memberList, memberDids, memberKids,
  epochOf, decodeKeyPackage, isActiveMember, generateOwnKeyPackage,
  type CommitResult, type OwnKeyPackage,
} from './group.ts'
import { loadGroup, saveGroup, deleteGroup, listGroups, withGroupLock, newGroupId, groupIdHex, takeKeyPackageForWelcome } from './store.ts'
import { receiveDelivery, catchUpGroup } from './delivery.ts'
import {
  createGroupOnDs, fetchKeyPackages, submitCommit, submitApplication, submitSelfRemove,
  isEpochConflict, fetchGroups, fetchDeliveries, type Delivery,
} from './transport.ts'
import { selfGroupIdHex } from './self-group.ts'
import type { MlsMemberId } from './identity.ts'

/** What a conversation's application messages carry. One JSON object with a
 * `t` tag, exactly like the self group's — and for the same reason it is the
 * ONLY layer that carries application metadata: everything in here is inside
 * the MLS PrivateMessage, so the Delivery Service sees a length and nothing
 * else. (PLANMLS.md §3.3 proposed a separate metadata layer encrypted under
 * the exporter secret; that is only needed when metadata rides in DIDComm
 * headers, which here it does not.) */
export type ConversationPayload =
  | { t: 'msg'; id: string; content: string; sentAt: string; subject?: string; fromName?: string; avatar?: string }
  /** The group's display name. Not part of MLS, which has no notion of one,
   * so it travels as an ordinary message any member can send — and a joiner
   * learns it from whoever last did. */
  | { t: 'name'; name: string; sentAt: string }

export interface ReceivedGroupMessage {
  groupId: string
  /** Who sent it, from the MLS leaf — the authenticated answer. */
  from: MlsMemberId
  payload: Extract<ConversationPayload, { t: 'msg' }>
}

/** A conversation as the UI wants it. Derived from group state every time
 * rather than stored: a second copy of the member list is one more thing that
 * can disagree with the group itself. */
export interface ConversationSummary {
  id: string
  name: string
  members: string[]
  epoch: bigint
  updatedAt: number
}

const encode = (payload: ConversationPayload): Uint8Array => new TextEncoder().encode(JSON.stringify(payload))

/** How a conversation is addressed in the message store: not a DID, because a
 * group is not an identity and has no keys of its own — the thread's name is
 * the group id, and the members are whatever the ratchet tree currently says. */
const GROUP_ADDRESS_PREFIX = 'mls:'

export function groupAddress(id: string): string { return `${GROUP_ADDRESS_PREFIX}${id}` }

/** The group id an address names, or undefined when it names something else
 * (an ordinary DID, an email address). */
export function groupIdOfAddress(address: string): string | undefined {
  return address.startsWith(GROUP_ADDRESS_PREFIX) ? address.slice(GROUP_ADDRESS_PREFIX.length) : undefined
}

/** One conversation as stored: its name and current membership, or undefined
 * when this device is not in it. */
export async function conversationInfo(id: string): Promise<{ name: string; members: string[] } | undefined> {
  const stored = await loadGroup(id)
  return stored ? { name: stored.name, members: memberDids(stored.state) } : undefined
}

/** Commit whatever proposals this conversation has pending — a member's
 * declared departure, in practice. An empty commit is enough: pending
 * proposals ride into the next commit whatever it is. */
export async function commitPendingProposalsIn(ds: MediatorInfo, own: DidCommSender, id: string): Promise<void> {
  await commitAndSubmit(ds, own, id, async state => ({ result: await rekey(state) }))
}

/** Every group that is a conversation — i.e. every group except this
 * identity's own device group, which is the same machinery used for something
 * that is not a conversation at all. */
export async function conversations(did: string): Promise<ConversationSummary[]> {
  const selfId = selfGroupIdHex(did)
  return (await listGroups())
    .filter(g => g.id !== selfId)
    .map(g => ({ id: g.id, name: g.name, members: memberDids(g.state), epoch: epochOf(g.state), updatedAt: g.updatedAt }))
}

/** The mediator acting as a group's Delivery Service. */
export async function conversationDs(id: string): Promise<MediatorInfo | undefined> {
  const stored = await loadGroup(id)
  if (!stored?.dsUrl) return undefined
  return fetchMediatorInfo(stored.dsUrl)
}

/** One key package per device of `did`, taken from THAT identity's own
 * mediator — the key package store role belongs to the invitee's home
 * mediator, not to ours, since that is where their devices publish.
 *
 * Empty when they have published none, or when their document names no
 * mediator. Both are the same answer to the caller: this identity cannot be
 * invited right now. */
async function fetchInviteeKeyPackages(own: DidCommSender, did: string): Promise<Array<{ kid: string; keyPackage: Uint8Array }>> {
  const doc = await resolveDidCommDoc(did).catch(() => null)
  const uri = doc?.service?.find(s => s.type === 'DIDCommMessaging')?.serviceEndpoint?.uri
  if (!uri) return []
  const store = await fetchMediatorInfo(uri)
  return fetchKeyPackages(store, own, did).catch(() => [])
}

/** Build a commit, submit it for ordering, and keep the result only if it won
 * its epoch.
 *
 * The retry is MLS's own remedy and not an error path: two members committing
 * from the same epoch both produce a valid commit, one is admitted, and the
 * loser applies the winner and tries again. What must never happen is keeping
 * the losing state — hence `confirmCommit` (which zeroes the keys the commit
 * consumed) runs only after the DS has accepted it.
 *
 * The group lock is held across build→submit→save so a delivery arriving
 * mid-flight cannot be overwritten by a state derived from before it, and
 * RELEASED before catching up, because catching up takes the same lock. */
async function commitAndSubmit(
  ds: MediatorInfo, own: DidCommSender, id: string,
  build: (state: ClientState) => Promise<{ result: CommitResult; welcomeTo?: string[] }>,
): Promise<void> {
  for (let attempt = 0; attempt < 3; attempt++) {
    const won = await withGroupLock(id, async () => {
      const stored = await loadGroup(id)
      if (!stored) throw new Error(`commitAndSubmit: no such group ${id}`)
      const { result, welcomeTo } = await build(stored.state)
      const roster = [...new Set([...memberDids(result.state), ...(welcomeTo ?? [])])]
      try {
        await submitCommit(ds, own, {
          groupId: id,
          epoch: epochOf(stored.state),
          commit: result.commit,
          roster,
          ...(result.welcome ? { welcome: result.welcome } : {}),
          ...(welcomeTo ? { welcomeTo } : {}),
          groupInfo: await groupInfoForExternalJoin(result.state),
        })
      } catch (e) {
        if (isEpochConflict(e)) return false
        throw e
      }
      confirmCommit(result)
      await saveGroup({ ...stored, state: result.state })
      return true
    })
    if (won) return
    await catchUpGroup(ds, own, id)
  }
  throw new Error(`commitAndSubmit: gave up after losing three epochs on ${id.slice(0, 12)}`)
}

/** Start a conversation.
 *
 * An invitee with no key packages left is SKIPPED rather than fatal, and
 * returned so the caller can say who is missing: the group is more useful
 * with the people who could be reached than not created at all, and the
 * missing ones can be added later by exactly the same path (`inviteToConversation`). */
export async function createConversation(
  ds: MediatorInfo, own: DidCommSender, name: string, memberDids_: string[],
  kp?: OwnKeyPackage,
): Promise<{ id: string; invited: string[]; skipped: string[] }> {
  const id = groupIdHex(newGroupId())
  const mine = kp ?? await generateOwnKeyPackage(own.xKid)
  const state = await createMlsGroup(newGroupIdFrom(id), mine)
  await createGroupOnDs(ds, own, id, [own.did])
  await saveGroup({ id, selfKid: own.xKid, dsDid: ds.did, dsUrl: ds.url, name, state })

  const invited: string[] = []
  const skipped: string[] = []
  for (const did of memberDids_.filter(d => d !== own.did)) {
    if (await inviteToConversation(ds, own, id, did)) invited.push(did)
    else skipped.push(did)
  }
  // Nobody was added, so no commit has happened and the DS holds no GroupInfo
  // — which would leave this identity's OTHER devices unable to join. One
  // empty commit fixes that, and costs an epoch nobody is using yet.
  if (invited.length === 0) await commitAndSubmit(ds, own, id, async s => ({ result: await rekey(s) }))
  // The name travels as a message, so everyone invited above learns it, and so
  // does anyone added later (the sender re-announces on each invite).
  else await announceName(ds, own, id, name)
  return { id, invited, skipped }
}

/** Hex group id → the bytes MLS wants. */
function newGroupIdFrom(hex: string): Uint8Array {
  return Uint8Array.from(hex.match(/../g)!.map(b => parseInt(b, 16)))
}

/** Add every device of one identity. False when they have no key packages
 * published — nothing was sent, nothing was committed, and the caller reports
 * that identity as not reached. */
export async function inviteToConversation(ds: MediatorInfo, own: DidCommSender, id: string, did: string): Promise<boolean> {
  const stored = await loadGroup(id)
  if (!stored) throw new Error(`inviteToConversation: no such group ${id}`)
  const known = new Set(memberList(stored.state).map(m => m.kid))
  const fetched = (await fetchInviteeKeyPackages(own, did)).filter(f => !known.has(f.kid))
  if (fetched.length === 0) return false
  await commitAndSubmit(ds, own, id, async state => ({
    result: await addMembers(state, fetched.map(f => decodeKeyPackage(f.keyPackage))),
    welcomeTo: [did],
  }))
  await announceName(ds, own, id, (await loadGroup(id))?.name ?? '')
  return true
}

/** Remove every device of one identity — the cryptographic removal, not a
 * politeness: the removed member is outside the next epoch's key schedule and
 * cannot read what follows, whatever it still has cached. */
export async function removeFromConversation(ds: MediatorInfo, own: DidCommSender, id: string, did: string): Promise<void> {
  const stored = await loadGroup(id)
  if (!stored) throw new Error(`removeFromConversation: no such group ${id}`)
  if (did === own.did) throw new Error('removeFromConversation: use leaveConversation to remove yourself')
  const kids = memberKids(stored.state, did)
  if (kids.length === 0) return
  await commitAndSubmit(ds, own, id, async state => ({ result: await removeMembers(state, kids) }))
  // A single Remove leaves no update path in this MLS implementation
  // (group.ts's REMOVAL_NEEDS_FOLLOWUP_REKEY), so the removed member would
  // derive the same next epoch and keep reading. The empty commit is what
  // actually locks them out, and it belongs here rather than with a caller:
  // between the two commits they can still read, so the window has to be one
  // round trip and never depend on anyone remembering.
  await commitAndSubmit(ds, own, id, async state => ({ result: await rekey(state) }))
}

/** Leave. MLS forbids committing one's own removal, so what this can do is
 * DECLARE it — signed by this device's own leaf, held by the DS, and carried
 * out by whoever commits next (mls-ds.ts's pendingRemovals).
 *
 * The local state goes immediately: leaving means not reading what follows,
 * and keeping the keys around to do so anyway would make "leave" a lie the
 * rest of the UI would then act on. */
export async function leaveConversation(ds: MediatorInfo, own: DidCommSender, id: string): Promise<void> {
  const stored = await loadGroup(id)
  if (!stored) return
  if (isActiveMember(stored.state, own.xKid)) {
    const { proposal } = await proposeSelfRemoval(stored.state)
    await submitSelfRemove(ds, own, id, epochOf(stored.state), proposal, own.xKid).catch(e => {
      console.warn('[mls] could not announce leaving:', e instanceof Error ? e.message : e)
    })
  }
  await deleteGroup(id)
}

/** Send a message. */
export async function sendToConversation(
  ds: MediatorInfo, own: DidCommSender, id: string, payload: Extract<ConversationPayload, { t: 'msg' }>,
): Promise<void> {
  await submitPayload(ds, own, id, payload)
}

/** Rename, locally and for everyone. */
export async function renameConversation(ds: MediatorInfo, own: DidCommSender, id: string, name: string): Promise<void> {
  const stored = await loadGroup(id)
  if (!stored) return
  await saveGroup({ ...stored, name })
  await announceName(ds, own, id, name)
}

async function announceName(ds: MediatorInfo, own: DidCommSender, id: string, name: string): Promise<void> {
  if (!name) return
  await submitPayload(ds, own, id, { t: 'name', name, sentAt: new Date().toISOString() })
}

/** Encrypt one payload to the group and hand it to the DS, under the group's
 * lock — an application message consumes key material, so two concurrent
 * sends on one group would otherwise race on the state they advance. */
async function submitPayload(ds: MediatorInfo, own: DidCommSender, id: string, payload: ConversationPayload): Promise<void> {
  await withGroupLock(id, async () => {
    const stored = await loadGroup(id)
    if (!stored) throw new Error(`submitPayload: no such group ${id}`)
    // A device removed from the group keeps its state, and the DS would accept
    // and fan out what it sends (it authorizes by identity and cannot see the
    // tree). The copy would reach everyone and decrypt for nobody. Refused
    // here, where it can still be reported, rather than silently.
    if (!isActiveMember(stored.state, own.xKid)) throw new Error('this device is no longer a member of that conversation')
    const sent = await encryptApplication(stored.state, encode(payload))
    await submitApplication(ds, own, id, sent.wire)
    await saveGroup({ ...stored, state: sent.state })
  })
}

/** Apply one delivery for a conversation — including the Welcome that creates
 * the conversation in the first place.
 *
 * Returns a message when the delivery was one. `joined` reports the group this
 * device has just become a member of, which the UI shows as a new
 * conversation appearing.
 *
 * `dsDid` is who the delivery came from, i.e. the group's Delivery Service:
 * for a group someone else created, this is the only moment its address is
 * knowable, and a joined group whose DS is unknown could be read but never
 * spoken to. */
export async function receiveConversationDelivery(
  own: DidCommSender, delivery: Delivery, dsDid: string,
): Promise<{ message?: ReceivedGroupMessage; joined?: string; renamed?: string; sawProposal?: boolean; retry?: boolean }> {
  const id = delivery.groupId
  if (delivery.kind === 'welcome') {
    const joined = await joinFromWelcome(own, delivery, dsDid)
    return joined ? { joined: id } : {}
  }
  // Every delivery names its Delivery Service — it is who sent it. A group
  // that has no address stored for one can be read and never spoken to, and
  // that state is reachable in more than one way (a build that failed to
  // persist it, a Welcome whose sender could not be resolved at the time), so
  // it is repaired whenever the answer walks past rather than only at the one
  // moment it is first learned.
  await learnDeliveryService(id, dsDid)
  const applied = await receiveDelivery(id, delivery)
  const payload = applied.payload as ConversationPayload | undefined
  if (payload?.t === 'name') {
    const stored = await loadGroup(id)
    if (stored) await saveGroup({ ...stored, name: payload.name })
    return { renamed: payload.name }
  }
  const rest = { ...(applied.sawProposal ? { sawProposal: true } : {}), ...(applied.retry ? { retry: true } : {}) }
  if (payload?.t !== 'msg') return rest
  // Attribution comes from the leaf MLS authenticated, which `receiveDelivery`
  // does not carry up — so it is read back from the state the delivery just
  // produced. A payload with no identifiable sender is not shown as coming
  // from someone: it is dropped, since an unattributed message in a group is
  // worse than a missing one.
  const from = applied.sender
  return from ? { ...rest, message: { groupId: id, from, payload } } : rest
}

/** Fetch and apply whatever this device is missing in one conversation, and
 * return the messages that came out of it — the pull counterpart of
 * `receiveConversationDelivery`, filed by the caller in exactly the same way.
 *
 * A rename that arrives here is applied the same as a pushed one: the two
 * paths must leave the conversation in the same state, or a group's name would
 * depend on which way its messages happened to arrive. */
export async function catchUpConversation(ds: MediatorInfo, own: DidCommSender, id: string): Promise<{ messages: ReceivedGroupMessage[]; sawProposal: boolean }> {
  const { applied, sawProposal } = await catchUpGroup(ds, own, id)
  const messages: ReceivedGroupMessage[] = []
  for (const a of applied) {
    const payload = a.payload as ConversationPayload | undefined
    if (payload?.t === 'name') {
      const stored = await loadGroup(id)
      if (stored) await saveGroup({ ...stored, name: payload.name })
    } else if (payload?.t === 'msg' && a.sender) {
      messages.push({ groupId: id, from: a.sender, payload })
    }
  }
  return { messages, sawProposal }
}

/** Record where a group's Delivery Service is, if we do not know already.
 *
 * Cheap and idempotent: nothing happens for the overwhelmingly common case of
 * a group that already has one. */
async function learnDeliveryService(id: string, dsDid: string, knownUrl?: string): Promise<void> {
  const stored = await loadGroup(id)
  if (!stored || stored.dsUrl) return
  const url = knownUrl ?? (await resolveDidCommDoc(dsDid).catch(() => null))?.service?.find(s => s.type === 'DIDCommMessaging')?.serviceEndpoint?.uri
  if (!url) return
  await withGroupLock(id, async () => {
    const fresh = await loadGroup(id)
    if (!fresh || fresh.dsUrl) return
    await saveGroup({ ...fresh, dsDid, dsUrl: url })
  })
  console.info(`[mls] learned where ${id.slice(0, 12)}'s delivery service is; it can be replied to now`)
}

/** Join every group this DS says we are in and this device has no state for.
 *
 * The recovery path for a lost invitation, and it exists because joining is
 * the one step that had no pull half. A Welcome is pushed exactly once: a
 * device that could not use the one it was sent — an old build that did not
 * understand the message, a key package whose private half is gone, a crash
 * between receiving it and joining — is left invited to a group it will never
 * see, while every other member sees it as a member and keeps talking. Nothing
 * in the group ever repairs that, and nothing surfaces it.
 *
 * The Welcome is still in the DS's log, and the DS will hand it over: pull
 * authorization is ever-membership (mls-ds.ts), which is exactly what being
 * invited made us. So the fix is to notice and ask.
 *
 * Returns the ids actually joined. Best-effort throughout: a group whose
 * Welcome has aged out of the log, or whose key package this device never
 * held, is left alone rather than retried forever. */
export async function recoverMissingGroups(ds: MediatorInfo, own: DidCommSender, selfDid: string): Promise<string[]> {
  const joined: string[] = []
  const selfId = selfGroupIdHex(selfDid)
  for (const { groupId } of await fetchGroups(ds, own).catch(() => [])) {
    if (groupId === selfId) continue
    if (await loadGroup(groupId)) {
      // Being listed here IS the answer to "where is this group's delivery
      // service" — it is the one that just answered. That repairs a group
      // joined by a build which did not keep the address, which otherwise
      // stays readable and unanswerable forever.
      await learnDeliveryService(groupId, ds.did, ds.url)
      continue
    }
    // The whole log, oldest first: the Welcome is the first thing in it, and
    // everything after it is what has happened since — which this device then
    // applies in order, arriving where the group actually is.
    const log = await fetchDeliveries(ds, own, groupId, 0).catch(() => [])
    // EVERY Welcome in the log, not the first: a group that has added people
    // more than once has one per addition, and only the one naming a key
    // package this device holds is ours. Trying just the first finds a
    // stranger's invitation and concludes, wrongly, that ours is unusable.
    const welcomes = log.filter(d => d.kind === 'welcome')
    if (welcomes.length === 0) {
      console.warn(`[mls] member of ${groupId.slice(0, 12)} with no state, and no welcome is left in the delivery service's log; ask to be added again`)
      continue
    }
    let entered = false
    for (const welcome of welcomes) {
      if (await joinFromWelcome(own, welcome, ds.did, ds.url)) { entered = true; break }
    }
    if (!entered) continue
    console.info(`[mls] recovered an invitation to ${groupId.slice(0, 12)} that never took effect`)
    joined.push(groupId)
    await catchUpConversation(ds, own, groupId).catch(() => {})
  }
  return joined
}

/** Join a group we were invited into. The key package the Welcome names is
 * consumed here (single-use), and a Welcome for one this device has no key
 * package for is simply not ours — a resend of one already joined, or another
 * device's invitation. */
async function joinFromWelcome(own: DidCommSender, delivery: Delivery, dsDid: string, knownDsUrl?: string): Promise<boolean> {
  const id = delivery.groupId
  return withGroupLock(id, async () => {
    if (await loadGroup(id)) return false
    const kp = await takeKeyPackageForWelcome(delivery.payload)
    // Not ours: a Welcome fans out to every joiner, and one this device holds
    // no key package for belongs to somebody else's invitation — or is a
    // resend of one already used. Ordinary, and not worth a warning; the
    // caller decides what a run of them means.
    if (!kp) {
      return false
    }
    const state = await joinMlsGroup(delivery.payload, kp)
    const doc = knownDsUrl ? null : await resolveDidCommDoc(dsDid).catch(() => null)
    const dsUrl = knownDsUrl ?? doc?.service?.find(s => s.type === 'DIDCommMessaging')?.serviceEndpoint?.uri ?? ''
    await saveGroup({ id, selfKid: own.xKid, dsDid, dsUrl, name: '', state, lastSeq: delivery.seq })
    if (!dsUrl) console.warn(`[mls] joined ${id.slice(0, 12)} but could not learn its delivery service's address; sending will not work`)
    return true
  })
}
