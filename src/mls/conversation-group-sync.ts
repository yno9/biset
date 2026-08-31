// Pull-based catch-up for a Conversation Group -- the receive side
// PLAN-mimi.md §7 calls for, rewritten as a poll loop (replacing the
// deleted `conversation-group-ingress.ts`, which unwrapped a message-notify
// DIDComm push that no longer exists -- conversation-mls-ds.ts's header
// explains why). Mirrors self-group.ts's `reflectPendingSelfGroupCommits`
// more than it does the old `IngressVerifierProjector` shape: pull
// everything after a stored cursor, apply each entry in order, persist
// progress.
//
// Ordering discipline: this device's stored MLS state/cursor are advanced
// past an entry ONLY AFTER `commitVaultRecord` resolves for that entry (or
// immediately, for a commit/proposal entry with no Vault record of its
// own) -- the same "don't persist a state advance until whatever depends
// on it is durable" rule `conversation-group-ingress.ts` followed, so a
// commit/save failure partway through a batch safely stalls the cursor at
// the true last-good point rather than skipping an entry.
import { ed25519 } from '@noble/curves/ed25519.js'
import { bytesToHex } from '../protocol/canonical.ts'
import { didOfKid, type DeviceId, type IdentityId } from '../protocol/ids.ts'
import type { VaultEventId } from '../protocol/ids.ts'
import { conversationDeliveriesPullSigningBytes } from '../protocol/conversation-mls-ds-signing.ts'
import type { ConversationDeliveriesPullV1 } from '../protocol/conversation-mls-ds.ts'
import type { ConversationMlsDeliveryTransport } from '../mls-ds/client-transport.ts'
import type { LocalJmapProjectionV1, LocalJmapSnapshot } from '../local-jmap/gateway.ts'
import { reduceLocalJmapProjection } from '../local-jmap/reducer.ts'
import { assertActiveVaultSegment, type ActiveVaultSegment } from '../vault/active-segment.ts'
import { decryptVaultObject } from '../vault/objects.ts'
import type { VaultEventSigner } from '../vault/events.ts'
import type { VaultEventRecord, VaultObjectRecord } from '../vault/store.ts'
import { epochOf, memberList } from './group.ts'
import type { ClientState } from './vendor/index.ts'
import { receiveConversationEntry, type ConversationGroupSigner } from './conversation-group.ts'
import { computeMimiMessageId, decodeMimiContent, mimiRoomUri } from './mimi-content.ts'
import { projectMimiConversationMessage } from './mimi-content-projector.ts'
import type { ConversationGroupRosterEntry, MlsConversationGroupStateStore } from './conversation-group-store.ts'
import type { ConversationLogEntry } from '../protocol/conversation-mls-ds.ts'

export interface ConversationGroupVaultRecord {
  objects: VaultObjectRecord[]
  events: VaultEventRecord[]
  projection: LocalJmapProjectionV1
  jmapState: { state: string }
}

/** Everything `applyConversationGroupLogEntry` needs to turn one entry into
 * a Vault record -- a subset of `ConversationGroupSyncOptions` (that also
 * carries `stateStore`/`transport`/`sign`, which only the pull loop needs).
 * Shared by both the pull loop below AND, once a caller wires it up, a live
 * `conversation-group-watch.ts` connection's `onEntry` -- neither this type
 * nor the function using it knows or cares which one is calling. */
export interface ConversationGroupApplyOptions {
  identityId: IdentityId
  actorDeviceId: DeviceId
  nextActorSeq(): Promise<number>
  initialParents(): Promise<VaultEventId[]>
  activeSegment(): Promise<ActiveVaultSegment>
  currentSnapshot(): Promise<LocalJmapSnapshot>
  signer: VaultEventSigner
  /** Must durably commit `record` (e.g. `IndexedDbVaultStore.commitIngress`)
   * before resolving -- see this file's header on why the ordering matters. */
  commitVaultRecord(record: ConversationGroupVaultRecord): Promise<void>
  now?: () => Date
}

export interface ConversationGroupSyncOptions extends ConversationGroupApplyOptions {
  stateStore: MlsConversationGroupStateStore
  transport: ConversationMlsDeliveryTransport
  sign: ConversationGroupSigner
}

export interface ConversationGroupSyncResult { applied: number }

export interface ConversationGroupApplyResult {
  state: ClientState
  /** True only for an application entry that decoded to a Vault mutation
   * and was committed -- a commit/proposal/welcome, or an application
   * entry skipped by the epoch guard, advances `state` (or doesn't) with
   * nothing to commit. */
  committed: boolean
}

/** Applies ONE deliveries entry against `state` -- the per-entry step
 * `syncConversationGroupDeliveries` loops over, extracted so a live watch
 * connection (conversation-group-watch.ts) can call it one entry at a time
 * instead of only ever in a pulled batch. A caller driving both a
 * poll-sync and a live watch for the SAME group concurrently is
 * responsible for serializing its own calls into this function -- there is
 * no internal mutex here (not a new limitation this extraction
 * introduces; the pull loop below was never safe to run twice
 * concurrently for the same group either, this just makes the first
 * caller for whom it could plausibly matter explicit about it).
 *
 * A `'welcome'`-kind entry is a no-op here (already-joined devices have
 * nothing to do with a Welcome; a NEW joiner consumes theirs once via
 * `joinMlsGroup`, outside this steady-state path entirely, same as
 * conversation-group.ts's own `receiveConversationEntry` doc note). */
export async function applyConversationGroupLogEntry(
  entry: ConversationLogEntry,
  state: ClientState,
  groupId: string,
  options: ConversationGroupApplyOptions,
): Promise<ConversationGroupApplyResult> {
  const now = options.now ?? (() => new Date())

  if (entry.kind === 'welcome') return { state, committed: false }

  if (entry.kind === 'commit' || entry.kind === 'proposal') {
    // Only apply a commit/proposal from THIS device's own current epoch --
    // the DS's log for this group also holds entries this device already
    // reflects some other way (most commonly: the very commit that added
    // it, already folded into the state a fresh joiner got via
    // `joinMlsGroup` from the Welcome, outside this loop entirely).
    // Re-decrypting one of those against an already-advanced key schedule
    // fails. Same guard self-group.ts's own `reflectPendingSelfGroupCommits`
    // uses, and for the same reason.
    if (entry.epoch === epochOf(state).toString()) state = (await receiveConversationEntry(state, entry.payload)).state
    return { state, committed: false }
  }

  // entry.kind === 'application'. Same epoch guard as commits/proposals
  // above, for a different reason: a message from strictly before this
  // device's current epoch is one it was never issued key material for
  // (a fresh Welcome-based joiner starts AT the join epoch, with no
  // historical receiver data for anything earlier -- group.ts's
  // processIncoming would throw "epoch too old" rather than silently
  // fail, so this is checked up front instead of caught after the fact).
  if (entry.epoch !== epochOf(state).toString()) return { state, committed: false }
  const received = await receiveConversationEntry(state, entry.payload)
  state = received.state
  if (received.plaintext === undefined || received.sender === undefined) return { state, committed: false }
  const record = await buildVaultRecord(options, groupId, state, received.plaintext, received.sender, now)
  await options.commitVaultRecord(record)
  return { state, committed: true }
}

/** Pulls and applies every entry after this device's stored cursor for
 * `groupId`, via `applyConversationGroupLogEntry` above. Throws if this
 * device holds no local state for the group at all (join first --
 * conversation-group-invite.ts's bootstrap flow). */
export async function syncConversationGroupDeliveries(groupId: string, options: ConversationGroupSyncOptions): Promise<ConversationGroupSyncResult> {
  const stored = await options.stateStore.load(groupId)
  if (!stored) throw new Error(`syncConversationGroupDeliveries: no local state for group ${groupId}`)
  const now = options.now ?? (() => new Date())
  const ownGroupLocalId = bytesToHex(ed25519.getPublicKey(stored.ownGroupLocalPrivateKey))

  const pull: Omit<ConversationDeliveriesPullV1, 'signature'> = { version: 1, groupId, requesterId: ownGroupLocalId, afterSeq: stored.lastSeenSeq, requestedAt: now().toISOString() }
  const entries = await options.transport.pullDeliveries({ ...pull, signature: await options.sign(conversationDeliveriesPullSigningBytes(pull)) })

  let state = stored.state
  let lastSeenSeq = stored.lastSeenSeq
  const roster: ConversationGroupRosterEntry[] = stored.roster
  let applied = 0

  for (const entry of [...entries].sort((a, b) => a.seq - b.seq)) {
    const result = await applyConversationGroupLogEntry(entry, state, groupId, options)
    state = result.state
    if (result.committed) applied++
    lastSeenSeq = entry.seq
    await options.stateStore.save(groupId, state, lastSeenSeq, stored.ownGroupLocalPrivateKey, roster)
  }

  return { applied }
}

async function buildVaultRecord(
  options: ConversationGroupApplyOptions,
  groupId: string,
  state: ClientState,
  plaintext: Uint8Array,
  senderMlsKid: string,
  now: () => Date,
): Promise<ConversationGroupVaultRecord> {
  const content = decodeMimiContent(plaintext)
  const senderUri = content.extensions.senderUri ?? senderMlsKid
  const roomUri = content.extensions.roomUri ?? mimiRoomUri(groupId)
  const messageId = await computeMimiMessageId(senderUri, roomUri, plaintext, content.salt)

  const senderDid = didOfKid(senderMlsKid)
  const otherMembers = memberList(state).map(m => m.did).filter(did => did !== senderDid)

  const segment = await options.activeSegment()
  assertActiveVaultSegment(options.identityId, segment, 'Conversation Group sync')
  const createdAt = now().toISOString()
  const context = {
    identityId: options.identityId,
    actorDeviceId: options.actorDeviceId,
    actorSeq: await options.nextActorSeq(),
    parents: await options.initialParents(),
    segmentId: segment.segmentId,
    segmentKey: segment.segmentKey,
    createdAt,
  }
  const record = await projectMimiConversationMessage({
    content, messageId, groupId, senderDid: senderUri, otherMembers, receivedAt: createdAt,
  }, context, options.signer)

  // Every kind projectMimiConversationMessage produces (add/edit/delete/
  // reaction) puts the mutation's own JSON payload in objects[0] --
  // add/edit's second object is the raw RFC 5322 blob, which
  // reduceLocalJmapProjection's own decodeVaultMutation doesn't read
  // (mail-message.ts's assertMessageAdd/assertMessageEdit bind to it by
  // objectRef, not by inlining its bytes into the mutation payload).
  const snapshot = await options.currentSnapshot()
  const decryptedForProjection = { event: record.events[0]!, plaintext: await decryptVaultObject(segment.segmentKey, record.objects[0]!) }
  const next = reduceLocalJmapProjection(options.identityId, { mailboxes: snapshot.mailboxes, emails: snapshot.emails }, [decryptedForProjection])
  const projection: LocalJmapProjectionV1 = { version: 1, identityId: options.identityId, ...next }
  return { objects: record.objects, events: record.events, projection, jmapState: { state: projection.state } }
}
