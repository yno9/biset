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
import { receiveConversationEntry, type ConversationGroupSigner } from './conversation-group.ts'
import { computeMimiMessageId, decodeMimiContent, mimiRoomUri } from './mimi-content.ts'
import { projectMimiConversationMessage } from './mimi-content-projector.ts'
import type { ConversationGroupRosterEntry, MlsConversationGroupStateStore } from './conversation-group-store.ts'

export interface ConversationGroupVaultRecord {
  objects: VaultObjectRecord[]
  events: VaultEventRecord[]
  projection: LocalJmapProjectionV1
  jmapState: { state: string }
}

export interface ConversationGroupSyncOptions {
  stateStore: MlsConversationGroupStateStore
  transport: ConversationMlsDeliveryTransport
  sign: ConversationGroupSigner
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

export interface ConversationGroupSyncResult { applied: number }

/** Pulls and applies every entry after this device's stored cursor for
 * `groupId`. Throws if this device holds no local state for the group at
 * all (join first -- conversation-group-invite.ts's bootstrap flow). A
 * `'welcome'`-kind entry is skipped here (already-joined devices have
 * nothing to do with a Welcome; a NEW joiner consumes theirs once via
 * `joinMlsGroup`, outside this steady-state loop, same as
 * conversation-group.ts's own `receiveConversationEntry` doc note). */
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
    if (entry.kind === 'welcome') {
      lastSeenSeq = entry.seq
      await options.stateStore.save(groupId, state, lastSeenSeq, stored.ownGroupLocalPrivateKey, roster)
      continue
    }
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
      lastSeenSeq = entry.seq
      await options.stateStore.save(groupId, state, lastSeenSeq, stored.ownGroupLocalPrivateKey, roster)
      continue
    }

    // entry.kind === 'application'. Same epoch guard as commits/proposals
    // above, for a different reason: a message from strictly before this
    // device's current epoch is one it was never issued key material for
    // (a fresh Welcome-based joiner starts AT the join epoch, with no
    // historical receiver data for anything earlier -- group.ts's
    // processIncoming would throw "epoch too old" rather than silently
    // fail, so this is checked up front instead of caught after the fact).
    if (entry.epoch === epochOf(state).toString()) {
      const received = await receiveConversationEntry(state, entry.payload)
      state = received.state
      if (received.plaintext !== undefined && received.sender !== undefined) {
        const record = await buildVaultRecord(options, groupId, state, received.plaintext, received.sender, now)
        await options.commitVaultRecord(record)
        applied++
      }
    }
    lastSeenSeq = entry.seq
    await options.stateStore.save(groupId, state, lastSeenSeq, stored.ownGroupLocalPrivateKey, roster)
  }

  return { applied }
}

async function buildVaultRecord(
  options: ConversationGroupSyncOptions,
  groupId: string,
  state: Awaited<ReturnType<typeof receiveConversationEntry>>['state'],
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
