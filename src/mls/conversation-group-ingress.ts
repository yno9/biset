// Turns one message-notify DIDComm plaintext (mls-ds/fanout.ts's own push,
// docs/protocols/mls-ds-1.0.md §5.2) into a Vault mutation -- the receive
// side PLAN-mimi.md §7 calls out as missing ("新規 ingress projector").
// Mirrors didcomm/ingress-projector.ts's DidCommIngressProjector shape and
// crypto (same JWE unpack helpers) closely enough to read side by side, but
// is its own class: the message TYPE it understands (`message-notify`) and
// the stateful MLS decrypt step in between have no equivalent there (1:1
// chat's JWE plaintext IS the content; here the JWE plaintext is a DS log
// entry whose `privateMessage` field still needs a second, MLS-level
// decrypt against this device's own Conversation Group state before any
// content exists to project).
import { base64urlToBytes, equalBytes, sha256Bytes } from '../protocol/canonical.ts'
import type { IngressEnvelopeV1 } from '../protocol/ingress.ts'
import { didOfKid, type DeviceId, type IdentityId, type VaultEventId } from '../protocol/ids.ts'
import type { LocalJmapProjectionV1, LocalJmapSnapshot } from '../local-jmap/gateway.ts'
import { reduceLocalJmapProjection } from '../local-jmap/reducer.ts'
import { assertActiveVaultSegment, type ActiveVaultSegment } from '../vault/active-segment.ts'
import { encodeVaultDeliveryPack } from '../vault/delivery-pack.ts'
import type { IngressVerifierProjector } from '../vault/ingress-ingest.ts'
import { decryptVaultObject } from '../vault/objects.ts'
import type { VaultEventSigner } from '../vault/events.ts'
import type { VaultDeliveryOutboxRecord, VaultEventRecord, VaultObjectRecord } from '../vault/store.ts'
import { parseJwe, unpackAuthcryptAuto, type SelfKeys, type ResolveSenderKey } from '../didcomm/crypto.ts'
import type { DidCommPlaintext } from '../didcomm/message.ts'
import { isExpired } from '../didcomm/message.ts'
import { MESSAGE_NOTIFY } from '../mls-ds/didcomm-types.ts'
import { decodeMimiContent, computeMimiMessageId, mimiRoomUri } from './mimi-content.ts'
import { projectMimiConversationMessage } from './mimi-content-projector.ts'
import { receiveConversationEntry } from './conversation-group.ts'
import { memberList } from './group.ts'
import type { MlsConversationGroupStateStore } from './conversation-group-store.ts'

export interface ConversationGroupIngressProjectorOptions {
  identityId: IdentityId
  actorDeviceId: DeviceId
  resolveOwnKey(kid: string): SelfKeys | null | Promise<SelfKeys | null>
  resolveSenderKey: ResolveSenderKey
  nextActorSeq(): Promise<number>
  initialParents(): Promise<VaultEventId[]>
  activeSegment(): Promise<ActiveVaultSegment>
  currentSnapshot(): Promise<LocalJmapSnapshot>
  stateStore: MlsConversationGroupStateStore
  signer: VaultEventSigner
  now?: () => Date
}

interface MessageNotifyBody { groupId: string; seq: number; epoch: string; privateMessage: string; at: string }

function isMessageNotifyBody(value: unknown): value is MessageNotifyBody {
  return typeof value === 'object' && value !== null
    && typeof (value as MessageNotifyBody).groupId === 'string'
    && typeof (value as MessageNotifyBody).seq === 'number'
    && typeof (value as MessageNotifyBody).privateMessage === 'string'
}

/** Endpoint-only projector for ONE message-notify: decrypts the DIDComm
 * envelope (same authcrypt unpack as 1:1 chat), decrypts the MLS
 * PrivateMessage it carries against this device's stored Conversation
 * Group state, decodes the resulting MimiContent, and projects it the same
 * way `mimi-content-projector.ts`'s own tests already exercise. A commit/
 * proposal never reaches this class -- `mls-ds/fanout.ts` only ever fans
 * out `'application'` log entries (mls-ds-1.0.md §5.2); a member catches up
 * on commits/proposals via `pullDeliveries` instead (poll-based, no Vault
 * mutation of its own -- membership changes are DeltaChat/chatmail-style
 * control messages PLAN-mimi.md §5 leaves to a separate, not-yet-built
 * path, same as this class's own header note). */
export class ConversationGroupIngressProjector implements IngressVerifierProjector {
  private readonly now: () => Date

  constructor(private readonly options: ConversationGroupIngressProjectorOptions) {
    if (!options.identityId || !options.actorDeviceId) throw new TypeError('Conversation Group ingress projector identity is required')
    this.now = options.now ?? (() => new Date())
  }

  async verifyAndProject(envelope: IngressEnvelopeV1): Promise<{
    objects: VaultObjectRecord[]
    events: VaultEventRecord[]
    projection: LocalJmapProjectionV1
    jmapState: { state: string }
    checkpointId: string
    deliveryOutbox: VaultDeliveryOutboxRecord
  }> {
    if (envelope.protocol !== 'didcomm' || envelope.recipientIdentityId !== this.options.identityId || envelope.protectedPayload.length === 0
      || !equalBytes(sha256Bytes(envelope.protectedPayload), envelope.protectedPayloadHash)) {
      throw new TypeError('Conversation Group ingress envelope is invalid for this endpoint')
    }
    let parsed: unknown
    try {
      parsed = JSON.parse(new TextDecoder().decode(envelope.protectedPayload))
    } catch {
      throw new TypeError('Conversation Group ingress payload is not valid JSON')
    }
    const jwe = parseJwe(parsed)
    if (!jwe) throw new TypeError('Conversation Group ingress payload is not a well-formed JWE')

    const recipientKid = jwe.recipients[0]?.header.kid
    if (!recipientKid) throw new TypeError('Conversation Group DIDComm JWE has no recipient kid')
    const selfKeys = await this.options.resolveOwnKey(recipientKid)
    if (!selfKeys || selfKeys.kid !== recipientKid) throw new TypeError(`Conversation Group DIDComm recipient kid ${recipientKid} is not available to this endpoint`)
    const { plaintext, senderKid: dsKid } = await unpackAuthcryptAuto(jwe, selfKeys, this.options.resolveSenderKey)
    let msg: DidCommPlaintext
    try {
      msg = JSON.parse(new TextDecoder().decode(plaintext)) as DidCommPlaintext
    } catch {
      throw new TypeError('Conversation Group DIDComm plaintext is not valid JSON')
    }
    if (isExpired(msg)) throw new TypeError('Conversation Group message-notify has expired')
    if (msg.type !== MESSAGE_NOTIFY) throw new TypeError(`unsupported DIDComm message type for Conversation Group ingress: ${msg.type}`)
    // dsKid authenticates the ENVELOPE's sender (the DS itself, per
    // fanout.ts) -- not the group message's sender, which MLS itself
    // authenticates two lines below. Referenced here only so a future
    // reader isn't tempted to (mis)use it for that.
    void dsKid
    if (!isMessageNotifyBody(msg.body)) throw new TypeError('Conversation Group message-notify body is malformed')
    const body = msg.body

    const stored = await this.options.stateStore.load(body.groupId)
    if (!stored) throw new TypeError(`Conversation Group ingress: no local state for group ${body.groupId} -- not a member, or state was lost`)
    if (body.seq <= stored.lastSeenSeq) throw new DidCommReplayError(`Conversation Group message-notify seq ${body.seq} was already applied (last seen ${stored.lastSeenSeq})`)

    const decrypted = await receiveConversationEntry(stored.state, base64urlToBytes(body.privateMessage))
    if (decrypted.plaintext === undefined || decrypted.sender === undefined) {
      throw new TypeError('Conversation Group message-notify did not decrypt to an attributed application message')
    }
    // Persisted only after the Vault commit this method's caller performs
    // succeeds (ingress-ingest.ts's own commit-then-ack ordering) -- see
    // conversation-group-store.ts's own doc comment on why an un-persisted
    // advance is safe to simply retry from the OLD stored state.
    const advancedState = decrypted.state
    const advancedSeq = body.seq

    const content = decodeMimiContent(decrypted.plaintext)
    const senderUri = content.extensions.senderUri ?? decrypted.sender
    const roomUri = content.extensions.roomUri ?? mimiRoomUri(body.groupId)
    // No separate replay-dedupe id (contrast ingress-projector.ts's
    // didCommMessageDedupeId, keyed off the ENVELOPE's own sender+message
    // id): this messageId is content-addressed, so a replayed envelope
    // under a different ingressId still lands on the identical Vault email
    // id, and local-jmap/reducer.ts's own message.add conflict check
    // (sameMessageIdentity) already refuses a second add for the same id --
    // the `body.seq <= stored.lastSeenSeq` check above additionally short-
    // circuits a replay of the exact same DS log entry before it gets this far.
    const messageId = await computeMimiMessageId(senderUri, roomUri, decrypted.plaintext, content.salt)

    const segment = await this.options.activeSegment()
    assertActiveVaultSegment(this.options.identityId, segment, 'Conversation Group ingress')
    const createdAt = this.now().toISOString()
    const context = {
      identityId: this.options.identityId,
      actorDeviceId: this.options.actorDeviceId,
      actorSeq: await this.options.nextActorSeq(),
      parents: await this.options.initialParents(),
      segmentId: segment.segmentId,
      segmentKey: segment.segmentKey,
      createdAt,
    }
    // "The other recipients" means everyone but the SENDER, not everyone
    // but this device -- the recipient (this device) belongs in `to`
    // alongside any other members, same as mimi-content-projector.ts's own
    // test fixture treats it (an add's `to` lists every current member
    // other than whoever is in `from`).
    const senderDid = didOfKid(decrypted.sender)
    const otherMembers = memberList(advancedState).map(m => m.did).filter(did => did !== senderDid)
    const record = await projectMimiConversationMessage({
      content, messageId, groupId: body.groupId, senderDid: senderUri, otherMembers, receivedAt: createdAt,
    }, context, this.options.signer)

    // A committed message-notify persists the advanced MLS state as a side
    // effect of building this projection, same ordering discipline
    // self-group.ts's reflectPendingSelfGroupCommits already relies on: the
    // caller (ingress-ingest.ts's ingestTransportIngress) dedupes on
    // envelope.ingressId BEFORE calling this method at all, so a genuine
    // retry after a failed Vault commit never reaches here a second time
    // for the SAME envelope; this save is what makes the NEXT, different
    // message-notify's seq check (`body.seq <= stored.lastSeenSeq` above)
    // correct.
    await this.options.stateStore.save(body.groupId, advancedState, advancedSeq)

    // Every kind projectMimiConversationMessage produces (add/edit/delete/
    // reaction) puts the mutation's own JSON payload in objects[0] --
    // add/edit's second object (objects[1]) is the raw RFC 5322 blob, which
    // reduceLocalJmapProjection's own decodeVaultMutation doesn't read
    // (mail-message.ts's assertMessageAdd/assertMessageEdit bind to it by
    // objectRef, not by inlining its bytes into the mutation payload).
    const snapshot = await this.options.currentSnapshot()
    const decryptedForProjection = { event: record.events[0]!, plaintext: await decryptVaultObject(segment.segmentKey, record.objects[0]!) }
    const next = reduceLocalJmapProjection(this.options.identityId, { mailboxes: snapshot.mailboxes, emails: snapshot.emails }, [decryptedForProjection])
    const projection: LocalJmapProjectionV1 = { version: 1, identityId: this.options.identityId, ...next }
    const payload = encodeVaultDeliveryPack({ version: 1, identityId: this.options.identityId, objects: record.objects, events: record.events, keyWraps: segment.keyWraps })
    return {
      objects: record.objects,
      events: record.events,
      projection,
      jmapState: { state: projection.state },
      checkpointId: projection.state,
      deliveryOutbox: {
        identityId: this.options.identityId,
        entryId: record.events[0]!.id,
        payload,
        payloadHash: sha256Bytes(payload),
        createdAt,
        attempts: 0,
      },
    }
  }
}

export class DidCommReplayError extends Error {}
