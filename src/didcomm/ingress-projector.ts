import { bytesToBase64url, canonicalHash, equalBytes, sha256Bytes } from '../protocol/canonical.ts'
import type { IngressEnvelopeV1 } from '../protocol/ingress.ts'
import { didOfKid } from '../protocol/ids.ts'
import type { DeviceId, IdentityId, VaultEventId } from '../protocol/ids.ts'
import type { LocalJmapProjectionV1, LocalJmapSnapshot } from '../local-jmap/gateway.ts'
import { reduceLocalJmapProjection } from '../local-jmap/reducer.ts'
import { assertActiveVaultSegment, type ActiveVaultSegment } from '../vault/active-segment.ts'
import { encodeVaultDeliveryPack } from '../vault/delivery-pack.ts'
import type { IngressVerifierProjector } from '../vault/ingress-ingest.ts'
import { decryptVaultObject } from '../vault/objects.ts'
import { buildVaultMutation } from '../vault/mutations.ts'
import { buildMailMessageAdd } from '../vault/mail-message.ts'
import type { VaultEventSigner } from '../vault/events.ts'
import type { VaultDeliveryOutboxRecord, VaultEventRecord, VaultObjectRecord } from '../vault/store.ts'
import { parseJwe, protectedHeaderOf, unpackAuthcryptAuto, type SelfKeys, type ResolveSenderKey } from './crypto.ts'
import { isPing, responseOwedFor } from './trust-ping.ts'
import { isBasicMessage, basicMessageBodyOf, didCommThreadId } from './basicmessage.ts'
import type { DidCommPlaintext } from './message.ts'
import { isExpired } from './message.ts'
import { isRelationshipMessage, relationshipBodyOf } from './relationship.ts'

export interface DidCommIngressProjectorOptions {
  identityId: IdentityId
  actorDeviceId: DeviceId
  /** Selects either the public front-door key or a private relationship key
   * from the JWE's addressed recipient kid. Unknown kids fail closed. */
  resolveOwnKey(kid: string): SelfKeys | null | Promise<SelfKeys | null>
  resolveSenderKey: ResolveSenderKey
  /** Maps a private sender kid back to its public counterparty DID for the
   * user-facing thread. Required only for established relationship chat. */
  resolveCounterpartyDid?(senderKid: string): string | null | Promise<string | null>
  /** True if a `didcomm.control` event for this exact (senderKid, message id)
   * pair has already been committed -- the caller's job since the answer
   * lives in already-committed local vault state, which this
   * protocol-decode-only class has no store handle to query itself (mirrors
   * nextActorSeq/initialParents/activeSegment: every other piece of "ask the
   * local vault" state here is injected the same way). A captured JWE
   * resubmitted under a NEW ingressId (a genuine replay attack, distinct
   * from IngressStore's own same-ingressId dedup) produces the identical
   * (senderKid, message id) pair on decrypt -- rejecting it here, keyed by
   * the message's own identity rather than the envelope's, is what actually
   * catches that. */
  alreadyProcessed(controlId: string): Promise<boolean>
  nextActorSeq(): Promise<number>
  initialParents(): Promise<VaultEventId[]>
  activeSegment(): Promise<ActiveVaultSegment>
  currentSnapshot(): Promise<LocalJmapSnapshot>
  signer: VaultEventSigner
  now?: () => Date
}

/**
 * Endpoint-only DIDComm ingress projector: decrypts a packed JWE with this
 * device's own keyAgreement key and verifies the sender via a live DID
 * resolve, then dispatches by DIDComm message type:
 *
 *   - Trust Ping 2.0 -- an audit-only `didcomm.control` vault event, never a
 *     mailbox change (local-jmap/reducer.ts's own no-op case for this kind).
 *     The minimal end-to-end proof that ingress -> decrypt -> vault commit
 *     works, nothing more.
 *   - Basic Message 2.0 -- a real 1:1 chat message, filed exactly like
 *     mail's own `message.add` (buildMailMessageAdd) so it renders through
 *     the existing thread.ts UI unmodified (confirmed with the user,
 *     2026-08-25: 1:1 text chat only -- MLS group conversations, push
 *     wake-up, and DID rotation from src.bak's old channel.ts stay
 *     explicitly out of scope).
 *
 * Anything else PLAN.md §6.1's external-ingress/OOB/bootstrap/control scope
 * eventually needs (OOB invitations, MLS Welcome delivery) is later, larger
 * work -- an unrecognized message type fails closed with `unsupported
 * DIDComm message type`, never a silent drop. Per-device fanout for
 * self-device history sync stays intentionally unported (crypto.ts's own
 * header): what changes here is ONLY that a chat message's ongoing content
 * is now something this projector understands, not a re-introduction of the
 * old mediator's per-device queue.
 */
export class DidCommIngressProjector implements IngressVerifierProjector {
  private readonly now: () => Date

  constructor(private readonly options: DidCommIngressProjectorOptions) {
    if (!options.identityId || !options.actorDeviceId) throw new TypeError('DIDComm ingress projector identity is required')
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
      || !sameHash(envelope.protectedPayload, envelope.protectedPayloadHash)) {
      throw new TypeError('DIDComm ingress envelope is invalid for this endpoint')
    }
    let parsed: unknown
    try {
      parsed = JSON.parse(new TextDecoder().decode(envelope.protectedPayload))
    } catch {
      throw new TypeError('DIDComm ingress payload is not valid JSON')
    }
    const jwe = parseJwe(parsed)
    if (!jwe) throw new TypeError('DIDComm ingress payload is not a well-formed JWE')

    const recipientKid = jwe.recipients[0]?.header.kid
    if (!recipientKid) throw new TypeError('DIDComm JWE has no recipient kid')
    const selfKeys = await this.options.resolveOwnKey(recipientKid)
    if (!selfKeys || selfKeys.kid !== recipientKid) throw new TypeError(`DIDComm recipient kid ${recipientKid} is not available to this endpoint`)
    const { plaintext, senderKid } = await unpackAuthcryptAuto(jwe, selfKeys, this.options.resolveSenderKey)
    let msg: DidCommPlaintext
    try {
      msg = JSON.parse(new TextDecoder().decode(plaintext)) as DidCommPlaintext
    } catch {
      throw new TypeError('DIDComm plaintext is not valid JSON')
    }
    if (isExpired(msg)) throw new TypeError('DIDComm message has expired')
    if (!isPing(msg) && !isBasicMessage(msg) && !isRelationshipMessage(msg)) throw new TypeError(`unsupported DIDComm message type for this endpoint slice: ${msg.type}`)

    const dedupeId = didCommMessageDedupeId(senderKid, msg.id)
    if (await this.options.alreadyProcessed(dedupeId)) throw new DidCommReplayError(`DIDComm message ${msg.id} from ${senderKid} was already processed`)

    const segment = await this.options.activeSegment()
    assertActiveVaultSegment(this.options.identityId, segment, 'DIDComm ingress')
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

    const objectRecords: VaultObjectRecord[] = []
    let event: VaultEventRecord
    let decryptedForProjection: { event: VaultEventRecord; plaintext: Uint8Array }

    if (isPing(msg) || isRelationshipMessage(msg)) {
      // Trust Ping 2.0: an audit record, never a thread row -- see
      // local-jmap/reducer.ts's own no-op case for `didcomm.control`.
      const alg = protectedHeaderOf(jwe)?.alg
      const relationshipBody = isRelationshipMessage(msg) ? relationshipBodyOf(msg) : null
      if (isRelationshipMessage(msg) && !relationshipBody) throw new TypeError('DIDComm relationship message has an invalid body')
      const record = await buildVaultMutation({
        kind: 'didcomm.control' as const,
        targetIds: [dedupeId],
        payload: {
          messageId: msg.id, type: msg.type, senderKid,
          recipientKid,
          ...(typeof alg === 'string' ? { alg } : {}),
          ...(isPing(msg) ? { responseOwed: responseOwedFor(msg) } : {}),
          ...(relationshipBody ? {
            relationshipKid: relationshipBody.relationshipKid,
            relationshipPublicKey: bytesToBase64url(relationshipBody.publicKey),
          } : {}),
          receivedAt: createdAt,
        },
      }, context, this.options.signer)
      event = identityScopedObject(record.event, this.options.identityId)
      objectRecords.push(identityScopedObject(record.object, this.options.identityId))
      decryptedForProjection = { event: record.event, plaintext: await decryptVaultObject(segment.segmentKey, record.object) }
    } else {
      // Basic Message 2.0: a chat message, filed exactly like mail's own
      // message.add (buildMailMessageAdd) -- same reducer, same read model,
      // same thread.ts UI, no DIDComm-specific rendering path needed. One
      // thread per correspondent DID pair (didCommThreadId), not per-subject
      // like mail: a chat's whole point is one continuous conversation.
      const senderDid = await resolveDidCommSenderDid(senderKid, kid => this.options.resolveCounterpartyDid?.(kid) ?? null)
      if (!senderDid) throw new TypeError('DIDComm relationship sender is not associated with a counterparty')
      const body = basicMessageBodyOf(msg)
      if (!body) throw new TypeError('DIDComm basicmessage has no readable content')
      const sentAt = body.sentAt ?? (msg.created_time ? new Date(msg.created_time * 1000).toISOString() : createdAt)
      const record = await buildMailMessageAdd({
        email: {
          id: dedupeId,
          threadId: didCommThreadId(this.options.identityId, senderDid),
          mailboxIds: { inbox: true },
          keywords: {},
          receivedAt: createdAt,
          sentAt,
          from: [{ email: senderDid }],
          to: [{ email: this.options.identityId }],
          ...(body.subject ? { subject: body.subject } : {}),
        },
        rawRfc5322: new TextEncoder().encode(body.content),
      }, context, this.options.signer)
      event = identityScopedObject(record.event, this.options.identityId)
      objectRecords.push(identityScopedObject(record.metadataObject, this.options.identityId))
      objectRecords.push(identityScopedObject(record.rawRfc5322Object, this.options.identityId))
      decryptedForProjection = { event: record.event, plaintext: await decryptVaultObject(segment.segmentKey, record.metadataObject) }
    }

    const snapshot = await this.options.currentSnapshot()
    const next = reduceLocalJmapProjection(this.options.identityId, { mailboxes: snapshot.mailboxes, emails: snapshot.emails }, [decryptedForProjection])
    const projection: LocalJmapProjectionV1 = { version: 1, identityId: this.options.identityId, ...next }
    const payload = encodeVaultDeliveryPack({ version: 1, identityId: this.options.identityId, objects: objectRecords, events: [event], keyWraps: segment.keyWraps })
    return {
      objects: objectRecords,
      events: [event],
      projection,
      jmapState: { state: projection.state },
      checkpointId: projection.state,
      deliveryOutbox: {
        identityId: this.options.identityId,
        entryId: event.id,
        payload,
        payloadHash: sha256Bytes(payload),
        createdAt,
        attempts: 0,
      },
    }
  }
}

/** Thrown when this exact (senderKid, message id) pair was already
 * processed -- a distinct type from the generic TypeErrors above so a
 * caller can tell "this is a replay, not a corrupt/hostile payload" apart
 * (mirrors MailRecipientResolutionError/SmtpIngressCongestionError's own
 * reason for being their own class rather than a plain Error). */
export class DidCommReplayError extends Error {}

/** A stable target/email id for the vault record, keyed by the MESSAGE's own
 * identity (who sent it, what they called it) rather than the ingress
 * envelope's -- deliberately NOT canonicalHash(ingressId, ...) the way
 * mail's own emailId is, because the whole point is that a captured JWE
 * resubmitted under a brand new ingressId must still land on the same id
 * here for alreadyProcessed to catch it (and, for a basicmessage, for the
 * SAME reason message.add's own duplicate-id conflict check in
 * local-jmap/reducer.ts serves as a second, independent line of replay
 * defense). Shared across both message types this projector understands --
 * a ping and a chat message from the same sender can never collide with
 * each other since sender+message-id already uniquely identifies one
 * specific DIDComm message regardless of its `type`. */
export function didCommMessageDedupeId(senderKid: string, messageId: string): string {
  return canonicalHash('biset/vault/didcomm/message-dedupe-id/v1', { senderKid, messageId })
}

/** A private relationship kid (`did:peer:2...`) has no public DID of its
 * own -- the caller's `resolveCounterpartyDid` looks up which established
 * `ContactKeyV1` it belongs to. A public front-door kid IS a fragment of a
 * real DID already (`didOfKid`). Shared by both the 1:1 basicmessage path
 * above and any other DIDComm feature (e.g. group chat) that needs to turn
 * an authenticated sender kid into a human-facing DID the same way. */
export async function resolveDidCommSenderDid(
  senderKid: string,
  resolveCounterpartyDid: (kid: string) => string | null | Promise<string | null>,
): Promise<string | null> {
  return senderKid.startsWith('did:peer:2.') ? await resolveCounterpartyDid(senderKid) : didOfKid(senderKid)
}

function identityScopedObject<T>(object: T, identityId: IdentityId): T & { identityId: IdentityId } {
  return { ...object, identityId }
}

function sameHash(payload: Uint8Array, expected: Uint8Array): boolean { return equalBytes(sha256Bytes(payload), expected) }
