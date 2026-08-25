import { canonicalHash, equalBytes, sha256Bytes } from '../protocol/canonical.ts'
import type { IngressEnvelopeV1 } from '../protocol/ingress.ts'
import type { DeviceId, IdentityId, VaultEventId } from '../protocol/ids.ts'
import type { LocalJmapProjectionV1, LocalJmapSnapshot } from '../local-jmap/gateway.ts'
import { reduceLocalJmapProjection } from '../local-jmap/reducer.ts'
import { assertActiveVaultSegment, type ActiveVaultSegment } from '../vault/active-segment.ts'
import { encodeVaultDeliveryPack } from '../vault/delivery-pack.ts'
import type { IngressVerifierProjector } from '../vault/ingress-ingest.ts'
import { decryptVaultObject } from '../vault/objects.ts'
import { buildVaultMutation } from '../vault/mutations.ts'
import type { VaultEventSigner } from '../vault/events.ts'
import type { VaultDeliveryOutboxRecord, VaultEventRecord, VaultObjectRecord } from '../vault/store.ts'
import { parseJwe, protectedHeaderOf, unpackAuthcryptAuto, type SelfKeys, type ResolveSenderKey } from './crypto.ts'
import { isPing, responseOwedFor } from './trust-ping.ts'
import type { DidCommPlaintext } from './message.ts'
import { isExpired } from './message.ts'

export interface DidCommIngressProjectorOptions {
  identityId: IdentityId
  actorDeviceId: DeviceId
  /** This device's own DIDComm keypair -- the kid matches actorDeviceId
   * exactly (didcomm/devicekid.ts: one derived kid names both the MLS leaf
   * credential and the keyAgreement entry for a given device). */
  selfKeys: SelfKeys
  resolveSenderKey: ResolveSenderKey
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
 * Endpoint-only DIDComm ingress projector (PLAN.md §6.1): decrypts a packed
 * JWE with this device's own keyAgreement key, verifies the sender via a
 * live DID resolve, and records the result as a `didcomm.control` vault
 * event -- an audit trail, not a mailbox change (local-jmap/reducer.ts's
 * own no-op case for this kind).
 *
 * Scope matches PLAN.md §6.1 exactly: external ingress, OOB, bootstrap, and
 * short control only, not a message channel (ongoing content moves through
 * shared vault delivery instead, same as mail -- see crypto.ts's own header
 * on why Forward/per-device fanout isn't ported at all). The only message
 * type this slice actually understands is Trust Ping 2.0, the minimal
 * end-to-end proof that ingress -> decrypt -> vault commit works; OOB
 * invitations and MLS Welcome delivery are later, larger work (this
 * projector's own `unsupported DIDComm message type` error is exactly the
 * fail-closed marker for "not yet implemented", never a silent drop).
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

    const { plaintext, senderKid } = await unpackAuthcryptAuto(jwe, this.options.selfKeys, this.options.resolveSenderKey)
    let msg: DidCommPlaintext
    try {
      msg = JSON.parse(new TextDecoder().decode(plaintext)) as DidCommPlaintext
    } catch {
      throw new TypeError('DIDComm plaintext is not valid JSON')
    }
    if (isExpired(msg)) throw new TypeError('DIDComm message has expired')
    if (!isPing(msg)) throw new TypeError(`unsupported DIDComm message type for this endpoint slice: ${msg.type}`)

    const controlId = didCommControlId(senderKid, msg.id)
    if (await this.options.alreadyProcessed(controlId)) throw new DidCommReplayError(`DIDComm message ${msg.id} from ${senderKid} was already processed`)

    const alg = protectedHeaderOf(jwe)?.alg
    const segment = await this.options.activeSegment()
    assertActiveVaultSegment(this.options.identityId, segment, 'DIDComm ingress')
    const createdAt = this.now().toISOString()
    const intent = {
      kind: 'didcomm.control' as const,
      targetIds: [controlId],
      payload: {
        messageId: msg.id,
        type: msg.type,
        senderKid,
        ...(typeof alg === 'string' ? { alg } : {}),
        responseOwed: responseOwedFor(msg),
        receivedAt: createdAt,
      },
    }
    const record = await buildVaultMutation(intent, {
      identityId: this.options.identityId,
      actorDeviceId: this.options.actorDeviceId,
      actorSeq: await this.options.nextActorSeq(),
      parents: await this.options.initialParents(),
      segmentId: segment.segmentId,
      segmentKey: segment.segmentKey,
      createdAt,
    }, this.options.signer)

    const plaintextObject = await decryptVaultObject(segment.segmentKey, record.object)
    const snapshot = await this.options.currentSnapshot()
    const next = reduceLocalJmapProjection(this.options.identityId, { mailboxes: snapshot.mailboxes, emails: snapshot.emails }, [{ event: record.event, plaintext: plaintextObject }])
    const projection: LocalJmapProjectionV1 = { version: 1, identityId: this.options.identityId, ...next }
    const objects = [identityScopedObject(record.object, this.options.identityId)]
    const payload = encodeVaultDeliveryPack({ version: 1, identityId: this.options.identityId, objects, events: [record.event], keyWraps: segment.keyWraps })
    return {
      objects,
      events: [record.event],
      projection,
      jmapState: { state: projection.state },
      checkpointId: projection.state,
      deliveryOutbox: {
        identityId: this.options.identityId,
        entryId: record.event.id,
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

/** A stable target id for the audit record, keyed by the MESSAGE's own
 * identity (who sent it, what they called it) rather than the ingress
 * envelope's -- deliberately NOT canonicalHash(ingressId, ...) the way
 * mail's emailId is, because the whole point is that a captured JWE
 * resubmitted under a brand new ingressId must still land on the same id
 * here for alreadyProcessed to catch it. */
function didCommControlId(senderKid: string, messageId: string): string {
  return canonicalHash('biset/vault/didcomm/control-id/v1', { senderKid, messageId })
}

function identityScopedObject<T>(object: T, identityId: IdentityId): T & { identityId: IdentityId } {
  return { ...object, identityId }
}

function sameHash(payload: Uint8Array, expected: Uint8Array): boolean { return equalBytes(sha256Bytes(payload), expected) }
