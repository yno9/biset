import { bytesToBase64url, canonicalHash, equalBytes, sha256Bytes } from '../protocol/canonical.ts'
import type { IngressEnvelopeV1 } from '../protocol/ingress.ts'
import type { DeviceId, IdentityId, VaultEventId } from '../protocol/ids.ts'
import type { LocalJmapProjectionV1, LocalJmapSnapshot } from '../local-jmap/gateway.ts'
import { reduceLocalJmapProjection } from '../local-jmap/reducer.ts'
import { assertActiveVaultSegment, type ActiveVaultSegment } from '../vault/active-segment.ts'
import { encodeVaultDeliveryPack } from '../vault/delivery-pack.ts'
import type { IngressVerifierProjector } from '../vault/ingress-ingest.ts'
import { decryptVaultObject } from '../vault/objects.ts'
import type { VaultEventSigner } from '../vault/events.ts'
import { buildMailMessageAdd } from '../vault/mail-message.ts'
import type { VaultDeliveryOutboxRecord, VaultEventRecord, VaultObjectRecord } from '../vault/store.ts'
import { readRfc5322HeaderSummary } from './rfc5322-headers.ts'

export interface MailIngressProjectorOptions {
  identityId: IdentityId
  actorDeviceId: DeviceId
  nextActorSeq(): Promise<number>
  initialParents(): Promise<VaultEventId[]>
  activeSegment(): Promise<ActiveVaultSegment>
  currentSnapshot(): Promise<LocalJmapSnapshot>
  signer: VaultEventSigner
  now?: () => Date
}

/**
 * Endpoint-only first stage for raw mail ingress.  It intentionally creates a
 * conservative JMAP envelope from the authoritative raw RFC 5322 bytes; a
 * later MIME/OpenPGP projector may add richer interpreted state without
 * changing this original blob.
 */
export class MailIngressProjector implements IngressVerifierProjector {
  private readonly now: () => Date

  constructor(private readonly options: MailIngressProjectorOptions) {
    if (!options.identityId || !options.actorDeviceId) throw new TypeError('mail ingress projector identity is required')
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
    if (envelope.protocol !== 'mail' || envelope.recipientIdentityId !== this.options.identityId || envelope.protectedPayload.length === 0
      || !sameHash(envelope.protectedPayload, envelope.protectedPayloadHash)) {
      throw new TypeError('mail ingress envelope is invalid for this endpoint')
    }
    const segment = await this.options.activeSegment()
    assertActiveVaultSegment(this.options.identityId, segment, 'mail ingress')
    const createdAt = this.now().toISOString()
    const emailId = mailEmailId(envelope)
    const headers = readRfc5322HeaderSummary(envelope.protectedPayload)
    const threadId = mailThreadId(envelope.recipientIdentityId, headers.inReplyTo ?? headers.references[0]) ?? emailId
    const record = await buildMailMessageAdd({
      email: {
        id: emailId,
        threadId,
        mailboxIds: { inbox: true },
        keywords: {},
        receivedAt: envelope.createdAt,
        size: envelope.protectedPayload.length,
        ...(headers.subject === undefined ? {} : { subject: headers.subject }),
        ...(headers.sentAt === undefined ? {} : { sentAt: headers.sentAt }),
      },
      rawRfc5322: envelope.protectedPayload,
    }, {
      identityId: this.options.identityId,
      actorDeviceId: this.options.actorDeviceId,
      actorSeq: await this.options.nextActorSeq(),
      parents: await this.options.initialParents(),
      segmentId: segment.segmentId,
      segmentKey: segment.segmentKey,
      createdAt,
    }, this.options.signer)
    const plaintext = await decryptVaultObject(segment.segmentKey, record.metadataObject)
    const snapshot = await this.options.currentSnapshot()
    const next = reduceLocalJmapProjection(this.options.identityId, { mailboxes: snapshot.mailboxes, emails: snapshot.emails }, [{ event: record.event, plaintext }])
    const projection: LocalJmapProjectionV1 = { version: 1, identityId: this.options.identityId, ...next }
    const objects = [mailObjectRecord(record.metadataObject, this.options.identityId), mailObjectRecord(record.rawRfc5322Object, this.options.identityId)]
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

function mailEmailId(envelope: IngressEnvelopeV1): string {
  return canonicalHash('biset/vault/mail/email-id/v1', {
    identityId: envelope.recipientIdentityId,
    ingressId: envelope.ingressId,
    protectedPayloadHash: bytesToBase64url(envelope.protectedPayloadHash),
  })
}

function mailThreadId(identityId: IdentityId, messageId: string | undefined): string | undefined {
  if (!messageId) return undefined
  return canonicalHash('biset/vault/mail/thread-id/v1', { identityId, messageId })
}

function mailObjectRecord<T>(object: T, identityId: IdentityId): T & { identityId: IdentityId } {
  return { ...object, identityId }
}

function sameHash(payload: Uint8Array, expected: Uint8Array): boolean { return equalBytes(sha256Bytes(payload), expected) }
