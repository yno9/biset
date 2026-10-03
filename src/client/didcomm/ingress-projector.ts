import { bytesToBase64url, canonicalHash, equalBytes, sha256Bytes } from '../../protocol/canonical.ts'
import type { IngressEnvelopeV1 } from '../../protocol/ingress.ts'
import { didOfKid } from '../../protocol/ids.ts'
import type { DeviceId, IdentityId, VaultEventId } from '../../protocol/ids.ts'
import type { LocalJmapProjectionV1, LocalJmapSnapshot } from '../store/projection/gateway.ts'
import { assertActiveVaultSegment, type ActiveVaultSegment } from '../store/vault/active-segment.ts'
import { buildVaultCommit } from '../store/vault/commit.ts'
import type { IngressVerifierProjector } from '../store/vault/ingress-ingest.ts'
import { decryptVaultObject } from '../store/vault/objects.ts'
import { buildVaultMutation } from '../store/vault/mutations.ts'
import { buildMailMessageAdd } from '../store/vault/mail-message.ts'
import type { VaultEventAuthor } from '../store/vault/events.ts'
import type { VaultEventRecord, VaultObjectRecord } from '../store/vault/store.ts'
import { parseJwe, protectedHeaderOf, unpackAuthcrypt, unpackAnoncrypt, type ResolveSenderKey } from '../../protocol/didcomm/crypto.ts'
import { isPing, responseOwedFor } from '../../protocol/didcomm/trust-ping.ts'
import { PermanentDeliveryError } from '../../protocol/didcomm/mediator-pickup.ts'
import { isBasicMessage, basicMessageBodyOf, didCommThreadId } from './basicmessage.ts'
import { isExternalFeedPost, externalFeedPostBodyOf, externalFeedThreadId, EXTERNAL_FEED_POST } from './external-feed.ts'
import type { DidCommPlaintext } from '../../protocol/didcomm/message.ts'
import { assertFromMatchesSender, isExpired } from '../../protocol/didcomm/message.ts'
import { isRelationshipMessage, relationshipBodyOf } from './relationship.ts'
import { MAIL_BRIDGE_INBOUND, MAIL_BRIDGE_SEND_RESULT, mailBridgeInboundBodyOf } from '../../server/mediator/mail-plugin/mail-bridge.ts'
import { readRfc5322HeaderSummary } from '../app/ui/message/rfc5322-headers.ts'

export interface OwnDidCommKey { kid: string; x25519PrivateKey: Uint8Array }

export interface DidCommIngressProjectorOptions {
  identityId: IdentityId
  actorDeviceId: DeviceId
  /** Selects either the public front-door key or a private relationship key
   * from the JWE's addressed recipient kid. Unknown kids fail closed. */
  resolveOwnKey(kid: string): OwnDidCommKey | null | Promise<OwnDidCommKey | null>
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
  signer: VaultEventAuthor
  now?: () => Date
}

/**
 * The exact set of DIDComm message types `verifyAndProject` below can
 * project; it throws "unsupported DIDComm message type" for anything else.
 *
 * Exported because that throw is NOT a safe default for a mediator-queue
 * caller: mediator-live.ts's onMessage contract leaves a message whose
 * handler threw UNACKNOWLEDGED and re-delivers it on every reconnect. For a
 * transient failure that retry is the point; for a permanently unsupported
 * type it is an unbounded redelivery loop that keeps the queue growing and
 * re-fails forever. So every mediator delivery handler must decide, BEFORE
 * reaching this projector, what to do with a type it has no branch for --
 * `msg.type`-dispatch it (the local-identity boot path's own onMessage does
 * this for the group-chat and mail-bridge types) or drop it deliberately.
 */
export function isProjectableDidCommIngress(msg: { type?: string }): boolean {
  return isPing(msg) || isBasicMessage(msg) || isRelationshipMessage(msg) || isExternalFeedPost(msg) || msg.type === MAIL_BRIDGE_INBOUND || msg.type === MAIL_BRIDGE_SEND_RESULT
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

    // anoncrypt (alg ECDH-ES+A256KW) has no sender to authenticate by
    // construction -- see crypto.ts's own header on why it exists at all
    // (Forward-wrapping so a mediator stays blind) and external-feed.ts's
    // header on why External Feed Post is the ONLY message type allowed to
    // ride on it: every other type this projector understands (chat, ping,
    // relationship, mail-bridge) assumes an authenticated sender somewhere
    // downstream, so admitting anoncrypt for them would silently swap out
    // that assumption's proof for nothing.
    const isAnoncrypt = protectedHeaderOf(jwe)?.alg === 'ECDH-ES+A256KW'
    const { plaintext, senderKid } = isAnoncrypt
      ? { plaintext: await unpackAnoncrypt(jwe, { kid: selfKeys.kid, privateKey: selfKeys.x25519PrivateKey }), senderKid: undefined as string | undefined }
      : await unpackAuthcrypt(jwe, { kid: selfKeys.kid, privateKey: selfKeys.x25519PrivateKey }, this.options.resolveSenderKey)
    let msg: DidCommPlaintext
    try {
      msg = JSON.parse(new TextDecoder().decode(plaintext)) as DidCommPlaintext
    } catch {
      throw new TypeError('DIDComm plaintext is not valid JSON')
    }
    if (senderKid) assertFromMatchesSender(msg, senderKid)
    if (isExpired(msg)) throw new TypeError('DIDComm message has expired')
    if (!isProjectableDidCommIngress(msg)) throw new TypeError(`unsupported DIDComm message type for this endpoint slice: ${msg.type}`)
    if (isAnoncrypt && !isExternalFeedPost(msg)) throw new TypeError(`anoncrypt is only accepted for ${EXTERNAL_FEED_POST}, got ${msg.type}`)

    const feedBody = isExternalFeedPost(msg) ? externalFeedPostBodyOf(msg) : null
    if (isExternalFeedPost(msg) && !feedBody) throw new TypeError('DIDComm external feed post has an invalid body')
    // No senderKid for anoncrypt -- the claimed actorId (unauthenticated,
    // same trust level as the rest of the body) stands in for it, so a
    // captured/resubmitted post from the same actor still dedupes the same
    // way chat's (senderKid, message id) pair does.
    const dedupeSubject = senderKid ?? feedBody?.actorId ?? 'anonymous'
    const dedupeId = didCommMessageDedupeId(dedupeSubject, msg.id)
    if (await this.options.alreadyProcessed(dedupeId)) throw new DidCommReplayError(`DIDComm message ${msg.id} from ${dedupeSubject} was already processed`)

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

    if (msg.type === MAIL_BRIDGE_INBOUND) {
      // SMTP is deliberately opaque in transit.  Only the endpoint reads its
      // inexpensive display/threading metadata; the original bytes are kept
      // unchanged in the encrypted Vault object for replies and download.
      // (senderKid is always defined here: anoncrypt is gated to External
      // Feed Post above, and this branch is never that type.)
      const inbound = mailBridgeInboundBodyOf(msg)
      if (!inbound) throw new TypeError('mail bridge message has an invalid inbound body')
      const headers = readRfc5322HeaderSummary(inbound.rawRfc5322)
      const emailId = didCommMessageDedupeId(senderKid!, msg.id)
      const threadId = headers.references[0] ?? headers.inReplyTo ?? headers.messageId ?? emailId
      const record = await buildMailMessageAdd({
        email: {
          id: emailId,
          threadId,
          mailboxIds: { inbox: true },
          keywords: {},
          receivedAt: createdAt,
          ...(headers.sentAt ? { sentAt: headers.sentAt } : {}),
          ...(headers.from ? { from: [headers.from] } : {}),
          to: [{ email: this.options.identityId }],
          ...(headers.subject ? { subject: headers.subject } : {}),
          ...(headers.inReplyTo ? { inReplyTo: headers.inReplyTo } : {}),
          size: inbound.rawRfc5322.length,
        },
        rawRfc5322: inbound.rawRfc5322,
      }, context, this.options.signer)
      event = identityScopedObject(record.event, this.options.identityId)
      objectRecords.push(identityScopedObject(record.metadataObject, this.options.identityId))
      objectRecords.push(identityScopedObject(record.rawRfc5322Object, this.options.identityId))
      decryptedForProjection = { event: record.event, plaintext: await decryptVaultObject(segment.segmentKey, record.metadataObject) }
    } else if (isPing(msg) || isRelationshipMessage(msg) || msg.type === MAIL_BRIDGE_SEND_RESULT) {
      // Trust Ping 2.0: an audit record, never a thread row -- see
      // local-jmap/reducer.ts's own no-op case for `didcomm.control`.
      // (senderKid is always defined here, same reasoning as the
      // MAIL_BRIDGE_INBOUND branch above.)
      const alg = protectedHeaderOf(jwe)?.alg
      const relationshipBody = isRelationshipMessage(msg) ? relationshipBodyOf(msg) : null
      if (isRelationshipMessage(msg) && !relationshipBody) throw new TypeError('DIDComm relationship message has an invalid body')
      const record = await buildVaultMutation({
        kind: 'didcomm.control' as const,
        targetIds: [dedupeId],
        payload: {
          messageId: msg.id, type: msg.type, senderKid: senderKid!,
          recipientKid,
          ...(typeof alg === 'string' ? { alg } : {}),
          ...(isPing(msg) ? { responseOwed: responseOwedFor(msg) } : {}),
          ...(relationshipBody ? {
            relationshipKid: relationshipBody.relationshipKid,
            relationshipPublicKey: bytesToBase64url(relationshipBody.publicKey),
          } : {}),
          ...(msg.type === MAIL_BRIDGE_SEND_RESULT ? { mailBridgeResultReceived: true, threadId: msg.thid ?? msg.id } : {}),
          receivedAt: createdAt,
        },
      }, context, this.options.signer)
      event = identityScopedObject(record.event, this.options.identityId)
      objectRecords.push(identityScopedObject(record.object, this.options.identityId))
      decryptedForProjection = { event: record.event, plaintext: await decryptVaultObject(segment.segmentKey, record.object) }
    } else if (isExternalFeedPost(msg)) {
      // External Feed Post: an anoncrypt-only, unauthenticated post from an
      // ActivityPub/AT Protocol actor the user follows, bridged in by
      // something that has no signing identity of its own yet (see
      // external-feed.ts's header). Filed the same way as Basic Message --
      // same buildMailMessageAdd, same thread.ts UI -- but threaded by
      // (source, actorId) instead of a resolved counterparty DID, since
      // there isn't one and the whole point of anoncrypt here is that there
      // never will be. `feedBody` was already parsed and validated above,
      // before dedupeId, since dedup needs actorId in place of a senderKid.
      const body = feedBody!
      const record = await buildMailMessageAdd({
        email: {
          id: dedupeId,
          threadId: externalFeedThreadId(this.options.identityId, body.source, body.actorId),
          mailboxIds: { inbox: true },
          keywords: {},
          receivedAt: createdAt,
          sentAt: msg.created_time ? new Date(msg.created_time * 1000).toISOString() : createdAt,
          from: [{ email: body.actorName ?? body.actorId }],
          to: [{ email: this.options.identityId }],
          ...(body.title ? { subject: body.title } : {}),
        },
        // Leading `\n\n` matters: body-text.ts's extractPlainTextBody() treats
        // rawRfc5322 as an RFC 5322 entity and splits it on the FIRST blank
        // line into headers/body. Without this leading blank line, `body.content`
        // itself (no colon in most posts) was silently consumed as an empty
        // header block (found live 2026-09-25 via folio's AP streaming adapter).
        // This forces an empty header section so `content` survives as the body.
        //
        // `body.url` is deliberately NOT inlined into the body text itself
        // (2026-09-25, user request) -- but it's still worth a clickable
        // link (2026-09-25, found live: RSS excerpts end in "続きを読む..."
        // with no way to reach the actual article). Carried as a
        // non-standard `X-Source-Url` header instead, read back by
        // rfc5322-headers.ts's readRfc5322HeaderSummary and rendered
        // separately by thread.ts -- keeps the body plaintext clean while
        // still surfacing the link.
        //
        // `body.url` arrives over unauthenticated anoncrypt (external-feed.ts's
        // header) -- a malicious sender could splice CR/LF into it to inject
        // extra header lines or forge the header/body boundary that
        // extractPlainTextBody() splits on. Only a bare CRLF-free http(s) URL
        // becomes a header; anything else is dropped from rawRfc5322 (the
        // rest of the message still gets delivered, just without the link).
        rawRfc5322: new TextEncoder().encode(safeSourceUrlHeader(body.url) + body.content),
      }, context, this.options.signer)
      event = identityScopedObject(record.event, this.options.identityId)
      objectRecords.push(identityScopedObject(record.metadataObject, this.options.identityId))
      objectRecords.push(identityScopedObject(record.rawRfc5322Object, this.options.identityId))
      decryptedForProjection = { event: record.event, plaintext: await decryptVaultObject(segment.segmentKey, record.metadataObject) }
    } else {
      // Basic Message 2.0: a chat message, filed exactly like mail's own
      // message.add (buildMailMessageAdd) -- same reducer, same read model,
      // same thread.ts UI, no DIDComm-specific rendering path needed. One
      // thread per correspondent DID pair (didCommThreadId), not per-subject
      // like mail: a chat's whole point is one continuous conversation.
      // (senderKid is always defined here: this branch is only reached for
      // authcrypt messages, since anoncrypt is gated to External Feed Post
      // above and that type is handled by the branch just above this one.)
      const senderDid = await resolveDidCommSenderDid(senderKid!, kid => this.options.resolveCounterpartyDid?.(kid) ?? null)
      // Only a relationship's CURRENT counterparty kid speaks for it: an old
      // one may be held by a device the counterparty removed. Final, so the
      // copy is dropped instead of redelivered.
      if (!senderDid) throw new PermanentDeliveryError('DIDComm relationship sender is not a current counterparty')
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

    const commit = buildVaultCommit({
      identityId: this.options.identityId,
      objects: objectRecords,
      events: [event],
      snapshot: await this.options.currentSnapshot(),
      reduce: [decryptedForProjection],
    })
    return { ...commit, checkpointId: commit.projection.state }
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

/** Builds the leading `X-Source-Url: ...\n\n` header block for an External
 * Feed Post's rawRfc5322 (see that call site's comment) -- or, when `url`
 * isn't a bare CRLF-free http(s) URL, just `\n\n` (empty header section,
 * same shape body-text.ts's extractPlainTextBody() expects either way).
 * `url` is unauthenticated anoncrypt data (external-feed.ts's header); a
 * sender could otherwise splice CR/LF into it to inject header lines or
 * forge the header/body boundary extractPlainTextBody() splits on. */
function safeSourceUrlHeader(url: string): string {
  if (/^https?:\/\//.test(url) && !/[\r\n]/.test(url)) return `X-Source-Url: ${url}\n\n`
  return '\n\n'
}
