import { canonicalHash, equalBytes, sha256Bytes } from '../../protocol/canonical.ts'
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
import { isPing, isPingResponse, responseOwedFor } from '../../protocol/didcomm/trust-ping.ts'
import { FromPriorError, fromPriorKeyResolver, verifyFromPrior, type DidRotation } from '../../protocol/didcomm/from-prior.ts'
import { contactCardForDid, contactSetIntent, counterpartyOfRotatedDid, currentRotation, didCommStateOf, didContactPatch, ownRotationPatch, rotationPatch, type ContactSetPayload, type LocalJmapContactCard } from '../store/projection/contacts.ts'
import { defaultFetch } from '../../protocol/net-fetch.ts'
import { PermanentDeliveryError } from '../../protocol/didcomm/mediator-pickup.ts'
import { isBasicMessage, basicMessageBodyOf, didCommThreadId } from './basicmessage.ts'
import { isExternalFeedPost, externalFeedPostBodyOf, externalFeedThreadId, EXTERNAL_FEED_POST } from './external-feed.ts'
import type { DidCommPlaintext } from '../../protocol/didcomm/message.ts'
import { DidCommSenderMismatchError, isExpired } from '../../protocol/didcomm/message.ts'
import { parseDidCommJws, SignatureError, signingKeyResolver, type SigningKeyResolver } from '../../protocol/didcomm/jws.ts'
import { openDidCommPayload, type OpenedMessage } from '../../protocol/didcomm/open.ts'
import { didcommGroupAddress, isGroupAudience } from './group-chat.ts'
import { describeProblem, isProblemReport } from '../../protocol/didcomm/problems.ts'

export interface OwnDidCommKey { kid: string; x25519PrivateKey: Uint8Array }

export interface DidCommIngressProjectorOptions {
  identityId: IdentityId
  actorDeviceId: DeviceId
  /** This device's key for the JWE's addressed recipient kid. Unknown kids
   * fail closed. */
  resolveOwnKey(kid: string): OwnDidCommKey | null | Promise<OwnDidCommKey | null>
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
  signer: VaultEventAuthor
  /** Verifies a `from_prior` against `from` (from-prior.ts). Defaults to a
   * live resolution; the caller should bypass a host's CDN. */
  verifyFromPrior?(jwt: string, from: string): Promise<DidRotation>
  /** Resolves a signer's key (a signed message, jws.ts). Defaults to a live
   * resolution; the caller should bypass a host's CDN. */
  resolveSigningKey?: SigningKeyResolver
  now?: () => Date
}

/** A message from a did:peer that no contact card names yet: the card that
 * would (a sibling's record of the rotation, by Vault Sync) has not arrived.
 * Not permanent -- the message stays queued and is tried again -- and never
 * projected with a guess, which would leave two devices disagreeing on who
 * sent it (PLAN-refactor.md §9.1). */
export class RotationPendingError extends Error {
  constructor(did: string) {
    super(`no contact names ${did} yet; waiting for this identity's other devices`)
    this.name = 'RotationPendingError'
  }
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
 * this for the group-chat and problem-report types) or drop it deliberately.
 */
export function isProjectableDidCommIngress(msg: { type?: string }): boolean {
  return isPing(msg) || isPingResponse(msg) || isBasicMessage(msg) || isExternalFeedPost(msg) || isProblemReport(msg)
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
  private readonly verify: (jwt: string, from: string) => Promise<DidRotation>
  private readonly resolveSigningKey: SigningKeyResolver

  constructor(private readonly options: DidCommIngressProjectorOptions) {
    if (!options.identityId || !options.actorDeviceId) throw new TypeError('DIDComm ingress projector identity is required')
    this.now = options.now ?? (() => new Date())
    this.verify = options.verifyFromPrior ?? ((jwt, from) => verifyFromPrior(jwt, from, fromPriorKeyResolver(defaultFetch())))
    this.resolveSigningKey = options.resolveSigningKey ?? signingKeyResolver(defaultFetch())
  }

  private counterpartyOf(msg: DidCommPlaintext, senderKid: string, recipientKid: string, cards: readonly LocalJmapContactCard[], at: string) {
    return resolveCounterparty(msg, senderKid, recipientKid, cards, at, this.verify)
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
    // A signed message may arrive without encryption (DIDComm v2.1 signed
    // messages); everything else is a JWE.
    const signedOnly = parseDidCommJws(parsed)
    const jwe = signedOnly ? null : parseJwe(parsed)
    if (!jwe && !signedOnly) throw new TypeError('DIDComm ingress payload is not a well-formed JWE or signed message')
    const open = async (bytes: Uint8Array, authcryptSenderKid?: string) => {
      try { return await openDidCommPayload(bytes, authcryptSenderKid, this.resolveSigningKey) } catch (error) {
        if (error instanceof SignatureError || error instanceof DidCommSenderMismatchError) throw new PermanentDeliveryError(error.message)
        throw error
      }
    }

    // The key of this device the message was encrypted to ('' for a signed
    // message that was not encrypted at all).
    let recipientKid = ''
    let opened: OpenedMessage
    if (jwe) {
      // A message to an identity is encrypted once for every device key its DID
      // document lists (multiplexed encryption), in the sender's order: this
      // device's key is any one of the recipients, not necessarily the first.
      const recipientKids = jwe.recipients.map(recipient => recipient.header.kid).filter((kid): kid is string => typeof kid === 'string' && kid.length > 0)
      if (recipientKids.length === 0) throw new TypeError('DIDComm JWE has no recipient kid')
      let selfKeys: OwnDidCommKey | null = null
      for (const kid of recipientKids) {
        const candidate = await this.options.resolveOwnKey(kid)
        if (candidate && candidate.kid === kid) { selfKeys = candidate; break }
      }
      if (!selfKeys) throw new TypeError(`none of the DIDComm recipient kids ${recipientKids.join(', ')} is available to this endpoint`)
      recipientKid = selfKeys.kid
      const self = { kid: selfKeys.kid, privateKey: selfKeys.x25519PrivateKey }
      if (protectedHeaderOf(jwe)?.alg === 'ECDH-ES+A256KW') {
        opened = await open(await unpackAnoncrypt(jwe, self))
      } else {
        const { plaintext, senderKid } = await unpackAuthcrypt(jwe, self, this.options.resolveSenderKey)
        opened = await open(plaintext, senderKid)
      }
    } else {
      opened = await open(new TextEncoder().encode(JSON.stringify(signedOnly)))
    }
    const msg = opened.message
    // Authenticated by the authcrypt sender or a signature; neither is an
    // anoncrypt message nobody signed. Such a message has no sender to
    // authenticate by construction -- see crypto.ts's own header on why
    // anoncrypt exists at all (Forward-wrapping so a mediator stays blind) and
    // external-feed.ts's header on why External Feed Post is the ONLY message
    // type allowed to arrive that way: every other type this projector
    // understands (chat, ping, problem-report) assumes an authenticated sender
    // somewhere downstream.
    const senderKid = opened.senderKid
    if (isExpired(msg)) throw new TypeError('DIDComm message has expired')
    if (!isProjectableDidCommIngress(msg)) throw new TypeError(`unsupported DIDComm message type for this endpoint slice: ${msg.type}`)
    if (!senderKid && !isExternalFeedPost(msg)) throw new TypeError(`an unauthenticated (anoncrypt, unsigned) message is only accepted for ${EXTERNAL_FEED_POST}, got ${msg.type}`)

    const feedBody = isExternalFeedPost(msg) ? externalFeedPostBodyOf(msg) : null
    if (isExternalFeedPost(msg) && !feedBody) throw new TypeError('DIDComm external feed post has an invalid body')
    // No senderKid for anoncrypt -- the claimed actorId (unauthenticated,
    // same trust level as the rest of the body) stands in for it, so a
    // captured/resubmitted post from the same actor still dedupes the same
    // way chat's (senderKid, message id) pair does.
    const dedupeSubject = senderKid ?? feedBody?.actorId ?? 'anonymous'
    const dedupeId = didCommMessageDedupeId(dedupeSubject, msg.id)
    if (await this.options.alreadyProcessed(dedupeId)) throw new DidCommReplayError(`DIDComm message ${msg.id} from ${dedupeSubject} was already processed`)

    const snapshot = await this.options.currentSnapshot()
    const createdAt = this.now().toISOString()
    // Chat and Trust Ping come from a counterparty: named by its public DID
    // whatever DID it sent from (§12.5), with what that teaches about it
    // written to its contact card in the same commit.
    const counterparty = senderKid && (isBasicMessage(msg) || isPing(msg) || isPingResponse(msg))
      ? await this.counterpartyOf(msg, senderKid, recipientKid, snapshot.contactCards, createdAt)
      : undefined

    const segment = await this.options.activeSegment()
    assertActiveVaultSegment(this.options.identityId, segment, 'DIDComm ingress')
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

    if (isPing(msg) || isPingResponse(msg) || isProblemReport(msg)) {
      // Trust Ping 2.0, and a problem-report (such as a mail bridge's
      // delivery failure, threaded by `pthid` to the message it is about): an
      // audit record, never a thread row -- see local-jmap/reducer.ts's own
      // no-op case for `didcomm.control`. (senderKid is always defined here:
      // anoncrypt is gated to External Feed Post.)
      const alg = jwe ? protectedHeaderOf(jwe)?.alg : 'signed'
      const record = await buildVaultMutation({
        kind: 'didcomm.control' as const,
        targetIds: [dedupeId],
        payload: {
          messageId: msg.id, type: msg.type, senderKid: senderKid!,
          recipientKid,
          ...(typeof alg === 'string' ? { alg } : {}),
          ...(isPing(msg) ? { responseOwed: responseOwedFor(msg) } : {}),
          ...(isProblemReport(msg) ? problemOf(msg) : {}),
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
      // same thread.ts UI. The sender is the counterparty's public DID,
      // whichever of its DIDs sent it (resolveCounterparty). A message addressed to more than one party is a group
      // conversation, threaded by `thid` (group-chat.ts); any other is the
      // 1:1 conversation with its sender (didCommThreadId). Every field below
      // comes from the message alone, never from this device's own state, so
      // two of this identity's devices record it identically (PLAN-refactor.md
      // §9.1: a mismatch stops the Vault's projection rebuild).
      // (senderKid is always defined here: anoncrypt is gated to External
      // Feed Post above, and that type is handled by the branch just above.)
      const senderDid = counterparty!.publicDid
      const group = isGroupAudience(msg.to)
      // This identity is in `to` by its public DID, or -- when the sender
      // writes to the DID this identity moved to -- by the DID of the key the
      // copy was encrypted to (DIDComm v2.1: `to` contains the recipient
      // kid's DID). Recorded by the public DID either way, the same on every
      // device of this identity.
      const ownDids = new Set([this.options.identityId, ...(recipientKid ? [didOfKid(recipientKid)] : [])])
      const audience = group ? [...new Set(msg.to!.map(did => ownDids.has(did) ? this.options.identityId : did))] : []
      if (group && !msg.to!.some(did => ownDids.has(did))) throw new PermanentDeliveryError('DIDComm group message does not name this identity among its recipients')
      const body = basicMessageBodyOf(msg)
      if (!body) throw new TypeError('DIDComm basicmessage has no readable content')
      const sentAt = body.sentAt ?? (msg.created_time ? new Date(msg.created_time * 1000).toISOString() : createdAt)
      const record = await buildMailMessageAdd({
        email: {
          id: dedupeId,
          // A thread is named by an id: compared case-insensitively (DIDComm v2.1).
          threadId: group ? didcommGroupAddress((msg.thid ?? msg.id).toLowerCase()) : didCommThreadId(this.options.identityId, senderDid),
          mailboxIds: { inbox: true },
          keywords: {},
          receivedAt: createdAt,
          sentAt,
          from: [{ email: senderDid, ...(body.fromName ? { name: body.fromName } : {}) }],
          to: (group ? audience : [this.options.identityId]).map(email => ({ email })),
          ...(body.subject ? { subject: body.subject } : {}),
          messageId: msg.id,
          ...(body.replyTo ? { replyTo: [{ email: body.replyTo }] } : {}),
          ...(body.auth ? { auth: body.auth } : {}),
        },
        rawRfc5322: new TextEncoder().encode(body.content),
      }, context, this.options.signer)
      event = identityScopedObject(record.event, this.options.identityId)
      objectRecords.push(identityScopedObject(record.metadataObject, this.options.identityId))
      objectRecords.push(identityScopedObject(record.rawRfc5322Object, this.options.identityId))
      decryptedForProjection = { event: record.event, plaintext: await decryptVaultObject(segment.segmentKey, record.metadataObject) }
    }

    const events: VaultEventRecord[] = [event]
    const reduce = [decryptedForProjection]
    for (const write of counterparty?.writes ?? []) {
      const record = await buildVaultMutation(contactSetIntent(write), {
        ...context, actorSeq: await this.options.nextActorSeq(), parents: [events.at(-1)!.id],
      }, this.options.signer)
      events.push(identityScopedObject(record.event, this.options.identityId))
      objectRecords.push(identityScopedObject(record.object, this.options.identityId))
      reduce.push({ event: record.event, plaintext: await decryptVaultObject(segment.segmentKey, record.object) })
    }
    const commit = buildVaultCommit({
      identityId: this.options.identityId,
      objects: objectRecords,
      events,
      snapshot,
      reduce,
    })
    return { ...commit, checkpointId: commit.projection.state }
  }
}

/** What a control record keeps of a problem-report: its code, the text it
 * gives (control characters out, 512 characters at most: the args may be a
 * remote server's words), the thread it is about, and the messages it
 * acknowledges -- by which the reducer finds the sent email that failed. */
function problemOf(msg: DidCommPlaintext): { problemCode?: string; problemText?: string; threadId?: string; acked?: string[] } {
  const body = (msg.body ?? {}) as { code?: unknown; comment?: unknown; args?: unknown }
  const text = describeProblem(body).replace(/[\u0000-\u001f\u007f]+/g, ' ').trim().slice(0, 512)
  const acked = Array.isArray(msg.ack) ? msg.ack.filter((id): id is string => typeof id === 'string' && id.length > 0).map(id => id.toLowerCase()) : []
  return {
    ...(typeof body.code === 'string' ? { problemCode: body.code } : {}),
    ...(text ? { problemText: text } : {}),
    ...(typeof msg.pthid === 'string' ? { threadId: msg.pthid.toLowerCase() } : {}),
    ...(acked.length ? { acked } : {}),
  }
}

/** The counterparty behind an authenticated sender, by its public DID, and
 * the contact writes the message justifies. */
async function resolveCounterparty(
  msg: DidCommPlaintext, senderKid: string, recipientKid: string, cards: readonly LocalJmapContactCard[], at: string,
  verify: (jwt: string, from: string) => Promise<DidRotation>,
): Promise<{ publicDid: string; writes: ContactSetPayload[] }> {
  const senderDid = didOfKid(senderKid)
  const writes: ContactSetPayload[] = []
  let publicDid: string
  if (typeof msg.from_prior === 'string') {
    // A DID Rotation: `from` now speaks for `iss` (DIDComm v2.1). Refused
    // outright when it does not verify -- retrying gives the same answer.
    let rotation: DidRotation
    try { rotation = await verify(msg.from_prior, senderDid) } catch (error) {
      if (error instanceof FromPriorError) throw new PermanentDeliveryError(error.message)
      throw error
    }
    const prior = rotation.prior.startsWith('did:peer:') ? counterpartyOfRotatedDid(cards, rotation.prior)?.publicDid : rotation.prior
    if (!prior) throw new RotationPendingError(rotation.prior)
    publicDid = prior
    const card = contactCardForDid(cards, publicDid)
    const latest = card ? currentRotation(card) : undefined
    // A rotation older than the one already processed: its DID was left.
    if (latest && latest.did !== senderDid && latest.iat > rotation.iat) throw new PermanentDeliveryError(`${senderDid} is not ${publicDid}'s current DID`)
    if (!card) writes.push(didContactPatch(publicDid))
    const cardId = card?.id ?? didContactPatch(publicDid).cardId
    if (!card || !didCommStateOf(card).rotations?.[senderDid]) writes.push(rotationPatch(cardId, { did: senderDid, prior: rotation.prior, iat: rotation.iat }))
  } else if (senderDid.startsWith('did:peer:')) {
    // Only a counterparty's rotated DID: no standalone did:peer parties (§10-5).
    const known = counterpartyOfRotatedDid(cards, senderDid)
    if (!known) throw new RotationPendingError(senderDid)
    // Once a newer rotation was processed, the old DID is ignored (DIDComm v2.1).
    if (!known.current) throw new PermanentDeliveryError(`${senderDid} is not ${known.publicDid}'s current DID`)
    publicDid = known.publicDid
  } else {
    publicDid = senderDid
    if (!contactCardForDid(cards, publicDid)) writes.push(didContactPatch(publicDid))
  }
  // Written to one of this identity's own rotation DIDs, by the counterparty
  // it is for: that rotation is confirmed, and `from_prior` stops (§4.3).
  const ownDid = recipientKid ? didOfKid(recipientKid) : undefined
  const card = contactCardForDid(cards, publicDid)
  const own = card && ownDid ? didCommStateOf(card).own?.[ownDid] : undefined
  if (card && ownDid && own?.startedAt && !own.confirmedAt) writes.push(ownRotationPatch(card.id, ownDid, 'confirmedAt', at))
  return { publicDid, writes }
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
  // DIDComm v2.1: a message id MUST be compared case-insensitively.
  return canonicalHash('biset/vault/didcomm/message-dedupe-id/v1', { senderKid, messageId: messageId.toLowerCase() })
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
