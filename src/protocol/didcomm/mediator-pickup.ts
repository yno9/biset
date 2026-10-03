// Pickup Protocol 3.0 client -- status-request/status, delivery-request/
// delivery, messages-received. Polls one of this device's mediator inboxes
// and unpacks each queued message. Ported from
// src.bak/did/didcomm/pickup.ts, trimmed of the sign-then-encrypt unwrap
// (signature.ts is out of scope for this phase -- ARC.md's design doc).
import { unpackAuthcrypt, unpackAnoncrypt, protectedHeaderOf, parseJwe, type DidCommJWE, type ResolveSenderKey } from './crypto.ts'
import { sendAndUnpack, type DidCommSender, type MediatorInboxClient, type MediatorInfo } from './mediator-transport.ts'
import { defaultFetch } from '../net-fetch.ts'
import { addressedTo, assertFromMatchesSender } from './message.ts'
import { SenderKeyNotPublishedError } from './webvh-resolve.ts'
import { STATUS_REQUEST, STATUS, DELIVERY_REQUEST, DELIVERY, MESSAGES_RECEIVED } from './mediator-protocol.ts'

/** A Pickup 3.0 status, plus biset's `missed`: the mediator dropped copies
 * meant for this inbox (it was dormant, or full) since it last asked -- the
 * device should catch up from a sibling via Vault Sync. */
export interface InboxStatus { messageCount: number; missed: boolean }

export function inboxStatusOf(body: unknown): InboxStatus {
  const b = (body ?? {}) as { message_count?: unknown; missed?: unknown }
  return { messageCount: typeof b.message_count === 'number' ? b.message_count : 0, missed: b.missed === true }
}

export async function pickupStatus(mediator: MediatorInfo, inbox: MediatorInboxClient, fetchImpl: typeof fetch = defaultFetch()): Promise<InboxStatus> {
  const reply = await sendAndUnpack(mediator, inbox, STATUS_REQUEST, { recipient_did: inbox.did, device: inbox.device }, fetchImpl)
  if (reply.type !== STATUS) throw new Error(`pickupStatus: unexpected reply type ${reply.type}`)
  return inboxStatusOf(reply.body)
}

// `ackId` is the mediator's queue id for this message (the delivery
// attachment id) -- the value acknowledgeMessages names back so the
// mediator removes it. `rawJwe` is the still-packed envelope this was
// decrypted from -- carried alongside the convenience-unpacked
// `plaintext`/`senderKid` for a caller that needs to feed it through its own
// full verify-and-project pipeline (biset's own DidCommIngressProjector does
// its own decrypt + replay-dedup from the raw bytes, not from
// already-decrypted content it would otherwise have to trust blind).
export interface DeliveredMessage { plaintext: unknown; senderKid: string; ackId: string; rawJwe: DidCommJWE }

/** Sentinel `senderKid` for a message that arrived anoncrypt (alg
 * ECDH-ES+A256KW) -- there is no sender to authenticate by construction
 * (crypto.ts's own header), so this is never a real kid and every DID-kid
 * parser (didOfKid, resolveDidCommSenderDid) would reject it as malformed
 * if it were accidentally fed one. A consumer that reaches for `senderKid`
 * before checking `msg.type` for the one message type anoncrypt is valid
 * for (External Feed Post -- ingress-projector.ts) is a bug either way;
 * this makes that bug loud instead of silently mistaking a sentinel for an
 * identity. */
const ANONCRYPT_SENDER_KID = 'anoncrypt'

/** A queued message that can never be handled -- not now, not on any
 * retry: it cannot be opened, its sender's key is not (or no longer) the
 * sender's, or it names a relationship that does not exist. The receiver
 * acknowledges it so the mediator drops it; leaving it queued would only
 * redeliver it on every connection until the mediator's retention ends.
 * Anything else that fails (the network, a resolution, local storage) is
 * transient and stays queued for a retry. */
export class PermanentDeliveryError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'PermanentDeliveryError'
  }
}

/** Unwraps ONE queued, still-packed JWE into a DeliveredMessage -- shared by
 * `pickupDeliver` and mediator-live.ts. A sender key that resolves only from
 * a cache gets one retry with a fresh resolve. Returns undefined when it
 * cannot be opened for a transient reason (the sender's DID did not
 * resolve); throws PermanentDeliveryError when it never can be: malformed,
 * not for this key, or from a kid its DID does not list
 * (SenderKeyNotPublishedError -- a removed device). */
export async function unpackQueuedMessage(
  packedJwe: unknown, ackId: string, own: DidCommSender, resolveSenderKey: ResolveSenderKey,
): Promise<DeliveredMessage | undefined> {
  let resolverFailure: unknown
  const open = async (fresh: boolean): Promise<DeliveredMessage> => {
    resolverFailure = undefined
    const self = { kid: own.xKid, privateKey: own.xPriv }
    const senderKeys: ResolveSenderKey = async (kid, options) => {
      try { return await resolveSenderKey(kid, fresh ? { fresh: true } : options) } catch (error) { resolverFailure = error; throw error }
    }
    // Queued by the mediator, but authored by whoever sent it (or, for
    // anoncrypt, by construction not attributable at all -- see
    // ANONCRYPT_SENDER_KID above). The `alg` peek routes an anoncrypt JWE to
    // unpackAnoncrypt instead of failing unpackAuthcrypt.
    const queued = parseJwe(packedJwe)
    if (!queued) throw new Error('queued attachment is not a DIDComm JWE')
    if (protectedHeaderOf(queued)?.alg === 'ECDH-ES+A256KW') {
      const plaintext = await unpackAnoncrypt(queued, self)
      return { plaintext: JSON.parse(new TextDecoder().decode(plaintext)), senderKid: ANONCRYPT_SENDER_KID, ackId, rawJwe: queued }
    }
    const { plaintext, senderKid } = await unpackAuthcrypt(queued, self, senderKeys)
    const message = JSON.parse(new TextDecoder().decode(plaintext)) as { from?: unknown; to?: unknown }
    assertFromMatchesSender(message, senderKid)
    if (!addressedTo(message, own.xKid)) console.warn(`[didcomm] queued message ${ackId} is addressed to someone else in \`to\``)
    return { plaintext: message, senderKid, ackId, rawJwe: queued }
  }
  try {
    return await open(false)
  } catch {
    try {
      return await open(true)
    } catch (error) {
      if (resolverFailure !== undefined && !(resolverFailure instanceof SenderKeyNotPublishedError)) {
        console.warn(`[didcomm] could not resolve the sender of ${ackId} yet; it stays queued:`, resolverFailure instanceof Error ? resolverFailure.message : resolverFailure)
        return undefined
      }
      throw new PermanentDeliveryError(`queued message ${ackId} can never be opened: ${error instanceof Error ? error.message : String(error)}`)
    }
  }
}

/** Fetches up to `limit` queued messages and unpacks each. Delivery is
 * NON-destructive (Pickup 3.0): the caller acks with acknowledgeMessages
 * once it has durably stored them. One that cannot be opened is skipped and
 * logged, never blocking the rest of the batch (the queue is served
 * oldest-first). */
export async function pickupDeliver(
  mediator: MediatorInfo,
  inbox: MediatorInboxClient,
  resolveSenderKey: ResolveSenderKey,
  limit = 10,
  fetchImpl: typeof fetch = defaultFetch(),
): Promise<DeliveredMessage[]> {
  const reply = await sendAndUnpack(mediator, inbox, DELIVERY_REQUEST, { recipient_did: inbox.did, device: inbox.device, limit }, fetchImpl)
  if (reply.type === STATUS) return [] // no messages queued
  if (reply.type !== DELIVERY) throw new Error(`pickupDeliver: unexpected reply type ${reply.type}`)

  const attachments = reply.attachments ?? []
  const out: DeliveredMessage[] = []
  for (const att of attachments) {
    try {
      const delivered = await unpackQueuedMessage(att.data.json, att.id, inbox, resolveSenderKey)
      if (delivered) out.push(delivered)
    } catch (error) {
      console.warn(`[didcomm] skipping an undeliverable queued message (${att.id}):`, error instanceof Error ? error.message : error)
    }
  }
  return out
}

/** The mediator's WebSocket: the same endpoint as its HTTPS one, upgraded
 * (https -> wss, http -> ws for an onion entrance). */
export function mediatorLiveUrl(mediatorUrl: string): string {
  const url = new URL(mediatorUrl)
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:'
  url.pathname = '/'
  url.search = ''
  url.hash = ''
  return url.toString()
}

/** Pickup 3.0 messages-received: confirms the listed ids are durably stored
 * so the mediator drops them from THIS inbox (siblings keep their copies).
 * `recipient_did` and `device` are biset additions to the body, naming
 * which of the sender's inboxes the ids belong to. */
export async function acknowledgeMessages(mediator: MediatorInfo, inbox: MediatorInboxClient, ackIds: string[], fetchImpl: typeof fetch = defaultFetch()): Promise<InboxStatus> {
  if (ackIds.length === 0) return pickupStatus(mediator, inbox, fetchImpl)
  const reply = await sendAndUnpack(mediator, inbox, MESSAGES_RECEIVED, { recipient_did: inbox.did, device: inbox.device, message_id_list: ackIds }, fetchImpl)
  if (reply.type !== STATUS) throw new Error(`acknowledgeMessages: unexpected reply type ${reply.type}`)
  return inboxStatusOf(reply.body)
}
