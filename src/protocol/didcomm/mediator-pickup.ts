// Pickup Protocol 3.0 client -- status-request/status, delivery-request/
// delivery, messages-received. Polls a mediator for messages queued
// against our own didCommKid and unpacks each one. Ported from
// src.bak/did/didcomm/pickup.ts, trimmed of the sign-then-encrypt unwrap
// (signature.ts is out of scope for this phase -- ARC.md's design doc).
import { unpackAuthcryptAuto, parseJwe, type DidCommJWE, type ResolveSenderKey } from './crypto.ts'
import { sendAndUnpack, type DidCommSender, type MediatorInfo } from './mediator-transport.ts'
import { defaultFetch } from '../net-fetch.ts'
import { STATUS_REQUEST, STATUS, DELIVERY_REQUEST, DELIVERY, MESSAGES_RECEIVED, WATCH_REQUEST, WATCH_GRANT } from './mediator-protocol.ts'

export async function pickupStatus(mediator: MediatorInfo, own: DidCommSender, fetchImpl: typeof fetch = defaultFetch()): Promise<number> {
  const reply = await sendAndUnpack(mediator, own, STATUS_REQUEST, { recipient_did: own.xKid }, fetchImpl)
  if (reply.type !== STATUS) throw new Error(`pickupStatus: unexpected reply type ${reply.type}`)
  return (reply.body as { message_count?: number }).message_count ?? 0
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

/** Fetches up to `limit` queued messages and unpacks each (authcrypt from
 * whoever sent them, resolved via `resolveSenderKey`).
 *
 * Delivery is NON-destructive (Pickup 3.0): the mediator keeps every
 * returned message queued until the caller confirms receipt with
 * acknowledgeMessages. The caller MUST ack (by ackId) once it has durably
 * stored them, or they will be redelivered on the next poll. */
/** Unwraps ONE queued, still-packed JWE into a DeliveredMessage -- shared by
 * `pickupDeliver`'s batch loop below and mediator-watch.ts's SSE frame
 * handler, which needs the identical fresh-key-retry behavior for a queued
 * item arriving one at a time instead of in a DELIVERY batch. Returns
 * undefined (never throws) for an attachment that could not be opened even
 * after a fresh-key retry -- the caller decides what "undeliverable" means
 * for its own delivery shape (pickupDeliver logs and skips; a watch just
 * leaves it for the next ordinary poll/backlog resend to retry). */
export async function unpackQueuedMessage(
  packedJwe: unknown, ackId: string, own: DidCommSender, resolveSenderKey: ResolveSenderKey,
): Promise<DeliveredMessage | undefined> {
  const open = async (fresh: boolean): Promise<DeliveredMessage> => {
    const self = { kid: own.xKid, x25519PrivateKey: own.xPriv }
    const senderKeys: ResolveSenderKey = fresh ? kid => resolveSenderKey(kid, { fresh: true }) : resolveSenderKey
    // Queued by the mediator, but authored by whoever sent it.
    const queued = parseJwe(packedJwe)
    if (!queued) throw new Error('queued attachment is not a DIDComm JWE')
    const { plaintext, senderKid } = await unpackAuthcryptAuto(queued, self, senderKeys)
    return { plaintext: JSON.parse(new TextDecoder().decode(plaintext)), senderKid, ackId, rawJwe: queued }
  }
  try {
    return await open(false)
  } catch (first) {
    // The one way a CACHED sender key could become a permanent failure: the
    // resolver may have handed back a stored key, and if that assumption
    // ever breaks for a peer, every future message from them fails to
    // unpack with no way back. One retry with a genuinely re-resolved key
    // both opens this message and repairs the cache.
    try {
      return await open(true)
    } catch {
      console.warn(`[didcomm] skipping an undeliverable queued message (${ackId}), the rest of the batch still arrives:`, first instanceof Error ? first.message : first)
      return undefined
    }
  }
}

export async function pickupDeliver(
  mediator: MediatorInfo,
  own: DidCommSender,
  resolveSenderKey: ResolveSenderKey,
  limit = 10,
  fetchImpl: typeof fetch = defaultFetch(),
): Promise<DeliveredMessage[]> {
  const reply = await sendAndUnpack(mediator, own, DELIVERY_REQUEST, { recipient_did: own.xKid, limit }, fetchImpl)
  if (reply.type === STATUS) return [] // no messages queued
  if (reply.type !== DELIVERY) throw new Error(`pickupDeliver: unexpected reply type ${reply.type}`)

  const attachments = reply.attachments ?? []
  const out: DeliveredMessage[] = []
  for (const att of attachments) {
    // Per attachment, NOT per batch -- one message that can't be unpacked
    // must not block every message queued behind it (the queue is served
    // oldest-first). Left UNACKNOWLEDGED on purpose (unpackQueuedMessage
    // itself never acks): a transient resolve failure must not turn a real
    // message into a lost one, so it is retried on every poll and
    // eventually aged out by the mediator's own retention bound rather than
    // discarded here.
    const delivered = await unpackQueuedMessage(att.data.json, att.id, own, resolveSenderKey)
    if (delivered) out.push(delivered)
  }
  return out
}

/** WATCH_REQUEST/WATCH_GRANT -- mints a short-lived token authorizing
 * `streamUrl`'s `GET /stream` connection (mediator/server.ts). The request
 * that CAN carry a signature (`EventSource` itself can't), mirroring
 * mls-ds/client-transport.ts's own `watchDeliveries`/`streamUrl` pair. */
export async function requestWatch(mediator: MediatorInfo, own: DidCommSender, fetchImpl: typeof fetch = defaultFetch()): Promise<{ token: string; expiresAt: string }> {
  const reply = await sendAndUnpack(mediator, own, WATCH_REQUEST, { recipient_did: own.xKid }, fetchImpl)
  if (reply.type !== WATCH_GRANT) throw new Error(`requestWatch: unexpected reply type ${reply.type}`)
  const body = reply.body as { token?: unknown; expires_at?: unknown }
  if (typeof body.token !== 'string' || typeof body.expires_at !== 'string') throw new Error('requestWatch: malformed WATCH_GRANT body')
  return { token: body.token, expiresAt: body.expires_at }
}

/** A plain URL, not a `fetch` call -- `EventSource` opens this itself
 * (mediator-watch.ts). `token` must come from `requestWatch`. */
export function mediatorStreamUrl(mediatorUrl: string, token: string): string {
  return `${mediatorUrl.replace(/\/$/, '')}/stream?token=${encodeURIComponent(token)}`
}

/** Pickup 3.0 messages-received: confirms the listed queue ids are durably
 * stored so the mediator drops them. Returns the count still queued. No-op
 * for an empty list. */
export async function acknowledgeMessages(mediator: MediatorInfo, own: DidCommSender, ackIds: string[], fetchImpl: typeof fetch = defaultFetch()): Promise<number> {
  if (ackIds.length === 0) return pickupStatus(mediator, own, fetchImpl)
  const reply = await sendAndUnpack(mediator, own, MESSAGES_RECEIVED, { recipient_did: own.xKid, message_id_list: ackIds }, fetchImpl)
  if (reply.type !== STATUS) throw new Error(`acknowledgeMessages: unexpected reply type ${reply.type}`)
  return (reply.body as { message_count?: number }).message_count ?? 0
}
