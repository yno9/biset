// Pickup Protocol 3.0 client -- status-request/status, delivery-request/
// delivery, messages-received. Polls a mediator for messages queued
// against our own didCommKid and unpacks each one. Ported from
// src.bak/did/didcomm/pickup.ts, trimmed of the sign-then-encrypt unwrap
// (signature.ts is out of scope for this phase -- ARC.md's design doc).
import { unpackAuthcryptAuto, parseJwe, type DidCommJWE, type ResolveSenderKey } from './crypto.ts'
import { sendAndUnpack, type DidCommSender, type MediatorInfo } from './mediator-transport.ts'
import { defaultFetch } from '../net-fetch.ts'
import { STATUS_REQUEST, STATUS, DELIVERY_REQUEST, DELIVERY, MESSAGES_RECEIVED } from './mediator-protocol.ts'

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
    // oldest-first). Left UNACKNOWLEDGED on purpose: a transient resolve
    // failure must not turn a real message into a lost one, so it is
    // retried on every poll and eventually aged out by the mediator's own
    // retention bound rather than discarded here.
    const open = async (fresh: boolean): Promise<DeliveredMessage> => {
      const self = { kid: own.xKid, x25519PrivateKey: own.xPriv }
      const senderKeys: ResolveSenderKey = fresh ? kid => resolveSenderKey(kid, { fresh: true }) : resolveSenderKey
      // Queued by the mediator, but authored by whoever sent it.
      const queued = parseJwe(att.data.json)
      if (!queued) throw new Error('queued attachment is not a DIDComm JWE')
      const { plaintext, senderKid } = await unpackAuthcryptAuto(queued, self, senderKeys)
      return { plaintext: JSON.parse(new TextDecoder().decode(plaintext)), senderKid, ackId: att.id, rawJwe: queued }
    }
    try {
      out.push(await open(false))
    } catch (first) {
      // The one way a CACHED sender key could become a permanent failure:
      // the resolver may have handed back a stored key, and if that
      // assumption ever breaks for a peer, every future message from them
      // fails to unpack with no way back. One retry with a genuinely
      // re-resolved key both opens this message and repairs the cache.
      try {
        out.push(await open(true))
      } catch {
        console.warn(`[didcomm] skipping an undeliverable queued message (${att.id}), the rest of the batch still arrives:`, first instanceof Error ? first.message : first)
      }
    }
  }
  return out
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
