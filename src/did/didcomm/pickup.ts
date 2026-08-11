// Pickup Protocol 3.0 client — status-request/status, delivery-request/
// delivery. Polls a mediator for messages queued against our own kid and
// unpacks each one.
import type { MediatorInfo } from './coordinate.ts'
import { unpackAuthcryptAuto, parseJwe, type ResolveSenderKey } from './crypto.ts'
import { sendAndUnpack, type DidCommSender } from './message.ts'
import { unwrapMaybeSigned, type ResolveSignerKey } from './signature.ts'

const STATUS_REQUEST = 'https://didcomm.org/messagepickup/3.0/status-request'
const STATUS = 'https://didcomm.org/messagepickup/3.0/status'
const DELIVERY_REQUEST = 'https://didcomm.org/messagepickup/3.0/delivery-request'
const DELIVERY = 'https://didcomm.org/messagepickup/3.0/delivery'
const MESSAGES_RECEIVED = 'https://didcomm.org/messagepickup/3.0/messages-received'

export async function pickupStatus(mediator: MediatorInfo, own: DidCommSender): Promise<number> {
  const reply = await sendAndUnpack(mediator, own, STATUS_REQUEST, { recipient_did: own.xKid })
  if (reply.type !== STATUS) throw new Error(`pickupStatus: unexpected reply type ${reply.type}`)
  return (reply.body as { message_count?: number }).message_count ?? 0
}

// `ackId` is the mediator's queue id for this message (the delivery attachment
// id) — the value acknowledgeMessages names back so the mediator removes it.
// `signerKid` is set when the inner message was sign-then-encrypt'd and the
// signature verified (signature.md); null for the ordinary repudiable case.
export interface DeliveredMessage { plaintext: unknown; senderKid: string; ackId: string; signerKid: string | null }

/** Fetches up to `limit` queued messages and unpacks each (authcrypt from
 * whoever sent them, resolved via `resolveSenderKey` — biset's own DID
 * resolver, or a did:peer self-decode for the interop-fallback path).
 *
 * When `resolveSignerKey` is given, a sign-then-encrypt'd inner message is
 * transparently peeled and its EdDSA signature verified (unwrapMaybeSigned) —
 * so signed and unsigned messages surface identically as `plaintext`, with
 * `signerKid` naming the verified signer when present. Without it, a signed
 * inner would surface as the raw JWS (the caller then simply doesn't recognize
 * its `type`), never mis-verified.
 *
 * Delivery is NON-destructive (Pickup 3.0): the mediator keeps every returned
 * message queued until the caller confirms receipt with acknowledgeMessages.
 * The caller MUST ack (by ackId) once it has durably stored them, or they will
 * be redelivered on the next poll. */
export async function pickupDeliver(
  mediator: MediatorInfo,
  own: DidCommSender,
  resolveSenderKey: ResolveSenderKey,
  limit = 10,
  resolveSignerKey?: ResolveSignerKey,
): Promise<DeliveredMessage[]> {
  const reply = await sendAndUnpack(mediator, own, DELIVERY_REQUEST, { recipient_did: own.xKid, limit })
  if (reply.type === STATUS) return [] // no messages queued
  if (reply.type !== DELIVERY) throw new Error(`pickupDeliver: unexpected reply type ${reply.type}`)

  const attachments = reply.attachments ?? []
  const out: DeliveredMessage[] = []
  for (const att of attachments) {
    // Per attachment, NOT per batch. One message that can't be unpacked used to
    // throw out of this whole function, so the caller ack'd nothing and the
    // mediator redelivered the same batch on the next poll — where it failed at
    // the same message again. Since the queue is served oldest-first, a single
    // undecryptable message therefore sat at the front and blocked every
    // message behind it, permanently, with no way for either party to notice.
    //
    // That is not an exotic state: a sender whose DID document momentarily
    // can't be resolved (resolveSenderKey throws), a peer that rotated keys, an
    // envelope encrypted in a way this build can't open — any of them arrives
    // as one bad attachment among good ones.
    //
    // Skipping leaves it UNACKNOWLEDGED on purpose: a transient resolve failure
    // must not turn a real message into a lost one, so it is retried on every
    // poll and eventually aged out by the mediator's own retention bound
    // (queue.ts's MAX_AGE_MS) rather than discarded here.
    // unpackAuthcryptAuto reads the JWE's own `alg` and dispatches to the
    // hybrid or plain path accordingly (PLAN.md "did:webvh PQハイブリッド化"
    // Phase 2) — the sender picked it based on OUR published keyAgreement, so
    // this side just has to be able to answer whichever one arrives.
    const open = async (fresh: boolean): Promise<DeliveredMessage> => {
      const self = { kid: own.xKid, x25519PrivateKey: own.xPriv, mlkemPrivateKey: own.mlkemPriv }
      const senderKeys: typeof resolveSenderKey = fresh ? kid => resolveSenderKey(kid, { fresh: true }) : resolveSenderKey
      // Queued by the mediator, but authored by whoever sent it — see parseJwe.
      const queued = parseJwe(att.data.json)
      if (!queued) throw new Error('queued attachment is not a DIDComm JWE')
      const { plaintext, senderKid } = await unpackAuthcryptAuto(queued, self, senderKeys)
      let bytes = plaintext
      let signerKid: string | null = null
      if (resolveSignerKey) {
        const signerKeys: ResolveSignerKey = fresh ? kid => resolveSignerKey(kid, { fresh: true }) : resolveSignerKey
        ;({ plaintext: bytes, signerKid } = await unwrapMaybeSigned(plaintext, signerKeys))
      }
      return { plaintext: JSON.parse(new TextDecoder().decode(bytes)), senderKid, ackId: att.id, signerKid }
    }
    try {
      out.push(await open(false))
    } catch (first) {
      // The one way a CACHED sender key could become a permanent failure: the
      // resolver may have handed back a stored key (didcomm/sender-keys.ts
      // persists them across reloads, on the sound assumption that a kid names
      // one key forever), and if that assumption ever breaks for a peer, every
      // future message from them fails to unpack with no way back. One retry
      // with a genuinely re-resolved key both opens this message and repairs
      // the cache. Costs a gateway round trip, on a path that is already
      // failing and about to be retried anyway.
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
 * stored so the mediator drops them. Returns the count still queued. No-op for
 * an empty list. */
export async function acknowledgeMessages(mediator: MediatorInfo, own: DidCommSender, ackIds: string[]): Promise<number> {
  if (ackIds.length === 0) return pickupStatus(mediator, own)
  const reply = await sendAndUnpack(mediator, own, MESSAGES_RECEIVED, { recipient_did: own.xKid, message_id_list: ackIds })
  if (reply.type !== STATUS) throw new Error(`acknowledgeMessages: unexpected reply type ${reply.type}`)
  return (reply.body as { message_count?: number }).message_count ?? 0
}
