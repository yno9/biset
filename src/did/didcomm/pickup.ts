// Pickup Protocol 3.0 client — status-request/status, delivery-request/
// delivery. Polls a mediator for messages queued against our own kid and
// unpacks each one.
import type { MediatorInfo } from './coordinate.ts'
import { unpackAuthcrypt, type DidCommJWE } from './crypto.ts'
import { sendAndUnpack, type DidCommSender } from './message.ts'

const STATUS_REQUEST = 'https://didcomm.org/messagepickup/3.0/status-request'
const STATUS = 'https://didcomm.org/messagepickup/3.0/status'
const DELIVERY_REQUEST = 'https://didcomm.org/messagepickup/3.0/delivery-request'
const DELIVERY = 'https://didcomm.org/messagepickup/3.0/delivery'

export async function pickupStatus(mediator: MediatorInfo, own: DidCommSender): Promise<number> {
  const reply = await sendAndUnpack(mediator, own, STATUS_REQUEST, { recipient_did: own.xKid })
  if (reply.type !== STATUS) throw new Error(`pickupStatus: unexpected reply type ${reply.type}`)
  return (reply.body as { message_count?: number }).message_count ?? 0
}

export interface DeliveredMessage { plaintext: unknown; senderKid: string }

/** Fetches up to `limit` queued messages and unpacks each (authcrypt from
 * whoever sent them, resolved via `resolveSenderKey` — biset's own DID
 * resolver, or a did:peer self-decode for the interop-fallback path). */
export async function pickupDeliver(
  mediator: MediatorInfo,
  own: DidCommSender,
  resolveSenderKey: (senderKid: string) => Uint8Array | Promise<Uint8Array>,
  limit = 10,
): Promise<DeliveredMessage[]> {
  const reply = await sendAndUnpack(mediator, own, DELIVERY_REQUEST, { recipient_did: own.xKid, limit })
  if (reply.type === STATUS) return [] // no messages queued
  if (reply.type !== DELIVERY) throw new Error(`pickupDeliver: unexpected reply type ${reply.type}`)

  const attachments = reply.attachments ?? []
  const out: DeliveredMessage[] = []
  for (const att of attachments) {
    const jwe = att.data.json as DidCommJWE
    const { plaintext, senderKid } = await unpackAuthcrypt(jwe, { kid: own.xKid, privateKey: own.xPriv }, resolveSenderKey)
    out.push({ plaintext: JSON.parse(new TextDecoder().decode(plaintext)), senderKid })
  }
  return out
}
