// Sends a DIDComm message to a recipient (did:peer or did:dht — see
// PLAN.md's "DIDComm transport identity"). Forward-wraps (anoncrypt) through
// the recipient's mediator when their DIDCommMessaging service lists routing
// keys, which is the normal case for a browser-only recipient that's never
// listening directly.
import type { PeerDidDoc } from '../peer.ts'
import { packAuthcrypt, packAnoncrypt, type DidCommJWE } from './crypto.ts'
import { buildPlaintext, publicKeyOf, type DidCommSender } from './message.ts'
import { resolveDidCommDoc } from './resolve.ts'

const FORWARD_TYPE = 'https://didcomm.org/routing/2.0/forward'

export interface SendOptions {
  type: string
  body: unknown
}

/** `toDid`/`toDoc` must already be resolved (biset's own resolver, or
 * resolveDidCommDoc). */
export async function sendDidComm(sender: DidCommSender, toDid: string, toDoc: PeerDidDoc, opts: SendOptions): Promise<void> {
  const toXKid = toDoc.keyAgreement[0]
  if (!toXKid) throw new Error('sendDidComm: recipient DID doc has no keyAgreement')
  const service = toDoc.service.find(s => s.type === 'DIDCommMessaging')
  if (!service) throw new Error('sendDidComm: recipient DID doc has no DIDCommMessaging service')

  const plaintext = buildPlaintext(opts.type, opts.body, sender.did, toDid)
  const innerJwe = packAuthcrypt(
    new TextEncoder().encode(JSON.stringify(plaintext)),
    { kid: sender.xKid, privateKey: sender.xPriv },
    { kid: toXKid, publicKey: publicKeyOf(toDoc, toXKid) },
  )

  const routingKeys = service.serviceEndpoint.routing_keys
  let outbound: DidCommJWE = innerJwe
  if (routingKeys.length > 0) {
    const routingKid = routingKeys[0]!
    // The routing key is a mediator's own kid — resolveDidCommDoc dispatches
    // on method (our own mediator, in the anchor, is did:peer: self-certifying
    // and free; a future did:dht-native one resolves the same way, no change).
    const routingDid = routingKid.split('#')[0]!
    const mediatorDoc = await resolveDidCommDoc(routingDid)
    if (!mediatorDoc) throw new Error(`sendDidComm: could not resolve mediator ${routingDid}`)
    const forward = buildPlaintext(FORWARD_TYPE, { next: toXKid })
    forward.attachments = [{ id: crypto.randomUUID(), data: { json: innerJwe } }]
    outbound = packAnoncrypt(
      new TextEncoder().encode(JSON.stringify(forward)),
      { kid: routingKid, publicKey: publicKeyOf(mediatorDoc, routingKid) },
    )
  }

  const resp = await fetch(service.serviceEndpoint.uri, {
    method: 'POST',
    headers: { 'content-type': 'application/didcomm-encrypted+json' },
    body: JSON.stringify(outbound),
  })
  if (!resp.ok) throw new Error(`sendDidComm: HTTP ${resp.status} ${await resp.text()}`)
}
