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
 * resolveDidCommDoc). Fans out to EVERY device the recipient has registered
 * (`toDoc.keyAgreement`, one kid per device — document.ts's DidKeyAgreement
 * note): each gets its own authcrypt'd copy and its own Forward, since Routing
 * 2.0's `next` names exactly one recipient kid. Succeeds if at least one
 * device received it — a device that's stopped registering (a stale kid still
 * cached in a sender's resolved doc) must not sink delivery to the rest. */
export async function sendDidComm(sender: DidCommSender, toDid: string, toDoc: PeerDidDoc, opts: SendOptions): Promise<void> {
  if (toDoc.keyAgreement.length === 0) throw new Error('sendDidComm: recipient DID doc has no keyAgreement')
  const service = toDoc.service.find(s => s.type === 'DIDCommMessaging')
  if (!service) throw new Error('sendDidComm: recipient DID doc has no DIDCommMessaging service')

  const plaintext = buildPlaintext(opts.type, opts.body, sender.did, toDid)
  const plaintextBytes = new TextEncoder().encode(JSON.stringify(plaintext))
  const routingKeys = service.serviceEndpoint.routing_keys

  // The mediator's doc is the same for every device fanned out to below (one
  // shared mediator per identity today) — resolve it once, outside the loop.
  let mediatorDoc: PeerDidDoc | null = null
  if (routingKeys.length > 0) {
    const routingDid = routingKeys[0]!.split('#')[0]!
    // resolveDidCommDoc dispatches on method (our own mediator, in the
    // anchor, is did:peer: self-certifying and free; a future did:dht-native
    // one resolves the same way, no change).
    mediatorDoc = await resolveDidCommDoc(routingDid)
    if (!mediatorDoc) throw new Error(`sendDidComm: could not resolve mediator ${routingDid}`)
  }

  const errors: string[] = []
  let delivered = 0
  for (const toXKid of toDoc.keyAgreement) {
    try {
      const innerJwe = packAuthcrypt(
        plaintextBytes,
        { kid: sender.xKid, privateKey: sender.xPriv },
        { kid: toXKid, publicKey: publicKeyOf(toDoc, toXKid) },
      )
      let outbound: DidCommJWE = innerJwe
      if (mediatorDoc) {
        const routingKid = routingKeys[0]!
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
      if (!resp.ok) throw new Error(`HTTP ${resp.status} ${await resp.text()}`)
      delivered++
    } catch (e) {
      errors.push(`${toXKid}: ${e instanceof Error ? e.message : String(e)}`)
    }
  }
  if (delivered === 0) throw new Error(`sendDidComm: failed to deliver to any device — ${errors.join('; ')}`)
}
