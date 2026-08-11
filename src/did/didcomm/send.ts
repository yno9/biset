// Sends a DIDComm message to a recipient (did:peer or did:dht — see
// PLAN.md's "DIDComm transport identity"). Forward-wraps (anoncrypt) through
// the recipient's mediator when their DIDCommMessaging service lists routing
// keys, which is the normal case for a browser-only recipient that's never
// listening directly.
import type { PeerDidDoc } from '../peer/peer.ts'
import { packAuthcrypt, packAuthcryptHybrid, packAnoncrypt, type DidCommJWE } from './crypto.ts'
import { buildPlaintext, publicKeyOf, mlkemPublicKeyOf, type DidCommSender, type PlaintextOptions } from './message.ts'
import { packSigned, type JwsSigner } from './signature.ts'
import { resolveDidCommDoc } from './resolve.ts'

const FORWARD_TYPE = 'https://didcomm.org/routing/2.0/forward'

export interface SendOptions {
  type: string
  body: unknown
  /** Extra plaintext headers (thid/pthid/ack/expires_time) for this message. */
  headers?: PlaintextOptions
  /** When set, sign-then-encrypt: the plaintext is wrapped in a JWS (EdDSA)
   * BEFORE authcrypt, adding non-repudiation (signature.md). Omit for the
   * default repudiable authcrypt, which already authenticates the sender. */
  sign?: JwsSigner
  /** Deliver without waking the recipient device: for a message to our OWN
   * other devices, where a notification would announce something the user just
   * did themselves.
   *
   * Implemented by AUTHENTICATING the outermost Forward envelope (authcrypt to
   * the mediator instead of the usual anoncrypt) rather than by asking for
   * silence in the message. The mediator then recognizes the sibling delivery
   * from its own keylist — see the FORWARD case in anchor/mediator/server.ts
   * for why "recognized, not declared" is the only safe shape here. Nothing
   * else changes: same routing/2.0 forward, same opaque inner JWE, and a
   * mediator that ignores the distinction simply notifies as before.
   *
   * Only for our own mediator, and only for our own devices. A forward to a
   * stranger stays anoncrypt — the privacy of NOT telling someone else's
   * mediator who is writing to their user is worth more than any of this. */
  silent?: boolean
}

/** `toDid`/`toDoc` must already be resolved (biset's own resolver, or
 * resolveDidCommDoc). Fans out to EVERY device the recipient has registered
 * (`toDoc.keyAgreement`, one kid per device — document.ts's DidKeyAgreement
 * note): each gets its own authcrypt'd copy and its own Forward, since Routing
 * 2.0's `next` names exactly one recipient kid. Succeeds if at least one
 * device received it — a device that's stopped registering (a stale kid still
 * cached in a sender's resolved doc) must not sink delivery to the rest. */
/** How the per-device fan-out went. `delivered < total` means the message is
 * on its way to some of the recipient's devices but not all of them.
 *
 * `deliveredKids` names WHICH ones, so a caller that intends to retry can
 * resend only to the devices that didn't get it — without it, the counts alone
 * force a retry to re-send to every device, and a mediator that already queued
 * a copy would hold two. */
export interface DidCommFanout { delivered: number; total: number; errors: string[]; deliveredKids: string[] }

/** The recipient's own published document says they cannot be reached over
 * DIDComm right now — no device key to encrypt to, or no mediator service to
 * hand the message to. A property of THEIR identity, not of this send: no
 * retry, no network condition and nothing the sender can fix, which is why it
 * is a distinct type rather than one more error string. channel.ts turns it
 * into something a human can act on (their name, and their mail/AP address if
 * one is known) instead of surfacing this wire-level wording. */
export class DidCommUnreachableError extends Error {
  constructor(message: string, readonly toDid: string) {
    super(message)
    this.name = 'DidCommUnreachableError'
  }
}

export async function sendDidComm(sender: DidCommSender, toDid: string, toDoc: PeerDidDoc, opts: SendOptions): Promise<DidCommFanout> {
  if (toDoc.keyAgreement.length === 0) throw new DidCommUnreachableError('sendDidComm: recipient DID doc has no keyAgreement', toDid)
  const service = toDoc.service.find(s => s.type === 'DIDCommMessaging')
  if (!service) throw new DidCommUnreachableError('sendDidComm: recipient DID doc has no DIDCommMessaging service', toDid)

  const plaintext = buildPlaintext(opts.type, opts.body, sender.did, toDid, opts.headers)
  const plaintextJson = new TextEncoder().encode(JSON.stringify(plaintext))
  // sign-then-encrypt (signature.md): when a non-repudiable signature is asked
  // for, the bytes that get authcrypt'd are the JWS wrapping the plaintext, not
  // the bare plaintext. The recipient's unwrapMaybeSigned peels it transparently.
  const plaintextBytes = opts.sign
    ? new TextEncoder().encode(JSON.stringify(packSigned(plaintextJson, opts.sign)))
    : plaintextJson
  const routingKeys = service.serviceEndpoint.routing_keys

  // Resolve each routing key's public key once, up front — the routing chain is
  // the same for every device fanned out to below. Keys can live under
  // different DIDs (routingKeys[0] the recipient's mediator, a later one
  // another hop), so cache resolved docs per DID. resolveDidCommDoc dispatches
  // on method (our own mediator, in the anchor, is did:peer: self-certifying
  // and free; a did:dht-native one resolves the same way, no change).
  const routingKeyPub = new Map<string, Uint8Array>()
  const docCache = new Map<string, PeerDidDoc>()
  for (const kid of routingKeys) {
    const did = kid.split('#')[0]!
    let doc = docCache.get(did)
    if (!doc) {
      const resolved = await resolveDidCommDoc(did)
      if (!resolved) throw new Error(`sendDidComm: could not resolve routing hop ${did}`)
      docCache.set(did, resolved)
      doc = resolved
    }
    routingKeyPub.set(kid, publicKeyOf(doc, kid))
  }

  const errors: string[] = []
  const deliveredKids: string[] = []
  for (const toXKid of toDoc.keyAgreement) {
    try {
      // Hybrid negotiation (PLAN.md "did:webvh PQハイブリッド化" Phase 2): use
      // the PQ path only when BOTH sides are capable — this device has its
      // own ML-KEM-768 key (sender.mlkemPriv, needed to derive the same Zpq
      // deriveEcdh1PUHybrid mixes in) AND the recipient device published one
      // at `#kk<n>`. Either side lacking it falls back to plain packAuthcrypt
      // silently — never an error, since a pre-PQ peer is the expected
      // common case for the foreseeable future.
      const recipientMlkemPub = sender.mlkemPriv ? mlkemPublicKeyOf(toDoc, toXKid) : null
      const innerJwe = recipientMlkemPub
        ? packAuthcryptHybrid(
            plaintextBytes,
            { kid: sender.xKid, privateKey: sender.xPriv },
            { kid: toXKid, x25519PublicKey: publicKeyOf(toDoc, toXKid), mlkemPublicKey: recipientMlkemPub },
          )
        : packAuthcrypt(
            plaintextBytes,
            { kid: sender.xKid, privateKey: sender.xPriv },
            { kid: toXKid, publicKey: publicKeyOf(toDoc, toXKid) },
          )
      // Routing 2.0 "Sender Process to Enable Forwarding" step 4: wrap the
      // message once per routing key, looping over routingKeys in REVERSE. Each
      // wrap's `next` names the recipient of the payload it encloses — the
      // innermost forward carries the recipient's own key (toXKid), each outer
      // one the routing key of the hop just inside it. The final envelope is
      // anoncrypt'd to routingKeys[0] and transmitted to the service uri. With
      // the common single-key case this produces exactly one forward, identical
      // to before; a recipient advertising several routing keys now routes
      // correctly instead of only through the first.
      let outbound: DidCommJWE = innerJwe
      for (let i = routingKeys.length - 1; i >= 0; i--) {
        const routingKid = routingKeys[i]!
        const next = i === routingKeys.length - 1 ? toXKid : routingKeys[i + 1]!
        const forward = buildPlaintext(FORWARD_TYPE, { next })
        forward.attachments = [{ id: crypto.randomUUID(), data: { json: outbound } }]
        const forwardBytes = new TextEncoder().encode(JSON.stringify(forward))
        const routingRecipient = { kid: routingKid, publicKey: routingKeyPub.get(routingKid)! }
        // i === 0 is the envelope our own mediator opens; inner hops stay
        // anoncrypt regardless, since they are not the party being asked to
        // recognize us (and may not be ours at all).
        outbound = opts.silent && i === 0
          ? packAuthcrypt(forwardBytes, { kid: sender.xKid, privateKey: sender.xPriv }, routingRecipient)
          : packAnoncrypt(forwardBytes, routingRecipient)
      }
      const resp = await fetch(service.serviceEndpoint.uri, {
        method: 'POST',
        headers: { 'content-type': 'application/didcomm-encrypted+json' },
        body: JSON.stringify(outbound),
      })
      if (!resp.ok) throw new Error(`HTTP ${resp.status} ${await resp.text()}`)
      deliveredKids.push(toXKid)
    } catch (e) {
      errors.push(`${toXKid}: ${e instanceof Error ? e.message : String(e)}`)
    }
  }
  const delivered = deliveredKids.length
  if (delivered === 0) throw new Error(`sendDidComm: failed to deliver to any device — ${errors.join('; ')}`)
  // A per-device failure here used to be permanently invisible whenever at
  // least one OTHER device succeeded (the common case: "delivered === 0"
  // never trips, so this never throws) — found live, chasing a report of one
  // specific device silently never receiving anything while its siblings
  // worked fine, with zero errors anywhere in either party's console.
  //
  // Still not a throw: the send to everyone else genuinely succeeded, and this
  // fan-out is best-effort per device by design. But it is now RETURNED rather
  // than only logged, so the caller can tell the person who pressed send that
  // one of the recipient's devices didn't get it — a console warning nobody
  // has open is the same as silence.
  if (errors.length > 0) console.warn(`[didcomm] sendDidComm: delivered to ${delivered}/${toDoc.keyAgreement.length} device(s) — ${errors.join('; ')}`)
  return { delivered, total: toDoc.keyAgreement.length, errors, deliveredKids }
}
