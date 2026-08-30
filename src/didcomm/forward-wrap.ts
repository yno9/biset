// Anoncrypt-Forward-wraps an already-packed JWE for delivery through a
// registered mediator -- the one piece of logic send-message.ts's two send
// paths (front-door and private-relationship) both needed, previously copied
// in each (feedback: unify common logic rather than let each caller grow its
// own copy, mediator-protocol.ts's own header notes the same past mistake).
//
// One hop only: a mediator's Forward handler (mediator/server.ts) queues the
// inner attachment for `next` if that kid is a connection registered
// directly with IT, and does not itself relay further to another mediator's
// URL. Multi-hop (ARC.md's onion-routing discussion) is not this function's
// job -- it would need an active relay client polling the upstream hop and
// re-forwarding, a separate component neither this helper nor the mediator's
// own dispatch loop implements yet.
import { packAnoncrypt, type DidCommJWE } from './crypto.ts'
import { buildPlaintext } from './message.ts'
import { FORWARD } from './mediator-protocol.ts'
import { decodePeerDid2, publicKeyOf } from './peer.ts'

/** Wraps `inner` in a single Routing 2.0 Forward addressed to `next`,
 * anoncrypt'd to `routingKid` (a mediator's own did:peer keyAgreement kid --
 * self-certifying, decoded here with no network resolve). Throws if
 * `routingKid` does not decode to a valid did:peer kid. */
export function wrapForward(inner: DidCommJWE, next: string, routingKid: string): DidCommJWE {
  const mediatorPublicKey = publicKeyOf(decodePeerDid2(routingKid.split('#', 1)[0]!), routingKid)
  const forward = buildPlaintext(FORWARD, { next })
  forward.attachments = [{ id: 'inner', data: { json: inner } }]
  return packAnoncrypt(new TextEncoder().encode(JSON.stringify(forward)), { kid: routingKid, publicKey: mediatorPublicKey })
}

/** Nests one Forward per entry in `routingKeys` (webvh-routing.ts's own
 * ordering: outermost/closest-to-sender first, same as DIDComm Routing
 * 2.0's own `routingKeys` semantics) around `inner`, addressed at
 * `finalKid` -- the recipient's real keyAgreement kid. Building from the
 * LAST entry outward: the innermost Forward names `finalKid` as `next` and
 * is anoncrypt'd to `routingKeys[routingKeys.length - 1]`; each Forward
 * built after that names the PREVIOUS hop's kid as `next`. The result is
 * what a sender POSTs to `routingKeys[0]`'s own published endpoint --
 * that hop, and every hop after it, needs no code aware of chaining (the
 * 2026-08-30 hop-chain discussion): each one just Forwards to whatever
 * `next` names, which for every hop but the last is another hop's kid, and
 * for the last is the real recipient's.
 *
 * `routingKeys.length === 0` throws -- a caller with no mediator at all
 * should skip calling this and deliver `inner` directly, same as
 * send-message.ts's own `mediatorRoutingKid` check. */
export function wrapForwardChain(inner: DidCommJWE, finalKid: string, routingKeys: readonly string[]): DidCommJWE {
  if (routingKeys.length === 0) throw new Error('wrapForwardChain: at least one routing key is required')
  let outbound = inner
  let next = finalKid
  for (let i = routingKeys.length - 1; i >= 0; i--) {
    outbound = wrapForward(outbound, next, routingKeys[i]!)
    next = routingKeys[i]!
  }
  return outbound
}
