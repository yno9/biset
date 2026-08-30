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
