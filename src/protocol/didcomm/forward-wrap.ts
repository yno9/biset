// Anoncrypt-Forward-wraps an already-packed JWE for delivery through a
// registered mediator -- the one piece of logic send-message.ts's two send
// paths (front-door and private-relationship) both needed, previously copied
// in each (feedback: unify common logic rather than let each caller grow its
// own copy, mediator-protocol.ts's own header notes the same past mistake).
//
// A mediator's Forward handler (mediator/server.ts) queues the inner
// attachment for `next` if that is registered directly with IT; relaying on
// to another mediator is relay-poller.ts's job (it polls the upstream hop).
import { packAnoncrypt, type DidCommJWE, type X25519Recipient } from './crypto.ts'
import { buildPlaintext } from './message.ts'
import { FORWARD } from './mediator-protocol.ts'
import { decodePeerDid2, publicKeyOf } from './peer.ts'

/** One hop of a route: a mediator, by the key(s) a Forward to it is
 * anoncrypt'd to. `kid` names the hop (the previous hop's `next`); a mediator
 * with several keyAgreement keys lists them all in `recipients`, and any of
 * them can open the Forward (multiplexed encryption). */
export interface ForwardHop {
  kid: string
  recipients: X25519Recipient[]
}

/** A hop named by a did:peer:2 kid -- self-certifying, so its key is read out
 * of the kid itself with no network resolve. Throws if `kid` is not one. */
export function peerHop(kid: string): ForwardHop {
  const publicKey = publicKeyOf(decodePeerDid2(kid.split('#', 1)[0]!), kid)
  return { kid, recipients: [{ kid, publicKey }] }
}

function wrapForwardTo(inner: DidCommJWE, next: string, hop: ForwardHop): DidCommJWE {
  const forward = buildPlaintext(FORWARD, { next })
  forward.attachments = [{ id: 'inner', data: { json: inner } }]
  return packAnoncrypt(new TextEncoder().encode(JSON.stringify(forward)), hop.recipients)
}

/** Wraps `inner` in a single Routing 2.0 Forward addressed to `next`,
 * anoncrypt'd to `routingKid` (a mediator's own did:peer keyAgreement kid).
 * Throws if `routingKid` does not decode to a valid did:peer kid. */
export function wrapForward(inner: DidCommJWE, next: string, routingKid: string): DidCommJWE {
  return wrapForwardTo(inner, next, peerHop(routingKid))
}

/** Nests one Forward per hop (outermost/closest-to-sender first, DIDComm
 * Routing 2.0's own `routingKeys` semantics) around `inner`, addressed at
 * `recipientDid` -- the recipient's DID, which the last mediator copies to
 * every device inbox of that DID. Built from the LAST hop outward: the
 * innermost Forward names `recipientDid` as `next` and is anoncrypt'd to the
 * last hop; each Forward built after that names the PREVIOUS hop as `next`.
 * The result is what a sender POSTs to the first hop's endpoint -- that hop,
 * and every hop after it, needs no code aware of chaining: each one just
 * Forwards to whatever `next` names.
 *
 * No hops throws -- a caller with no mediator at all delivers `inner` directly. */
export function wrapForwardHops(inner: DidCommJWE, recipientDid: string, hops: readonly ForwardHop[]): DidCommJWE {
  if (hops.length === 0) throw new Error('wrapForwardHops: at least one hop is required')
  let outbound = inner
  let next = recipientDid
  for (let i = hops.length - 1; i >= 0; i--) {
    outbound = wrapForwardTo(outbound, next, hops[i]!)
    next = hops[i]!.kid
  }
  return outbound
}

/** `wrapForwardHops` for a route given as did:peer kids (the `routingKeys` of a
 * service endpoint that names its mediator by URL). */
export function wrapForwardChain(inner: DidCommJWE, recipientDid: string, routingKeys: readonly string[]): DidCommJWE {
  return wrapForwardHops(inner, recipientDid, routingKeys.map(peerHop))
}
