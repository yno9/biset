// Mediator Coordination Protocol 2.0 client -- mediate-request/grant,
// keylist-update/keylist-query. Ported from src.bak/did/didcomm/coordinate.ts,
// trimmed of the Web Push extension (deferred, ARC.md's Phase 3 minimum).
import { sendAndUnpack, type DidCommSender, type MediatorInfo } from './mediator-transport.ts'
import { defaultFetch } from '../../client/app/net-fetch.ts'
import { MEDIATE_REQUEST, MEDIATE_GRANT, KEYLIST_UPDATE, KEYLIST_UPDATE_RESPONSE, KEYLIST_QUERY, KEYLIST } from './mediator-protocol.ts'

export { fetchMediatorInfo, type MediatorInfo } from './mediator-transport.ts'

export interface MediationGrant {
  /** The DID that will appear as Forward's `next` target once we register
   * a kid -- always this mediator's own DID (routing IS the mediator here,
   * there is no multi-hop chain in this deployment). */
  routingDid: string
}

/** mediate-request -> mediate-grant. */
export async function requestMediation(mediator: MediatorInfo, own: DidCommSender, fetchImpl: typeof fetch = defaultFetch()): Promise<MediationGrant> {
  const reply = await sendAndUnpack(mediator, own, MEDIATE_REQUEST, {}, fetchImpl)
  if (reply.type !== MEDIATE_GRANT) throw new Error(`requestMediation: unexpected reply type ${reply.type}`)
  const body = reply.body as { routing_did?: string }
  if (!body.routing_did) throw new Error('requestMediation: mediate-grant missing routing_did')
  return { routingDid: body.routing_did }
}

/** keylist-update: register (or remove) one recipient kid -- normally our
 * own didCommKid, so the mediator will queue Forward messages addressed to
 * it. */
export async function updateKeylist(mediator: MediatorInfo, own: DidCommSender, recipientKid: string, action: 'add' | 'remove', fetchImpl: typeof fetch = defaultFetch()): Promise<void> {
  const reply = await sendAndUnpack(mediator, own, KEYLIST_UPDATE, { updates: [{ recipient_did: recipientKid, action }] }, fetchImpl)
  if (reply.type !== KEYLIST_UPDATE_RESPONSE) throw new Error(`updateKeylist: unexpected reply type ${reply.type}`)
  const updated = (reply.body as { updated?: Array<{ recipient_did: string; result: string }> }).updated ?? []
  const entry = updated.find(u => u.recipient_did === recipientKid)
  // `no_change` is a success for our purposes and MUST be accepted: the
  // mediator reports it when the keylist was already in the requested
  // state -- the registration loop (Phase 4's self-heal) re-adds this kid
  // on every boot on purpose, which is the ordinary case, not the
  // exception.
  if (!entry || (entry.result !== 'success' && entry.result !== 'no_change')) {
    throw new Error(`updateKeylist: mediator did not confirm ${recipientKid} (${entry?.result ?? 'no result'})`)
  }
}

/** keylist-query -> keylist: the kids the mediator currently has
 * registered for THIS identity (every device shares one clientDid, so this
 * is the authoritative live-device set). Throws on any transport or
 * protocol failure: a caller MUST distinguish "the mediator says this kid
 * is gone" from "couldn't ask" and never prune on the latter. */
export interface KeylistEntry {
  /** Full kid URL. */
  kid: string
  /** Epoch ms of that device's last pickup, per the mediator's own record
   * (`last_seen`, biset's additive extension to the keylist entry). Absent
   * for a mediator that doesn't send it, and for a kid that has never
   * picked anything up: both mean "no evidence either way", never "dead". */
  lastSeen?: number
}

export async function queryKeylist(mediator: MediatorInfo, own: DidCommSender, fetchImpl: typeof fetch = defaultFetch()): Promise<KeylistEntry[]> {
  const reply = await sendAndUnpack(mediator, own, KEYLIST_QUERY, {}, fetchImpl)
  if (reply.type !== KEYLIST) throw new Error(`queryKeylist: unexpected reply type ${reply.type}`)
  const keys = (reply.body as { keys?: Array<{ recipient_did: string; last_seen?: number }> }).keys ?? []
  return keys.map(k => (typeof k.last_seen === 'number' ? { kid: k.recipient_did, lastSeen: k.last_seen } : { kid: k.recipient_did }))
}
