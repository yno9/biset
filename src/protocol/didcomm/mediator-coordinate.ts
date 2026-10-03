// Mediator Coordination Protocol 2.0 client -- mediate-request/grant,
// keylist-update/keylist-query. Ported from src.bak/did/didcomm/coordinate.ts,
// trimmed of the Web Push extension (deferred, ARC.md's Phase 3 minimum).
import { sendAndUnpack, type DidCommSender, type MediatorInboxClient, type MediatorInfo } from './mediator-transport.ts'
import { defaultFetch } from '../net-fetch.ts'
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

/** keylist-update: opens (or removes) this device's inbox for `inbox.did`.
 * Sent from `inbox.did`'s own key -- that is the mediator's proof this
 * device owns the DID. A refusal because the DID already has the
 * mediator's maximum of devices arrives as a DidCommProblemError with code
 * MAX_DEVICES_PROBLEM. `device` defaults to the client's own inbox; any
 * device of the DID may remove a sibling's inbox by naming its label. */
export async function updateKeylist(mediator: MediatorInfo, inbox: MediatorInboxClient, action: 'add' | 'remove', fetchImpl: typeof fetch = defaultFetch(), device = inbox.device): Promise<void> {
  const reply = await sendAndUnpack(mediator, inbox, KEYLIST_UPDATE, { device, updates: [{ recipient_did: inbox.did, action }] }, fetchImpl)
  if (reply.type !== KEYLIST_UPDATE_RESPONSE) throw new Error(`updateKeylist: unexpected reply type ${reply.type}`)
  const updated = (reply.body as { updated?: Array<{ recipient_did: string; result: string }> }).updated ?? []
  const entry = updated.find(u => u.recipient_did === inbox.did)
  // `no_change` is a success for our purposes and MUST be accepted: the
  // mediator reports it when the keylist was already in the requested
  // state -- the registration loop (Phase 4's self-heal) re-adds this kid
  // on every boot on purpose, which is the ordinary case, not the
  // exception.
  if (!entry || (entry.result !== 'success' && entry.result !== 'no_change')) {
    throw new Error(`updateKeylist: mediator did not confirm ${inbox.did} (${entry?.result ?? 'no result'})`)
  }
}

/** keylist-query -> keylist: every device inbox the mediator holds for the
 * sender's own DID, with each one's last pickup -- what a user needs to see
 * to decide which device to remove when the limit is reached. Throws on
 * any transport or protocol failure: never prune on "couldn't ask". */
export interface KeylistEntry {
  device: string
  /** Epoch ms of that inbox's last pickup (or its registration). */
  lastSeen: number
}

export async function queryKeylist(mediator: MediatorInfo, own: DidCommSender, fetchImpl: typeof fetch = defaultFetch()): Promise<KeylistEntry[]> {
  const reply = await sendAndUnpack(mediator, own, KEYLIST_QUERY, {}, fetchImpl)
  if (reply.type !== KEYLIST) throw new Error(`queryKeylist: unexpected reply type ${reply.type}`)
  const keys = (reply.body as { keys?: Array<{ device?: unknown; last_seen?: unknown }> }).keys ?? []
  return keys.flatMap(k => typeof k.device === 'string' && typeof k.last_seen === 'number' ? [{ device: k.device, lastSeen: k.last_seen }] : [])
}

/** Hands this DID's did:webvh log to the mediator (`POST /webvh-log`), which
 * authenticates did:webvh device keys only against the latest log it has
 * verified. Self-certifying, so sending it needs no authentication. A
 * newer log is also how a removed device's inbox gets revoked. */
export async function pushWebvhLog(mediator: MediatorInfo, logJsonl: string, fetchImpl: typeof fetch = defaultFetch()): Promise<void> {
  const resp = await fetchImpl(`${mediator.url.replace(/\/$/, '')}/webvh-log`, { method: 'POST', headers: { 'content-type': 'application/jsonl' }, body: logJsonl })
  if (!resp.ok) throw new Error(`pushWebvhLog: HTTP ${resp.status} ${await resp.text()}`)
}
