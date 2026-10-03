// Coordinate Mediation 3.0 client -- mediate-request/grant,
// recipient-update/recipient-query. Every request asks for its answer on the
// same connection (`return_route: "all"`, mediator-transport.ts).
import { sendAndUnpack, type DidCommSender, type MediatorInboxClient, type MediatorInfo } from './mediator-transport.ts'
import { defaultFetch } from '../net-fetch.ts'
import { MEDIATE_REQUEST, MEDIATE_GRANT, RECIPIENT_UPDATE, RECIPIENT_UPDATE_RESPONSE, RECIPIENT_QUERY, RECIPIENT } from './mediator-protocol.ts'

export { fetchMediatorInfo, type MediatorInfo } from './mediator-transport.ts'

export interface MediationGrant {
  /** The DIDs a sender's Forward goes through to reach us, outermost
   * first -- here just this mediator's own DID. */
  routingDids: string[]
}

/** mediate-request -> mediate-grant. */
export async function requestMediation(mediator: MediatorInfo, own: DidCommSender, fetchImpl: typeof fetch = defaultFetch()): Promise<MediationGrant> {
  const reply = await sendAndUnpack(mediator, own, MEDIATE_REQUEST, {}, fetchImpl)
  if (reply.type !== MEDIATE_GRANT) throw new Error(`requestMediation: unexpected reply type ${reply.type}`)
  const routing = (reply.body as { routing_did?: unknown }).routing_did
  if (!Array.isArray(routing) || routing.length === 0 || routing.some(did => typeof did !== 'string')) throw new Error('requestMediation: mediate-grant has no routing_did')
  return { routingDids: routing as string[] }
}

/** recipient-update: opens (or removes) this device's inbox for `inbox.did`.
 * Sent from `inbox.did`'s own key -- that is the mediator's proof this
 * device owns the DID. A refusal because the DID already has the
 * mediator's maximum of devices arrives as a DidCommProblemError with code
 * MAX_DEVICES_PROBLEM. */
export async function updateRecipient(mediator: MediatorInfo, inbox: MediatorInboxClient, action: 'add' | 'remove', fetchImpl: typeof fetch = defaultFetch()): Promise<void> {
  const reply = await sendAndUnpack(mediator, inbox, RECIPIENT_UPDATE, { device: inbox.device, updates: [{ recipient_did: inbox.did, action }] }, fetchImpl)
  if (reply.type !== RECIPIENT_UPDATE_RESPONSE) throw new Error(`updateRecipient: unexpected reply type ${reply.type}`)
  const updated = (reply.body as { updated?: Array<{ recipient_did: string; result: string }> }).updated ?? []
  const entry = updated.find(u => u.recipient_did === inbox.did)
  // `no_change` is a success: registration re-adds this inbox on every boot
  // on purpose (self-heal), so "already there" is the ordinary case.
  if (!entry || (entry.result !== 'success' && entry.result !== 'no_change')) {
    throw new Error(`updateRecipient: mediator did not confirm ${inbox.did} (${entry?.result ?? 'no result'})`)
  }
}

/** One device inbox the mediator holds for the sender's own DID: when it
 * was last used -- what a user needs to see when the device limit is
 * reached. (Which device it is the mediator does not say; see server.ts.) */
export interface RecipientEntry {
  /** Epoch ms of that inbox's last pickup (or its registration). */
  lastSeen: number
}

/** recipient-query -> recipient. Throws on any transport or protocol
 * failure: never prune on "couldn't ask". */
export async function queryRecipients(mediator: MediatorInfo, own: DidCommSender, fetchImpl: typeof fetch = defaultFetch()): Promise<RecipientEntry[]> {
  const reply = await sendAndUnpack(mediator, own, RECIPIENT_QUERY, {}, fetchImpl)
  if (reply.type !== RECIPIENT) throw new Error(`queryRecipients: unexpected reply type ${reply.type}`)
  const dids = (reply.body as { dids?: Array<{ last_seen?: unknown }> }).dids ?? []
  return dids.flatMap(entry => typeof entry.last_seen === 'number' ? [{ lastSeen: entry.last_seen }] : [])
}

/** Hands this DID's did:webvh log to the mediator (`POST /webvh-log`), which
 * authenticates did:webvh device keys only against the latest log it has
 * verified. Self-certifying, so sending it needs no authentication. A
 * newer log is also how a removed device's inbox gets revoked. */
export async function pushWebvhLog(mediator: MediatorInfo, logJsonl: string, fetchImpl: typeof fetch = defaultFetch()): Promise<void> {
  const resp = await fetchImpl(`${mediator.url.replace(/\/$/, '')}/webvh-log`, { method: 'POST', headers: { 'content-type': 'application/jsonl' }, body: logJsonl })
  if (!resp.ok) throw new Error(`pushWebvhLog: HTTP ${resp.status} ${await resp.text()}`)
}
