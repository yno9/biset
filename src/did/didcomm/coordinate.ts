// Mediator Coordination Protocol 2.0 client — mediate-request/grant,
// keylist-update. Works for either DIDComm transport identity (PLAN.md
// "DIDComm transport identity"): a per-contact did:peer, or a did:dht
// identity's _k1 key — `own` only needs {did, xKid, xPriv}, so either
// satisfies it structurally (see message.ts's DidCommSender).
import type { PeerDidDoc } from '../peer.ts'
import { sendAndUnpack, type DidCommSender } from './message.ts'

const MEDIATE_REQUEST = 'https://didcomm.org/coordinate-mediation/2.0/mediate-request'
const MEDIATE_GRANT = 'https://didcomm.org/coordinate-mediation/2.0/mediate-grant'
const KEYLIST_UPDATE = 'https://didcomm.org/coordinate-mediation/2.0/keylist-update'
const KEYLIST_UPDATE_RESPONSE = 'https://didcomm.org/coordinate-mediation/2.0/keylist-update-response'
const KEYLIST_QUERY = 'https://didcomm.org/coordinate-mediation/2.0/keylist-query'
const KEYLIST = 'https://didcomm.org/coordinate-mediation/2.0/keylist'

export interface MediatorInfo {
  url: string
  did: string
  doc: PeerDidDoc
}

function trimSlash(u: string): string { return u.replace(/\/$/, '') }

// A mediator's did:peer is baked into its `mediator_url` at deploy time
// (anchor/index.ts's own comment: changing it later strands every registered
// client) — this document is static for all practical purposes. Yet
// ownSender() (channel.ts) re-fetched it fresh on EVERY poll tick and EVERY
// send, adding one full network round trip ahead of the actual pickup/send
// work each time — a steady, avoidable chunk of the "10-20 seconds" latency,
// worst on the receive side where it repeated every poll cycle. Cached
// in-memory per mediatorUrl for the tab's lifetime; a real change to the
// mediator's own identity is an operator-side event rare enough that a reload
// picking it up is fine.
const mediatorInfoCache = new Map<string, MediatorInfo>()

export async function fetchMediatorInfo(mediatorUrl: string): Promise<MediatorInfo> {
  const cached = mediatorInfoCache.get(mediatorUrl)
  if (cached) return cached
  const resp = await fetch(`${trimSlash(mediatorUrl)}/.well-known/did.json`)
  if (!resp.ok) throw new Error(`fetchMediatorInfo: HTTP ${resp.status}`)
  const doc: PeerDidDoc = await resp.json()
  const info = { url: mediatorUrl, did: doc.id, doc }
  mediatorInfoCache.set(mediatorUrl, info)
  return info
}

export interface MediationGrant {
  routingDid: string // the DID that will appear as Forward's target once we register a kid
}

/** mediate-request -> mediate-grant. */
export async function requestMediation(mediator: MediatorInfo, own: DidCommSender): Promise<MediationGrant> {
  const reply = await sendAndUnpack(mediator, own, MEDIATE_REQUEST, {})
  if (reply.type !== MEDIATE_GRANT) throw new Error(`requestMediation: unexpected reply type ${reply.type}`)
  const body = reply.body as { routing_did?: string }
  if (!body.routing_did) throw new Error('requestMediation: mediate-grant missing routing_did')
  return { routingDid: body.routing_did }
}

/** keylist-update: register (or remove) one recipient kid — normally our own
 * xKid, so the mediator will queue Forward messages addressed to it. */
export async function updateKeylist(mediator: MediatorInfo, own: DidCommSender, recipientKid: string, action: 'add' | 'remove'): Promise<void> {
  const reply = await sendAndUnpack(mediator, own, KEYLIST_UPDATE, { updates: [{ recipient_did: recipientKid, action }] })
  if (reply.type !== KEYLIST_UPDATE_RESPONSE) throw new Error(`updateKeylist: unexpected reply type ${reply.type}`)
  const updated = (reply.body as { updated?: Array<{ recipient_did: string; result: string }> }).updated ?? []
  const entry = updated.find(u => u.recipient_did === recipientKid)
  if (!entry || entry.result !== 'success') throw new Error(`updateKeylist: mediator did not confirm ${recipientKid}`)
}

/** keylist-query -> keylist: the kids the mediator currently has registered
 * for THIS identity (every device of it shares one clientDid, so this is the
 * authoritative live-device set). Returns full kid URLs (`did#kN`). syncDevice
 * Position uses it to drop a keyAgreementKey the mediator no longer lists — a
 * logged-out sibling — so a removal converges across every device instead of
 * being resurrected from a stale sibling cache. Throws on any transport or
 * protocol failure: a caller MUST distinguish "the mediator says this kid is
 * gone" from "couldn't ask" and never prune on the latter. */
export async function queryKeylist(mediator: MediatorInfo, own: DidCommSender): Promise<string[]> {
  const reply = await sendAndUnpack(mediator, own, KEYLIST_QUERY, {})
  if (reply.type !== KEYLIST) throw new Error(`queryKeylist: unexpected reply type ${reply.type}`)
  const keys = (reply.body as { keys?: Array<{ recipient_did: string }> }).keys ?? []
  return keys.map(k => k.recipient_did)
}
