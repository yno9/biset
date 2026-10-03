// Outbound DIDComm send: resolve the recipient's DID document (keyAgreement
// key + DIDCommMessaging service endpoint), authcrypt a Basic Message 2.0
// JWE to their kid, then -- when they've registered with a mediator
// (webvh-routing.ts's `routingKeys`) -- anoncrypt-Forward-wrap it and POST
// to the mediator instead of delivering directly (ARC.md's 2026-08-27
// redesign). Network-only, mirroring core/adapters/mail-smtp-client.ts's own
// split (that module dials out; identity/bootstrap.ts's buildMailSubmitter
// does the vault-commit side separately) -- the local "sent" copy is the
// caller's job, via the already-generic local-jmap/vault-mutation-sink.ts's
// commitMailMessage (no DIDComm-specific vault-commit code needed: a chat
// message's local echo is exactly the same message.add shape mail's own
// sendReply already commits).
import { didCommPost, packAuthcrypt, type DidCommJWE } from '../../protocol/didcomm/crypto.ts'
import { PING_RESPONSE, isPing, responseOwedFor } from '../../protocol/didcomm/trust-ping.ts'
import { buildPlaintext, type DidCommPlaintext } from '../../protocol/didcomm/message.ts'
import { BASIC_MESSAGE } from './basicmessage.ts'
import { wrapForward } from '../../protocol/didcomm/forward-wrap.ts'
import { decodePeerDid2, deriveRelationshipPeerIdentity, publicKeyOf, type PeerIdentity } from '../../protocol/didcomm/peer.ts'
import { defaultFetch } from '../../protocol/net-fetch.ts'
import { registerWithMediator } from './mediator-sync.ts'
import { mediatorInbox } from '../../protocol/didcomm/mediator-device.ts'
import {
  RELATIONSHIP_ACCEPT,
  RELATIONSHIP_INIT,
  relationshipBodyToWire,
  relationshipMediatorService,
} from './relationship.ts'
import { GROUP_INVITE, GROUP_MESSAGE, type GroupInviteBody, type GroupMessageBody } from './group-chat.ts'
import type { ContactKeyV1 } from '../store/vault/contact-key.ts'
import type { DidCommSender } from '../../protocol/didcomm/mediator-transport.ts'
import { x25519 } from '@noble/curves/ed25519.js'
import { frontDoorMediatorRoute, sendFrontDoorMessage, type DidCommSendResult, type SendDidCommMessageOptions } from './front-door-send.ts'

export { type DidCommSendResult, type SendDidCommMessageOptions }

interface PendingRelationship {
  counterpartyDid: string
  peer: PeerIdentity
  mediatorUrl: string
}

export type RelationshipInitiationResult =
  | { ok: true; pending: PendingRelationship }
  | { ok: false; error: string }

/** Sends a chat message to `toDid`. Resolves the recipient's CURRENT
 * keyAgreement key fresh on every send (no caching) -- correctness over
 * speed for a message that only sends once. Picks the first published
 * keyAgreement entry when the recipient has more than one (multi-device):
 * PLAN.md §6.1's per-device-fanout ban means this project deliberately does
 * not address every device individually, and the recipient side's own
 * multidevice-ingress handling (any trusted device may claim the resulting
 * ingress item) is what actually delivers it, same as mail addressed to one
 * identity reaches every device that pulls it. */
export async function sendDidCommMessage(toDid: string, content: string, opts: SendDidCommMessageOptions): Promise<DidCommSendResult> {
  return sendFrontDoorMessage(toDid, BASIC_MESSAGE, {
    content, sentAt: new Date().toISOString(), ...(opts.subject ? { subject: opts.subject } : {}),
  }, opts)
}

/** Registers this counterparty's deterministically-derived private did:peer
 * before advertising it in INIT. This ordering is required: ACCEPT is
 * addressed to this kid and cannot be queued by the mediator until the
 * recipient has enrolled it. Deriving (not minting a random identity) means
 * a retry -- after a reload, a second concurrent send racing this one, or
 * the SAME Wallet identity's OTHER device racing this one -- recomputes the
 * exact same did:peer rather than orphaning the first attempt (peer.ts's
 * `deriveRelationshipPeerIdentity`); `relationshipSeed` (not `opts`'s own
 * per-device front-door key) is what makes that hold across devices, not
 * just across retries on this one. `opts` still supplies THIS device's own
 * front-door identity for the INIT envelope itself, via `sendFrontDoorMessage`
 * below. */
export async function initiateRelationship(toDid: string, relationshipSeed: Uint8Array, opts: SendDidCommMessageOptions & { mediatorDeviceSecret: Uint8Array }): Promise<RelationshipInitiationResult> {
  const fetchImpl = opts.fetch ?? defaultFetch()
  let route: { url: string; routingKid: string }
  try {
    route = await frontDoorMediatorRoute(toDid, fetchImpl)
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : String(error) }
  }
  const peer = deriveRelationshipPeerIdentity(relationshipSeed, toDid, route.routingKid)
  try {
    await registerWithMediator(route.url, mediatorInbox({ did: peer.did, xKid: peer.xKid, xPriv: peer.xPriv }, opts.mediatorDeviceSecret), fetchImpl)
  } catch (error) {
    return { ok: false, error: `could not register private relationship key: ${error instanceof Error ? error.message : String(error)}` }
  }
  const sent = await sendFrontDoorMessage(toDid, RELATIONSHIP_INIT, relationshipBodyToWire({ relationshipKid: peer.xKid, publicKey: peer.xPub }), opts)
  return sent.ok ? { ok: true, pending: { counterpartyDid: toDid, peer, mediatorUrl: route.url } } : sent
}

/** Sends chat content only through an already-established private route. */
export async function sendRelationshipMessage(
  contactKey: ContactKeyV1,
  content: string,
  subject?: string,
  fetchImpl: typeof fetch = defaultFetch(),
  message?: { id: string; sentAt: string },
): Promise<DidCommSendResult> {
  return sendPrivateRelationshipMessage(contactKey, BASIC_MESSAGE, {
    content, sentAt: message?.sentAt ?? new Date().toISOString(), ...(subject ? { subject } : {}),
  }, fetchImpl, message ? { id: message.id, createdTime: Math.floor(Date.parse(message.sentAt) / 1000) } : undefined)
}

/** The answer to a counterparty's INIT: this side's relationship did:peer,
 * sent over the front door like the INIT itself, so the counterparty knows
 * it came from a device in this identity's DID document -- not from anyone
 * who merely saw the INIT's did:peer (its mediator, say) and answered first. */
export async function sendRelationshipAccept(contactKey: ContactKeyV1, opts: SendDidCommMessageOptions): Promise<DidCommSendResult> {
  return sendFrontDoorMessage(contactKey.counterpartyDid, RELATIONSHIP_ACCEPT, relationshipBodyToWire({
    relationshipKid: contactKey.ownRelationshipKid,
    publicKey: x25519.getPublicKey(contactKey.ownX25519PrivateKey),
  }), opts)
}

/** DIDComm group chat (group-chat.ts): both control/content types ride the
 * SAME established pairwise relationship channel every ordinary 1:1
 * message does -- unlike Conversation Groups' own invite (which goes over
 * the front door, since MLS's own crypto is what establishes membership
 * there), full-mesh group chat already REQUIRES a pairwise ContactKeyV1
 * with every member before anything group-related can happen, so there is
 * no separate bootstrap channel to reach for. */
export async function sendGroupInvite(contactKey: ContactKeyV1, body: GroupInviteBody, fetchImpl: typeof fetch = defaultFetch()): Promise<DidCommSendResult> {
  return sendPrivateRelationshipMessage(contactKey, GROUP_INVITE, body, fetchImpl)
}

export async function sendGroupChatMessage(
  contactKey: ContactKeyV1,
  body: GroupMessageBody,
  fetchImpl: typeof fetch = defaultFetch(),
  message?: { id: string; sentAt: string },
): Promise<DidCommSendResult> {
  return sendPrivateRelationshipMessage(contactKey, GROUP_MESSAGE, body, fetchImpl, message ? { id: message.id, createdTime: Math.floor(Date.parse(message.sentAt) / 1000) } : undefined)
}

/** Trust Ping 2.0: answers a received ping that asked for a response
 * (the default), threaded to it, on the channel it arrived on -- the
 * relationship whose did:peer it was addressed to, else this identity's
 * front door. Null when no answer is owed. */
export async function answerTrustPing(
  ping: DidCommPlaintext,
  recipientKid: string,
  options: {
    contactKeyForOwnKid(kid: string): Promise<ContactKeyV1 | null>
    frontDoor: { fromKid: string; x25519PrivateKey: Uint8Array }
    fetch?: typeof fetch
  },
): Promise<DidCommSendResult | null> {
  if (!isPing(ping) || !responseOwedFor(ping) || typeof ping.from !== 'string') return null
  const fetchImpl = options.fetch ?? defaultFetch()
  const contactKey = await options.contactKeyForOwnKid(recipientKid)
  if (contactKey) return sendPrivateRelationshipMessage(contactKey, PING_RESPONSE, {}, fetchImpl, { thid: ping.id })
  return sendFrontDoorMessage(ping.from, PING_RESPONSE, {}, { ...options.frontDoor, thid: ping.id, fetch: fetchImpl })
}

async function sendPrivateRelationshipMessage(contactKey: ContactKeyV1, type: string, body: unknown, fetchImpl: typeof fetch, message?: { id?: string; createdTime?: number; thid?: string }): Promise<DidCommSendResult> {
  let route: ReturnType<typeof relationshipMediatorService>
  let recipientPublicKey: Uint8Array
  try {
    route = relationshipMediatorService(contactKey.counterpartyRelationshipKid)
    const counterpartyDid = contactKey.counterpartyRelationshipKid.split('#', 1)[0]!
    recipientPublicKey = publicKeyOf(decodePeerDid2(counterpartyDid), contactKey.counterpartyRelationshipKid)
  } catch (error) {
    return { ok: false, error: `private relationship route is invalid: ${error instanceof Error ? error.message : String(error)}` }
  }
  const ownDid = contactKey.ownRelationshipKid.split('#', 1)[0]!
  const recipientDid = contactKey.counterpartyRelationshipKid.split('#', 1)[0]!
  const plaintext = buildPlaintext(type, body, ownDid, recipientDid, { ...message })
  const inner = packAuthcrypt(
    new TextEncoder().encode(JSON.stringify(plaintext)),
    { kid: contactKey.ownRelationshipKid, privateKey: contactKey.ownX25519PrivateKey },
    [{ kid: contactKey.counterpartyRelationshipKid, publicKey: recipientPublicKey }],
  )
  let outbound: DidCommJWE
  try {
    outbound = wrapForward(inner, recipientDid, route.routingKid)
  } catch {
    return { ok: false, error: 'private relationship mediator routing kid is invalid' }
  }
  const controller = new AbortController(); const timeout = setTimeout(() => controller.abort(), 15_000)
  let response: Response
  try { response = await fetchImpl(route.url, didCommPost(outbound, controller.signal)) }
  catch (error) { return { ok: false, error: controller.signal.aborted ? 'send timed out after 15 seconds' : `send failed: ${error instanceof Error ? error.message : String(error)}` } }
  finally { clearTimeout(timeout) }
  if (response.status !== 202) return { ok: false, error: `send failed: HTTP ${response.status} ${(await response.text().catch(() => '')).slice(0, 256)}` }
  return { ok: true }
}
