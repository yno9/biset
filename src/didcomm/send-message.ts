// Outbound DIDComm send: resolve the recipient's routing.json (keyAgreement
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
import { resolveWithRouting } from './webvh-resolve.ts'
import { decodeX25519Multikey, decodeMlkem768Multikey } from './multikey.ts'
import { packAuthcrypt, packAuthcryptHybrid, type DidCommJWE } from './crypto.ts'
import { mlkemKidFor } from './devicekid.ts'
import { buildPlaintext } from './message.ts'
import { BASIC_MESSAGE } from './basicmessage.ts'
import { wrapForward, wrapForwardChain } from './forward-wrap.ts'
import { decodePeerDid2, generatePeerIdentity, publicKeyOf, type PeerIdentity } from './peer.ts'
import type { DidCommServiceEndpoint } from './webvh-routing.ts'
import { defaultFetch } from '../net-fetch.ts'
import { registerWithMediator } from './mediator-sync.ts'
import {
  RELATIONSHIP_INIT,
  relationshipBodyToWire,
  relationshipMediatorService,
} from './relationship.ts'
import type { ContactKeyV1 } from '../vault/contact-key.ts'
import type { DidCommSender } from './mediator-transport.ts'
import { x25519 } from '@noble/curves/ed25519.js'

export type DidCommSendResult = { ok: true } | { ok: false; error: string }

export interface SendDidCommMessageOptions {
  /** This device's own DIDComm kid (identity/bootstrap.ts's `enableDidComm`
   * -- didcomm/devicekid.ts's deviceKidFragment, distinct from the MLS
   * leaf's own deviceKid). */
  fromKid: string
  x25519PrivateKey: Uint8Array
  subject?: string
  fetch?: typeof fetch
}

export interface PendingRelationship {
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

/** Registers a fresh private did:peer before advertising it in INIT. This
 * ordering is required: ACCEPT is addressed to this kid and cannot be queued
 * by the mediator until the recipient has enrolled it. */
export async function initiateRelationship(toDid: string, opts: SendDidCommMessageOptions): Promise<RelationshipInitiationResult> {
  const fetchImpl = opts.fetch ?? defaultFetch()
  let route: { url: string; routingKid: string }
  try {
    route = await frontDoorMediatorRoute(toDid, fetchImpl)
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : String(error) }
  }
  const peer = generatePeerIdentity({ uri: route.url, routingKeys: [route.routingKid] })
  const own: DidCommSender = { did: peer.did, xKid: peer.xKid, xPriv: peer.xPriv }
  try {
    await registerWithMediator(route.url, own, fetchImpl)
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

export async function sendRelationshipAccept(contactKey: ContactKeyV1, fetchImpl: typeof fetch = defaultFetch()): Promise<DidCommSendResult> {
  return sendPrivateRelationshipMessage(contactKey, 'https://biset.md/relationship/1.0/accept', relationshipBodyToWire({
    relationshipKid: contactKey.ownRelationshipKid,
    publicKey: x25519.getPublicKey(contactKey.ownX25519PrivateKey),
  }), fetchImpl)
}

/** The generic "resolve routing.json, authcrypt (Forward-wrapped if the
 * recipient registered a mediator), POST" primitive `sendDidCommMessage`/
 * `initiateRelationship` are thin wrappers around -- exported so a caller
 * needing an arbitrary `type`/`body` (mls-ds/fanout.ts's `message-notify`
 * delivery, mls-ds-1.0.md §5.2) doesn't have to reimplement routing.json
 * resolution and Forward-wrapping to get one. */
export async function sendFrontDoorMessage(toDid: string, type: string, body: unknown, opts: SendDidCommMessageOptions): Promise<DidCommSendResult> {
  const fetchImpl = opts.fetch ?? defaultFetch()
  let doc: Awaited<ReturnType<typeof resolveWithRouting>>
  try {
    doc = await resolveWithRouting(toDid, fetchImpl)
  } catch (error) {
    return { ok: false, error: `could not resolve ${toDid}: ${error instanceof Error ? error.message : String(error)}` }
  }
  if (!doc) return { ok: false, error: `${toDid} does not resolve to a published identity` }

  const service = doc.service.find(s => s.type === 'DIDCommMessaging')
  const serviceEndpoint = service?.serviceEndpoint
  const endpoint = serviceEndpoint && typeof serviceEndpoint === 'object' && !Array.isArray(serviceEndpoint)
    ? (serviceEndpoint as Partial<DidCommServiceEndpoint>)
    : undefined
  if (!endpoint || typeof endpoint.uri !== 'string' || !endpoint.uri) return { ok: false, error: `${toDid} has no DIDComm service endpoint published` }
  // A non-empty routingKeys (webvh-routing.ts's own header) means the
  // recipient has registered with an independent, blind mediator: deliver
  // Forward-wrapped through it rather than authcrypt'ing straight to
  // `endpoint.uri` (the legacy first-party-infra model, still supported for
  // an identity that hasn't migrated yet). The full array is a hop chain
  // (forward-wrap.ts's `wrapForwardChain`, outermost/closest-to-sender
  // first) -- not just its first entry.
  const routingKeys = endpoint.routingKeys ?? []

  const keyAgreementIds = new Set(doc.keyAgreement ?? [])
  const kaVm = doc.verificationMethod.find(v => keyAgreementIds.has(v.id))
  if (!kaVm) return { ok: false, error: `${toDid} has no keyAgreement key published -- they need to enable DIDComm first` }
  let recipientPublicKey: Uint8Array
  try {
    recipientPublicKey = decodeX25519Multikey(kaVm.publicKeyMultibase)
  } catch {
    return { ok: false, error: `${toDid}'s published keyAgreement key is not a valid X25519 key` }
  }

  const plaintext = buildPlaintext(type, body, opts.fromKid.split('#', 1)[0], toDid)
  const plaintextBytes = new TextEncoder().encode(JSON.stringify(plaintext))
  const sender = { kid: opts.fromKid, privateKey: opts.x25519PrivateKey }

  // Upgrade to the hybrid X25519+ML-KEM-768 authcrypt whenever the recipient
  // published an ML-KEM entry alongside their X25519 one (mlkemKidFor's
  // naming convention -- devicekid.ts) -- this is the only production path
  // that ever reaches packAuthcryptHybrid; without it the fully-implemented,
  // tested PQ-hybrid mode was unreachable and every message stayed exposed
  // to harvest-now-decrypt-later even between two devices that both
  // supported it (found live, 2026-08-26). Falls back to classical authcrypt
  // on any malformed mlkem entry rather than failing the send outright.
  let mlkemVm: (typeof doc.verificationMethod)[number] | undefined
  try {
    const mlkemId = mlkemKidFor(kaVm.id)
    mlkemVm = doc.verificationMethod.find(v => v.id === mlkemId)
  } catch {
    mlkemVm = undefined
  }
  let jwe: DidCommJWE
  if (mlkemVm) {
    try {
      const mlkemPublicKey = decodeMlkem768Multikey(mlkemVm.publicKeyMultibase)
      jwe = packAuthcryptHybrid(plaintextBytes, sender, { kid: kaVm.id, x25519PublicKey: recipientPublicKey, mlkemPublicKey })
    } catch {
      jwe = packAuthcrypt(plaintextBytes, sender, { kid: kaVm.id, publicKey: recipientPublicKey })
    }
  } else {
    jwe = packAuthcrypt(plaintextBytes, sender, { kid: kaVm.id, publicKey: recipientPublicKey })
  }
  let outbound: DidCommJWE = jwe
  if (routingKeys.length > 0) {
    try {
      outbound = wrapForwardChain(jwe, kaVm.id, routingKeys)
    } catch {
      return { ok: false, error: `${toDid}'s registered mediator routing keys (${routingKeys.join(', ')}) are not valid did:peer kids` }
    }
  }
  const response = await fetchImpl(endpoint.uri, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(outbound) })
  if (response.status !== 202) {
    return { ok: false, error: `send failed: HTTP ${response.status} ${(await response.text().catch(() => '')).slice(0, 256)}` }
  }
  return { ok: true }
}

async function frontDoorMediatorRoute(toDid: string, fetchImpl: typeof fetch): Promise<{ url: string; routingKid: string }> {
  const doc = await resolveWithRouting(toDid, fetchImpl)
  if (!doc) throw new Error(`${toDid} does not resolve to a published identity`)
  const service = doc.service.find(value => value.type === 'DIDCommMessaging')
  const endpoint = service?.serviceEndpoint
  if (!endpoint || typeof endpoint !== 'object' || Array.isArray(endpoint)) throw new Error(`${toDid} has no DIDComm mediator service published`)
  const value = endpoint as Partial<DidCommServiceEndpoint>
  if (!value.uri || !value.routingKeys?.[0]) throw new Error(`${toDid} has no independent DIDComm mediator published`)
  // Decode before registration so a hostile routing document cannot make us
  // enroll a private key against a malformed/non-self-certifying route.
  publicKeyOf(decodePeerDid2(value.routingKeys[0].split('#', 1)[0]!), value.routingKeys[0])
  return { url: value.uri, routingKid: value.routingKeys[0] }
}

async function sendPrivateRelationshipMessage(contactKey: ContactKeyV1, type: string, body: unknown, fetchImpl: typeof fetch, message?: { id: string; createdTime: number }): Promise<DidCommSendResult> {
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
  const plaintext = buildPlaintext(type, body, ownDid, recipientDid, message)
  const inner = packAuthcrypt(
    new TextEncoder().encode(JSON.stringify(plaintext)),
    { kid: contactKey.ownRelationshipKid, privateKey: contactKey.ownX25519PrivateKey },
    { kid: contactKey.counterpartyRelationshipKid, publicKey: recipientPublicKey },
  )
  let outbound: DidCommJWE
  try {
    outbound = wrapForward(inner, contactKey.counterpartyRelationshipKid, route.routingKid)
  } catch {
    return { ok: false, error: 'private relationship mediator routing kid is invalid' }
  }
  const response = await fetchImpl(route.url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(outbound) })
  if (response.status !== 202) return { ok: false, error: `send failed: HTTP ${response.status} ${(await response.text().catch(() => '')).slice(0, 256)}` }
  return { ok: true }
}
