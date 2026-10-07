// The client-to-mediator wire: fetch a mediator's did:peer document, then
// authcrypt a request and unpack its authcrypt'd reply -- the one
// synchronous "POST, get the answer in the same HTTP response" round trip
// in this codebase, and it belongs here specifically: talking to a
// standalone mediator (ARC.md's 2026-08-27 redesign) IS a synchronous
// request/reply exchange, unlike biset-core's own store-and-pull ingress
// (didcomm/message.ts's header explains why THAT path has no such
// function). mediator-coordinate.ts and mediator-pickup.ts both build on
// this. Ported from src.bak/did/didcomm/coordinate.ts's fetchMediatorInfo
// and message.ts's sendAndUnpack.
import { didCommPost, packAuthcrypt, unpackAuthcrypt, parseJwe, type DidCommJWE } from './crypto.ts'
import { assertFromMatchesSender, buildPlaintext, type DidCommPlaintext } from './message.ts'
import { isProblemReport, problemReportError } from './problems.ts'
import { publicKeyOf, type PeerDidDoc } from './peer.ts'
import { keyAgreementRecipients } from './webvh-route.ts'
import { defaultFetch } from '../net-fetch.ts'

/** A DIDComm key this device holds: its own device key of its did:webvh,
 * or a relationship did:peer's key. */
export interface DidCommSender { did: string; xKid: string; xPriv: Uint8Array }

/** One device's inbox for `did` at a mediator (mediator/server.ts): the
 * keyAgreement key that proves this device owns `did`, plus the `device`
 * label that tells this device's inbox apart from its siblings'. The label
 * must not link inboxes of different DIDs (see mediator-device.ts). */
export interface MediatorInboxClient extends DidCommSender { device: string }

export interface MediatorInfo { url: string; did: string; xKid: string; xPub: Uint8Array }

function trimSlash(u: string): string { return u.replace(/\/$/, '') }

// A mediator's did:peer is baked into its own deploy config -- this
// document is static for all practical purposes. Cached in-memory per
// mediatorUrl for the tab's lifetime so every coordinate/pickup call
// doesn't pay a network round trip just to re-fetch it.
const mediatorInfoCache = new Map<string, MediatorInfo>()

export async function fetchMediatorInfo(mediatorUrl: string, fetchImpl: typeof fetch = defaultFetch()): Promise<MediatorInfo> {
  const cached = mediatorInfoCache.get(mediatorUrl)
  if (cached) return cached
  const resp = await fetchImpl(`${trimSlash(mediatorUrl)}/.well-known/did.json`)
  if (!resp.ok) throw new Error(`fetchMediatorInfo: HTTP ${resp.status}`)
  // The mediator's own DID document: its did:web (a recipient's DID document
  // names that as its endpoint), or the did:peer of the same keys.
  const doc = await resp.json() as PeerDidDoc | { id: string; keyAgreement?: string[]; verificationMethod?: Array<{ id: string; publicKeyMultibase: string }> }
  let info: MediatorInfo
  if (doc.id.startsWith('did:peer:')) {
    const peer = doc as PeerDidDoc
    const xKid = peer.keyAgreement[0]
    if (!xKid) throw new Error(`fetchMediatorInfo: ${doc.id} has no keyAgreement key`)
    info = { url: mediatorUrl, did: doc.id, xKid, xPub: publicKeyOf(peer, xKid) }
  } else {
    const key = keyAgreementRecipients(doc as Parameters<typeof keyAgreementRecipients>[0])[0]
    if (!key) throw new Error(`fetchMediatorInfo: ${doc.id} has no keyAgreement key`)
    info = { url: mediatorUrl, did: doc.id, xKid: key.kid, xPub: key.publicKey }
  }
  mediatorInfoCache.set(mediatorUrl, info)
  return info
}

/** Authcrypts one request to the mediator. `return_route: "all"` always:
 * a client of this mediator (a browser) has no endpoint of its own, so the
 * answer must come back on the connection the request went out on -- the
 * HTTP response, or the live WebSocket (mediator-live.ts). */
export function packMediatorRequest(mediator: MediatorInfo, own: DidCommSender, type: string, body: unknown): DidCommJWE {
  const plaintext = buildPlaintext(type, body, own.did, mediator.did, { returnRoute: 'all' })
  return packAuthcrypt(
    new TextEncoder().encode(JSON.stringify(plaintext)),
    { kid: own.xKid, privateKey: own.xPriv },
    [{ kid: mediator.xKid, publicKey: mediator.xPub }],
  )
}

/** Unpacks one authcrypt'd message from the mediator to `own`. The
 * mediator's key is already known (fetchMediatorInfo, did:peer is
 * self-certifying) so this needs no resolver. A problem-report is returned
 * like any other message; the caller decides what it means. */
export async function unpackMediatorMessage(mediator: MediatorInfo, own: DidCommSender, raw: unknown): Promise<DidCommPlaintext> {
  // The far end's message is as untrusted as any other body -- see parseJwe.
  const jwe: DidCommJWE | null = parseJwe(raw)
  if (!jwe) throw new Error('the mediator message is not a DIDComm JWE')
  const { plaintext, senderKid } = await unpackAuthcrypt(jwe, { kid: own.xKid, privateKey: own.xPriv }, async () => mediator.xPub)
  const message = JSON.parse(new TextDecoder().decode(plaintext)) as DidCommPlaintext
  assertFromMatchesSender(message, senderKid)
  return message
}

/** Authcrypts `type`/`body` to the mediator, POSTs it, and unpacks the
 * reply from the HTTP response. A problem-report reply is thrown as a
 * DidCommProblemError rather than returned, so every coordinate/pickup
 * caller gets a uniform "why" instead of each re-checking `reply.type`. */
export async function sendAndUnpack(
  mediator: MediatorInfo, own: DidCommSender, type: string, body: unknown,
  fetchImpl: typeof fetch = defaultFetch(),
): Promise<DidCommPlaintext> {
  const resp = await fetchImpl(`${trimSlash(mediator.url)}/`, didCommPost(packMediatorRequest(mediator, own, type, body)))
  if (!resp.ok) throw new Error(`mediator request failed: HTTP ${resp.status} ${await resp.text()}`)
  const reply = await unpackMediatorMessage(mediator, own, await resp.json())
  if (isProblemReport(reply)) throw problemReportError(reply)
  return reply
}
