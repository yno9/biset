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
import { packAuthcrypt, unpackAuthcrypt, parseJwe, type DidCommJWE } from './crypto.ts'
import { buildPlaintext, type DidCommPlaintext } from './message.ts'
import { isProblemReport, problemReportError } from './problems.ts'
import { publicKeyOf, type PeerDidDoc } from './peer.ts'
import { defaultFetch } from '../net-fetch.ts'

/** This device's own DIDComm transport identity -- the identity-shared
 * X25519 credential (vault/didcomm-credential.ts), read from whichever
 * device is running this. */
export interface DidCommSender { did: string; xKid: string; xPriv: Uint8Array }

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
  const doc = await resp.json() as PeerDidDoc
  const xKid = doc.keyAgreement[0]
  if (!xKid) throw new Error(`fetchMediatorInfo: ${doc.id} has no keyAgreement key`)
  const info: MediatorInfo = { url: mediatorUrl, did: doc.id, xKid, xPub: publicKeyOf(doc, xKid) }
  mediatorInfoCache.set(mediatorUrl, info)
  return info
}

/** Authcrypts `type`/`body` to the mediator, POSTs it, and unpacks the
 * mediator's authcrypt'd reply -- the mediator's key is already known
 * (fetchMediatorInfo, did:peer is self-certifying) so unpacking needs no
 * resolver. A problem-report reply is thrown as a DidCommProblemError
 * rather than returned, so every coordinate/pickup caller gets a uniform
 * "why" instead of each re-checking `reply.type`. */
export async function sendAndUnpack(
  mediator: MediatorInfo, own: DidCommSender, type: string, body: unknown,
  fetchImpl: typeof fetch = defaultFetch(),
): Promise<DidCommPlaintext> {
  const plaintext = buildPlaintext(type, body, own.did, mediator.did)
  const jwe = packAuthcrypt(
    new TextEncoder().encode(JSON.stringify(plaintext)),
    { kid: own.xKid, privateKey: own.xPriv },
    { kid: mediator.xKid, publicKey: mediator.xPub },
  )
  const resp = await fetchImpl(`${trimSlash(mediator.url)}/`, {
    method: 'POST',
    headers: { 'content-type': 'application/didcomm-encrypted+json' },
    body: JSON.stringify(jwe),
  })
  if (!resp.ok) throw new Error(`mediator request failed: HTTP ${resp.status} ${await resp.text()}`)

  // The far end's reply is as untrusted as any other body -- see parseJwe.
  const replyJwe: DidCommJWE | null = parseJwe(await resp.json())
  if (!replyJwe) throw new Error('the reply is not a DIDComm JWE')
  const resolveSenderKey = async () => mediator.xPub
  const { plaintext: replyBytes } = await unpackAuthcrypt(replyJwe, { kid: own.xKid, privateKey: own.xPriv }, resolveSenderKey)
  const reply = JSON.parse(new TextDecoder().decode(replyBytes)) as DidCommPlaintext
  if (isProblemReport(reply)) throw problemReportError(reply)
  return reply
}
