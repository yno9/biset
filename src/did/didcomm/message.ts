// Shared DIDComm plaintext-message envelope helpers, used by coordinate.ts,
// send.ts and pickup.ts alike — kept in one place so the envelope shape
// (id/typ/type/body/from/to) can't drift between them.
import type { PeerDidDoc } from '../peer/peer.ts'
import { b64urlToBytes, packAuthcrypt, unpackAuthcrypt, type DidCommJWE } from './crypto.ts'
import { isProblemReport, problemReportError } from './problems.ts'

// The minimal shape sendAndUnpack actually needs — deliberately narrower than
// PeerIdentity so a did:dht identity (just {did, xKid, xPriv}, no did:peer-
// specific fields like edKid/doc/secrets) satisfies it too (PLAN.md "DIDComm
// transport identity": did:peer and did:dht direct are both first-class
// senders now, not just the did:peer fallback). PeerIdentity already
// structurally satisfies this — no changes needed at existing call sites.
// mlkemPriv (PLAN.md "did:webvh PQハイブリッド化" Phase 2) is optional and
// did:webvh-only: a did:dht sender/recipient, or a did:webvh device that
// hasn't minted its ML-KEM-768 key yet, simply has none, and every hybrid
// path here already treats "no key" as "not PQ-capable" rather than an error.
export interface DidCommSender { did: string; xKid: string; xPriv: Uint8Array; mlkemPriv?: Uint8Array }

export interface DidCommPlaintext {
  id: string
  typ: string
  type: string
  body: unknown
  from?: string
  to?: string[]
  // Threading (threading.md): thid identifies the thread, pthid the parent
  // thread. Absent thid means "id IS the thid" per spec — carried through here
  // so a reply/problem-report can correlate, though biset's 1:1 basicmessage
  // chat doesn't thread and omits both (matching reference basicmessage).
  thid?: string
  pthid?: string
  // ack (problems.md "ACKs"): ids of prior messages this one acknowledges.
  //
  // Only ever in ANSWER to a `please_ack` — the spec's SHOULD is conditional on
  // the sender having asked ("cooperative parties who wish to honor such a
  // request SHOULD include an `ack` header", problems.md). Sending it
  // unprompted is not just noise: didcomm-jvm — what Identus/PRISM, RootsID and
  // the DIDComm v2 mediator test suite are all built on — models this header as
  // a plain String and throws MalformedMessageException on an array, so an
  // unrequested `ack` made every problem-report this mediator emitted
  // unparseable for a large part of the ecosystem.
  ack?: string[]
  // please_ack (problems.md "ACKs"): the sender asking to be told the message
  // arrived. Read, not written — biset never requests one, but must recognize
  // one to know when answering with `ack` is warranted.
  please_ack?: string[]
  // from_prior (signature.md "DID Rotation"): a compact JWT signed by the prior
  // DID asserting rotation to the DID now in `from`. See rotation.ts.
  from_prior?: string
  // created_time is spec-recommended on every message; expires_time is set only
  // when a sender wants a deadline. Both are UTC epoch SECONDS as integers
  // (message_structure.md) — NOT millis, a common interop trap.
  created_time?: number
  expires_time?: number
  attachments?: Array<{ id: string; data: { json: unknown } }>
}

/** UTC epoch seconds as an integer — the unit every DIDComm time header uses. */
export function nowEpochSeconds(): number { return Math.floor(Date.now() / 1000) }

export interface PlaintextOptions {
  thid?: string
  pthid?: string
  ack?: string[]
  /** Compact JWT for the `from_prior` header (rotation.ts buildFromPrior). */
  fromPrior?: string
  /** UTC epoch seconds. Omit for no expiry (the sender's default per spec). */
  expiresTime?: number
}

export function buildPlaintext(type: string, body: unknown, from?: string, to?: string, opts: PlaintextOptions = {}): DidCommPlaintext {
  const msg: DidCommPlaintext = {
    id: crypto.randomUUID(),
    typ: 'application/didcomm-plain+json',
    type, body,
    created_time: nowEpochSeconds(), // OPTIONAL but recommended (message_structure.md)
  }
  if (from) msg.from = from
  if (to) msg.to = [to]
  if (opts.thid) msg.thid = opts.thid
  if (opts.pthid) msg.pthid = opts.pthid
  if (opts.ack && opts.ack.length) msg.ack = opts.ack
  if (opts.fromPrior) msg.from_prior = opts.fromPrior
  if (opts.expiresTime !== undefined) msg.expires_time = opts.expiresTime
  return msg
}

/** True if the message declares an `expires_time` already in the past. A small
 * skew allowance absorbs clock divergence between sender and receiver — the
 * spec (message_structure.md) explicitly notes created_time/expires_time exist
 * so a recipient can reason about "transport latency and clock divergence", so
 * rejecting a message that is only seconds past its deadline would be brittle.
 * A message with no expires_time never expires (returns false). */
export function isExpired(msg: { expires_time?: number }, skewSeconds = 60): boolean {
  return typeof msg.expires_time === 'number' && msg.expires_time + skewSeconds < nowEpochSeconds()
}

export function publicKeyOf(doc: PeerDidDoc, kid: string): Uint8Array {
  const vm = doc.verificationMethod.find(v => v.id === kid)
  if (!vm) throw new Error(`publicKeyOf: kid ${kid} not found in DID doc`)
  return b64urlToBytes(vm.publicKeyJwk.x)
}

/** The ML-KEM-768 keyAgreement key this peer published at `#kk<n>`, paired by
 * slot number with the X25519 kid `#k<n>` (webvh/document.ts's
 * DidMlkemKeyAgreement) — PLAN.md "did:webvh PQハイブリッド化" Phase 2's
 * negotiation signal. null means this peer/device isn't PQ-capable (a
 * did:dht doc never has a `#kk<n>` vm at all; a did:webvh doc's device may
 * not have published one yet) — send.ts reads that as "use plain
 * packAuthcrypt for this device", never as an error. */
export function mlkemPublicKeyOf(doc: PeerDidDoc, x25519Kid: string): Uint8Array | null {
  const n = /#k(\d+)$/.exec(x25519Kid)?.[1]
  if (!n) return null
  const did = x25519Kid.slice(0, x25519Kid.indexOf('#'))
  const vm = doc.verificationMethod.find(v => v.id === `${did}#kk${n}`)
  return vm ? b64urlToBytes(vm.publicKeyJwk.x) : null
}

export interface MediatorLike { url: string; did: string; doc: PeerDidDoc }

/** Sends an authcrypt'd plaintext message to a mediator and returns its
 * (also authcrypt'd) reply, decrypted and parsed — the shared request/reply
 * shape behind both Coordination and Pickup protocol messages. */
export async function sendAndUnpack(mediator: MediatorLike, own: DidCommSender, type: string, body: unknown): Promise<DidCommPlaintext> {
  const mediatorXKid = mediator.doc.keyAgreement[0]
  if (!mediatorXKid) throw new Error('sendAndUnpack: mediator DID doc has no keyAgreement')
  const plaintext = buildPlaintext(type, body, own.did, mediator.did)
  const jwe = packAuthcrypt(
    new TextEncoder().encode(JSON.stringify(plaintext)),
    { kid: own.xKid, privateKey: own.xPriv },
    { kid: mediatorXKid, publicKey: publicKeyOf(mediator.doc, mediatorXKid) },
  )

  const resp = await fetch(mediator.url, {
    method: 'POST',
    headers: { 'content-type': 'application/didcomm-encrypted+json' },
    body: JSON.stringify(jwe),
  })
  if (!resp.ok) throw new Error(`mediator request failed: HTTP ${resp.status} ${await resp.text()}`)

  const replyJwe = await resp.json() as DidCommJWE
  const resolveSenderKey = (senderKid: string) => publicKeyOf(mediator.doc, senderKid)
  const { plaintext: replyBytes } = await unpackAuthcrypt(replyJwe, { kid: own.xKid, privateKey: own.xPriv }, resolveSenderKey)
  const reply = JSON.parse(new TextDecoder().decode(replyBytes)) as DidCommPlaintext
  // A mediator that answers with a problem-report (Report Problem 2.0) is
  // telling us WHY the request failed via a structured `code` — surface that
  // as the thrown error, uniformly for every coordinate/pickup caller, rather
  // than letting each one report the generic "unexpected reply type".
  if (isProblemReport(reply)) throw problemReportError(reply)
  return reply
}
