// Shared DIDComm plaintext-message envelope helpers, used by coordinate.ts,
// send.ts and pickup.ts alike — kept in one place so the envelope shape
// (id/typ/type/body/from/to) can't drift between them.
import type { PeerDidDoc } from '../peer.ts'
import { b64urlToBytes, packAuthcrypt, unpackAuthcrypt, type DidCommJWE } from './crypto.ts'

// The minimal shape sendAndUnpack actually needs — deliberately narrower than
// PeerIdentity so a did:dht identity (just {did, xKid, xPriv}, no did:peer-
// specific fields like edKid/doc/secrets) satisfies it too (PLAN.md "DIDComm
// transport identity": did:peer and did:dht direct are both first-class
// senders now, not just the did:peer fallback). PeerIdentity already
// structurally satisfies this — no changes needed at existing call sites.
export interface DidCommSender { did: string; xKid: string; xPriv: Uint8Array }

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
  return JSON.parse(new TextDecoder().decode(replyBytes))
}
