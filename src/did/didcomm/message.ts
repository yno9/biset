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
  attachments?: Array<{ id: string; data: { json: unknown } }>
}

export function buildPlaintext(type: string, body: unknown, from?: string, to?: string): DidCommPlaintext {
  const msg: DidCommPlaintext = { id: crypto.randomUUID(), typ: 'application/didcomm-plain+json', type, body }
  if (from) msg.from = from
  if (to) msg.to = [to]
  return msg
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
