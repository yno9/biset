import type { MailDkimSigner } from '../mediator/mail-plugin/dkim.ts'
import { deliverMail } from '../mediator/mail-plugin/smtp-client.ts'
import { MAIL_BRIDGE_SEND, MAIL_BRIDGE_SEND_RESULT, mailBridgeSendBodyOf } from '../mediator/mail-plugin/mail-bridge.ts'
import { parseJwe, unpackAuthcryptAuto } from '../../protocol/didcomm/crypto.ts'
import { resolveDidCommSenderKey } from '../../protocol/didcomm/webvh-resolve.ts'
import { resolve } from '../../protocol/webvh/resolver.ts'
import { didCommRouteFromDocument, absoluteKid } from '../../protocol/didcomm/webvh-route.ts'
import { decodeX25519Multikey } from '../../protocol/didcomm/multikey.ts'
import { buildPlaintext } from '../../protocol/didcomm/message.ts'
import { packForDelivery } from '../mediator/route-deliver.ts'
import { mailFromForIdentity } from '../../protocol/webvh/identifier.ts'
import { didOfKid } from '../../protocol/ids.ts'

const PATH = '/v1/mail'

export function createMailBridgeAgent(options: { hostname: string; signDkim?: MailDkimSigner; apexDomain: string; identity: { kid: string; privateKey: Uint8Array } }): (request: Request) => Promise<Response> {
  return async request => {
    const headers = { 'access-control-allow-origin': '*', 'access-control-allow-methods': 'POST, OPTIONS', 'access-control-allow-headers': 'Content-Type' }
    if (new URL(request.url).pathname !== PATH) return new Response('Not found\n', { status: 404 })
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers })
    if (request.method !== 'POST') return new Response('Method not allowed\n', { status: 405, headers })
    try {
      const jwe = parseJwe(await request.json())
      if (!jwe) throw new TypeError('DIDComm payload is not a JWE')
      const unpacked = await unpackAuthcryptAuto(jwe, { kid: options.identity.kid, x25519PrivateKey: options.identity.privateKey }, kid => resolveDidCommSenderKey(kid))
      const message = JSON.parse(new TextDecoder().decode(unpacked.plaintext)) as { id?: unknown; type?: unknown; thid?: unknown; body?: unknown; attachments?: unknown }
      if (typeof message.id !== 'string' || typeof message.type !== 'string' || message.type !== MAIL_BRIDGE_SEND) throw new TypeError('unsupported DIDComm mail bridge message')
      const input = mailBridgeSendBodyOf(message as never)
      if (!input) throw new TypeError('mail bridge send request is invalid')
      const senderDid = didOfKid(unpacked.senderKid)
      if (mailFromForIdentity(senderDid, options.apexDomain).toLowerCase() !== input.mailFrom.toLowerCase()) throw new Error('mailFrom does not match the authenticated sender DID')
      const result = await deliverMail({ hostname: options.hostname, signDkim: options.signDkim }, input)
      await sendResult(options.identity, senderDid, message.id, typeof message.thid === 'string' ? message.thid : message.id, result)
      return new Response(null, { status: 202, headers })
    } catch (error) {
      return new Response(`${error instanceof Error ? error.message : 'mail bridge request rejected'}\n`, { status: 400, headers })
    }
  }
}

async function sendResult(
  sender: { kid: string; privateKey: Uint8Array }, senderDid: string, messageId: string, thid: string,
  results: Awaited<ReturnType<typeof deliverMail>>,
): Promise<void> {
  const doc = await resolve(senderDid)
  if (!doc) throw new Error('authenticated sender DID no longer resolves')
  const { endpoint, keyAgreement } = didCommRouteFromDocument(doc)
  if (!endpoint?.uri || !keyAgreement) throw new Error('authenticated sender has no DIDComm return route')
  const body = { requestId: messageId, status: results.every(result => result.outcome === 'delivered' && result.rejected.length === 0) ? 'accepted' : 'temporary-failure', results }
  const plaintext = buildPlaintext(MAIL_BRIDGE_SEND_RESULT, body, sender.kid.split('#', 1)[0], senderDid, { thid })
  const delivery = packForDelivery(new TextEncoder().encode(JSON.stringify(plaintext)), sender, absoluteKid(doc, keyAgreement.id), decodeX25519Multikey(keyAgreement.publicKeyMultibase), { uri: endpoint.uri, routingKeys: endpoint.routingKeys })
  const response = await fetch(delivery.postUrl, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(delivery.outbound) })
  if (response.status !== 202) throw new Error(`mail send-result delivery failed: HTTP ${response.status}`)
}
