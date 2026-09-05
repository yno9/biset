// buildInboundMailForward's whole job: turn an accepted SMTP message into a
// Forward-ready DIDComm envelope by resolving the recipient's routing.json
// from the mail address's domain alone (no SCID, no signed-log resolve --
// 2026-08-30 redesign, the did:webvh<->mail mapping is already public).
import { describe, expect, test } from 'bun:test'
import { x25519 } from '@noble/curves/ed25519.js'
import { generatePeerIdentity } from '../../../src/didcomm/peer.ts'
import { encodeX25519Multikey } from '../../../src/didcomm/multikey.ts'
import { unpackAuthcrypt, unpackAnoncrypt, parseJwe } from '../../../src/didcomm/crypto.ts'
import { buildInboundMailForward } from '../../../src/server/mail-plugin/bridge.ts'
import { MAIL_BRIDGE_INBOUND, mailBridgeInboundBodyOf } from '../../../src/didcomm/mail-bridge.ts'
import { FORWARD } from '../../../src/didcomm/mediator-protocol.ts'

const utf8 = (s: string) => new TextEncoder().encode(s)
const recipientDid = 'did:webvh:{SCID}:y.biset.md'
const recipientKid = `${recipientDid}#k_recipienthash`

function fetchServing(routingJson: unknown): typeof fetch {
  return (async (input) => {
    const url = typeof input === 'string' ? input : input.toString()
    if (url === 'https://y.biset.md/.well-known/routing.json') {
      if (routingJson === undefined) return new Response('not found', { status: 404 })
      return new Response(JSON.stringify(routingJson), { status: 200 })
    }
    return new Response('unexpected request: ' + url, { status: 500 })
  }) as typeof fetch
}

describe('buildInboundMailForward', () => {
  test('fails clearly when the address is not this apex domain\'s mail convention', async () => {
    const sender = generatePeerIdentity()
    const result = await buildInboundMailForward(
      'y@wrong.example', 'biset.md',
      { rawRfc5322: utf8('Subject: hi\r\n\r\nbody'), smtpEnvelope: 'MAIL FROM:<a@example.com> RCPT TO:<y@wrong.example>' },
      { kid: sender.xKid, privateKey: sender.xPriv },
      fetchServing(undefined),
    )
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.error).toMatch(/is not a biset\.md address/)
  })

  test('fails clearly when the recipient has no routing.json', async () => {
    const sender = generatePeerIdentity()
    const result = await buildInboundMailForward(
      'y@biset.md', 'biset.md',
      { rawRfc5322: utf8('Subject: hi\r\n\r\nbody'), smtpEnvelope: 'MAIL FROM:<a@example.com> RCPT TO:<y@biset.md>' },
      { kid: sender.xKid, privateKey: sender.xPriv },
      fetchServing(undefined),
    )
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.error).toMatch(/does not resolve/)
  })

  test('delivers directly to the recipient when they have no mediator hop chain', async () => {
    const sender = generatePeerIdentity()
    const recipientX = x25519.utils.randomSecretKey()
    const recipientXPub = x25519.getPublicKey(recipientX)
    const routingJson = {
      service: [{ id: `${recipientDid}#didcomm`, type: 'DIDCommMessaging', serviceEndpoint: { uri: 'https://recipient-core.test.example/v1/didcomm/ingress', accept: ['didcomm/v2'], routingKeys: [] } }],
      keyAgreementVerificationMethod: [{ id: recipientKid, type: 'Multikey', controller: recipientDid, publicKeyMultibase: encodeX25519Multikey(recipientXPub) }],
    }
    const rawRfc5322 = utf8('Subject: hello\r\n\r\nbody text')
    const result = await buildInboundMailForward(
      'y@biset.md', 'biset.md',
      { rawRfc5322, smtpEnvelope: 'MAIL FROM:<a@example.com> RCPT TO:<y@biset.md>' },
      { kid: sender.xKid, privateKey: sender.xPriv },
      fetchServing(routingJson),
    )
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.delivery.postUrl).toBe('https://recipient-core.test.example/v1/didcomm/ingress')

    const { plaintext, senderKid } = await unpackAuthcrypt(result.delivery.outbound, { kid: recipientKid, privateKey: recipientX }, async () => sender.xPub)
    expect(senderKid).toBe(sender.xKid)
    const msg = JSON.parse(new TextDecoder().decode(plaintext))
    expect(msg.type).toBe(MAIL_BRIDGE_INBOUND)
    const body = mailBridgeInboundBodyOf(msg)
    expect(body).not.toBeNull()
    expect(new TextDecoder().decode(body!.rawRfc5322)).toBe('Subject: hello\r\n\r\nbody text')
    expect(body!.smtpEnvelope).toBe('MAIL FROM:<a@example.com> RCPT TO:<y@biset.md>')
  })

  test('Forward-wraps through the recipient\'s full hop chain', async () => {
    const sender = generatePeerIdentity()
    const recipientX = x25519.utils.randomSecretKey()
    const recipientXPub = x25519.getPublicKey(recipientX)
    const hop1 = generatePeerIdentity({ uri: 'https://hop1.test.example', accept: ['didcomm/v2'] })
    const hop2 = generatePeerIdentity()
    const routingJson = {
      service: [{ id: `${recipientDid}#didcomm`, type: 'DIDCommMessaging', serviceEndpoint: { uri: 'https://hop1.test.example', accept: ['didcomm/v2'], routingKeys: [hop1.xKid, hop2.xKid] } }],
      keyAgreementVerificationMethod: [{ id: recipientKid, type: 'Multikey', controller: recipientDid, publicKeyMultibase: encodeX25519Multikey(recipientXPub) }],
    }
    const result = await buildInboundMailForward(
      'y@biset.md', 'biset.md',
      { rawRfc5322: utf8('Subject: via hops\r\n\r\nbody'), smtpEnvelope: 'MAIL FROM:<a@example.com> RCPT TO:<y@biset.md>' },
      { kid: sender.xKid, privateKey: sender.xPriv },
      fetchServing(routingJson),
    )
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.delivery.postUrl).toBe('https://hop1.test.example')

    const toHop1Bytes = await unpackAnoncrypt(result.delivery.outbound, { kid: hop1.xKid, privateKey: hop1.xPriv })
    const toHop1 = JSON.parse(new TextDecoder().decode(toHop1Bytes))
    expect(toHop1.type).toBe(FORWARD)
    expect(toHop1.body.next).toBe(hop2.xKid)

    const toHop2Jwe = parseJwe(toHop1.attachments[0].data.json)
    const toHop2Bytes = await unpackAnoncrypt(toHop2Jwe!, { kid: hop2.xKid, privateKey: hop2.xPriv })
    const toHop2 = JSON.parse(new TextDecoder().decode(toHop2Bytes))
    expect(toHop2.type).toBe(FORWARD)
    expect(toHop2.body.next).toBe(recipientKid)

    const innerJwe = parseJwe(toHop2.attachments[0].data.json)
    const { plaintext } = await unpackAuthcrypt(innerJwe!, { kid: recipientKid, privateKey: recipientX }, async () => sender.xPub)
    const msg = JSON.parse(new TextDecoder().decode(plaintext))
    expect(mailBridgeInboundBodyOf(msg)?.smtpEnvelope).toBe('MAIL FROM:<a@example.com> RCPT TO:<y@biset.md>')
  })
})
