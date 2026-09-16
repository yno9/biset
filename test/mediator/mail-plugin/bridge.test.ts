// buildInboundMailForward's whole job: turn an accepted SMTP message into a
// Forward-ready DIDComm envelope by resolving the recipient's did:webvh log
// from the mail address's domain alone (no SCID known up front -- the
// did:webvh<->mail mapping is public, 2026-08-30 redesign). The fixtures are
// did.jsonl since routing.json was retired (2026-09-16).
import { describe, expect, test } from 'bun:test'
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { generatePeerIdentity } from '../../../src/protocol/didcomm/peer.ts'
import { buildDidCommLog } from '../../protocol/support/webvh-log-fixture.ts'
import type { LogEntry } from '../../../src/protocol/webvh/log.ts'
import { unpackAuthcrypt, unpackAnoncrypt, parseJwe } from '../../../src/protocol/didcomm/crypto.ts'
import { buildInboundMailForward } from '../../../src/server/mediator/mail-plugin/bridge.ts'
import { MAIL_BRIDGE_INBOUND, mailBridgeInboundBodyOf } from '../../../src/server/mediator/mail-plugin/mail-bridge.ts'
import { FORWARD } from '../../../src/protocol/didcomm/mediator-protocol.ts'

const utf8 = (s: string) => new TextEncoder().encode(s)

function fetchServing(log: LogEntry[] | undefined): typeof fetch {
  return (async (input) => {
    const url = typeof input === 'string' ? input : input.toString()
    if (url === 'https://y.biset.md/.well-known/did.jsonl') {
      if (log === undefined) return new Response('not found', { status: 404 })
      return new Response(log.map(e => JSON.stringify(e)).join('\n') + '\n', { status: 200 })
    }
    return new Response('unexpected request: ' + url, { status: 500 })
  }) as typeof fetch
}

/** A DIDComm-enabled `y.biset.md` identity: one device X25519 key in
 * `keyAgreement`, and a `#didcomm` service pointing at `endpointUri` through
 * `routingKeys`. */
function recipient(endpointUri: string, routingKeys: string[] = []) {
  const rootPrivateKey = ed25519.utils.randomSecretKey()
  const x25519PrivateKey = x25519.utils.randomSecretKey()
  const { did, log } = buildDidCommLog({
    rootPrivateKey,
    rootPublicKey: ed25519.getPublicKey(rootPrivateKey),
    keyAgreementKeys: [{ fragment: 'k_recipienthash', x25519PublicKey: x25519.getPublicKey(x25519PrivateKey) }],
    endpointUri,
    routingKeys,
    domain: 'y.biset.md',
  })
  return { did, log, kid: `${did}#k_recipienthash`, privateKey: x25519PrivateKey }
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

  test('fails clearly when the recipient has no published did:webvh log', async () => {
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
    const to = recipient('https://recipient-core.test.example/v1/didcomm/ingress')
    const rawRfc5322 = utf8('Subject: hello\r\n\r\nbody text')
    const result = await buildInboundMailForward(
      'y@biset.md', 'biset.md',
      { rawRfc5322, smtpEnvelope: 'MAIL FROM:<a@example.com> RCPT TO:<y@biset.md>' },
      { kid: sender.xKid, privateKey: sender.xPriv },
      fetchServing(to.log),
    )
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.delivery.postUrl).toBe('https://recipient-core.test.example/v1/didcomm/ingress')

    const { plaintext, senderKid } = await unpackAuthcrypt(result.delivery.outbound, { kid: to.kid, privateKey: to.privateKey }, async () => sender.xPub)
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
    const hop1 = generatePeerIdentity({ uri: 'https://hop1.test.example', accept: ['didcomm/v2'] })
    const hop2 = generatePeerIdentity()
    const to = recipient('https://hop1.test.example', [hop1.xKid, hop2.xKid])
    const result = await buildInboundMailForward(
      'y@biset.md', 'biset.md',
      { rawRfc5322: utf8('Subject: via hops\r\n\r\nbody'), smtpEnvelope: 'MAIL FROM:<a@example.com> RCPT TO:<y@biset.md>' },
      { kid: sender.xKid, privateKey: sender.xPriv },
      fetchServing(to.log),
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
    expect(toHop2.body.next).toBe(to.kid)

    const innerJwe = parseJwe(toHop2.attachments[0].data.json)
    const { plaintext } = await unpackAuthcrypt(innerJwe!, { kid: to.kid, privateKey: to.privateKey }, async () => sender.xPub)
    const msg = JSON.parse(new TextDecoder().decode(plaintext))
    expect(mailBridgeInboundBodyOf(msg)?.smtpEnvelope).toBe('MAIL FROM:<a@example.com> RCPT TO:<y@biset.md>')
  })
})
