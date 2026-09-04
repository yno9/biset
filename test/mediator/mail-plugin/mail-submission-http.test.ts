// Authenticated outbound submission (mail-submission-http.ts): the auth
// check must reject an unsigned/mis-signed/spoofed-mailFrom request BEFORE
// deliverMail() ever dials an external MX -- that boundary is what keeps
// this from being an open relay, so every rejection path gets its own test.
import { describe, expect, test } from 'bun:test'
import { ed25519 } from '@noble/curves/ed25519.js'
import { createMailSubmissionHttpHandler } from '../../../src/mediator/mail-plugin/mail-submission-http.ts'
import { encodeMailSubmissionRequestWire } from '../../../src/shared/protocol/mail-submission-wire.ts'
import { mailSubmissionSigningBytes } from '../../../src/shared/protocol/signing.ts'
import { encodeMultikey } from '../../protocol/support/webvh-log-fixture.ts'
import type { MailSubmissionRequestV1 } from '../../../src/shared/protocol/mail-submission.ts'
import type { MailDeliveryResult } from '../../../src/mediator/mail-plugin/smtp-client.ts'

const apexDomain = 'biset.example'
const identityId = 'did:webvh:Qm11111111111111111111111111111111111111111111:alice.biset.example'

function unsignedRequest(overrides: Partial<Omit<MailSubmissionRequestV1, 'signature'>> = {}): Omit<MailSubmissionRequestV1, 'signature'> {
  return {
    version: 1,
    identityId,
    deviceId: 'device-1',
    mailFrom: 'alice@biset.example',
    rcptTo: ['bob@external.example'],
    rawRfc5322: new TextEncoder().encode('Subject: hi\r\n\r\nhello'),
    submittedAt: '2026-09-04T00:00:00.000Z',
    ...overrides,
  }
}

function post(handler: (request: Request) => Promise<Response>, body: MailSubmissionRequestV1): Promise<Response> {
  return handler(new Request('https://mediator.example/v1/mail/submit', { method: 'POST', body: encodeMailSubmissionRequestWire(body) }))
}

describe('createMailSubmissionHttpHandler', () => {
  test('accepts a validly signed request and calls deliverMail', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const unsigned = unsignedRequest()
    const signature = ed25519.sign(mailSubmissionSigningBytes(unsigned), rootPrivateKey)

    let deliverMailCalled: unknown
    const handler = createMailSubmissionHttpHandler({
      hostname: 'mail.biset.example',
      apexDomain,
      resolveUpdateKeys: async id => (id === identityId ? [encodeMultikey(rootPublicKey)] : []),
      deliverMailFn: async (options, message) => {
        deliverMailCalled = { options, message }
        return [{ domain: 'external.example', target: 'mx.external.example:25', accepted: message.rcptTo, rejected: [], outcome: 'delivered' }] satisfies MailDeliveryResult[]
      },
    })

    const response = await post(handler, { ...unsigned, signature })
    expect(response.status).toBe(200)
    const body = await response.json() as { status: string }
    expect(body.status).toBe('accepted')
    expect(deliverMailCalled).toBeTruthy()
  })

  test('rejects a request whose signature does not verify against the resolved update key', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const wrongPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const unsigned = unsignedRequest()
    const signature = ed25519.sign(mailSubmissionSigningBytes(unsigned), wrongPrivateKey) // signed with the WRONG key

    let deliverMailCalled = false
    const handler = createMailSubmissionHttpHandler({
      hostname: 'mail.biset.example',
      apexDomain,
      resolveUpdateKeys: async () => [encodeMultikey(rootPublicKey)],
      deliverMailFn: async () => { deliverMailCalled = true; return [] },
    })

    const response = await post(handler, { ...unsigned, signature })
    expect(response.status).toBe(403)
    expect(deliverMailCalled).toBe(false)
  })

  test('rejects a mailFrom that does not belong to the signing identity (anti-spoof)', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    // Validly signed by alice's own key, but claiming to send AS a different mailbox.
    const unsigned = unsignedRequest({ mailFrom: 'someone-else@biset.example' })
    const signature = ed25519.sign(mailSubmissionSigningBytes(unsigned), rootPrivateKey)

    let deliverMailCalled = false
    const handler = createMailSubmissionHttpHandler({
      hostname: 'mail.biset.example',
      apexDomain,
      resolveUpdateKeys: async () => [encodeMultikey(rootPublicKey)],
      deliverMailFn: async () => { deliverMailCalled = true; return [] },
    })

    const response = await post(handler, { ...unsigned, signature })
    expect(response.status).toBe(403)
    expect(deliverMailCalled).toBe(false)
  })

  test('rejects an identity with no resolvable update keys', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const unsigned = unsignedRequest()
    const signature = ed25519.sign(mailSubmissionSigningBytes(unsigned), rootPrivateKey)

    const handler = createMailSubmissionHttpHandler({
      hostname: 'mail.biset.example',
      apexDomain,
      resolveUpdateKeys: async () => [], // no such identity / deactivated
      deliverMailFn: async () => { throw new Error('must not be called') },
    })

    const response = await post(handler, { ...unsigned, signature })
    expect(response.status).toBe(403)
  })

  test('404s on any other path, 405s on any other method', async () => {
    const handler = createMailSubmissionHttpHandler({ hostname: 'mail.biset.example', apexDomain })
    expect((await handler(new Request('https://mediator.example/v1/other'))).status).toBe(404)
    expect((await handler(new Request('https://mediator.example/v1/mail/submit', { method: 'GET' }))).status).toBe(405)
  })
})
