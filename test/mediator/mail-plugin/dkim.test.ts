import { expect, test } from 'bun:test'
import { createPublicKey, generateKeyPairSync } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { dkimVerify } from 'mailauth'
import { createMailDkimSigner } from '../../../src/server/mediator/mail-plugin/dkim.ts'
import { loadMailRelayDkim } from '../../../src/server/mail-relay/dkim-config.ts'
import { deliverMail } from '../../../src/server/mediator/mail-plugin/smtp-client.ts'
import { createSmtpSocketServer } from '../../../src/server/mediator/mail-plugin/smtp-socket-server.ts'

const { privateKey, publicKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  publicKeyEncoding: { type: 'spki', format: 'pem' },
})
const publicDer = createPublicKey(publicKey).export({ type: 'spki', format: 'der' }).toString('base64')
const signer = createMailDkimSigner({ domainName: 'example.com', keySelector: 'test', privateKey })
const header = 'From: Alice\r\n <alice@example.com>\r\nTo: bob@example.net\r\nSubject: test\r\n\r\n'
const message = (raw = Buffer.from(`${header}hello\r\n`)) => ({ mailFrom: 'alice@example.com', rcptTo: ['bob@example.net'], rawRfc5322: raw })

async function verification(raw: Uint8Array) {
  const result = await dkimVerify(Buffer.from(raw), {
    resolver: async (name, type) => {
      expect(name).toBe('test._domainkey.example.com')
      expect(type).toBe('TXT')
      return [[`v=DKIM1; k=rsa; p=${publicDer}`]]
    },
  })
  expect(result.results).toHaveLength(1)
  return result.results[0]!.status.result
}

for (const [label, body] of [
  ['plain', Buffer.from('hello\r\n')],
  ['no final newline', Buffer.from('hello')],
  ['empty', Buffer.alloc(0)],
  ['UTF8 and opaque bytes', Buffer.from([0xc3, 0xa9, 0xff, 13, 10])],
  ['whitespace and dot lines', Buffer.from('hello \t world\t\r\n.\r\n..two\r\n\r\n')],
] as const) {
  test(`independent DKIM verification passes: ${label}`, async () => {
    const raw = Buffer.concat([Buffer.from(header), body])
    const signed = Buffer.from(await signer(message(raw)))
    expect(await verification(signed)).toBe('pass')
    const expected = raw.subarray(-2).equals(Buffer.from('\r\n')) ? raw : Buffer.concat([raw, Buffer.from('\r\n')])
    expect(signed.subarray(-expected.length).equals(expected)).toBe(true)
  })
}

test('independent verifier detects body and signed header changes', async () => {
  const signed = Buffer.from(await signer(message()))
  expect(await verification(Buffer.from(signed.toString().replace('hello', 'changed')))).not.toBe('pass')
  expect(await verification(Buffer.from(signed.toString().replace('Subject: test', 'Subject: changed')))).not.toBe('pass')
})

test('rejects mismatched, missing, duplicate and group From headers before signing', async () => {
  for (const from of ['', 'From: mallory@example.com\r\n', 'From: alice@example.com\r\nFrom: alice@example.com\r\n', 'From: Group: alice@example.com;\r\n']) {
    await expect(signer(message(Buffer.from(`${from}To: bob@example.net\r\n\r\nhello\r\n`)))).rejects.toThrow()
  }
  for (const raw of ['From: alice@example.com\n\nhello\n', `${header}hello\n`, ' From: alice@example.com\r\n\r\nhello\r\n']) {
    await expect(signer(message(Buffer.from(raw)))).rejects.toThrow()
  }
  await expect(signer({ ...message(), mailFrom: 'alice@other.example' })).rejects.toThrow('domain')
  await expect(signer({ ...message(), rcptTo: ['invalid address'] })).rejects.toThrow('envelope')
})

test('configuration is all-or-nothing and requires an independent strong RSA key', () => {
  const env = { MAIL_RELAY_DKIM_DOMAIN: 'example.com', MAIL_RELAY_DKIM_SELECTOR: 'test', MAIL_RELAY_DKIM_PRIVATE_KEY_PATH: '/dkim.pem' }
  expect(loadMailRelayDkim({})).toBeUndefined()
  expect(() => loadMailRelayDkim({ MAIL_RELAY_DKIM_DOMAIN: 'example.com' })).toThrow('together')
  expect(() => loadMailRelayDkim({ ...env, MAIL_RELAY_TLS_KEY_PATH: '/dkim.pem' })).toThrow('TLS')
  expect(loadMailRelayDkim(env, () => privateKey)).toBeDefined()
  expect(() => loadMailRelayDkim(env, () => 'invalid key')).toThrow()
  const weak = generateKeyPairSync('rsa', { modulusLength: 1024 }).privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()
  expect(() => loadMailRelayDkim(env, () => weak)).toThrow('2048')
  expect(() => loadMailRelayDkim({ ...env, MAIL_RELAY_DKIM_SELECTOR: 'invalid;tag' }, () => privateKey)).toThrow('selector')
})

test('signing failure prevents DNS and SMTP, never falls back to unsigned', async () => {
  let dnsCalls = 0
  await expect(deliverMail({
    hostname: 'mail.example.com',
    mxResolver: async () => { dnsCalls++; return [] },
    signDkim: async () => { throw new Error('signer down') },
  }, message())).rejects.toThrow('signer down')
  expect(dnsCalls).toBe(0)
})

for (const tls of [false, true]) {
  test(`signed SMTP DATA verifies after dot-unstuffing (STARTTLS=${tls})`, async () => {
    const received: Array<{ bytes: Uint8Array; tls: boolean }> = []
    const certPath = new URL('../../fixtures/dkim-smtp-cert.pem', import.meta.url).pathname
    const keyPath = new URL('../../fixtures/dkim-smtp-key.pem', import.meta.url).pathname
    const caPath = new URL('../../fixtures/dkim-smtp-ca.pem', import.meta.url).pathname
    const server = createSmtpSocketServer({
      hostname: '127.0.0.1', port: 0, helloName: 'localhost', maxMessageBytes: 1024 * 1024,
      ...(tls ? { tls: { certPath, keyPath } } : {}),
      resolveRecipient: async () => ({}),
      acceptIngress: async (input, connection) => { received.push({ bytes: input.rawRfc5322, tls: connection.tls }) },
    })
    let signatures = 0
    try {
      const results = await deliverMail({
        hostname: 'mail.example.com', port: server.port,
        mxResolver: async () => ['localhost'],
        ...(tls ? { tlsOptions: { ca: readFileSync(caPath), serverName: 'mail.example.com', rejectUnauthorized: true } } : {}),
        signDkim: async input => { signatures++; return signer(input) },
      }, { ...message(Buffer.from(`${header}.\r\n..two\r\nhello`)), rcptTo: ['bob@example.net', 'carol@example.org'] })
      expect(results).toEqual([
        { domain: 'example.net', target: `localhost:${server.port}`, accepted: ['bob@example.net'], rejected: [], outcome: 'delivered' },
        { domain: 'example.org', target: `localhost:${server.port}`, accepted: ['carol@example.org'], rejected: [], outcome: 'delivered' },
      ])
      expect(signatures).toBe(1)
      expect(received).toHaveLength(2)
      for (const mail of received) {
        expect(mail.tls).toBe(tls)
        expect(await verification(mail.bytes)).toBe('pass')
        expect(Buffer.from(mail.bytes).toString()).toContain('\r\n.\r\n..two\r\nhello\r\n')
      }
    } finally { server.stop() }
  }, 10000)
}
