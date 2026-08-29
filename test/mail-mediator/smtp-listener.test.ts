import { describe, expect, test } from 'bun:test'
import { connect } from 'node:net'
import { connect as tlsConnect } from 'node:tls'
import type { Socket } from 'node:net'
import { ed25519 } from '@noble/curves/ed25519.js'
import { createSmtpMailListener } from '../../src/mail-mediator/smtp-listener.ts'
import { RouteStore } from '../../src/mail-mediator/route-store.ts'
import { SpoolStore } from '../../src/mail-mediator/spool-store.ts'
import { ContactHistoryStore } from '../../src/mail-mediator/contact-history-store.ts'
import { buildSignedMessage, bytesToBase64 } from './support/dkim-fixture.ts'

const certPath = `${import.meta.dir}/../fixtures/smtp-tls-cert.pem`
const keyPath = `${import.meta.dir}/../fixtures/smtp-tls-key.pem`
const ADDRESS = 'alice@mail.test.example'
const dkimPrivateKey = ed25519.utils.randomSecretKey()
const dkimPublicKey = ed25519.getPublicKey(dkimPrivateKey)

function boundRoutes(): RouteStore {
  const routes = new RouteStore()
  routes.bind(ADDRESS, { relationshipKid: 'did:peer:2.a#key-1', pickupPublicKey: new Uint8Array(32), expiresAt: '2030-01-01T00:00:00.000Z' }, 'gen-1', '2026-01-01T00:00:00.000Z')
  return routes
}

function connectRaw(port: number): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const socket = connect(port, '127.0.0.1')
    socket.once('connect', () => resolve(socket))
    socket.once('error', reject)
  })
}

/** Reads until the buffered text contains a full reply ending in `\r\n`
 * whose final line is not a continuation ("250-..."). Good enough for
 * this test's scripted, well-behaved exchanges. */
function readReply(socket: Socket): Promise<string> {
  return new Promise((resolve, reject) => {
    let buf = ''
    const onData = (chunk: Buffer) => {
      buf += chunk.toString('utf8')
      const lines = buf.split('\r\n').filter(Boolean)
      const last = lines[lines.length - 1]
      if (last && /^\d{3} /.test(last)) { cleanup(); resolve(buf) }
    }
    const onError = (error: Error) => { cleanup(); reject(error) }
    const cleanup = () => { socket.off('data', onData); socket.off('error', onError) }
    socket.on('data', onData)
    socket.on('error', onError)
  })
}

describe('SMTP mail listener', () => {
  test('a full EHLO/MAIL/RCPT/DATA transaction over plaintext lands a claimable spool entry', async () => {
    const routes = boundRoutes()
    const spool = new SpoolStore()
    const listener = createSmtpMailListener({ port: 0, helloName: 'mail.test.example', routes, spool })
    try {
      const socket = await connectRaw(listener.port)
      await readReply(socket) // 220 banner
      socket.write('EHLO client.example\r\n'); await readReply(socket)
      socket.write('MAIL FROM:<sender@example.test>\r\n'); await readReply(socket)
      socket.write(`RCPT TO:<${ADDRESS}>\r\n`)
      expect(await readReply(socket)).toContain('250')
      socket.write('DATA\r\n'); await readReply(socket)
      socket.write('Subject: hi\r\n\r\nhello world\r\n.\r\n')
      expect(await readReply(socket)).toContain('250')
      socket.write('QUIT\r\n')
      await readReply(socket)
      socket.end()

      const claimed = spool.claim(ADDRESS, 'holder-a', 60_000, 10, '2026-01-01T00:00:00.000Z')
      expect(claimed).toHaveLength(1)
      expect(new TextDecoder().decode(claimed[0]!.encryptedBody)).toBe('Subject: hi\r\n\r\nhello world\r\n')
      expect(claimed[0]!.mailFrom).toBe('sender@example.test')
    } finally {
      listener.stop()
    }
  })

  test('RCPT to an address with no bound route is rejected 550, nothing lands', async () => {
    const routes = new RouteStore()
    const spool = new SpoolStore()
    const listener = createSmtpMailListener({ port: 0, helloName: 'mail.test.example', routes, spool })
    try {
      const socket = await connectRaw(listener.port)
      await readReply(socket)
      socket.write('EHLO client.example\r\n'); await readReply(socket)
      socket.write('MAIL FROM:<sender@example.test>\r\n'); await readReply(socket)
      socket.write(`RCPT TO:<${ADDRESS}>\r\n`)
      expect(await readReply(socket)).toContain('550')
      socket.end()
      expect(spool.pendingCount(ADDRESS)).toBe(0)
    } finally {
      listener.stop()
    }
  })

  test('STARTTLS discards pre-upgrade state: MAIL right after the 220 without a fresh EHLO is refused', async () => {
    const routes = boundRoutes()
    const spool = new SpoolStore()
    const listener = createSmtpMailListener({ port: 0, helloName: 'mail.test.example', routes, spool, tls: { certPath, keyPath } })
    try {
      const raw = await connectRaw(listener.port)
      await readReply(raw)
      raw.write('EHLO client.example\r\n'); await readReply(raw)
      raw.write('STARTTLS\r\n')
      expect(await readReply(raw)).toContain('220')

      const upgraded: Socket = await new Promise((resolve, reject) => {
        const tlsSocket = tlsConnect({ socket: raw, rejectUnauthorized: false }, () => resolve(tlsSocket as unknown as Socket))
        tlsSocket.once('error', reject)
      })

      upgraded.write('MAIL FROM:<sender@example.test>\r\n')
      expect(await readReply(upgraded)).toContain('502')

      upgraded.write('EHLO client.example\r\n'); await readReply(upgraded)
      upgraded.write('MAIL FROM:<sender@example.test>\r\n'); await readReply(upgraded)
      upgraded.write(`RCPT TO:<${ADDRESS}>\r\n`)
      expect(await readReply(upgraded)).toContain('250')
      upgraded.write('DATA\r\n'); await readReply(upgraded)
      upgraded.write('body\r\n.\r\n')
      expect(await readReply(upgraded)).toContain('250')
      upgraded.end()

      expect(spool.pendingCount(ADDRESS)).toBe(1)
    } finally {
      listener.stop()
    }
  })

  test('a DKIM-verified, aligned sender is recorded as a known contact', async () => {
    const routes = boundRoutes()
    const spool = new SpoolStore()
    const contactHistory = new ContactHistoryStore()
    const listener = createSmtpMailListener({
      port: 0, helloName: 'mail.test.example', routes, spool, contactHistory,
      resolveDkimTxt: async name => name === 'sel1._domainkey.example.test' ? [`v=DKIM1; k=ed25519; p=${bytesToBase64(dkimPublicKey)}`] : [],
    })
    try {
      const raw = await buildSignedMessage(
        [{ name: 'From', value: ' sender@example.test' }, { name: 'To', value: ` ${ADDRESS}` }],
        'hello\r\n',
        { domain: 'example.test', selector: 'sel1', algorithm: 'ed25519-sha256', sign: input => ed25519.sign(input, dkimPrivateKey) },
      )
      const socket = await connectRaw(listener.port)
      await readReply(socket)
      socket.write('EHLO client.example\r\n'); await readReply(socket)
      socket.write('MAIL FROM:<sender@example.test>\r\n'); await readReply(socket)
      socket.write(`RCPT TO:<${ADDRESS}>\r\n`); await readReply(socket)
      socket.write('DATA\r\n'); await readReply(socket)
      socket.write(Buffer.from(raw))
      socket.write('.\r\n')
      expect(await readReply(socket)).toContain('250')
      socket.end()

      // The DKIM check runs fire-and-forget after the spool commit
      // (smtp-listener.ts's own note) -- give its microtasks a chance
      // to land before asserting.
      await new Promise(resolve => setTimeout(resolve, 20))
      expect(contactHistory.hasContact(ADDRESS, 'sender@example.test')).toBe(true)
    } finally {
      listener.stop()
    }
  })

  test('an unsigned message is NOT recorded as a known contact', async () => {
    const routes = boundRoutes()
    const spool = new SpoolStore()
    const contactHistory = new ContactHistoryStore()
    const listener = createSmtpMailListener({ port: 0, helloName: 'mail.test.example', routes, spool, contactHistory })
    try {
      const socket = await connectRaw(listener.port)
      await readReply(socket)
      socket.write('EHLO client.example\r\n'); await readReply(socket)
      socket.write('MAIL FROM:<sender@example.test>\r\n'); await readReply(socket)
      socket.write(`RCPT TO:<${ADDRESS}>\r\n`); await readReply(socket)
      socket.write('DATA\r\n'); await readReply(socket)
      socket.write('Subject: hi\r\n\r\nno signature here\r\n.\r\n')
      expect(await readReply(socket)).toContain('250')
      socket.end()
      await new Promise(resolve => setTimeout(resolve, 20))
      expect(contactHistory.hasContact(ADDRESS, 'sender@example.test')).toBe(false)
    } finally {
      listener.stop()
    }
  })

  test('a DKIM-verified but UNALIGNED signature (d= does not match MAIL FROM domain) is NOT recorded', async () => {
    const routes = boundRoutes()
    const spool = new SpoolStore()
    const contactHistory = new ContactHistoryStore()
    const listener = createSmtpMailListener({
      port: 0, helloName: 'mail.test.example', routes, spool, contactHistory,
      resolveDkimTxt: async name => name === 'sel1._domainkey.unrelated.example' ? [`v=DKIM1; k=ed25519; p=${bytesToBase64(dkimPublicKey)}`] : [],
    })
    try {
      // Signed by unrelated.example, but the envelope MAIL FROM claims
      // example.test -- a valid signature for a domain that never
      // vouched for THIS address must grant nothing.
      const raw = await buildSignedMessage(
        [{ name: 'From', value: ' sender@example.test' }, { name: 'To', value: ` ${ADDRESS}` }],
        'hello\r\n',
        { domain: 'unrelated.example', selector: 'sel1', algorithm: 'ed25519-sha256', sign: input => ed25519.sign(input, dkimPrivateKey) },
      )
      const socket = await connectRaw(listener.port)
      await readReply(socket)
      socket.write('EHLO client.example\r\n'); await readReply(socket)
      socket.write('MAIL FROM:<sender@example.test>\r\n'); await readReply(socket)
      socket.write(`RCPT TO:<${ADDRESS}>\r\n`); await readReply(socket)
      socket.write('DATA\r\n'); await readReply(socket)
      socket.write(Buffer.from(raw))
      socket.write('.\r\n')
      expect(await readReply(socket)).toContain('250')
      socket.end()
      await new Promise(resolve => setTimeout(resolve, 20))
      expect(contactHistory.hasContact(ADDRESS, 'sender@example.test')).toBe(false)
    } finally {
      listener.stop()
    }
  })

  test('disconnecting mid-DATA, before the terminator, delivers nothing', async () => {
    const routes = boundRoutes()
    const spool = new SpoolStore()
    const listener = createSmtpMailListener({ port: 0, helloName: 'mail.test.example', routes, spool })
    try {
      const socket = await connectRaw(listener.port)
      await readReply(socket)
      socket.write('EHLO client.example\r\n'); await readReply(socket)
      socket.write('MAIL FROM:<sender@example.test>\r\n'); await readReply(socket)
      socket.write(`RCPT TO:<${ADDRESS}>\r\n`); await readReply(socket)
      socket.write('DATA\r\n'); await readReply(socket)
      socket.write('Subject: partial\r\nthis never gets a terminator')
      socket.destroy()
      await new Promise(resolve => setTimeout(resolve, 50))
      expect(spool.pendingCount(ADDRESS)).toBe(0)
    } finally {
      listener.stop()
    }
  })
})
