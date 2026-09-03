// Socket-level coverage for the mail plugin's SMTP listener: a real
// EHLO/MAIL/RCPT/DATA transaction over a plaintext TCP connection must
// resolve the recipient's routing.json, authcrypt a MAIL_BRIDGE_INBOUND
// message, and POST it -- exercising resolveMailRecipientRoute (RCPT) and
// packInboundMailForward (DATA) through the shared smtp-socket-server.ts
// plumbing, not just the pure bridge.ts functions in isolation.
import { describe, expect, test } from 'bun:test'
import { connect } from 'node:net'
import type { Socket } from 'node:net'
import { generatePeerIdentity } from '../../../src/didcomm/peer.ts'
import { encodeX25519Multikey } from '../../../src/didcomm/multikey.ts'
import { unpackAuthcrypt } from '../../../src/didcomm/crypto.ts'
import { createMailPluginListener } from '../../../src/mediator/mail-plugin/listener.ts'
import { x25519 } from '@noble/curves/ed25519.js'

function connectRaw(port: number): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const socket = connect(port, '127.0.0.1')
    socket.once('connect', () => resolve(socket))
    socket.once('error', reject)
  })
}

/** Reads until the buffered text contains a full reply ending in `\r\n` whose
 * final line is not a continuation ("250-..."). */
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

describe('mail plugin SMTP listener', () => {
  test('a full EHLO/MAIL/RCPT/DATA transaction resolves routing.json and delivers a MAIL_BRIDGE_INBOUND Forward', async () => {
    const sender = generatePeerIdentity()
    const recipientX = x25519.utils.randomSecretKey()
    const recipientXPub = x25519.getPublicKey(recipientX)
    const recipientKid = 'did:webvh:{SCID}:y.biset.md#k_recipienthash'
    const routingJson = {
      service: [{ id: 'did:webvh:{SCID}:y.biset.md#didcomm', type: 'DIDCommMessaging', serviceEndpoint: { uri: 'https://recipient-core.test.example/v1/didcomm/ingress', accept: ['didcomm/v2'], routingKeys: [] } }],
      keyAgreementVerificationMethod: [{ id: recipientKid, type: 'Multikey', controller: 'did:webvh:{SCID}:y.biset.md', publicKeyMultibase: encodeX25519Multikey(recipientXPub) }],
    }
    const delivered: { url: string; body: string }[] = []
    const fetchImpl = (async (input, init) => {
      const url = typeof input === 'string' ? input : input.toString()
      if (url === 'https://y.biset.md/.well-known/routing.json') return new Response(JSON.stringify(routingJson), { status: 200 })
      if (url === 'https://recipient-core.test.example/v1/didcomm/ingress') {
        delivered.push({ url, body: init?.body as string })
        return new Response(null, { status: 202 })
      }
      return new Response('unexpected request: ' + url, { status: 500 })
    }) as typeof fetch

    const listener = createMailPluginListener({
      port: 0,
      helloName: 'mail.biset.md',
      apexDomain: 'biset.md',
      senderIdentity: { kid: sender.xKid, privateKey: sender.xPriv },
      fetch: fetchImpl,
    })
    try {
      const socket = await connectRaw(listener.port)
      await readReply(socket) // 220 banner
      socket.write('EHLO client.example\r\n'); await readReply(socket)
      socket.write('MAIL FROM:<a@example.com>\r\n'); await readReply(socket)
      socket.write('RCPT TO:<y@biset.md>\r\n')
      expect(await readReply(socket)).toContain('250')
      socket.write('DATA\r\n'); await readReply(socket)
      const body = 'Subject: hi\r\n\r\nhello world\r\n.\r\n'
      socket.write(body)
      expect(await readReply(socket)).toContain('250')
      socket.write('QUIT\r\n')
      await readReply(socket)
      socket.end()
    } finally {
      listener.stop()
    }

    expect(delivered).toHaveLength(1)
    const { plaintext, senderKid } = await unpackAuthcrypt(JSON.parse(delivered[0]!.body), { kid: recipientKid, privateKey: recipientX }, async () => sender.xPub)
    expect(senderKid).toBe(sender.xKid)
    const msg = JSON.parse(new TextDecoder().decode(plaintext))
    expect(msg.type).toBe('https://biset.md/mail-bridge/1.0/inbound')
  })

  test('RCPT TO an address with no routing.json is rejected 550', async () => {
    const sender = generatePeerIdentity()
    const fetchImpl = (async () => new Response('not found', { status: 404 })) as typeof fetch
    const listener = createMailPluginListener({
      port: 0, helloName: 'mail.biset.md', apexDomain: 'biset.md',
      senderIdentity: { kid: sender.xKid, privateKey: sender.xPriv }, fetch: fetchImpl,
    })
    try {
      const socket = await connectRaw(listener.port)
      await readReply(socket)
      socket.write('EHLO client.example\r\n'); await readReply(socket)
      socket.write('MAIL FROM:<a@example.com>\r\n'); await readReply(socket)
      socket.write('RCPT TO:<nobody@biset.md>\r\n')
      expect(await readReply(socket)).toContain('550')
      socket.end()
    } finally {
      listener.stop()
    }
  })
})
