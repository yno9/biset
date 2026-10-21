import { describe, expect, test, vi } from 'vitest'
import * as openpgp from 'openpgp'
import { generatePgpKey } from './support/pgp.ts'
import { autocryptKeydata } from '../src/client/pgp/keyring.ts'
import { composeEncryptedMail, HIDDEN_SUBJECT, messageIdOf } from '../src/client/pgp/compose.ts'
import { decodeEncodedWords, parseInnerMime } from '../src/client/pgp/mime.ts'
import { decryptMessage } from '../src/client/pgp/message-crypto.ts'
import { bridgeHostOf, mailAddressOfBridgeDid, shouldEncrypt } from '../src/client/pgp/autocrypt.ts'
import { bytesToBase64url } from '../src/protocol/canonical.ts'

const sent: Array<{ toDid: string; type: string; body: Record<string, unknown>; opts: Record<string, unknown> }> = []
vi.mock('../src/client/didcomm/front-door-send.ts', () => ({
  sendFrontDoorMessage: async (toDid: string, type: string, body: Record<string, unknown>, opts: Record<string, unknown>) => { sent.push({ toDid, type, body, opts }); return { ok: true } },
}))
const { sendDidCommMessage } = await import('../src/client/didcomm/send-message.ts')

const publicBytes = async (key: { publicArmor: string }) => (await openpgp.readKey({ armoredKey: key.publicArmor })).write()

describe('writing an encrypted mail', () => {
  test('the recipient reads the real subject, the Message-ID the bridge will set, the thread and the sender\'s key; the outside shows nothing', async () => {
    const alice = await generatePgpKey('alice@did.md'), bob = await generatePgpKey('bob@x.test')
    const keydata = await autocryptKeydata(alice.privateKey, 'alice@did.md')
    const { armored, outerSubject } = await composeEncryptedMail({
      id: 'm-1', thid: 'abc@mail.x.test', bridgeHost: 'did.md', subject: '秘密の話', content: 'the words', sentAt: '2026-10-21T01:02:03.000Z',
      fromAddress: 'alice@did.md', fromName: 'Alice', toAddress: 'bob@x.test', own: { privateKey: alice.privateKey, keydata }, peerKey: await publicBytes(bob),
    })
    expect(outerSubject).toBe(HIDDEN_SUBJECT)
    expect(armored).not.toContain('the words')
    const opened = await decryptMessage({ armored, privateKey: bob.privateKey, senderKeys: [await publicBytes(alice)] })
    expect(opened.signature?.verified).toBe(true)
    const mime = parseInnerMime(opened.plaintext)
    expect(mime.body).toBe('the words')
    expect(decodeEncodedWords(mime.headers.subject!)).toBe('秘密の話')
    expect(mime.headers['message-id']).toBe('<m-1@did.md>')
    expect(mime.headers['chat-version']).toBe('1.0') // so that Delta Chat shows the text alone
    expect(mime.headers['in-reply-to']).toBe('<abc@mail.x.test>')
    expect(mime.headers.references).toBe('<abc@mail.x.test>')
    expect(mime.headers.to).toBe('bob@x.test')
    expect(mime.headers.date).toBe('Wed, 21 Oct 2026 01:02:03 GMT')
    expect(mime.headers.autocrypt).toMatch(/^addr=alice@did\.md; prefer-encrypt=mutual; keydata=/)
    // Alice reads her own copy, too.
    expect(parseInnerMime((await decryptMessage({ armored, privateKey: alice.privateKey })).plaintext).body).toBe('the words')
  })

  test('the Message-ID follows the bridge\'s rule: an id with no @ gets the bridge host, one with an @ is the Message-ID', () => {
    expect(messageIdOf('m-1', 'did.md')).toBe('<m-1@did.md>')
    expect(messageIdOf('x@y.test', 'did.md')).toBe('<x@y.test>')
  })

  test('a bridge DID gives its host and its address; only a key that asks for mutual encryption is written to encrypted', () => {
    expect(bridgeHostOf('did:web:did.md:4r.ma:n')).toBe('did.md')
    expect(mailAddressOfBridgeDid('did:web:did.md:gmail.com:bob%2Bnews')).toBe('bob+news@gmail.com')
    expect(bridgeHostOf('did:webvh:Qm1:alice.did.md')).toBeUndefined()
    expect(shouldEncrypt({ preferEncrypt: 'mutual' })).toBe(true)
    expect(shouldEncrypt({})).toBe(false)
    expect(shouldEncrypt(undefined)).toBe(false)
  })
})

describe('sending it', () => {
  const opts = { fromKid: 'did:webvh:x:alice.did.md#k1', x25519PrivateKey: new Uint8Array(32) }

  test('an encrypted message is a basicmessage with encryption=openpgp and the armor as the one `pgp` attachment, no content', async () => {
    sent.length = 0
    const armored = '-----BEGIN PGP MESSAGE-----\n\nwcBMA0\n=abcd\n-----END PGP MESSAGE-----\n'
    await sendDidCommMessage('did:web:did.md:4r.ma:n', 'secret words', { ...opts, subject: '[...]', encrypted: { armored } })
    const [only] = sent
    expect(only!.body).toMatchObject({ content: '', encryption: 'openpgp', subject: '[...]' })
    expect(JSON.stringify(only!.body)).not.toContain('secret words')
    expect(only!.opts.attachments).toEqual([{ id: 'pgp', filename: 'encrypted.asc', media_type: 'application/octet-stream', data: { base64: bytesToBase64url(new TextEncoder().encode(armored)) } }])
  })

  test('an ordinary message carries its content and no attachment', async () => {
    sent.length = 0
    await sendDidCommMessage('did:web:did.md:4r.ma:n', 'plain words', opts)
    expect(sent[0]!.body).toMatchObject({ content: 'plain words' })
    expect('encryption' in sent[0]!.body).toBe(false)
    expect(sent[0]!.opts.attachments).toBeUndefined()
  })
})
