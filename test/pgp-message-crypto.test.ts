import { describe, expect, test } from 'vitest'
import * as openpgp from 'openpgp'
import { generatePgpKey, autocryptKeydata } from '../src/client/pgp/keyring.ts'
import { buildInnerMime, decodeEncodedWords, encodeHeaderValue, keydataHeader, parseInnerMime } from '../src/client/pgp/mime.ts'
import { decryptMessage, encryptMessage, ensureArmorChecksum, extractArmor, NotEncryptedToUsError } from '../src/client/pgp/message-crypto.ts'

const publicBytes = async (key: { publicArmor: string }) => (await openpgp.readKey({ armoredKey: key.publicArmor })).write()

describe('the inner MIME', () => {
  test('a message built here reads back: protected headers, non-ASCII subject and name, the body', () => {
    const text = buildInnerMime({
      headers: [['Subject', 'こんにちは'], ['From', 'Alice é <alice@did.md>'], ['To', 'n@4r.ma'], ['Message-ID', '<m1@did.md>'], ['Chat-Version', '1.0']],
      text: 'hello\r\nsecond line',
    })
    expect(text.startsWith('Content-Type: text/plain; charset=utf-8')).toBe(true)
    expect(/[^\x00-\x7f]/.test(text.split('\r\n\r\n')[0]!)).toBe(false) // headers are ASCII on the wire
    const mime = parseInnerMime(text)
    expect(decodeEncodedWords(mime.headers.subject!)).toBe('こんにちは')
    expect(decodeEncodedWords(mime.headers.from!)).toBe('Alice é <alice@did.md>')
    expect(mime.headers['chat-version']).toBe('1.0')
    expect(mime.headers['message-id']).toBe('<m1@did.md>')
    expect(mime.body).toBe('hello\r\nsecond line')
  })

  test('a header value cannot carry a line break, and a header name must be a token', () => {
    const text = buildInnerMime({ headers: [['Subject', 'hi\r\nBcc: evil@x.test']], text: 'x' })
    expect(parseInnerMime(text).headers.bcc).toBeUndefined()
    expect(() => buildInnerMime({ headers: [['Bad Name', 'x']], text: 'x' })).toThrow('header name')
    expect(encodeHeaderValue('plain')).toBe('plain')
  })

  test('Autocrypt and Autocrypt-Gossip: keydata folded on continuation lines, every gossip header kept', async () => {
    const key = await generatePgpKey('alice@did.md')
    const keydata = await autocryptKeydata(key.privateKey, 'alice@did.md')
    const text = buildInnerMime({
      lines: [keydataHeader('Autocrypt', 'alice@did.md', keydata, true), keydataHeader('Autocrypt-Gossip', 'bob@x.test', keydata), keydataHeader('Autocrypt-Gossip', 'carol@x.test', keydata)],
      text: 'hi',
    })
    const mime = parseInnerMime(text)
    expect(mime.headers.autocrypt).toMatch(/^addr=alice@did\.md; prefer-encrypt=mutual; keydata=/)
    expect(mime.headers.autocrypt!.replace(/.*keydata=/, '').replace(/\s/g, '')).toBe(keydata)
    expect(mime.gossip.map(value => /addr=([^;]+)/.exec(value)![1])).toEqual(['bob@x.test', 'carol@x.test'])
  })

  test('a Delta Chat style multipart body: the text part is the body, the rest are attachments; quoted-printable decodes', () => {
    const text = [
      'Content-Type: multipart/mixed; boundary="B1"', 'Chat-Version: 1.0', 'Subject: s', '', '--B1',
      'Content-Type: text/plain; charset=utf-8', 'Content-Transfer-Encoding: quoted-printable', '', 'caf=C3=A9', '--B1',
      'Content-Type: image/png; name="a.png"', 'Content-Disposition: attachment; filename="a.png"', 'Content-Transfer-Encoding: base64', '', 'AQID', '--B1--', '',
    ].join('\r\n')
    const mime = parseInnerMime(text)
    expect(mime.body).toBe('café')
    expect(mime.attachments).toEqual([{ contentType: 'image/png', filename: 'a.png', bytes: new Uint8Array([1, 2, 3]) }])
  })

  test('text with no header block is just a body; the nesting is bounded', () => {
    expect(parseInnerMime('just words').body).toBe('just words')
    const deep = Array.from({ length: 30 }, (_, index) => `Content-Type: multipart/mixed; boundary="b${index}"\r\n\r\n--b${index}\r\n`).join('')
    expect(() => parseInnerMime(deep)).not.toThrow()
  })
})

describe('encryptMessage and decryptMessage', () => {
  test('the recipient reads it and the signature verifies against the sender\'s key; the sender reads its own copy', async () => {
    const alice = await generatePgpKey('alice@did.md'), bob = await generatePgpKey('bob@x.test')
    const inner = buildInnerMime({ headers: [['Subject', 'secret'], ['Chat-Version', '1.0']], text: 'for bob' })
    const armored = await encryptMessage({ plaintext: inner, recipients: [await publicBytes(bob)], signer: alice.privateKey })
    expect(armored).toContain('BEGIN PGP MESSAGE')
    expect(/^=[A-Za-z0-9+/]{4}$/m.test(armored)).toBe(true) // the CRC-24 line, which chatmail expects

    const forBob = await decryptMessage({ armored, privateKey: bob.privateKey, senderKeys: [await publicBytes(alice)] })
    expect(parseInnerMime(forBob.plaintext).body).toBe('for bob')
    expect(forBob.signature).toEqual({ keyId: expect.stringMatching(/^[0-9A-F]{16}$/), verified: true })
    const forAlice = await decryptMessage({ armored, privateKey: alice.privateKey })
    expect(parseInnerMime(forAlice.plaintext).headers.subject).toBe('secret')
    expect(forAlice.signature?.verified).toBe(false) // no sender key given: signed, but not checked
  })

  test('a signature from another key does not verify; a key that is not a recipient cannot read it', async () => {
    const alice = await generatePgpKey('alice@did.md'), bob = await generatePgpKey('bob@x.test'), mallory = await generatePgpKey('mallory@x.test')
    const armored = await encryptMessage({ plaintext: 'x', recipients: [await publicBytes(bob)], signer: alice.privateKey })
    expect((await decryptMessage({ armored, privateKey: bob.privateKey, senderKeys: [await publicBytes(mallory)] })).signature?.verified).toBe(false)
    await expect(decryptMessage({ armored, privateKey: mallory.privateKey })).rejects.toBeInstanceOf(NotEncryptedToUsError)
  })

  test('the armor may sit in a text a bridge added around it', async () => {
    const alice = await generatePgpKey('alice@did.md'), bob = await generatePgpKey('bob@x.test')
    const armored = await encryptMessage({ plaintext: 'hi', recipients: [await publicBytes(bob)], signer: alice.privateKey })
    const wrapped = `This message is encrypted with OpenPGP.\n\n${armored}\n-- \nfooter`
    expect(extractArmor(wrapped)).toBe(armored.trim())
    expect((await decryptMessage({ armored: wrapped, privateKey: bob.privateKey })).plaintext).toBe('hi')
  })

  test('ensureArmorChecksum adds the CRC-24 openpgp.js leaves out of an AEAD message, and leaves a complete one alone', async () => {
    // A password message is SEIPD v2 whenever AEAD is on (a public key message is v2 only for keys that say they support it).
    const aead = await openpgp.encrypt({ message: await openpgp.createMessage({ text: 'aead' }), passwords: ['secret'], config: { aeadProtect: true } }) as string
    expect(/^=[A-Za-z0-9+/]{4}$/m.test(aead)).toBe(false)
    const fixed = ensureArmorChecksum(aead)
    expect(/^=[A-Za-z0-9+/]{4}$/m.test(fixed)).toBe(true)
    expect(ensureArmorChecksum(fixed)).toBe(fixed)
    const read = await openpgp.decrypt({ message: await openpgp.readMessage({ armoredMessage: fixed }), passwords: ['secret'], config: { aeadProtect: true } })
    expect(read.data).toBe('aead')
  })
})
