import { describe, expect, test } from 'bun:test'
import * as openpgp from 'openpgp'
import { decryptOpenPgpMessage } from '../../src/mail/openpgp-message.ts'
import { generateOpenPgpPrivateCredential, publishableOpenPgpPublicKey, readOpenPgpPrivateCredential } from '../../src/mail/openpgp-credential.ts'
import { extractRfc3156EncryptedPacket } from '../../src/mail/rfc3156.ts'

const identityId = 'did:web:alice.example'

describe('endpoint OpenPGP message decrypt', () => {
  test('decrypts and verifies an extracted OpenPGP packet without any core dependency', async () => {
    const credential = await generateOpenPgpPrivateCredential({ identityId, userIDs: [{ email: 'alice@example.com' }], createdAt: '2026-08-22T00:00:00.000Z' })
    const publicCertificate = await publishableOpenPgpPublicKey(credential)
    const privateKey = await readOpenPgpPrivateCredential(credential)
    const publicKey = await openpgp.readKey({ armoredKey: publicCertificate.armoredPublicKey })
    const encrypted = await openpgp.encrypt({
      message: await openpgp.createMessage({ binary: new TextEncoder().encode('mail body') }),
      encryptionKeys: publicKey,
      signingKeys: privateKey,
      format: 'binary',
    })
    const decrypted = await decryptOpenPgpMessage({ credential, encryptedMessage: encrypted, verificationArmoredKeys: [publicCertificate.armoredPublicKey], requireValidSignature: true })
    expect(new TextDecoder().decode(decrypted.plaintext)).toBe('mail body')
    expect(decrypted.signatures).toMatchObject([{ valid: true }])
  })

  test('does not treat unsigned encrypted mail as authenticated when a signature is required', async () => {
    const credential = await generateOpenPgpPrivateCredential({ identityId, userIDs: [{ email: 'alice@example.com' }], createdAt: '2026-08-22T00:00:00.000Z' })
    const publicKey = await openpgp.readKey({ armoredKey: (await publishableOpenPgpPublicKey(credential)).armoredPublicKey })
    const encrypted = await openpgp.encrypt({ message: await openpgp.createMessage({ binary: new Uint8Array([1]) }), encryptionKeys: publicKey, format: 'binary' })
    await expect(decryptOpenPgpMessage({ credential, encryptedMessage: encrypted, requireValidSignature: true })).rejects.toThrow('valid required signature')
  })

  test('uses the RFC 3156 extractor before endpoint-only packet decryption', async () => {
    const credential = await generateOpenPgpPrivateCredential({ identityId, userIDs: [{ email: 'alice@example.com' }], createdAt: '2026-08-22T00:00:00.000Z' })
    const publicKey = await openpgp.readKey({ armoredKey: (await publishableOpenPgpPublicKey(credential)).armoredPublicKey })
    const encrypted = await openpgp.encrypt({ message: await openpgp.createMessage({ binary: new TextEncoder().encode('RFC 3156 body') }), encryptionKeys: publicKey, format: 'binary' })
    const raw = [
      'Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary="pgp"', '',
      '--pgp', 'Content-Type: application/pgp-encrypted', '', 'Version: 1',
      '--pgp', 'Content-Type: application/octet-stream', 'Content-Transfer-Encoding: base64', '', binaryBase64(encrypted), '--pgp--',
    ].join('\r\n')
    const packet = extractRfc3156EncryptedPacket(new TextEncoder().encode(raw))
    expect(new TextDecoder().decode((await decryptOpenPgpMessage({ credential, encryptedMessage: packet })).plaintext)).toBe('RFC 3156 body')
  })
})

function binaryBase64(bytes: Uint8Array): string {
  let text = ''
  for (const byte of bytes) text += String.fromCharCode(byte)
  return btoa(text)
}
