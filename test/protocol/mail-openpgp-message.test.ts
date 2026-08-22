import { describe, expect, test } from 'bun:test'
import * as openpgp from 'openpgp'
import { decryptOpenPgpMessage } from '../../src/mail/openpgp-message.ts'
import { generateOpenPgpPrivateCredential, publishableOpenPgpPublicKey, readOpenPgpPrivateCredential } from '../../src/mail/openpgp-credential.ts'

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
})
