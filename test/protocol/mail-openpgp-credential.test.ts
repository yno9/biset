import { describe, expect, test } from 'bun:test'
import * as openpgp from 'openpgp'
import { generateOpenPgpPrivateCredential, publishableOpenPgpPublicKey, readOpenPgpPrivateCredential } from '../../src/mail/openpgp-credential.ts'

describe('endpoint OpenPGP credential', () => {
  test('generates a dedicated OpenPGP key that is valid before vault storage', async () => {
    const credential = await generateOpenPgpPrivateCredential({ identityId: 'did:web:alice.example', userIDs: [{ name: 'Alice', email: 'alice@example.com' }], createdAt: '2026-08-21T00:00:00.000Z' })
    expect(credential.fingerprint).toMatch(/^[0-9A-F]{40}$/)
    expect((await readOpenPgpPrivateCredential(credential)).getFingerprint().toUpperCase()).toBe(credential.fingerprint)
  })

  test('rejects a credential whose declared fingerprint does not belong to its private packet', async () => {
    const credential = await generateOpenPgpPrivateCredential({ identityId: 'did:web:alice.example', userIDs: [{ email: 'alice@example.com' }], createdAt: '2026-08-21T00:00:00.000Z' })
    await expect(readOpenPgpPrivateCredential({ ...credential, fingerprint: '0123456789ABCDEF0123456789ABCDEF01234567' })).rejects.toThrow('fingerprint')
  })

  test('exports only a matching public certificate for DID/WKD/Autocrypt publication', async () => {
    const credential = await generateOpenPgpPrivateCredential({ identityId: 'did:web:alice.example', userIDs: [{ email: 'alice@example.com' }], createdAt: '2026-08-21T00:00:00.000Z' })
    const publication = await publishableOpenPgpPublicKey(credential)
    expect(publication).toMatchObject({ version: 1, identityId: credential.identityId, fingerprint: credential.fingerprint })
    expect(publication.armoredPublicKey).not.toContain('PRIVATE KEY')
    expect((await openpgp.readKey({ armoredKey: publication.armoredPublicKey })).getFingerprint().toUpperCase()).toBe(credential.fingerprint)
  })
})
