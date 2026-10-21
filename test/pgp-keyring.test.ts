import { describe, expect, test } from 'vitest'
import * as openpgp from 'openpgp'
import { generatePgpKey } from './support/pgp.ts'
import { autocryptKeydata } from '../src/client/pgp/keyring.ts'

describe('autocryptKeydata', () => {
  test('a generated key is already minimal; the keydata reads back as the same key', async () => {
    const key = await generatePgpKey('alice@did.md', 'Alice')
    const keydata = await autocryptKeydata(key.privateKey, 'alice@did.md')
    expect(keydata).toMatch(/^[A-Za-z0-9+/]+={0,2}$/)
    const bytes = Uint8Array.from(atob(keydata), char => char.charCodeAt(0))
    expect(bytes[0]).toBe(0xc6) // a new-format Public-Key packet
    const back = await openpgp.readKey({ binaryKey: bytes })
    expect(back.getFingerprint().toUpperCase()).toBe(key.fingerprint)
    expect(back.isPrivate()).toBe(false)
    expect(bytes.length).toBeLessThan(700)
  })

  test('an imported key with other user IDs and subkeys is cut down to one user ID and one encryption subkey', async () => {
    const { privateKey } = await openpgp.generateKey({
      type: 'curve25519', userIDs: [{ email: 'old@example.com' }, { name: 'Carol', email: 'carol@example.com' }],
      subkeys: [{}, { sign: true }], format: 'object',
    })
    const keydata = await autocryptKeydata(privateKey.write(), 'carol@example.com')
    const back = await openpgp.readKey({ binaryKey: Uint8Array.from(atob(keydata), char => char.charCodeAt(0)) })
    expect(back.getFingerprint()).toBe(privateKey.getFingerprint())
    expect(back.getUserIDs()).toEqual(['Carol <carol@example.com>'])
    expect(back.subkeys).toHaveLength(1)
    const message = await openpgp.encrypt({ message: await openpgp.createMessage({ text: 'hi' }), encryptionKeys: back })
    const decrypted = await openpgp.decrypt({ message: await openpgp.readMessage({ armoredMessage: message }), decryptionKeys: privateKey })
    expect(decrypted.data).toBe('hi')
  })
})
