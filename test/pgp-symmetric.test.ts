import { describe, expect, test } from 'vitest'
import * as openpgp from 'openpgp'
import { generatePgpKey } from './support/pgp.ts'
import { symmetricDecrypt, symmetricEncryptSigned } from '../src/client/pgp/symmetric.ts'

const publicBytes = async (key: { publicArmor: string }) => (await openpgp.readKey({ armoredKey: key.publicArmor })).write()

describe('password-encrypted messages (Secure-Join)', () => {
  test('what is encrypted to a password is opened by that password only, and the signature checks against the signer\'s key', async () => {
    const alice = await generatePgpKey('alice@did.md'), mallory = await generatePgpKey('mallory@x.test')
    const armored = await symmetricEncryptSigned('Secure-Join: vc-pubkey\r\n\r\nSecure-Join', 'securejoin/AAAA/secret', alice.privateKey)
    expect(armored).toContain('BEGIN PGP MESSAGE')
    expect(/^=[A-Za-z0-9+/]{4}$/m.test(armored)).toBe(true) // the CRC-24 chatmail expects

    expect(await symmetricDecrypt(armored, ['wrong', 'other'])).toBeUndefined()
    const opened = (await symmetricDecrypt(armored, ['wrong', 'securejoin/AAAA/secret'], [await publicBytes(alice)]))!
    expect(opened.plaintext.replace(/\r\n/g, '\n')).toBe('Secure-Join: vc-pubkey\n\nSecure-Join') // text mode: line ends are normalised
    expect(opened.signedBy).toEqual([(await openpgp.readKey({ armoredKey: alice.publicArmor })).getKeyID().toHex().toUpperCase()])
    expect((await symmetricDecrypt(armored, ['securejoin/AAAA/secret'], [await publicBytes(mallory)]))!.signedBy).toEqual([])
    expect((await symmetricDecrypt(armored, ['securejoin/AAAA/secret']))!.signedBy).toEqual([]) // signed, but not checked without a key
  })

  test('it has the shape of the password messages Delta Chat writes: a v6 session key packet (AES-128, OCB, salted S2K with SHA-256), then a v2 encrypted data packet', async () => {
    const alice = await generatePgpKey('alice@did.md')
    const armored = await symmetricEncryptSigned('x', 'pw', alice.privateKey)
    const bytes = (await openpgp.unarmor(armored)).data as Uint8Array
    // The same bytes, field by field, as the session key packet of a real Delta Chat message (captured 2026-10-21):
    // c3 3e 06 1c 07 02 0a 01 08 <salt 8> <nonce 15> <sealed session key 16 + tag 16>
    expect([...bytes.slice(0, 9)]).toEqual([0xc3, 0x3e, 0x06, 0x1c, 0x07, 0x02, 0x0a, 0x01, 0x08])
    // ...and then the encrypted data packet: type 18, version 2, AES-128 (7), OCB (2).
    const data = bytes.slice(2 + 0x3e)
    expect(data[0]! & 0x3f).toBe(18)
    const header = data[1]! < 192 ? 2 : data[1]! < 224 ? 3 : 6
    expect([...data.slice(header, header + 4)]).toEqual([2, 7, 2, 7]) // version 2, AES-128, OCB, 8 KiB chunks
  })

  test('a salted S2K and not a fixed password: two messages with the same password differ, and both open', async () => {
    const alice = await generatePgpKey('alice@did.md')
    const [first, second] = [await symmetricEncryptSigned('x', 'pw', alice.privateKey), await symmetricEncryptSigned('x', 'pw', alice.privateKey)]
    expect(first).not.toBe(second)
    expect((await symmetricDecrypt(first, ['pw']))!.plaintext).toBe('x')
    expect((await symmetricDecrypt(second, ['pw']))!.plaintext).toBe('x')
  })

  test('a message that is not a password message, or not armor, is simply not opened', async () => {
    const alice = await generatePgpKey('alice@did.md')
    const forKey = await openpgp.encrypt({ message: await openpgp.createMessage({ text: 'x' }), encryptionKeys: await openpgp.readKey({ armoredKey: alice.publicArmor }) }) as string
    expect(await symmetricDecrypt(forKey, ['pw'])).toBeUndefined()
    expect(await symmetricDecrypt('not armor', ['pw'])).toBeUndefined()
  })
})
