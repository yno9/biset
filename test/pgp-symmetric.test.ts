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

  test('the session key packet is the v4 salted S2K kind Delta Chat insists on, with no encrypted session key', async () => {
    const alice = await generatePgpKey('alice@did.md')
    const armored = await symmetricEncryptSigned('x', 'pw', alice.privateKey)
    const packets = await openpgp.PacketList.fromBinary((await openpgp.readMessage({ armoredMessage: armored })).write(), { [openpgp.enums.packet.symEncryptedSessionKey]: openpgp.SymEncryptedSessionKeyPacket, [openpgp.enums.packet.symEncryptedIntegrityProtectedData]: openpgp.SymEncryptedIntegrityProtectedDataPacket } as never, openpgp.config)
    const skesk = packets[0] as unknown as { version: number; s2k: { type: string; algorithm: number }; sessionKeyEncryptionAlgorithm: number | null; encrypted: unknown }
    expect(skesk.version).toBe(4)
    expect(skesk.s2k.type).toBe('salted')
    expect(skesk.s2k.algorithm).toBe(openpgp.enums.hash.sha256)
    expect(skesk.encrypted).toBeNull()
  })

  test('a message that is not a password message, or not armor, is simply not opened', async () => {
    const alice = await generatePgpKey('alice@did.md')
    const forKey = await openpgp.encrypt({ message: await openpgp.createMessage({ text: 'x' }), encryptionKeys: await openpgp.readKey({ armoredKey: alice.publicArmor }) }) as string
    expect(await symmetricDecrypt(forKey, ['pw'])).toBeUndefined()
    expect(await symmetricDecrypt('not armor', ['pw'])).toBeUndefined()
  })
})
