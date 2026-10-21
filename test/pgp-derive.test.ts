import { describe, expect, test } from 'vitest'
import * as openpgp from 'openpgp'
import { ed25519 } from '@noble/curves/ed25519.js'
import { DERIVED_KEY_TIME, derivePgpKey, isPrimaryOf } from '../src/client/pgp/derive.ts'
import { autocryptKeydata, keyNamesAddress } from '../src/client/pgp/keyring.ts'
import { rotationSigningKey } from '../src/client/didcomm/rotation-key.ts'
import { decryptMessage, encryptMessage } from '../src/client/pgp/message-crypto.ts'

const seed = () => crypto.getRandomValues(new Uint8Array(32))

describe('the PGP key derived from the generation seed', () => {
  test('the same seed and address give the same key, byte for byte: secret and public', async () => {
    const value = seed()
    const first = await derivePgpKey(value, 'alice@did.md'), second = await derivePgpKey(value.slice(), 'alice@did.md')
    expect([...second.privateKey]).toEqual([...first.privateKey])
    expect(second.publicArmor).toBe(first.publicArmor)
    expect(second.fingerprint).toBe(first.fingerprint)
    expect(second.fingerprint).toMatch(/^[0-9A-F]{40}$/)
  })

  test('another seed (another generation) or another address is another key', async () => {
    const value = seed()
    const base = await derivePgpKey(value, 'alice@did.md')
    expect((await derivePgpKey(seed(), 'alice@did.md')).fingerprint).not.toBe(base.fingerprint)
    expect((await derivePgpKey(value, 'bob@did.md')).publicArmor).not.toBe(base.publicArmor)
  })

  test('it has the format Delta Chat uses: v4, EdDSA legacy primary, ECDH curve25519 subkey, the address as user ID, no expiry', async () => {
    const key = await openpgp.readKey({ armoredKey: (await derivePgpKey(seed(), 'alice@did.md')).publicArmor })
    expect(key.keyPacket.version).toBe(4)
    expect(key.keyPacket.algorithm).toBe(openpgp.enums.publicKey.eddsaLegacy)
    expect(key.subkeys).toHaveLength(1)
    expect(key.subkeys[0]!.keyPacket.algorithm).toBe(openpgp.enums.publicKey.ecdh)
    expect(key.getUserIDs()).toEqual(['<alice@did.md>'])
    expect(key.keyPacket.created).toEqual(DERIVED_KEY_TIME)
    expect(await key.getExpirationTime()).toBe(Infinity)
    expect(await key.verifyPrimaryKey()).toBeUndefined()
  })

  test('its primary key is the one the DID document publishes as #biset-generation', async () => {
    const value = seed()
    const key = await openpgp.readKey({ armoredKey: (await derivePgpKey(value, 'alice@did.md')).publicArmor })
    const published = rotationSigningKey(value).publicKey
    expect(Uint8Array.from((key.keyPacket.publicParams as { Q: Uint8Array }).Q.slice(1))).toEqual(Uint8Array.from(published))
    expect(isPrimaryOf(value, published)).toBe(true)
    expect(isPrimaryOf(seed(), published)).toBe(false)
    expect(ed25519.getPublicKey(rotationSigningKey(value).privateKey)).toEqual(published)
  })

  test('it works as a key: names its address, signs, and decrypts what is encrypted to its public half', async () => {
    const alice = await derivePgpKey(seed(), 'alice@did.md'), bob = await derivePgpKey(seed(), 'bob@x.test')
    expect(keyNamesAddress(alice, 'alice@did.md')).toBe(true)
    const publicBytes = async (key: { publicArmor: string }) => (await openpgp.readKey({ armoredKey: key.publicArmor })).write()
    const armored = await encryptMessage({ plaintext: 'derived', recipients: [await publicBytes(bob)], signer: alice.privateKey })
    const opened = await decryptMessage({ armored, privateKey: bob.privateKey, senderKeys: [await publicBytes(alice)] })
    expect(opened.plaintext).toBe('derived')
    expect(opened.signature?.verified).toBe(true)
    // the sender's own copy
    expect((await decryptMessage({ armored, privateKey: alice.privateKey })).plaintext).toBe('derived')
  })

  test('the Autocrypt keydata of the derived key is the same wherever it is made, and is small', async () => {
    const value = seed()
    const key = await derivePgpKey(value, 'alice@did.md')
    const keydata = await autocryptKeydata(key.privateKey, 'alice@did.md')
    expect(keydata).toBe(await autocryptKeydata((await derivePgpKey(value, 'alice@did.md')).privateKey, 'alice@did.md'))
    expect(atob(keydata).length).toBeLessThan(400)
  })
})
