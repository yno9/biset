import { describe, expect, test } from 'vitest'
import * as openpgp from 'openpgp'
import { generatePgpKey, importPgpKey, keyNamesAddress, readPgpKey } from '../src/client/pgp/keyring.ts'
import { currentOpenPgpCredential, type OpenPgpPrivateCredentialV1 } from '../src/client/store/vault/openpgp-credential.ts'
import { resolveMailBridgeDid } from '../src/client/didcomm/address-resolver.ts'
import { publishPgpKey } from '../src/client/pgp/publish.ts'

describe('OpenPGP key', () => {
  test('a generated key names the address, has a v4 fingerprint, and its stored bytes give the same key back', async () => {
    const key = await generatePgpKey('alice@did.md', 'Alice')
    expect(key.fingerprint).toMatch(/^[0-9A-F]{40}$/)
    expect(keyNamesAddress(key, 'ALICE@did.md')).toBe(true)
    expect(keyNamesAddress(key, 'bob@did.md')).toBe(false)
    expect(key.publicArmor).toContain('BEGIN PGP PUBLIC KEY BLOCK')
    expect(key.publicArmor).not.toContain('PRIVATE')
    const again = await readPgpKey(key.privateKey)
    expect([again.fingerprint, again.publicArmor]).toEqual([key.fingerprint, key.publicArmor])
  })

  test('the stored secret key decrypts what the published public key encrypted, and signs what that key verifies', async () => {
    const key = await generatePgpKey('alice@did.md')
    const message = await openpgp.createMessage({ text: 'for alice' })
    const encrypted = await openpgp.encrypt({ message, encryptionKeys: await openpgp.readKey({ armoredKey: key.publicArmor }) })
    const secret = await openpgp.readPrivateKey({ binaryKey: key.privateKey })
    const decrypted = await openpgp.decrypt({ message: await openpgp.readMessage({ armoredMessage: encrypted }), decryptionKeys: secret })
    expect(decrypted.data).toBe('for alice')

    const signed = await openpgp.sign({ message: await openpgp.createMessage({ text: 'signed by alice' }), signingKeys: secret, detached: true })
    const verified = await openpgp.verify({ message: await openpgp.createMessage({ text: 'signed by alice' }), signature: await openpgp.readSignature({ armoredSignature: signed }), verificationKeys: await openpgp.readKey({ armoredKey: key.publicArmor }) })
    expect(await verified.signatures[0]!.verified).toBe(true)
  })

  test('an existing key is taken in: armored or binary; a passphrase-protected one needs its passphrase, which is not kept', async () => {
    const { privateKey } = await openpgp.generateKey({ type: 'curve25519', userIDs: [{ email: 'carol@example.com' }], passphrase: 'correct horse', format: 'armored' })
    await expect(importPgpKey(privateKey)).rejects.toThrow('passphrase')
    await expect(importPgpKey(privateKey, 'wrong')).rejects.toThrow('does not unlock')
    const imported = await importPgpKey(privateKey, 'correct horse')
    expect(keyNamesAddress(imported, 'carol@example.com')).toBe(true)
    // the stored bytes open with no passphrase
    expect((await readPgpKey(imported.privateKey)).fingerprint).toBe(imported.fingerprint)
    expect((await importPgpKey(imported.privateKey)).fingerprint).toBe(imported.fingerprint)
    await expect(importPgpKey('not a key')).rejects.toThrow('not an OpenPGP secret key')
    await expect(importPgpKey(imported.publicArmor)).rejects.toThrow('not an OpenPGP secret key')
  })
})

describe('current OpenPGP credential', () => {
  const credential = (fingerprint: string, createdAt: string, supersedesFingerprint?: string): OpenPgpPrivateCredentialV1 => ({
    version: 1, kind: 'credential.openpgp.private', identityId: 'did:web:x', fingerprint, privateKey: new Uint8Array([1]), createdAt, ...(supersedesFingerprint ? { supersedesFingerprint } : {}),
  })
  const [A, B, C] = ['A'.repeat(40), 'B'.repeat(40), 'C'.repeat(40)]
  test('the newest key that nothing supersedes', () => {
    expect(currentOpenPgpCredential([])).toBeUndefined()
    expect(currentOpenPgpCredential([credential(A, '2026-01-01T00:00:00.000Z')])!.fingerprint).toBe(A)
    expect(currentOpenPgpCredential([credential(A, '2026-01-01T00:00:00.000Z'), credential(B, '2026-02-01T00:00:00.000Z', A)])!.fingerprint).toBe(B)
    // two devices made one each: the later is used, whichever device reads
    expect(currentOpenPgpCredential([credential(C, '2026-03-01T00:00:00.000Z'), credential(B, '2026-02-01T00:00:00.000Z')])!.fingerprint).toBe(C)
  })
})

describe('publishing the key at the mail bridge', () => {
  const fetchFor = (bridgeLink: unknown): typeof fetch => (async (input: string | URL | Request) => {
    const url = new URL(String(input))
    if (url.host === 'did.md' && url.pathname === '/.well-known/webfinger') return Response.json({ subject: 'x', aliases: ['did:webvh:Qm:alice.did.md'], links: bridgeLink ? [bridgeLink] : [] })
    return new Response('unexpected: ' + url, { status: 500 })
  }) as typeof fetch

  test('the bridge DID of the address is the link the gateway names, not the DID the address resolves to', async () => {
    const fetchImpl = fetchFor({ rel: 'https://did.md/rel/mail-bridge', href: 'did:web:did.md:did.md:alice' })
    expect(await resolveMailBridgeDid('alice@did.md', ['did.md'], fetchImpl)).toBe('did:web:did.md:did.md:alice')
    await expect(resolveMailBridgeDid('alice@did.md', ['did.md'], fetchFor(undefined))).rejects.toThrow('No mail gateway answers')
    await expect(resolveMailBridgeDid('alice@did.md', [], fetchImpl)).rejects.toThrow('No mail gateway is configured')
  })

  test('a gateway that does not name a bridge DID stops the publication before anything is sent', async () => {
    await expect(publishPgpKey({ address: 'alice@did.md', gateways: ['did.md'], publicArmor: 'x', fromKid: 'did:webvh:Qm:alice.did.md#k', x25519PrivateKey: new Uint8Array(32), fetch: fetchFor(undefined) })).rejects.toThrow('No mail gateway answers')
  })
})
