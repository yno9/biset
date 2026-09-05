import { expect, test } from 'bun:test'
import { ed25519 } from '@noble/curves/ed25519.js'
import { decryptAndVerifyIdentityLink, encryptIdentityLinkTbe } from '../../src/server/mimi/anon/identity-link.ts'

const roomId = 'mimi://anon.example/r/identity-link'
const exporter = { async exportSecret() { return new Uint8Array(32).fill(5) } }

test('IdentityLinkTBE binds its encrypted real credential to the exact pseudonymous credential', async () => {
  const secret = ed25519.utils.randomSecretKey()
  const tbs = { clientPseudonym: 'mimi://anon.example/c/a', userPseudonym: 'mimi://anon.example/u/a', signaturePublicKey: ed25519.getPublicKey(secret) }
  const credential = { kind: 'pseudonymous' as const, ...tbs, identityLinkCiphertext: await encryptIdentityLinkTbe(exporter, roomId, tbs, new TextEncoder().encode('verified real credential'), bytes => ed25519.sign(bytes, secret)) }
  const verify = (clientCredential: Uint8Array, signingKey: Uint8Array) => new TextDecoder().decode(clientCredential) === 'verified real credential' && signingKey.every((byte, index) => byte === tbs.signaturePublicKey[index])
  expect(new TextDecoder().decode((await decryptAndVerifyIdentityLink(exporter, roomId, credential, verify)).clientCredential)).toBe('verified real credential')
  await expect(decryptAndVerifyIdentityLink(exporter, roomId, { ...credential, userPseudonym: 'mimi://anon.example/u/attacker' }, verify)).rejects.toThrow('does not bind')
  await expect(decryptAndVerifyIdentityLink(exporter, roomId, credential, () => false)).rejects.toThrow('real credential does not match')
})
