import { expect, test } from 'bun:test'
import { createMimiDeployment } from '../../src/mimi/deployment.ts'
import { createMimiVaultRoom } from '../../src/mls/mimi-vault-room.ts'
import { MimiClientTransport } from '../../src/mls/mimi-client-transport.ts'
import { createMlsDeviceCredential } from '../../src/mls/device-credential.ts'
import { ed25519 } from '@noble/curves/ed25519.js'

test('creates a random self room with its initial MLS AppData and persists only after acceptance', async () => {
  const deployment = createMimiDeployment({ databasePath: ':memory:', mode: 'normal', allowExternalJoin: true, publicBaseUrl: 'https://self.example' })
  const transport = new MimiClientTransport({ normalBaseUrl: 'https://normal.example', anonBaseUrl: 'https://anon.example', selfBaseUrl: 'https://self.example', fetch: (input, init) => deployment.fetch(new Request(input, init)) })
  const root = ed25519.utils.randomSecretKey(); const sign = ed25519.utils.randomSecretKey()
  const identity = 'did:example:owner'; const deviceId = `${identity}#device`
  const credential = createMlsDeviceCredential(identity, `1-${'A'.repeat(20)}`, ed25519.getPublicKey(sign), root, sign)
  let saved: { roomId: string } | undefined
  const created = await createMimiVaultRoom({ identityId: identity, deviceId, selfGroupId: 'self', credential, signaturePrivateKey: sign, transport, stateStore: {
    async loadMimiVault() { return undefined }, async saveMimiVault(_identity, value) { saved = value },
  }, providerHost: 'self.example' })
  expect(created.roomId).toMatch(/^mimi:\/\/self\.example\/r\/vault-[A-Za-z0-9_-]{43}$/)
  expect(saved?.roomId).toBe(created.roomId)
  expect(deployment.store.room(created.roomId)?.metadata.roomName).toBe('Biset Vault')
  deployment.close()
})
