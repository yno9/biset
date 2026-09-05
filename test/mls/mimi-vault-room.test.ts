import { expect, test } from 'bun:test'
import { createMimiDeployment } from '../../src/server/mimi/deployment.ts'
import { createMimiVaultRoom, joinMimiVaultRoom } from '../../src/mls/mimi-vault-room.ts'
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

test('a freshly restored device obtains GroupInfo and externally joins its owner self room', async () => {
  const deployment = createMimiDeployment({ databasePath: ':memory:', mode: 'normal', allowExternalJoin: true, publicBaseUrl: 'https://self.example' })
  const transport = new MimiClientTransport({ normalBaseUrl: 'https://normal.example', anonBaseUrl: 'https://anon.example', selfBaseUrl: 'https://self.example', fetch: (input, init) => deployment.fetch(new Request(input, init)) })
  const root = ed25519.utils.randomSecretKey(); const firstSign = ed25519.utils.randomSecretKey(); const restoredSign = ed25519.utils.randomSecretKey()
  const identity = 'did:example:owner'
  const firstCredential = createMlsDeviceCredential(identity, `1-${'B'.repeat(20)}`, ed25519.getPublicKey(firstSign), root, firstSign)
  const firstDevice = firstCredential.deviceKid
  let firstRecord: any
  const firstStore = { async loadMimiVault() { return firstRecord }, async saveMimiVault(_identity: string, value: any) { firstRecord = value } }
  const created = await createMimiVaultRoom({ identityId: identity, deviceId: firstDevice, selfGroupId: 'self', credential: firstCredential, signaturePrivateKey: firstSign, transport, stateStore: firstStore, providerHost: 'self.example' })

  const restoredCredential = createMlsDeviceCredential(identity, `1-${'B'.repeat(20)}`, ed25519.getPublicKey(restoredSign), root, restoredSign)
  const restoredDevice = restoredCredential.deviceKid
  let restoredRecord: any
  const restoredStore = { async loadMimiVault() { return restoredRecord }, async saveMimiVault(_identity: string, value: any) { restoredRecord = value } }
  const sender = await joinMimiVaultRoom({ identityId: identity, deviceId: restoredDevice, selfGroupId: 'self', roomId: created.roomId, credential: restoredCredential, signaturePrivateKey: restoredSign, transport, stateStore: restoredStore })

  expect(sender.client).toBe(restoredDevice)
  expect(restoredRecord.roomId).toBe(created.roomId)
  expect(restoredRecord.deliveryCursor).toBe(2)
  expect(deployment.store.room(created.roomId)?.memberCredentials.map(member => member.kind === 'visible' ? member.client : '')).toEqual([firstDevice, restoredDevice])
  deployment.close()
})
