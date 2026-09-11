import { expect, test } from 'bun:test'
import { createMimiDeployment } from '../../src/server/mimi/deployment.ts'
import { createMimiVaultRoom, joinMimiVaultRoom } from '../../src/client/mimi/vault-room.ts'
import { MimiClientTransport } from '../../src/client/mimi/client-transport.ts'
import { createMlsDeviceCredential } from '../../src/client/mls/device-credential.ts'
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

// Regression for the live 400 hit on 2026-09-06: a device that lost its
// local MLS state (e.g. cleared storage) but never lost its Wallet-sealed
// signature key retries joinMimiVaultRoom with the SAME credential it used
// the first time. The hub still has that device's old leaf, so a plain
// rejoin is correctly rejected -- and must be rejected with the specific
// "duplicate client" message (store.ts's validateRoomState) that
// ensureWalletMimiVaultRoom's retry looks for, not the ambiguous message
// this replaced. Passing resync: true is what lets the SAME device recover:
// it removes its own stale leaf as part of adding the fresh one.
test('rejoining with the same device credential is rejected as a duplicate, and resync recovers it', async () => {
  const deployment = createMimiDeployment({ databasePath: ':memory:', mode: 'normal', allowExternalJoin: true, publicBaseUrl: 'https://self.example' })
  const transport = new MimiClientTransport({ normalBaseUrl: 'https://normal.example', anonBaseUrl: 'https://anon.example', selfBaseUrl: 'https://self.example', fetch: (input, init) => deployment.fetch(new Request(input, init)) })
  const root = ed25519.utils.randomSecretKey(); const firstSign = ed25519.utils.randomSecretKey(); const lostSign = ed25519.utils.randomSecretKey()
  const identity = 'did:example:owner'
  const firstCredential = createMlsDeviceCredential(identity, `1-${'B'.repeat(20)}`, ed25519.getPublicKey(firstSign), root, firstSign)
  const firstDevice = firstCredential.deviceKid
  let firstRecord: any
  const firstStore = { async loadMimiVault() { return firstRecord }, async saveMimiVault(_identity: string, value: any) { firstRecord = value } }
  const created = await createMimiVaultRoom({ identityId: identity, deviceId: firstDevice, selfGroupId: 'self', credential: firstCredential, signaturePrivateKey: firstSign, transport, stateStore: firstStore, providerHost: 'self.example' })

  const lostCredential = createMlsDeviceCredential(identity, `1-${'B'.repeat(20)}`, ed25519.getPublicKey(lostSign), root, lostSign)
  const lostDevice = lostCredential.deviceKid
  let lostRecord: any
  const lostStore = { async loadMimiVault() { return lostRecord }, async saveMimiVault(_identity: string, value: any) { lostRecord = value } }
  await joinMimiVaultRoom({ identityId: identity, deviceId: lostDevice, selfGroupId: 'self', roomId: created.roomId, credential: lostCredential, signaturePrivateKey: lostSign, transport, stateStore: lostStore })

  // "Lost its local MLS state" is simulated by retrying with no local record
  // and the same signature key/client id. A later DID service edit may have
  // reissued the credential at a newer generation; that must still be
  // recognized as the same client and recovered through resync.
  lostRecord = undefined
  const refreshedCredential = createMlsDeviceCredential(identity, `2-${'C'.repeat(20)}`, ed25519.getPublicKey(lostSign), root, lostSign)
  expect(refreshedCredential.deviceKid).toBe(lostDevice)
  const plainRetry = joinMimiVaultRoom({ identityId: identity, deviceId: lostDevice, selfGroupId: 'self', roomId: created.roomId, credential: refreshedCredential, signaturePrivateKey: lostSign, transport, stateStore: lostStore })
  await expect(plainRetry).rejects.toThrow(/credential duplicates an existing client in this room/)

  const resynced = await joinMimiVaultRoom({ identityId: identity, deviceId: lostDevice, selfGroupId: 'self', roomId: created.roomId, credential: refreshedCredential, signaturePrivateKey: lostSign, transport, stateStore: lostStore, resync: true })
  expect(resynced.client).toBe(lostDevice)
  const clientIds = deployment.store.room(created.roomId)?.memberCredentials.map(member => member.kind === 'visible' ? member.client : '')
  expect(clientIds).toEqual([firstDevice, lostDevice]) // exactly one leaf per device -- no duplicate
  deployment.close()
})
