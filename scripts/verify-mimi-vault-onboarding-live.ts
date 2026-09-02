/** Live external-onboarding probe for §19.f.
 *
 * It creates a random room, adds a second device through GroupInfo + an MLS
 * external commit, then proves the original device can consume a message
 * encrypted by the restored one. No existing identity or room is touched. */
import { ed25519 } from '@noble/curves/ed25519.js'
import { createMlsDeviceCredential } from '../src/mls/device-credential.ts'
import { MimiClientTransport } from '../src/mls/mimi-client-transport.ts'
import { createMimiVaultRoom, joinMimiVaultRoom } from '../src/mls/mimi-vault-room.ts'
import { PersistedMimiVaultSession, type MimiVaultSessionRecord } from '../src/mls/mimi-vault-session.ts'
import { deliveriesPullSigningBytes } from '../src/mimi/authorizer.ts'
import { decodeMimiVaultBatch, sendMimiVaultCheckpoint } from '../src/vault/mimi-vault-sync.ts'

const baseUrl = (process.env.MIMI_SELF_URL ?? 'https://mimi-self.biset.md').replace(/\/$/, '')
const identity = `did:biset:onboarding-${crypto.randomUUID()}`
const generation = `1-${'A'.repeat(20)}`
const root = ed25519.utils.randomSecretKey()
const firstSign = ed25519.utils.randomSecretKey()
const restoredSign = ed25519.utils.randomSecretKey()
const firstCredential = createMlsDeviceCredential(identity, generation, ed25519.getPublicKey(firstSign), root, firstSign)
const restoredCredential = createMlsDeviceCredential(identity, generation, ed25519.getPublicKey(restoredSign), root, restoredSign)
const transport = new MimiClientTransport({ normalBaseUrl: baseUrl, anonBaseUrl: baseUrl, selfBaseUrl: baseUrl })

let firstRecord: MimiVaultSessionRecord | undefined
const firstStore = {
  async loadMimiVault() { return firstRecord },
  async saveMimiVault(_identity: string, value: MimiVaultSessionRecord) { firstRecord = value },
}
const created = await createMimiVaultRoom({
  identityId: identity, deviceId: firstCredential.deviceKid, selfGroupId: 'self', credential: firstCredential,
  signaturePrivateKey: firstSign, transport, stateStore: firstStore, providerHost: new URL(baseUrl).hostname,
})
let restoredRecord: MimiVaultSessionRecord | undefined
const restoredStore = {
  async loadMimiVault() { return restoredRecord },
  async saveMimiVault(_identity: string, value: MimiVaultSessionRecord) { restoredRecord = value },
}
const restoredSender = await joinMimiVaultRoom({
  identityId: identity, deviceId: restoredCredential.deviceKid, selfGroupId: 'self', roomId: created.roomId,
  credential: restoredCredential, signaturePrivateKey: restoredSign, transport, stateStore: restoredStore,
})
if (!firstRecord || !restoredRecord) throw new Error('onboarding state was not persisted')
const firstSession = new PersistedMimiVaultSession({ identityId: identity, mode: 'self', credential: created.credential, sign: bytes => ed25519.sign(bytes, firstSign), transport, stateStore: firstStore })
const restoredSession = new PersistedMimiVaultSession({ identityId: identity, mode: 'self', credential: restoredSender, sign: bytes => ed25519.sign(bytes, restoredSign), transport, stateStore: restoredStore })
const plaintext = new TextEncoder().encode(`restored-device-${crypto.randomUUID()}`)
await restoredSession.sendApplication(plaintext, crypto.randomUUID().replaceAll('-', ''))
const pullUnsigned = { version: 1 as const, roomId: created.roomId, requester: created.credential, afterSeq: 0, requestedAt: new Date().toISOString() }
const deliveries = await transport.pullDeliveries('self', { ...pullUnsigned, signature: ed25519.sign(deliveriesPullSigningBytes(pullUnsigned), firstSign) })
let received: Uint8Array | undefined
for (const entry of deliveries) received ??= await firstSession.receive(entry)
if (!received || new TextDecoder().decode(received) !== new TextDecoder().decode(plaintext)) throw new Error('original device did not receive restored-device application')
// The original device observes the new member and emits a new checkpoint at
// the post-join epoch. The restored device begins at its commit cursor, so it
// skips historical ciphertext yet can recover this fresh checkpoint exactly.
const checkpointPayload = new TextEncoder().encode(`checkpoint-for-${crypto.randomUUID()}`)
await sendMimiVaultCheckpoint(checkpointPayload, 2, firstSession)
const restoredPullUnsigned = { version: 1 as const, roomId: created.roomId, requester: restoredSender, afterSeq: restoredRecord.deliveryCursor!, requestedAt: new Date().toISOString() }
const restoredDeliveries = await transport.pullDeliveries('self', { ...restoredPullUnsigned, signature: ed25519.sign(deliveriesPullSigningBytes(restoredPullUnsigned), restoredSign) })
const decoded = await decodeMimiVaultBatch(restoredDeliveries, restoredSession)
if (decoded.checkpoints.length !== 1 || new TextDecoder().decode(decoded.checkpoints[0]!.payload) !== new TextDecoder().decode(checkpointPayload)) throw new Error('restored device did not recover the post-join checkpoint')
console.log(JSON.stringify({ verified: true, baseUrl, roomId: created.roomId, firstDevice: firstCredential.deviceKid, restoredDevice: restoredCredential.deviceKid, deliveries: deliveries.length, checkpointSeq: decoded.checkpoints[0]!.finalSequence }))
