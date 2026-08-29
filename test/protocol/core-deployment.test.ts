import { afterEach, describe, expect, test } from 'bun:test'
import { rmSync } from 'node:fs'
import { ed25519 } from '@noble/curves/ed25519.js'
import { createBisetCoreDeployment } from '../../src/core/deployment.ts'
import { CoreVaultDeliveryTransport } from '../../src/vault/core-delivery-transport.ts'
import { CoreIngressTransport } from '../../src/vault/core-ingress-transport.ts'
import { sha256Bytes } from '../../src/protocol/canonical.ts'
import { ingressAckSigningBytes, ingressPullSigningBytes, vaultDeliveryAppendSigningBytes, vaultDeliveryPullSigningBytes } from '../../src/protocol/signing.ts'

const path = `/tmp/biset-core-${process.pid}-${Date.now()}.sqlite`
const identityId = 'did:web:alice.example'
const privateKey = ed25519.utils.randomSecretKey()
const publicKey = ed25519.getPublicKey(privateKey)

afterEach(() => { try { rmSync(path) } catch {} })

describe('core deployment composition', () => {
  test('uses the persisted roster and DID-resolved public key to operate bounded delivery end to end', async () => {
    const core = createBisetCoreDeployment({
      databasePath: path,
      signingKeys: { async resolveEd25519PublicKey(keyId) { return keyId === `${identityId}#device-a` ? publicKey : undefined } },
    })
    await core.roster.installAcceptedProjection({ version: 1, identityId, selfGroupId: 'self-group-1', epoch: '1', acceptedAt: '2099-08-21T00:00:00.000Z', devices: [{ deviceId: 'device-a', deliveryFloor: '1', signingPublicKey: publicKey, deviceCredential: new Uint8Array([1]) }] })
    const transport = new CoreVaultDeliveryTransport({ baseUrl: 'https://core.example', fetch: (input, init) => core.fetch(new Request(input, init)) })
    const payload = new Uint8Array([1, 2, 3])
    const appendUnsigned = { version: 1 as const, identityId, appendId: 'event-1', payload, payloadHash: sha256Bytes(payload), senderDeviceId: 'device-a', sentAt: '2099-08-21T00:00:00.000Z' }
    await transport.append({ ...appendUnsigned, signature: ed25519.sign(vaultDeliveryAppendSigningBytes(appendUnsigned), privateKey) })
    const pullUnsigned = { version: 1 as const, identityId, recipientDeviceId: 'device-a', after: '0', requestedAt: '2099-08-21T00:00:00.000Z' }
    expect(await transport.pull({ ...pullUnsigned, signature: ed25519.sign(vaultDeliveryPullSigningBytes(pullUnsigned), privateKey) })).toMatchObject({ kind: 'items', items: [{ payload }] })
    const ingress = { version: 1 as const, ingressId: 'ingress-1', protocol: 'mail' as const, recipientIdentityId: identityId, createdAt: '2099-08-21T00:00:00.000Z', expiresAt: '2099-08-22T00:00:00.000Z', transportMetadata: {}, sourceEvidence: new Uint8Array([1]), protectedPayload: new Uint8Array([2]), protectedPayloadHash: sha256Bytes(new Uint8Array([2])) }
    await core.ingressAdapter.offer(ingress)
    const ingressTransport = new CoreIngressTransport({ baseUrl: 'https://core.example', fetch: (input, init) => core.fetch(new Request(input, init)) })
    const ingressPullUnsigned = { version: 1 as const, identityId, recipientDeviceId: 'device-a', requestedAt: '2099-08-21T00:00:30.000Z' }
    expect(await ingressTransport.pull({ ...ingressPullUnsigned, signature: ed25519.sign(ingressPullSigningBytes(ingressPullUnsigned), privateKey) })).toEqual([{ ...ingress, recipientDeviceSnapshot: ['device-a'] }])
    const ackUnsigned = { version: 1 as const, ingressId: ingress.ingressId, protectedPayloadHash: ingress.protectedPayloadHash, recipientDeviceId: 'device-a', vaultEventId: 'event-1', checkpointId: 'checkpoint-1', ackedAt: '2099-08-21T00:01:00.000Z' }
    await ingressTransport.acknowledge({ ...ackUnsigned, signature: ed25519.sign(ingressAckSigningBytes(ackUnsigned), privateKey) })
    expect((await core.fetch(new Request('https://core.example/v1/ingress/offer', { method: 'POST', body: '{}' }))).status).toBe(404)
    core.close()
  })
})
