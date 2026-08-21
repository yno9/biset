import { afterEach, describe, expect, test } from 'bun:test'
import { rmSync } from 'node:fs'
import { ed25519 } from '@noble/curves/ed25519.js'
import { createBisetCoreDeployment } from '../../src/core/deployment.ts'
import { CoreVaultDeliveryTransport } from '../../src/vault/core-delivery-transport.ts'
import { sha256Bytes } from '../../src/protocol/canonical.ts'
import { vaultDeliveryAppendSigningBytes, vaultDeliveryPullSigningBytes } from '../../src/protocol/signing.ts'

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
    await core.roster.installAcceptedProjection({ version: 1, identityId, selfGroupId: 'self-group-1', epoch: '1', acceptedAt: '2026-08-21T00:00:00.000Z', devices: [{ deviceId: 'device-a', deliveryFloor: '1', signingKeyId: `${identityId}#device-a` }] })
    const transport = new CoreVaultDeliveryTransport({ baseUrl: 'https://core.example', fetch: (input, init) => core.fetch(new Request(input, init)) })
    const payload = new Uint8Array([1, 2, 3])
    const appendUnsigned = { version: 1 as const, identityId, appendId: 'event-1', payload, payloadHash: sha256Bytes(payload), senderDeviceId: 'device-a', sentAt: '2026-08-21T00:00:00.000Z' }
    await transport.append({ ...appendUnsigned, signature: ed25519.sign(vaultDeliveryAppendSigningBytes(appendUnsigned), privateKey) })
    const pullUnsigned = { version: 1 as const, identityId, recipientDeviceId: 'device-a', after: '0', requestedAt: '2026-08-21T00:00:00.000Z' }
    expect(await transport.pull({ ...pullUnsigned, signature: ed25519.sign(vaultDeliveryPullSigningBytes(pullUnsigned), privateKey) })).toMatchObject({ kind: 'items', items: [{ payload }] })
    core.close()
  })
})
