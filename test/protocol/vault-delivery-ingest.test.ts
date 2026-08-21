import { describe, expect, test } from 'bun:test'
import { equalBytes, sha256Bytes } from '../../src/protocol/canonical.ts'
import { vaultDeliveryAckSigningBytes } from '../../src/protocol/signing.ts'
import { encodeVaultDeliveryPack } from '../../src/vault/delivery-pack.ts'
import { ingestVaultDelivery } from '../../src/vault/delivery-ingest.ts'
import type { VaultDeliveryCommit } from '../../src/vault/store.ts'

const identityId = 'did:web:alice.example'
const payload = encodeVaultDeliveryPack({
  version: 1, identityId, objects: [], events: [], keyWraps: [],
})
const item = {
  version: 1 as const, identityId, seq: '1', payload, payloadHash: sha256Bytes(payload),
  createdAt: '2026-08-21T00:00:00.000Z', expiresAt: '2026-08-22T00:00:00.000Z',
}

describe('vault delivery ingest', () => {
  test('does not make an ACK available until pack verification, projection, and durable commit finish', async () => {
    let committed: VaultDeliveryCommit | undefined
    const result = await ingestVaultDelivery(item, {
      deviceId: 'device-b', async sign(bytes) { return sha256Bytes(bytes) },
    }, {
      async verifyAndProject(pack) {
        expect(pack.identityId).toBe(identityId)
        return { projection: { version: 1 }, jmapState: { state: 'root-1' }, checkpointId: 'checkpoint-1' }
      },
    }, {
      async commitDelivery(input) { committed = input; return 'committed' },
    }, () => new Date('2026-08-21T01:00:00.000Z'))
    expect(result).toMatchObject({ result: 'committed', ack: { identityId, seq: '1', recipientDeviceId: 'device-b', checkpointId: 'checkpoint-1' } })
    expect(committed?.ackOutbox.ack).toEqual(result.ack)
    const { signature, ...unsigned } = result.ack
    expect(equalBytes(signature, sha256Bytes(vaultDeliveryAckSigningBytes(unsigned)))).toBe(true)
  })

  test('rejects a body whose payload hash no longer matches before invoking the projector', async () => {
    await expect(ingestVaultDelivery({ ...item, payloadHash: new Uint8Array([9]) }, {
      deviceId: 'device-b', async sign() { return new Uint8Array([1]) },
    }, {
      async verifyAndProject() { throw new Error('must not project') },
    }, {
      async commitDelivery() { throw new Error('must not commit') },
    })).rejects.toThrow('invalid')
  })
})
