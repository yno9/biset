import { afterEach, describe, expect, test } from 'bun:test'
import { rmSync } from 'node:fs'
import { sha256Bytes } from '../../src/protocol/canonical.ts'
import { SqliteVaultDeliveryStore } from '../../src/core/mediation/sqlite-vault-delivery-store.ts'
import type { VaultDeliveryAuthorizer } from '../../src/core/mediation/vault-delivery-store.ts'
import type { VaultDeliveryAppendV1, VaultDeliveryPullV1 } from '../../src/protocol/vault.ts'

const path = `/tmp/biset-delivery-${process.pid}-${Date.now()}.sqlite`
const identityId = 'did:web:alice.example'
const payload = new Uint8Array([1, 2, 3])
const authorizer: VaultDeliveryAuthorizer = {
  async deliveryFloor() { return '1' }, async recipientsAtAppend() { return ['device-a', 'device-b'] }, async verifyAppend() { return true }, async verifyPull() { return true }, async verifyAck() { return true },
}
const append: VaultDeliveryAppendV1 = { version: 1, identityId, appendId: 'event-1', payload, payloadHash: sha256Bytes(payload), senderDeviceId: 'device-a', sentAt: '2026-08-21T00:00:00.000Z', signature: new Uint8Array([1]) }
const pull: VaultDeliveryPullV1 = { version: 1, identityId, recipientDeviceId: 'device-b', after: '0', requestedAt: '2026-08-21T00:00:00.000Z', signature: new Uint8Array([1]) }

afterEach(() => { try { rmSync(path) } catch {} })

describe('SQLite vault delivery store', () => {
  test('survives a core restart while retaining only one pending ciphertext body', async () => {
    const first = SqliteVaultDeliveryStore.open(path, authorizer)
    await first.append(append, new Date('2026-08-21T00:00:00.000Z'))
    first.close()
    const restarted = SqliteVaultDeliveryStore.open(path, authorizer)
    expect(await restarted.pull(pull, new Date('2026-08-21T01:00:00.000Z'))).toMatchObject({ kind: 'items', items: [{ seq: '1', payload }] })
    expect(await restarted.status(identityId)).toMatchObject({ pendingItems: 1, payloadBytes: 3 })
    restarted.close()
  })
})
