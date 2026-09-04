import { describe, expect, test } from 'bun:test'
import { VAULT_EVENT_KINDS, type VaultEventKind } from '../src/protocol/vault.ts'
import { decodeVaultDeliveryPack, encodeVaultDeliveryPack } from '../src/vault/delivery-pack.ts'

describe('vault delivery pack', () => {
  test.each(VAULT_EVENT_KINDS)('round-trips the %s event kind', (kind: VaultEventKind) => {
    const payload = encodeVaultDeliveryPack({
      version: 1,
      identityId: 'did:webvh:alice.example',
      objects: [],
      events: [{
        version: 1,
        id: `event:${kind}`,
        identityId: 'did:webvh:alice.example',
        actorDeviceId: 'device-a',
        actorSeq: 1,
        kind,
        targetIds: [],
        objectRefs: [],
        parents: [],
        createdAt: '2026-08-28T00:00:00.000Z',
        signature: new Uint8Array([1, 2, 3]),
      }],
      keyWraps: [],
    })

    expect(decodeVaultDeliveryPack(payload).events[0]?.kind).toBe(kind)
  })
})
