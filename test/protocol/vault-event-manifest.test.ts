import { describe, expect, test } from 'bun:test'
import { equalBytes, sha256Bytes } from '../../src/shared/protocol/canonical.ts'
import { buildVaultManifest, diffVaultManifests, verifyVaultManifest } from '../../src/client/store/vault/manifest.ts'
import { createVaultEvent, verifyVaultEvent, type VaultEventSigner } from '../../src/client/store/vault/events.ts'

const signer: VaultEventSigner = {
  deviceId: 'device-a',
  sign: async (bytes) => sha256Bytes(bytes),
  verify: async (deviceId, bytes, signature) => deviceId === 'device-a' && equalBytes(sha256Bytes(bytes), signature),
}

describe('vault events', () => {
  test('binds the ID to both canonical event content and signature', async () => {
    const event = await createVaultEvent({
      identityId: 'did:webvh:example:alice',
      actorDeviceId: 'device-a',
      actorSeq: 1,
      kind: 'message.add',
      targetIds: ['message-1'],
      objectRefs: ['object-1'],
      parents: [],
      createdAt: '2026-08-21T00:00:00.000Z',
    }, signer)
    expect(await verifyVaultEvent(event, signer)).toBe(true)
    expect(await verifyVaultEvent({ ...event, signature: new Uint8Array([1]) }, signer)).toBe(false)
  })
})

describe('vault manifests', () => {
  test('has a stable root independent of input ordering and duplicates', () => {
    const first = buildVaultManifest('did:webvh:example:alice', ['event-b', 'event-a', 'event-a'], ['object-b', 'object-a'], '2026-08-21T00:00:00.000Z')
    const second = buildVaultManifest('did:webvh:example:alice', ['event-a', 'event-b'], ['object-a', 'object-b'], '2026-08-21T01:00:00.000Z')
    expect(first.root).toBe(second.root)
    expect(verifyVaultManifest(first)).toBe(true)
  })

  test('returns only objects and events absent from the target', () => {
    const source = buildVaultManifest('did:webvh:example:alice', ['event-a', 'event-b'], ['object-a', 'object-b'], '2026-08-21T00:00:00.000Z')
    const target = buildVaultManifest('did:webvh:example:alice', ['event-a'], ['object-b'], '2026-08-21T00:00:00.000Z')
    expect(diffVaultManifests(source, target)).toEqual({ missingEvents: ['event-b'], missingObjects: ['object-a'] })
  })
})
