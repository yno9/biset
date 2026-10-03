import { describe, expect, test } from 'bun:test'
import { buildVaultManifest, diffVaultManifests, verifyVaultManifest } from '../../src/client/store/vault/manifest.ts'
import { createVaultEvent, verifyVaultEvent, type VaultEventAuthor } from '../../src/client/store/vault/events.ts'

const signer: VaultEventAuthor = { deviceId: 'device-a' }

describe('vault events', () => {
  test('binds the ID to the canonical event content', async () => {
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
    expect(verifyVaultEvent(event)).toBe(true)
    expect(verifyVaultEvent({ ...event, actorSeq: 2 })).toBe(false)
    await expect(createVaultEvent({ identityId: event.identityId, actorDeviceId: 'device-b', actorSeq: 1, kind: 'message.add', targetIds: [], objectRefs: [], parents: [], createdAt: event.createdAt }, signer)).rejects.toThrow('author')
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
