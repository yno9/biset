import { describe, expect, test } from 'bun:test'
import { buildVaultManifest } from '../../src/vault/manifest.ts'
import { createCoordinatorCheckpoint, createPortableCoordinatorCheckpoint, deriveCoordinatorRecoveryKek, openCoordinatorCheckpoint, openPortableCoordinatorCheckpoint } from '../../src/vault/coordinator-checkpoint.ts'

const vaultId = `vlt_${'R'.repeat(43)}` as const
const identityId = 'did:webvh:secret:alice.example'
const createdAt = '2026-08-28T00:00:00.000Z'
const snapshot = {
  version: 1 as const,
  identityId,
  manifest: buildVaultManifest(identityId, [], [], createdAt),
  events: [],
  objects: [],
  segmentKeys: [],
  createdAt,
}

describe('opaque Coordinator checkpoint', () => {
  test('round-trips a full recovery snapshot without exposing identity metadata', async () => {
    const key = deriveCoordinatorRecoveryKek(new Uint8Array(32).fill(7), vaultId, 'https://coordinator.example/path')
    const payload = await createCoordinatorCheckpoint(key, snapshot, { vaultId, coveredSeq: '4', coordinatorUrl: 'https://coordinator.example' })
    expect(new TextDecoder().decode(payload)).not.toContain(identityId)
    expect(await openCoordinatorCheckpoint(key, payload, { vaultId, coveredSeq: '4', coordinatorUrl: 'https://coordinator.example' })).toEqual(snapshot)
  })

  test('binds ciphertext to root phrase, Vault, sequence, and Coordinator origin', async () => {
    const key = deriveCoordinatorRecoveryKek(new Uint8Array(32).fill(7), vaultId, 'https://coordinator.example')
    const payload = await createCoordinatorCheckpoint(key, snapshot, { vaultId, coveredSeq: '4', coordinatorUrl: 'https://coordinator.example' })
    const wrongKey = deriveCoordinatorRecoveryKek(new Uint8Array(32).fill(8), vaultId, 'https://coordinator.example')
    await expect(openCoordinatorCheckpoint(wrongKey, payload, { vaultId, coveredSeq: '4', coordinatorUrl: 'https://coordinator.example' })).rejects.toThrow('cannot be unwrapped')
    await expect(openCoordinatorCheckpoint(key, payload, { vaultId, coveredSeq: '5', coordinatorUrl: 'https://coordinator.example' })).rejects.toThrow('cannot be unwrapped')
  })

  test('v2 checkpoint survives a Coordinator origin change and still opens legacy v1', async () => {
    const seed = new Uint8Array(32).fill(7)
    const portable = await createPortableCoordinatorCheckpoint(seed, snapshot, { vaultId, coveredSeq: '4' })
    expect(await openPortableCoordinatorCheckpoint(seed, portable, { vaultId, coveredSeq: '4', coordinatorUrl: 'https://another.example' })).toEqual(snapshot)

    const legacyKey = deriveCoordinatorRecoveryKek(seed, vaultId, 'https://coordinator.example')
    const legacy = await createCoordinatorCheckpoint(legacyKey, snapshot, { vaultId, coveredSeq: '4', coordinatorUrl: 'https://coordinator.example' })
    expect(await openPortableCoordinatorCheckpoint(seed, legacy, { vaultId, coveredSeq: '4', coordinatorUrl: 'https://coordinator.example' })).toEqual(snapshot)
  })
})
