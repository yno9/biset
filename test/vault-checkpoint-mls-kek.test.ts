import { expect, test } from 'bun:test'
import { sha256 } from '@noble/hashes/sha2.js'
import { canonicalBytes, type CanonicalValue } from '../src/shared/protocol/canonical.ts'
import type { MlsEpoch } from '../src/shared/protocol/ids.ts'
import { buildVaultManifest } from '../src/vault/manifest.ts'
import { MlsVaultEpochKeyResolver, type MlsEpochExporter } from '../src/mls/vault-epoch.ts'
import {
  createVaultCheckpoint,
  openVaultCheckpoint,
  readVaultCheckpointEpoch,
  VaultCheckpointEpochUnavailableError,
} from '../src/vault/vault-checkpoint.ts'
import { shouldRecreateVaultCheckpoint, synchronizeMimiVault, type MimiVaultSyncGap } from '../src/vault/mimi-vault-sync.ts'
import { encodeMimiVaultChunk, splitMimiVaultPayload } from '../src/vault/mimi-vault-chunks.ts'
import type { MimiDeliveryEntry } from '../src/mimi/protocol-types.ts'

const identityId = 'did:webvh:test:example.test'
const vaultId = 'vlt_checkpoint_test' as never
const coveredSeq = '42'
const createdAt = '2026-09-05T00:00:00.000Z'
const selfGroupId = 'urn:biset:self-group:checkpoint-test'
const snapshot = {
  version: 1 as const,
  identityId,
  manifest: buildVaultManifest(identityId, [], ['obj_test'], createdAt),
  events: [],
  objects: [{
    version: 1 as const, identityId, objectId: 'obj_test', segmentId: 'seg_test', nonce: new Uint8Array(12),
    ciphertext: new Uint8Array([1]), ciphertextHash: new Uint8Array(32), plaintextLength: 0, aad: new Uint8Array([2]),
  }],
  segmentKeys: [{ segmentId: 'seg_test', key: new Uint8Array(32).fill(7) }],
  createdAt,
}

/** A stand-in MLS self group whose exporter is a deterministic function of
 * (root secret, exporter context). The context includes the epoch, so a
 * different epoch necessarily yields a different VEK -- the exact property
 * the checkpoint's forward secrecy relies on. */
function fakeSelfGroup(epoch: MlsEpoch): MlsEpochExporter {
  return {
    selfGroupId,
    epoch,
    async exportSecret(label, context, length) {
      expect(length).toBe(32)
      return sha256(canonicalBytes({ root: 'checkpoint-test-root', label, context: [...context] })).slice(0, length)
    },
  }
}

async function vekFor(epoch: MlsEpoch): Promise<Uint8Array> {
  const resolver = new MlsVaultEpochKeyResolver({ async currentSelfGroup() { return fakeSelfGroup(epoch) } })
  return resolver.deriveVaultEpochKey(identityId, selfGroupId, epoch)
}

test('a checkpoint sealed at an epoch opens with that same epoch\'s VEK', async () => {
  const vek = await vekFor('7')
  const payload = await createVaultCheckpoint(vek, snapshot, { vaultId, coveredSeq, selfGroupId, epoch: '7' })
  expect(readVaultCheckpointEpoch(payload)).toEqual({ selfGroupId, epoch: '7' })
  const opened = await openVaultCheckpoint(vek, payload, { vaultId, coveredSeq })
  expect(opened.identityId).toBe(identityId)
  expect(opened.objects.map(object => object.objectId)).toEqual(['obj_test'])
  expect(opened.segmentKeys[0]!.key).toEqual(new Uint8Array(32).fill(7))
})

test('a checkpoint sealed at epoch N cannot be opened with the epoch N+1 VEK', async () => {
  const vek7 = await vekFor('7')
  const vek8 = await vekFor('8')
  expect(vek8).not.toEqual(vek7)
  const payload = await createVaultCheckpoint(vek7, snapshot, { vaultId, coveredSeq, selfGroupId, epoch: '7' })
  await expect(openVaultCheckpoint(vek8, payload, { vaultId, coveredSeq }))
    .rejects.toThrow('Vault checkpoint key cannot be unwrapped')
  // And the epoch-7 VEK itself is genuinely gone once the group has moved
  // on: the resolver refuses to re-derive a past epoch at all. This is why
  // the recovery is "recreate", never "rewrap".
  const advanced = new MlsVaultEpochKeyResolver({ async currentSelfGroup() { return fakeSelfGroup('8') } })
  await expect(advanced.deriveVaultEpochKey(identityId, selfGroupId, '7'))
    .rejects.toThrow('MLS self-group epoch changed; retry vault operation')
})

test('every AAD field is bound: vaultId, coveredSeq, selfGroupId and epoch all fail the unwrap when altered', async () => {
  const vek = await vekFor('7')
  const payload = await createVaultCheckpoint(vek, snapshot, { vaultId, coveredSeq, selfGroupId, epoch: '7' })

  await expect(openVaultCheckpoint(vek, payload, { vaultId: 'vlt_other' as never, coveredSeq }))
    .rejects.toThrow('Vault checkpoint key cannot be unwrapped')
  await expect(openVaultCheckpoint(vek, payload, { vaultId, coveredSeq: '43' }))
    .rejects.toThrow('Vault checkpoint key cannot be unwrapped')

  // selfGroupId and epoch live in the envelope itself, so tampering means
  // rewriting the envelope. The AAD is rebuilt from those same envelope
  // fields on open, so a swap must fail the unwrap rather than silently
  // pointing a reader at another group's or epoch's key.
  const rewritten = (patch: Record<string, string>): Uint8Array => {
    const wire = JSON.parse(new TextDecoder().decode(payload)) as Record<string, unknown>
    return canonicalBytes({ ...wire, ...patch } as CanonicalValue)
  }
  expect(readVaultCheckpointEpoch(rewritten({ epoch: '8' }))).toEqual({ selfGroupId, epoch: '8' })
  await expect(openVaultCheckpoint(vek, rewritten({ epoch: '8' }), { vaultId, coveredSeq }))
    .rejects.toThrow('Vault checkpoint key cannot be unwrapped')
  await expect(openVaultCheckpoint(vek, rewritten({ selfGroupId: 'urn:biset:self-group:someone-else' }), { vaultId, coveredSeq }))
    .rejects.toThrow('Vault checkpoint key cannot be unwrapped')
})

test('a checkpoint whose epoch is gone is reported as a gap, never thrown out of the sync round', async () => {
  // A device that cannot derive the checkpoint's VEK must not wedge its own
  // poll loop: the round still ingests everything else it pulled, and the
  // loss is reported as structured data with its own kind, distinct from an
  // ordinary restore failure (nothing about this checkpoint can be repaired).
  const checkpointChunk = splitMimiVaultPayload(new Uint8Array([9, 9]), 'E'.repeat(24))[0]!
  const ordinary = splitMimiVaultPayload(new Uint8Array([1, 2]), 'F'.repeat(24))[0]!
  const entries: MimiDeliveryEntry[] = [
    { seq: 1, kind: 'application', payload: encodeMimiVaultChunk(checkpointChunk), epoch: '1', acceptedAt: createdAt },
    { seq: 2, kind: 'vaultCheckpoint', payload: new Uint8Array(), epoch: '1', acceptedAt: createdAt, vaultCheckpoint: { coveredSeq: 1, transferId: checkpointChunk.transferId, chunkCount: 1, payloadHash: checkpointChunk.payloadHash } },
    { seq: 3, kind: 'application', payload: encodeMimiVaultChunk(ordinary), epoch: '1', acceptedAt: createdAt },
  ]
  const ingested: number[] = []
  const result = await synchronizeMimiVault({
    pull: async () => entries,
    signPull: async () => new Uint8Array(64),
    pullRequest: { version: 1, roomId: 'mimi://self.example/r/vault-test', requester: { kind: 'visible', user: identityId, client: 'client', credential: new Uint8Array([1]), signaturePublicKey: new Uint8Array(32) }, requestedAt: createdAt },
    receiver: { async receive(entry) { return entry.kind === 'application' ? entry.payload : undefined } },
    outbox: { async readDeliveryOutbox() { return [] } },
    sender: { async sendApplication() {}, async sendCheckpoint() {} },
    identityId: identityId as never,
    async ingest(_payload, seq) { ingested.push(Number(seq)) },
    async restoreCheckpoint() {
      throw new VaultCheckpointEpochUnavailableError({ selfGroupId, epoch: '7' }, { selfGroupId, epoch: '8' })
    },
  })
  expect(ingested).toEqual([3]) // the rest of the round still applied
  expect(result.gaps).toEqual([{
    kind: 'checkpoint-epoch-unavailable',
    detail: `${checkpointChunk.transferId}: Vault checkpoint was sealed for ${selfGroupId}@7, but this device is at ${selfGroupId}@8`,
  }])
})

test('the recreation gate republishes when the existing checkpoint is sealed for a past epoch', async () => {
  const base = { latestSequence: 12, gaps: [] as MimiVaultSyncGap[], sinceLastRecreateMs: 30_000 }

  // The case W5 exists for: a checkpoint manifest IS present, so the
  // pre-existing "no manifest" condition alone would leave the unopenable
  // checkpoint in place forever and no new device could ever restore.
  expect(shouldRecreateVaultCheckpoint({ ...base, sawCheckpointManifest: true, staleCheckpointEpoch: true })).toBe(true)
  expect(shouldRecreateVaultCheckpoint({ ...base, sawCheckpointManifest: true, staleCheckpointEpoch: false })).toBe(false)
  expect(shouldRecreateVaultCheckpoint({ ...base, sawCheckpointManifest: false, staleCheckpointEpoch: false })).toBe(true)

  // A stale epoch never overrides the guards that protect siblings from a
  // checkpoint built out of incomplete local state.
  expect(shouldRecreateVaultCheckpoint({
    ...base, sawCheckpointManifest: true, staleCheckpointEpoch: true,
    gaps: [{ kind: 'ingest-failed', detail: 'seq 4: conflict' }],
  })).toBe(false)
  expect(shouldRecreateVaultCheckpoint({
    ...base, sawCheckpointManifest: true, staleCheckpointEpoch: true,
    gaps: [{ kind: 'checkpoint-epoch-unavailable', detail: 'this device needed it and does not have it' }],
  })).toBe(false)
  expect(shouldRecreateVaultCheckpoint({ ...base, sawCheckpointManifest: true, staleCheckpointEpoch: true, sinceLastRecreateMs: 1_000 })).toBe(false)
  expect(shouldRecreateVaultCheckpoint({ ...base, latestSequence: 1, sawCheckpointManifest: true, staleCheckpointEpoch: true })).toBe(false)
})
