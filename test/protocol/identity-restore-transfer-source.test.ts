// End-to-end: buildRestoreTransferSource (the sending side of a peer restore
// transfer) paired with buildRestoreTransferVerifier (the receiving side) --
// confirms PLAN.md §4.2's "restore grant" (re-wrap a SegmentKey for a
// requester's current epoch, without touching the ciphertext or minting a
// new SegmentKey) actually produces a chunk createRestoreTransferChunk/
// verifyRestoreTransferChunk accept, and that the requester can decrypt the
// transferred object with the SAME SegmentKey the source never exposed in
// the clear over the wire.
import { describe, expect, test } from 'bun:test'
import { buildRestoreTransferSource, buildRestoreTransferVerifier } from '../../src/identity/bootstrap.ts'
import { createMlsGroup, epochOf, exportSecret, generateOwnKeyPackage } from '../../src/mls/group.ts'
import { MlsMembershipSegmentKeyWrapSigner } from '../../src/mls/segment-key-membership.ts'
import { selfGroupIdHex } from '../../src/mls/self-group.ts'
import { deriveVaultEpochKey } from '../../src/mls/vault-epoch.ts'
import { createVaultEvent } from '../../src/vault/events.ts'
import { createSegmentKeyWrap, unwrapSegmentKey } from '../../src/vault/crypto.ts'
import { createSegmentKey, decryptVaultObject, encryptVaultObject } from '../../src/vault/objects.ts'
import { buildVaultManifest } from '../../src/vault/manifest.ts'
import { createRestoreTransferChunk, verifyRestoreTransferChunk } from '../../src/vault/restore-transfer.ts'
import { mlsEpoch } from '../../src/protocol/ids.ts'
import type { LoadedMlsSelfGroup, MlsSelfGroupStateStore } from '../../src/mls/store.ts'
import type { SegmentKeyWrapReader, SegmentKeyWrapWriter, VaultRecordReader } from '../../src/vault/store.ts'
import type { IdentityRecord } from '../../src/identity/record-store.ts'
import type { SegmentKeyWrapV1, VaultEventV1, VaultObjectV1 } from '../../src/protocol/vault.ts'

const identityId = 'did:web:alice.example'
const deviceKid = `${identityId}#device-a`

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return bytes
}

function memorySelfGroupStore(): MlsSelfGroupStateStore {
  const rows = new Map<string, LoadedMlsSelfGroup>()
  return {
    async save(id, selfGroupId, state) { rows.set(id, { selfGroupId, state }) },
    async load(id) { return rows.get(id) },
  }
}

function memoryWrapStore(): SegmentKeyWrapReader & SegmentKeyWrapWriter {
  const rows = new Map<string, SegmentKeyWrapV1>()
  const key = (id: string, segmentId: string, epoch: string) => `${id} ${segmentId} ${epoch}`
  return {
    async readSegmentKeyWrap(id, segmentId, epoch) { return rows.get(key(id, segmentId, epoch)) },
    async writeSegmentKeyWrap(wrap) { rows.set(key(wrap.identityId, wrap.segmentId, wrap.recipientEpoch), wrap) },
  }
}

function memoryRecordReader(events: VaultEventV1[], objects: VaultObjectV1[]): VaultRecordReader {
  return {
    async readVaultEvents() { return events as (VaultEventV1 & { identityId: string })[] },
    async readVaultObjects() { return objects as (VaultObjectV1 & { identityId: string })[] },
  }
}

describe('buildRestoreTransferSource', () => {
  test('a restore-transfer chunk built by the source verifies, and the requester decrypts the transferred object', async () => {
    const kp = await generateOwnKeyPackage(deviceKid)
    const state = await createMlsGroup(hexToBytes(selfGroupIdHex(identityId)), kp)
    const selfGroupStore = memorySelfGroupStore()
    await selfGroupStore.save(identityId, selfGroupIdHex(identityId), state)
    const epoch = mlsEpoch(epochOf(state))

    // Device A already has one segment (with real content in it) from before
    // this restore transfer -- minted directly here rather than through
    // ActiveVaultSegmentManager, since this test only cares about the
    // source/verifier pairing.
    const segmentKey = createSegmentKey()
    const loadState = async () => state
    const signer = new MlsMembershipSegmentKeyWrapSigner(deviceKid, loadState)
    const vek = await deriveVaultEpochKey({ selfGroupId: selfGroupIdHex(identityId), epoch, exportSecret: (label, ctx, len) => exportSecret(state, label, ctx, len) })
    const originalWrap = await createSegmentKeyWrap(vek, segmentKey, {
      identityId, selfGroupId: selfGroupIdHex(identityId), segmentId: 'segment-1',
      sourceEpoch: epoch, recipientEpoch: epoch, grantorDeviceId: deviceKid, grantedAt: new Date().toISOString(),
    }, signer)
    const wraps = memoryWrapStore()
    await wraps.writeSegmentKeyWrap(originalWrap)

    const plaintext = new TextEncoder().encode('hello from device A')
    const object = await encryptVaultObject(segmentKey, { segmentId: 'segment-1', plaintext, aad: new TextEncoder().encode('aad') })
    const event = await createVaultEvent({
      identityId, actorDeviceId: deviceKid, actorSeq: 1, kind: 'message.add',
      targetIds: ['msg-1'], objectRefs: [object.objectId], parents: [], createdAt: new Date().toISOString(),
    }, signer)

    const records = memoryRecordReader([event], [object])
    const record: IdentityRecord = { did: identityId, deviceKid, rootPublicKey: '', rootPrivateKey: '' }
    const source = buildRestoreTransferSource(records, wraps, selfGroupStore, record)

    const sourceManifest = await source.manifest(identityId)
    const requesterManifest = buildVaultManifest(identityId, [], [], new Date().toISOString())

    const chunk = await createRestoreTransferChunk(source, requesterManifest, undefined, epoch)
    expect(chunk.events).toHaveLength(1)
    expect(chunk.objects).toHaveLength(1)
    expect(chunk.keyWraps).toHaveLength(1)
    // The re-wrap is a NEW SegmentKeyWrap, not a copy of the original --
    // the source never exposes the original wrap or the SegmentKey itself.
    expect(chunk.keyWraps[0]!.wrappedSegmentKey).not.toEqual(originalWrap.wrappedSegmentKey)

    const verifier = buildRestoreTransferVerifier(selfGroupStore, identityId)
    const ok = await verifyRestoreTransferChunk(chunk, sourceManifest, requesterManifest, epoch, verifier)
    expect(ok).toBe(true)

    // The requester unwraps the SAME SegmentKey via its own VEK for this epoch...
    const requesterVek = await deriveVaultEpochKey({ selfGroupId: selfGroupIdHex(identityId), epoch, exportSecret: (label, ctx, len) => exportSecret(state, label, ctx, len) })
    const unwrapped = await unwrapSegmentKey(requesterVek, chunk.keyWraps[0]!, verifier.eventVerifier)
    expect(unwrapped).toEqual(segmentKey)

    // ...and decrypts the transferred object with it.
    const decrypted = await decryptVaultObject(unwrapped, chunk.objects[0]!)
    expect(decrypted).toEqual(plaintext)
  })

  test('readCurrentEpochWraps refuses to grant for an epoch that is not this device\'s own current one', async () => {
    const kp = await generateOwnKeyPackage(deviceKid)
    const state = await createMlsGroup(hexToBytes(selfGroupIdHex(identityId)), kp)
    const selfGroupStore = memorySelfGroupStore()
    await selfGroupStore.save(identityId, selfGroupIdHex(identityId), state)

    const record: IdentityRecord = { did: identityId, deviceKid, rootPublicKey: '', rootPrivateKey: '' }
    const source = buildRestoreTransferSource(memoryRecordReader([], []), memoryWrapStore(), selfGroupStore, record)

    await expect(source.readCurrentEpochWraps(identityId, ['segment-1'], mlsEpoch(999n))).rejects.toThrow('not this device')
  })
})
