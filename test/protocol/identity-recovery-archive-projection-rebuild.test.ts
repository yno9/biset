// PLAN.md §4.3's other open "projection rebuild" case: recovery archive
// import. importRecoveryArchive's own doc comment says "callers must still
// rebuild JMAP projection before presenting the account as restored" --
// this proves rebuildLocalJmapProjection (built for §5.2, record-source-
// agnostic) actually does that correctly against a REAL MLS self group,
// the same way identity-restore-transfer-projection-rebuild.test.ts
// already proved it for the restore-transfer case. The existing
// recovery-archive-import.test.ts only exercises the atomic-commit
// contract with a fixture signer/resolver, never a real self group, and
// never calls rebuild afterward.
import { describe, expect, test } from 'bun:test'
import { buildLocalJmapProjectionRebuild } from '../../src/identity/bootstrap.ts'
import { createMlsGroup, generateOwnKeyPackage } from '../../src/mls/group.ts'
import { mlsDeviceFixture } from './support/mls-device-fixture.ts'
import { MlsMembershipSegmentKeyWrapSigner } from '../../src/mls/segment-key-membership.ts'
import { MlsVaultEpochKeyResolver } from '../../src/mls/vault-epoch.ts'
import { StoredMlsSelfGroupProvider } from '../../src/mls/store.ts'
import { createRecoveryArchive, createRecoveryKey, type RecoveryArchiveSnapshotV1 } from '../../src/vault/recovery-archive.ts'
import { importRecoveryArchive } from '../../src/vault/recovery-archive-import.ts'
import { buildMailMessageAdd } from '../../src/vault/mail-message.ts'
import { buildVaultManifest } from '../../src/vault/manifest.ts'
import { createSegmentKey } from '../../src/vault/objects.ts'
import type { LoadedMlsSelfGroup, MlsSelfGroupStateStore } from '../../src/mls/store.ts'
import type { RecoveryArchiveImportCommit, SegmentKeyWrapReader, VaultRecordReader } from '../../src/vault/store.ts'
import type { SegmentKeyWrapV1, VaultEventV1, VaultObjectV1 } from '../../src/shared/protocol/vault.ts'

const identityId = 'did:web:alice.example'
const selfGroupId = 'test-self-group'
const device = await mlsDeviceFixture(identityId)
const deviceKid = device.kid

function memorySelfGroupStore(): MlsSelfGroupStateStore {
  const rows = new Map<string, LoadedMlsSelfGroup>()
  return {
    async save(id, selfGroupId, state) { rows.set(id, { selfGroupId, state }) },
    async load(id) { return rows.get(id) },
  }
}

/** Combined recovery-archive commit target + VaultRecordReader/SegmentKeyWrapReader, same as the requester's real IndexedDbVaultStore would end up being after import. */
function memoryArchiveTarget(): { commitRecoveryArchive(input: RecoveryArchiveImportCommit): Promise<void> } & VaultRecordReader & SegmentKeyWrapReader {
  const events: VaultEventV1[] = []
  const objects: VaultObjectV1[] = []
  const wraps = new Map<string, SegmentKeyWrapV1>()
  const wrapKey = (id: string, segmentId: string, epoch: string) => `${id} ${segmentId} ${epoch}`
  return {
    async commitRecoveryArchive(input) {
      events.push(...input.events)
      objects.push(...input.objects)
      for (const wrap of input.keyWraps) wraps.set(wrapKey(wrap.identityId, wrap.segmentId, wrap.recipientEpoch), wrap)
    },
    async readVaultEvents() { return events.map(event => ({ ...event, identityId })) },
    async readVaultObjects() { return objects.map(object => ({ ...object, identityId })) },
    async readSegmentKeyWrap(id, segmentId, epoch) { return wraps.get(wrapKey(id, segmentId, epoch)) },
  }
}

describe('projection rebuild after a real recovery archive import', () => {
  test('reconstructs the correct Local JMAP projection from archive-imported records, re-wrapped to the current real MLS epoch', async () => {
    const kp = await generateOwnKeyPackage(device.credential, device.signaturePrivateKey)
    const state = await createMlsGroup(new TextEncoder().encode(selfGroupId), kp)
    const selfGroupStore = memorySelfGroupStore()
    await selfGroupStore.save(identityId, selfGroupId, state)

    // Build the pre-loss snapshot: a real mail item this same device wrote
    // before its local storage was lost, encrypted under a segment key the
    // archive itself carries (archives store raw SegmentKeys, encrypted by
    // the recovery passphrase, not MLS wraps). Signed with this device's
    // real MLS leaf key -- rebuildLocalJmapProjection's verifier checks
    // against CURRENT self-group membership, so the archived event's actor
    // must still be a member for the "happy path" rebuild this test wants.
    const segmentKey = createSegmentKey()
    const archiveSigner = new MlsMembershipSegmentKeyWrapSigner(deviceKid, async () => state)
    const { metadataObject, rawRfc5322Object, event } = await buildMailMessageAdd(
      {
        email: { id: 'msg-1', threadId: 'thread-1', mailboxIds: { inbox: true }, keywords: {}, receivedAt: '2026-08-24T00:00:00.000Z' },
        rawRfc5322: new TextEncoder().encode('Subject: hi\r\n\r\nhello'),
      },
      { identityId, actorDeviceId: deviceKid, actorSeq: 1, parents: [], segmentId: 'segment-1', segmentKey, createdAt: '2026-08-24T00:00:00.000Z' },
      archiveSigner,
    )
    const snapshot: RecoveryArchiveSnapshotV1 = {
      version: 1,
      identityId,
      manifest: buildVaultManifest(identityId, [event.id], [metadataObject.objectId, rawRfc5322Object.objectId], '2026-08-24T00:00:00.000Z'),
      events: [event],
      objects: [metadataObject, rawRfc5322Object],
      segmentKeys: [{ segmentId: 'segment-1', key: segmentKey }],
      createdAt: '2026-08-24T00:00:00.000Z',
    }
    const recoveryKey = createRecoveryKey()
    const archive = await createRecoveryArchive(recoveryKey, snapshot)

    // The restored device imports it, re-wrapping the SegmentKey to its own
    // REAL current MLS epoch.
    const loadState = async () => state
    const epochs = new MlsVaultEpochKeyResolver(new StoredMlsSelfGroupProvider(selfGroupStore))
    const signer = new MlsMembershipSegmentKeyWrapSigner(deviceKid, loadState)
    const target = memoryArchiveTarget()
    const imported = await importRecoveryArchive(archive, recoveryKey, epochs, signer, target, '2026-08-24T01:00:00.000Z')
    expect(imported.keyWraps).toHaveLength(1)
    expect(imported.keyWraps[0]!.selfGroupId).toBe(selfGroupId)

    // Rebuild: exactly what importRecoveryArchive's own doc comment says the
    // caller must still do before presenting the account as restored.
    const projections = { rows: new Map<string, unknown>(), async readProjection(id: string) { return this.rows.get(id) }, async writeProjection(id: string, projection: unknown) { this.rows.set(id, projection) } }
    const rebuild = buildLocalJmapProjectionRebuild(target, target, projections, selfGroupStore, identityId)
    const projection = await rebuild()

    expect(projection.emails).toHaveLength(1)
    expect(projection.emails[0]).toMatchObject({ id: 'msg-1', threadId: 'thread-1', mailboxIds: { inbox: true }, blobId: rawRfc5322Object.objectId })
    expect(await projections.readProjection(identityId)).toEqual(projection)
  })
})
