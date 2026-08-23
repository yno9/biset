// End-to-end: CoreMlsDeliveryTransport (client) against
// createMlsDeliveryHttpHandler (core), through the shared protocol/mls-ds-wire.ts
// encode/decode -- confirms the client and server sides of the wire actually
// agree, not just that each one independently parses its own fixtures.
import { afterEach, describe, expect, test } from 'bun:test'
import { rmSync } from 'node:fs'
import { ed25519 } from '@noble/curves/ed25519.js'
import { SqliteMlsDeliveryService } from '../../src/core/mediation/mls-delivery-store.ts'
import { Ed25519MlsDsSignatureVerifier } from '../../src/core/mediation/mls-delivery-authorizer.ts'
import { createMlsDeliveryHttpHandler } from '../../src/core/mediation/mls-delivery-http.ts'
import { CoreMlsDeliveryTransport } from '../../src/mls/core-mls-delivery-transport.ts'
import {
  mlsCommitSubmissionSigningBytes, mlsDeliveriesPullSigningBytes, mlsGroupCreationSigningBytes,
  mlsGroupInfoPullSigningBytes, mlsGroupsForPullSigningBytes, mlsKeyPackageCountPullSigningBytes,
  mlsKeyPackageDropSigningBytes, mlsKeyPackagePublishSigningBytes, mlsKeyPackageTakeSigningBytes,
  mlsPendingRemovalsClearSigningBytes, mlsSelfRemoveSubmissionSigningBytes,
} from '../../src/protocol/signing.ts'
import type {
  MlsCommitSubmissionV1, MlsDeliveriesPullV1, MlsGroupCreationV1, MlsGroupInfoPullV1, MlsGroupsForPullV1,
  MlsKeyPackageCountPullV1, MlsKeyPackageDropV1, MlsKeyPackagePublishV1, MlsKeyPackageTakeV1,
  MlsPendingRemovalsClearV1, MlsSelfRemoveSubmissionV1,
} from '../../src/protocol/mls-ds.ts'

const path = `/tmp/biset-mls-ds-client-${process.pid}-${Date.now()}.sqlite`
const identityId = 'did:web:alice.example'
const groupId = 'group-1'
const deviceAKey = ed25519.utils.randomSecretKey()
const deviceAPublicKey = ed25519.getPublicKey(deviceAKey)
const deviceAKid = `${identityId}#device-a`

afterEach(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { rmSync(`${path}${suffix}`) } catch {}
  }
})

function setup() {
  const ds = SqliteMlsDeliveryService.open(path)
  const verifier = new Ed25519MlsDsSignatureVerifier({ async resolveEd25519PublicKey(kid) { return kid === deviceAKid ? deviceAPublicKey : undefined } })
  const handle = createMlsDeliveryHttpHandler(ds, verifier, async () => true)
  const transport = new CoreMlsDeliveryTransport({ baseUrl: 'https://core.example', fetch: (input, init) => handle(new Request(input, init)) })
  return { ds, transport }
}

describe('CoreMlsDeliveryTransport <-> core HTTP handler', () => {
  test('createGroup then submitCommit round-trip, and a stale-epoch retry surfaces as ok:false, not a throw', async () => {
    const { ds, transport } = setup()
    const creation: Omit<MlsGroupCreationV1, 'signature'> = { version: 1, groupId, identityId, creatorKid: deviceAKid, roster: [], createdAt: '2026-08-23T00:00:00.000Z' }
    const roster = await transport.createGroup({ ...creation, signature: ed25519.sign(mlsGroupCreationSigningBytes(creation), deviceAKey) })
    expect(roster).toEqual([deviceAKid])

    const commit: Omit<MlsCommitSubmissionV1, 'signature'> = { version: 1, groupId, identityId, senderKid: deviceAKid, epoch: '0', commit: new Uint8Array([1]), roster: [deviceAKid], submittedAt: '2026-08-23T00:00:01.000Z' }
    const accepted = await transport.submitCommit({ ...commit, signature: ed25519.sign(mlsCommitSubmissionSigningBytes(commit), deviceAKey) })
    expect(accepted).toEqual({ ok: true, roster: [deviceAKid] })

    // Same (now stale) epoch again: a normal tie-break loss, not a network error.
    const stale = await transport.submitCommit({ ...commit, signature: ed25519.sign(mlsCommitSubmissionSigningBytes(commit), deviceAKey) })
    expect(stale).toEqual({ ok: false, reason: 'epoch-conflict', epoch: '1' })
    ds.close()
  })

  test('pullGroupInfo decodes the answer core encoded', async () => {
    const { ds, transport } = setup()
    ds.createGroup(groupId, identityId, deviceAKid, [])
    ds.submitCommit(groupId, deviceAKid, '0', new Uint8Array([1]), [deviceAKid], undefined, undefined, new Uint8Array([9]))
    const pull: Omit<MlsGroupInfoPullV1, 'signature'> = { version: 1, groupId, identityId, requesterKid: deviceAKid, requestedAt: '2026-08-23T00:00:00.000Z' }
    const answer = await transport.pullGroupInfo({ ...pull, signature: ed25519.sign(mlsGroupInfoPullSigningBytes(pull), deviceAKey) })
    expect(answer).toEqual({ groupInfo: new Uint8Array([9]), pendingRemovals: [] })
    ds.close()
  })

  test('publishKeyPackages / takeKeyPackages / dropKeyPackages / keyPackageCount round-trip binary payloads', async () => {
    const { ds, transport } = setup()
    const publish: Omit<MlsKeyPackagePublishV1, 'signature'> = { version: 1, identityId, kid: deviceAKid, packages: [new Uint8Array([1, 2]), new Uint8Array([3])], publishedAt: '2026-08-23T00:00:00.000Z' }
    expect(await transport.publishKeyPackages({ ...publish, signature: ed25519.sign(mlsKeyPackagePublishSigningBytes(publish), deviceAKey) })).toBe(2)

    const countPull: Omit<MlsKeyPackageCountPullV1, 'signature'> = { version: 1, identityId, kid: deviceAKid, requestedAt: '2026-08-23T00:00:01.000Z' }
    expect(await transport.keyPackageCount({ ...countPull, signature: ed25519.sign(mlsKeyPackageCountPullSigningBytes(countPull), deviceAKey) })).toBe(2)

    const take: Omit<MlsKeyPackageTakeV1, 'signature'> = { version: 1, identityId, requesterKid: deviceAKid, requestedAt: '2026-08-23T00:00:02.000Z' }
    const taken = await transport.takeKeyPackages({ ...take, signature: ed25519.sign(mlsKeyPackageTakeSigningBytes(take), deviceAKey) })
    expect(taken).toEqual([{ kid: deviceAKid, keyPackage: new Uint8Array([1, 2]) }])

    const drop: Omit<MlsKeyPackageDropV1, 'signature'> = { version: 1, identityId, kid: deviceAKid, droppedAt: '2026-08-23T00:00:03.000Z' }
    await transport.dropKeyPackages({ ...drop, signature: ed25519.sign(mlsKeyPackageDropSigningBytes(drop), deviceAKey) })
    expect(ds.keyPackageCount(deviceAKid)).toBe(0)
    ds.close()
  })

  test('submitSelfRemove / clearPendingRemovals / pullDeliveries round-trip', async () => {
    const { ds, transport } = setup()
    ds.createGroup(groupId, identityId, deviceAKid, [])
    ds.submitCommit(groupId, deviceAKid, '0', new Uint8Array([1]), [deviceAKid])

    const selfRemove: Omit<MlsSelfRemoveSubmissionV1, 'signature'> = { version: 1, groupId, identityId, senderKid: deviceAKid, epoch: '1', proposal: new Uint8Array([5]), removedKid: deviceAKid, submittedAt: '2026-08-23T00:00:00.000Z' }
    const removed = await transport.submitSelfRemove({ ...selfRemove, signature: ed25519.sign(mlsSelfRemoveSubmissionSigningBytes(selfRemove), deviceAKey) })
    expect(removed.ok).toBe(true)

    const clear: Omit<MlsPendingRemovalsClearV1, 'signature'> = { version: 1, groupId, identityId, requesterKid: deviceAKid, clearedKids: [deviceAKid], clearedAt: '2026-08-23T00:00:01.000Z' }
    await transport.clearPendingRemovals({ ...clear, signature: ed25519.sign(mlsPendingRemovalsClearSigningBytes(clear), deviceAKey) })
    // device-a IS the group's last committer (it committed the genesis epoch above), so this clear takes effect.
    expect(ds.groupInfoFor(groupId, identityId)?.pendingRemovals).toEqual([])

    const pull: Omit<MlsDeliveriesPullV1, 'signature'> = { version: 1, groupId, identityId, requesterKid: deviceAKid, afterSeq: 0, requestedAt: '2026-08-23T00:00:02.000Z' }
    const entries = await transport.pullDeliveries({ ...pull, signature: ed25519.sign(mlsDeliveriesPullSigningBytes(pull), deviceAKey) })
    expect(entries.map(e => ({ seq: e.seq, kind: e.kind }))).toEqual([{ seq: 1, kind: 'commit' }, { seq: 2, kind: 'proposal' }])
    ds.close()
  })

  test('groupsFor round-trips the epoch as a decimal string', async () => {
    const { ds, transport } = setup()
    ds.createGroup(groupId, identityId, deviceAKid, [])
    const pull: Omit<MlsGroupsForPullV1, 'signature'> = { version: 1, identityId, requesterKid: deviceAKid, requestedAt: '2026-08-23T00:00:00.000Z' }
    expect(await transport.groupsFor({ ...pull, signature: ed25519.sign(mlsGroupsForPullSigningBytes(pull), deviceAKey) })).toEqual([{ groupId, epoch: '0' }])
    ds.close()
  })
})
