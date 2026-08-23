import { afterEach, describe, expect, test } from 'bun:test'
import { rmSync } from 'node:fs'
import { ed25519 } from '@noble/curves/ed25519.js'
import { SqliteMlsDeliveryService } from '../../src/core/mediation/mls-delivery-store.ts'
import {
  createMlsGroup, Ed25519MlsDsSignatureVerifier, publishMlsKeyPackages, pullMlsGroupInfo,
  submitMlsCommit, submitMlsExternalCommit, takeMlsKeyPackages,
} from '../../src/core/mediation/mls-delivery-authorizer.ts'
import {
  mlsCommitSubmissionSigningBytes, mlsExternalCommitSubmissionSigningBytes, mlsGroupCreationSigningBytes,
  mlsGroupInfoPullSigningBytes, mlsKeyPackagePublishSigningBytes, mlsKeyPackageTakeSigningBytes,
} from '../../src/protocol/signing.ts'
import type { MlsCommitSubmissionV1, MlsExternalCommitSubmissionV1, MlsGroupCreationV1, MlsGroupInfoPullV1, MlsKeyPackagePublishV1, MlsKeyPackageTakeV1 } from '../../src/protocol/mls-ds.ts'

const path = `/tmp/biset-mls-ds-auth-${process.pid}-${Date.now()}.sqlite`
const identityId = 'did:web:alice.example'
const groupId = 'group-1'
const deviceAKey = ed25519.utils.randomSecretKey()
const deviceAPublicKey = ed25519.getPublicKey(deviceAKey)
const strangerKey = ed25519.utils.randomSecretKey()
const deviceAKid = `${identityId}#device-a`

afterEach(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { rmSync(`${path}${suffix}`) } catch {}
  }
})

function verifier() {
  return new Ed25519MlsDsSignatureVerifier({
    async resolveEd25519PublicKey(kid) { return kid === deviceAKid ? deviceAPublicKey : undefined },
  })
}

function open(): SqliteMlsDeliveryService { return SqliteMlsDeliveryService.open(path) }

describe('MLS DS authorizer (signature verification over the sender\'s own device key)', () => {
  test('createMlsGroup accepts a validly self-signed genesis, rejects a forged one', async () => {
    const ds = open()
    const unsigned: Omit<MlsGroupCreationV1, 'signature'> = { version: 1, groupId, identityId, creatorKid: deviceAKid, roster: [], createdAt: '2026-08-23T00:00:00.000Z' }
    const valid = { ...unsigned, signature: ed25519.sign(mlsGroupCreationSigningBytes(unsigned), deviceAKey) }
    const outcome = await createMlsGroup(ds, verifier(), valid)
    expect(outcome).toEqual({ ok: true, roster: [deviceAKid] })

    const forged = { ...unsigned, groupId: 'group-2', signature: ed25519.sign(mlsGroupCreationSigningBytes(unsigned), strangerKey) }
    expect(await createMlsGroup(ds, verifier(), forged)).toEqual({ ok: false })
    ds.close()
  })

  test('submitMlsCommit rejects a forged submission as unauthorized without touching DS state', async () => {
    const ds = open()
    ds.createGroup(groupId, identityId, deviceAKid, [])
    const unsigned: Omit<MlsCommitSubmissionV1, 'signature'> = { version: 1, groupId, identityId, senderKid: deviceAKid, epoch: '0', commit: new Uint8Array([1]), roster: [deviceAKid], submittedAt: '2026-08-23T00:00:00.000Z' }
    const forged = { ...unsigned, signature: ed25519.sign(mlsCommitSubmissionSigningBytes(unsigned), strangerKey) }
    expect(await submitMlsCommit(ds, verifier(), forged)).toEqual({ ok: false, reason: 'unauthorized', epoch: '0' })

    const valid = { ...unsigned, signature: ed25519.sign(mlsCommitSubmissionSigningBytes(unsigned), deviceAKey) }
    const accepted = await submitMlsCommit(ds, verifier(), valid)
    expect(accepted.ok).toBe(true)
    ds.close()
  })

  test('submitMlsExternalCommit requires the sender\'s own signature too', async () => {
    const ds = open()
    ds.createGroup(groupId, identityId, deviceAKid, [])
    ds.submitCommit(groupId, deviceAKid, '0', new Uint8Array([1]), [deviceAKid], undefined, undefined, new Uint8Array([9]))
    const unsigned: Omit<MlsExternalCommitSubmissionV1, 'signature'> = { version: 1, groupId, identityId, senderKid: deviceAKid, epoch: '1', commit: new Uint8Array([2]), submittedAt: '2026-08-23T00:00:00.000Z' }
    const forged = { ...unsigned, signature: ed25519.sign(mlsExternalCommitSubmissionSigningBytes(unsigned), strangerKey) }
    expect(await submitMlsExternalCommit(ds, verifier(), forged)).toEqual({ ok: false, reason: 'unauthorized', epoch: '0' })

    const valid = { ...unsigned, signature: ed25519.sign(mlsExternalCommitSubmissionSigningBytes(unsigned), deviceAKey) }
    const accepted = await submitMlsExternalCommit(ds, verifier(), valid)
    expect(accepted.ok).toBe(true)
    ds.close()
  })

  test('pullMlsGroupInfo returns undefined for an unsigned/forged pull, the answer for a valid one', async () => {
    const ds = open()
    ds.createGroup(groupId, identityId, deviceAKid, [])
    ds.submitCommit(groupId, deviceAKid, '0', new Uint8Array([1]), [deviceAKid], undefined, undefined, new Uint8Array([9]))
    const unsigned: Omit<MlsGroupInfoPullV1, 'signature'> = { version: 1, groupId, identityId, requesterKid: deviceAKid, requestedAt: '2026-08-23T00:00:00.000Z' }
    const forged = { ...unsigned, signature: ed25519.sign(mlsGroupInfoPullSigningBytes(unsigned), strangerKey) }
    expect(await pullMlsGroupInfo(ds, verifier(), forged)).toBeUndefined()

    const valid = { ...unsigned, signature: ed25519.sign(mlsGroupInfoPullSigningBytes(unsigned), deviceAKey) }
    expect(await pullMlsGroupInfo(ds, verifier(), valid)).toEqual({ groupInfo: new Uint8Array([9]), pendingRemovals: [] })
    ds.close()
  })

  test('publishMlsKeyPackages and takeMlsKeyPackages both require the sender\'s own signature', async () => {
    const ds = open()
    const publishUnsigned: Omit<MlsKeyPackagePublishV1, 'signature'> = { version: 1, identityId, kid: deviceAKid, packages: [new Uint8Array([1])], publishedAt: '2026-08-23T00:00:00.000Z' }
    const publishForged = { ...publishUnsigned, signature: ed25519.sign(mlsKeyPackagePublishSigningBytes(publishUnsigned), strangerKey) }
    expect(await publishMlsKeyPackages(ds, verifier(), publishForged)).toBeUndefined()

    const publishValid = { ...publishUnsigned, signature: ed25519.sign(mlsKeyPackagePublishSigningBytes(publishUnsigned), deviceAKey) }
    expect(await publishMlsKeyPackages(ds, verifier(), publishValid)).toBe(1)

    const takeUnsigned: Omit<MlsKeyPackageTakeV1, 'signature'> = { version: 1, identityId, requesterKid: deviceAKid, requestedAt: '2026-08-23T00:00:00.000Z' }
    const takeForged = { ...takeUnsigned, signature: ed25519.sign(mlsKeyPackageTakeSigningBytes(takeUnsigned), strangerKey) }
    expect(await takeMlsKeyPackages(ds, verifier(), takeForged, async () => true)).toBeUndefined()

    const takeValid = { ...takeUnsigned, signature: ed25519.sign(mlsKeyPackageTakeSigningBytes(takeUnsigned), deviceAKey) }
    expect(await takeMlsKeyPackages(ds, verifier(), takeValid, async () => true)).toEqual([{ kid: deviceAKid, keyPackage: new Uint8Array([1]) }])
    ds.close()
  })
})
