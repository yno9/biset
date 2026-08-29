import { afterEach, describe, expect, test } from 'bun:test'
import { rmSync } from 'node:fs'
import { ed25519 } from '@noble/curves/ed25519.js'
import { SqliteMlsDeliveryService } from '../../src/coordinator/mls-delivery-store.ts'
import { Ed25519MlsDsSignatureVerifier } from '../../src/coordinator/mls-delivery-authorizer.ts'
import { createMlsDeliveryHttpHandler } from '../../src/coordinator/mls-delivery-http.ts'
import { bytesToBase64url } from '../../src/protocol/canonical.ts'
import {
  mlsCommitSubmissionSigningBytes, mlsDeliveriesPullSigningBytes, mlsGroupCreationSigningBytes,
  mlsKeyPackagePublishSigningBytes, mlsKeyPackageTakeSigningBytes, mlsSelfRemoveSubmissionSigningBytes,
} from '../../src/protocol/signing.ts'
import type { MlsCommitSubmissionV1, MlsDeliveriesPullV1, MlsGroupCreationV1, MlsKeyPackagePublishV1, MlsKeyPackageTakeV1, MlsSelfRemoveSubmissionV1 } from '../../src/protocol/mls-ds.ts'

const path = `/tmp/biset-mls-ds-http-${process.pid}-${Date.now()}.sqlite`
const identityId = 'did:web:alice.example'
const deviceAKey = ed25519.utils.randomSecretKey()
const deviceAPublicKey = ed25519.getPublicKey(deviceAKey)
const deviceAKid = `${identityId}#device-a`

afterEach(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { rmSync(`${path}${suffix}`) } catch {}
  }
})

function handler() {
  const ds = SqliteMlsDeliveryService.open(path)
  const verifier = new Ed25519MlsDsSignatureVerifier({ async resolveEd25519PublicKey(kid) { return kid === deviceAKid ? deviceAPublicKey : undefined } })
  const handle = createMlsDeliveryHttpHandler(ds, verifier, async () => true)
  return { ds, handle }
}

function body(json: unknown): string {
  return JSON.stringify(json && typeof json === 'object' ? { ...json, deviceCredential: bytesToBase64url(new Uint8Array([1])) } : json)
}

describe('MLS DS HTTP endpoint', () => {
  test('group/create then commit/submit round-trips through the wire format', async () => {
    const { ds, handle } = handler()
    const creation: Omit<MlsGroupCreationV1, 'signature'> = { version: 1, groupId: 'group-1', identityId, creatorKid: deviceAKid, roster: [], createdAt: '2026-08-23T00:00:00.000Z' }
    const createResponse = await handle(new Request('https://coordinator.example/v1/mls/group/create', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: body({ ...creation, signature: bytesToBase64url(ed25519.sign(mlsGroupCreationSigningBytes(creation), deviceAKey)) }),
    }))
    expect(createResponse.status).toBe(201)
    expect(await createResponse.json()).toEqual({ roster: [deviceAKid] })

    const commit: Omit<MlsCommitSubmissionV1, 'signature'> = {
      version: 1, groupId: 'group-1', identityId, senderKid: deviceAKid, epoch: '0',
      commit: new Uint8Array([1, 2, 3]), roster: [deviceAKid], submittedAt: '2026-08-23T00:01:00.000Z',
    }
    const commitResponse = await handle(new Request('https://coordinator.example/v1/mls/commit/submit', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: body({ ...commit, commit: bytesToBase64url(commit.commit), signature: bytesToBase64url(ed25519.sign(mlsCommitSubmissionSigningBytes(commit), deviceAKey)) }),
    }))
    expect(commitResponse.status).toBe(201)
    expect(await commitResponse.json()).toEqual({ roster: [deviceAKid] })
    ds.close()
  })

  test('a forged commit submission is rejected with 403 and does not advance the epoch', async () => {
    const { ds, handle } = handler()
    const strangerKey = ed25519.utils.randomSecretKey()
    ds.createGroup('group-1', identityId, deviceAKid, [])
    const commit: Omit<MlsCommitSubmissionV1, 'signature'> = {
      version: 1, groupId: 'group-1', identityId, senderKid: deviceAKid, epoch: '0',
      commit: new Uint8Array([1]), roster: [deviceAKid], submittedAt: '2026-08-23T00:00:00.000Z',
    }
    const response = await handle(new Request('https://coordinator.example/v1/mls/commit/submit', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: body({ ...commit, commit: bytesToBase64url(commit.commit), signature: bytesToBase64url(ed25519.sign(mlsCommitSubmissionSigningBytes(commit), strangerKey)) }),
    }))
    expect(response.status).toBe(403)
    expect(ds.roster('group-1')).toEqual([deviceAKid])
    ds.close()
  })

  test('key package publish then take round-trips binary packages through base64url', async () => {
    const { ds, handle } = handler()
    const publish: Omit<MlsKeyPackagePublishV1, 'signature'> = { version: 1, identityId, kid: deviceAKid, packages: [new Uint8Array([9, 9])], publishedAt: '2026-08-23T00:00:00.000Z' }
    const publishResponse = await handle(new Request('https://coordinator.example/v1/mls/keypackage/publish', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: body({ ...publish, packages: publish.packages.map(bytesToBase64url), signature: bytesToBase64url(ed25519.sign(mlsKeyPackagePublishSigningBytes(publish), deviceAKey)) }),
    }))
    expect(publishResponse.status).toBe(200)
    expect(await publishResponse.json()).toEqual({ count: 1 })

    const take: Omit<MlsKeyPackageTakeV1, 'signature'> = { version: 1, identityId, requesterKid: deviceAKid, requestedAt: '2026-08-23T00:01:00.000Z' }
    const takeResponse = await handle(new Request('https://coordinator.example/v1/mls/keypackage/take', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: body({ ...take, signature: bytesToBase64url(ed25519.sign(mlsKeyPackageTakeSigningBytes(take), deviceAKey)) }),
    }))
    expect(takeResponse.status).toBe(200)
    expect(await takeResponse.json()).toEqual({ items: [{ kid: deviceAKid, keyPackage: bytesToBase64url(new Uint8Array([9, 9])) }] })
    ds.close()
  })

  test('an unknown path is 404, a non-POST method is 405', async () => {
    const { ds, handle } = handler()
    expect((await handle(new Request('https://coordinator.example/v1/mls/nope', { method: 'POST', body: '{}' }))).status).toBe(404)
    expect((await handle(new Request('https://coordinator.example/v1/mls/group/create', { method: 'GET' }))).status).toBe(405)
    ds.close()
  })

  test('self-remove/submit then deliveries/pull round-trip through the wire format', async () => {
    const { ds, handle } = handler()
    ds.createGroup('group-1', identityId, deviceAKid, [])
    ds.submitCommit('group-1', deviceAKid, '0', new Uint8Array([1]), [deviceAKid])

    const selfRemove: Omit<MlsSelfRemoveSubmissionV1, 'signature'> = { version: 1, groupId: 'group-1', identityId, senderKid: deviceAKid, epoch: '1', proposal: new Uint8Array([7]), removedKid: deviceAKid, submittedAt: '2026-08-23T00:00:00.000Z' }
    const selfRemoveResponse = await handle(new Request('https://coordinator.example/v1/mls/self-remove/submit', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: body({ ...selfRemove, proposal: bytesToBase64url(selfRemove.proposal), signature: bytesToBase64url(ed25519.sign(mlsSelfRemoveSubmissionSigningBytes(selfRemove), deviceAKey)) }),
    }))
    expect(selfRemoveResponse.status).toBe(201)

    const pull: Omit<MlsDeliveriesPullV1, 'signature'> = { version: 1, groupId: 'group-1', identityId, requesterKid: deviceAKid, afterSeq: 0, requestedAt: '2026-08-23T00:01:00.000Z' }
    const pullResponse = await handle(new Request('https://coordinator.example/v1/mls/deliveries/pull', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: body({ ...pull, signature: bytesToBase64url(ed25519.sign(mlsDeliveriesPullSigningBytes(pull), deviceAKey)) }),
    }))
    expect(pullResponse.status).toBe(200)
    const parsed = await pullResponse.json() as { entries: Array<{ seq: number; kind: string }> }
    expect(parsed.entries.map(e => ({ seq: e.seq, kind: e.kind }))).toEqual([{ seq: 1, kind: 'commit' }, { seq: 2, kind: 'proposal' }])
    ds.close()
  })
})
