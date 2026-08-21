import { describe, expect, test } from 'bun:test'
import { equalBytes } from '../../src/protocol/canonical.ts'
import type { VaultEventSigner } from '../../src/vault/events.ts'
import { buildOpenPgpPrivateCredential, type OpenPgpPrivateCredentialV1 } from '../../src/vault/openpgp-credential.ts'
import { OpenPgpCredentialReader } from '../../src/vault/openpgp-credential-reader.ts'
import { createSegmentKey } from '../../src/vault/objects.ts'

const identityId = 'did:web:alice.example'
const segmentId = 'segment-1'
const segmentKey = createSegmentKey()
const signer: VaultEventSigner = {
  deviceId: 'device-a',
  async sign(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)) },
  async verify(deviceId, bytes, signature) { return deviceId === 'device-a' && equalBytes(signature, await this.sign(bytes)) },
}

describe('OpenPGP credential vault reader', () => {
  test('selects the unique unsuperseded credential while retaining historical credentials', async () => {
    const old = await record(1, credential('0123456789ABCDEF0123456789ABCDEF01234567', '2026-08-22T00:00:00.000Z'))
    const current = await record(2, credential('89ABCDEF0123456789ABCDEF0123456789ABCDEF', '2026-08-22T01:00:00.000Z', old.credential.fingerprint))
    const reader = makeReader([old, current])

    expect((await reader.readAll()).map(value => value.fingerprint)).toEqual([old.credential.fingerprint, current.credential.fingerprint])
    expect((await reader.readCurrent()).fingerprint).toBe(current.credential.fingerprint)
  })

  test('fails closed when independently introduced credentials have no rotation relation', async () => {
    const first = await record(1, credential('0123456789ABCDEF0123456789ABCDEF01234567', '2026-08-22T00:00:00.000Z'))
    const second = await record(2, credential('89ABCDEF0123456789ABCDEF0123456789ABCDEF', '2026-08-22T01:00:00.000Z'))
    await expect(makeReader([first, second]).readCurrent()).rejects.toThrow('ambiguous')
  })

  test('rejects a credential event whose signature is no longer valid', async () => {
    const value = await record(1, credential('0123456789ABCDEF0123456789ABCDEF01234567', '2026-08-22T00:00:00.000Z'))
    const tampered = { ...value, event: { ...value.event, signature: new Uint8Array([0]) } }
    await expect(makeReader([tampered]).readAll()).rejects.toThrow('signature')
  })
})

function credential(fingerprint: string, createdAt: string, supersedesFingerprint?: string): OpenPgpPrivateCredentialV1 {
  return { version: 1, kind: 'credential.openpgp.private', identityId, fingerprint, privateKey: new Uint8Array([1, 2, 3]), createdAt, ...(supersedesFingerprint === undefined ? {} : { supersedesFingerprint }) }
}

async function record(actorSeq: number, value: OpenPgpPrivateCredentialV1) {
  return buildOpenPgpPrivateCredential(value, { identityId, actorDeviceId: 'device-a', actorSeq, parents: actorSeq === 1 ? [] : ['event-1'], segmentId, segmentKey }, signer)
}

function makeReader(records: Awaited<ReturnType<typeof record>>[]): OpenPgpCredentialReader {
  const objects = new Map(records.map(value => [value.object.objectId, { ...value.object, identityId }]))
  return new OpenPgpCredentialReader({
    identityId,
    objects: { async readObject(_identityId, objectId) { return objects.get(objectId) },
    },
    events: { async readCredentialEvents() { return records.map(value => ({ ...value.event, identityId, targetIds: [...value.event.targetIds], objectRefs: [...value.event.objectRefs], parents: [...value.event.parents], signature: value.event.signature.slice() })) } },
    segmentKeys: { async resolveSegmentKey() { return segmentKey.slice() } },
    verifier: signer,
  })
}
