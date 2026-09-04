import { describe, expect, test } from 'bun:test'
import { equalBytes, sha256Bytes } from '../../src/shared/protocol/canonical.ts'
import { decryptVaultObject } from '../../src/vault/objects.ts'
import { buildOpenPgpPrivateCredential, decodeOpenPgpPrivateCredential, openPgpCredentialAad } from '../../src/vault/openpgp-credential.ts'
import type { VaultEventSigner } from '../../src/vault/events.ts'

const signer: VaultEventSigner = { deviceId: 'device-a', async sign(bytes) { return sha256Bytes(bytes) }, async verify(deviceId, bytes, signature) { return deviceId === 'device-a' && equalBytes(sha256Bytes(bytes), signature) } }
const credential = { version: 1 as const, kind: 'credential.openpgp.private' as const, identityId: 'did:web:alice.example', fingerprint: '0123456789abcdef0123456789abcdef01234567', privateKey: new Uint8Array([1, 2, 3]), createdAt: '2026-08-21T00:00:00.000Z' }

describe('OpenPGP vault credential', () => {
  test('encrypts a canonical private credential and binds it to identity, segment, and fingerprint', async () => {
    const key = new Uint8Array(32).fill(7)
    const record = await buildOpenPgpPrivateCredential(credential, { identityId: credential.identityId, actorDeviceId: 'device-a', actorSeq: 3, parents: [], segmentId: 'segment-1', segmentKey: key }, signer)
    expect(record.event.kind).toBe('credential.openpgp.set')
    expect(record.event.targetIds).toEqual(['openpgp:0123456789ABCDEF0123456789ABCDEF01234567'])
    const plaintext = await decryptVaultObject(key, record.object)
    expect(decodeOpenPgpPrivateCredential(plaintext)).toMatchObject({ fingerprint: '0123456789ABCDEF0123456789ABCDEF01234567', privateKey: new Uint8Array([1, 2, 3]) })
    expect(record.object.aad).toEqual(openPgpCredentialAad(credential.identityId, 'segment-1', credential.fingerprint))
  })

  test('rejects non-canonical or malformed fingerprints before a private key is used', () => {
    expect(() => decodeOpenPgpPrivateCredential(new TextEncoder().encode(JSON.stringify({ ...credential, fingerprint: credential.fingerprint.toLowerCase(), privateKey: 'AQID' })))).toThrow('not canonical')
    expect(() => openPgpCredentialAad(credential.identityId, 'segment-1', 'not-a-fingerprint')).toThrow('fingerprint')
  })
})
