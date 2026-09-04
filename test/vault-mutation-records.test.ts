import { describe, expect, test } from 'bun:test'
import { equalBytes } from '../src/shared/protocol/canonical.ts'
import { deviceKidFragment } from '../src/didcomm/devicekid.ts'
import { x25519 } from '@noble/curves/ed25519.js'
import { buildDidCommPrivateCredential } from '../src/vault/didcomm-credential.ts'
import { type VaultEventSigner } from '../src/vault/events.ts'
import { decryptVaultMutationRecords } from '../src/vault/mutation-records.ts'
import { createSegmentKey } from '../src/vault/objects.ts'

const identityId = 'did:webvh:alice.example'
const segmentId = 'segment-1'
const segmentKey = createSegmentKey()
const signer: VaultEventSigner = {
  deviceId: 'device-a',
  async sign(bytes) { return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)) },
  async verify(deviceId, bytes, signature) {
    return deviceId === this.deviceId && equalBytes(signature, await this.sign(bytes))
  },
}

describe('vault mutation records', () => {
  test('validates a DIDComm credential with its dedicated record format', async () => {
    const privateKey = new Uint8Array(32).fill(7)
    const record = await buildDidCommPrivateCredential({
      version: 1,
      kind: 'credential.didcomm.private',
      identityId,
      didCommKid: `${identityId}${deviceKidFragment(x25519.getPublicKey(privateKey))}`,
      privateKey,
      createdAt: '2026-08-28T00:00:00.000Z',
    }, {
      identityId,
      actorDeviceId: signer.deviceId,
      actorSeq: 1,
      parents: [],
      segmentId,
      segmentKey,
    }, signer)

    const records = await decryptVaultMutationRecords(
      identityId,
      [record.event],
      [record.object],
      { async resolveSegmentKey() { return segmentKey.slice() } },
      signer,
    )

    expect(records).toEqual([])
  })
})
