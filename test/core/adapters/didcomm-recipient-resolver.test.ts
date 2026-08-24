import { describe, expect, test } from 'bun:test'
import { createDidCommRecipientResolver } from '../../../src/core/adapters/didcomm-recipient-resolver.ts'
import { MemoryTrustedDeviceRoster } from '../../../src/core/identity/device-roster.ts'

const did = 'did:webvh:abc123:alice.test.example'
const kid = `${did}#k_devicehash`

async function rosterWithDevice(): Promise<MemoryTrustedDeviceRoster> {
  const roster = new MemoryTrustedDeviceRoster()
  await roster.installAcceptedProjection({
    version: 1, identityId: did, selfGroupId: 'self-group-1', epoch: '1', acceptedAt: '2026-08-24T00:00:00.000Z',
    devices: [{ deviceId: kid, deliveryFloor: '1', signingKeyId: kid }],
  })
  return roster
}

describe('createDidCommRecipientResolver', () => {
  test('resolves a trusted device kid to its identityId and trusted device ids', async () => {
    const roster = await rosterWithDevice()
    const resolver = createDidCommRecipientResolver({ roster })
    const result = await resolver({ did: kid })
    expect(result).toEqual({ identityId: did, deviceIds: [kid] })
  })

  test('resolves to undefined for a kid not in the trusted-device roster (never claims a body for an untrusted device)', async () => {
    const roster = new MemoryTrustedDeviceRoster()
    const resolver = createDidCommRecipientResolver({ roster })
    const result = await resolver({ did: kid })
    expect(result).toBeUndefined()
  })

  test('resolves to undefined for a bare DID with no fragment (not a device kid)', async () => {
    const roster = await rosterWithDevice()
    const resolver = createDidCommRecipientResolver({ roster })
    const result = await resolver({ did })
    expect(result).toBeUndefined()
  })

  test('resolves to undefined for a non-did:webvh identifier', async () => {
    const roster = await rosterWithDevice()
    const resolver = createDidCommRecipientResolver({ roster })
    const result = await resolver({ did: 'did:key:z6Mk...#k1' })
    expect(result).toBeUndefined()
  })

  test('ignores an address-only reference (DIDComm resolves by kid only)', async () => {
    const resolver = createDidCommRecipientResolver({ roster: new MemoryTrustedDeviceRoster() })
    const result = await resolver({ address: 'alice@mail.test.example' })
    expect(result).toBeUndefined()
  })
})
