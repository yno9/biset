import { describe, expect, test } from 'bun:test'
import { MemoryTrustedDeviceRoster, type AcceptedSelfGroupProjectionV1 } from '../../src/core/identity/device-roster.ts'

function projection(overrides: Partial<AcceptedSelfGroupProjectionV1> = {}): AcceptedSelfGroupProjectionV1 {
  return {
    version: 1,
    identityId: 'did:web:alice.example',
    selfGroupId: 'self-group-alice',
    epoch: '7',
    devices: [
      { deviceId: 'device-a', deliveryFloor: '1', signingPublicKey: new Uint8Array(32).fill(1), deviceCredential: new Uint8Array([1]) },
      { deviceId: 'device-b', deliveryFloor: '4', signingPublicKey: new Uint8Array(32).fill(2), deviceCredential: new Uint8Array([2]) },
    ],
    acceptedAt: '2026-08-21T00:00:00.000Z',
    ...overrides,
  }
}

describe('trusted device roster', () => {
  test('makes an accepted MLS projection the sole authority for trusted devices and delivery floors', async () => {
    const roster = new MemoryTrustedDeviceRoster()
    expect(await roster.installAcceptedProjection(projection())).toBe('installed')
    expect(await roster.isTrustedDevice('did:web:alice.example', 'device-a')).toBe(true)
    expect(await roster.deliveryFloor('did:web:alice.example', 'device-b')).toBe('4')
    expect(await roster.isTrustedDevice('did:web:alice.example', 'device-c')).toBe(false)
    expect(await roster.installAcceptedProjection(projection())).toBe('already-current')
  })

  test('removes devices only in a later accepted MLS epoch and rejects stale projections', async () => {
    const roster = new MemoryTrustedDeviceRoster()
    await roster.installAcceptedProjection(projection())
    await roster.installAcceptedProjection(projection({
      epoch: '8',
      devices: [{ deviceId: 'device-a', deliveryFloor: '1', signingPublicKey: new Uint8Array(32).fill(1), deviceCredential: new Uint8Array([1]) }],
      acceptedAt: '2026-08-21T00:01:00.000Z',
    }))
    expect(await roster.isTrustedDevice('did:web:alice.example', 'device-b')).toBe(false)
    await expect(roster.installAcceptedProjection(projection())).rejects.toThrow('stale MLS projection')
  })

  test('keeps the full uint64 MLS epoch outside JavaScript Number', async () => {
    const roster = new MemoryTrustedDeviceRoster()
    await roster.installAcceptedProjection(projection({ epoch: '18446744073709551615' }))
    expect((await roster.projection('did:web:alice.example'))?.epoch).toBe('18446744073709551615')
  })
})
