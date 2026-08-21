import { afterEach, describe, expect, test } from 'bun:test'
import { rmSync } from 'node:fs'
import { SqliteTrustedDeviceRoster } from '../../src/core/identity/sqlite-device-roster.ts'

const path = `/tmp/biset-roster-${process.pid}-${Date.now()}.sqlite`
const projection = {
  version: 1 as const, identityId: 'did:web:alice.example', selfGroupId: 'self-group-1', epoch: '7', acceptedAt: '2026-08-21T00:00:00.000Z',
  devices: [{ deviceId: 'device-a', deliveryFloor: '1', signingKeyId: 'did:web:alice.example#device-a' }, { deviceId: 'device-b', deliveryFloor: '4', signingKeyId: 'did:web:alice.example#device-b' }],
}

afterEach(() => { try { rmSync(path) } catch {} })

describe('SQLite trusted device roster', () => {
  test('persists only the accepted public roster across a core restart', async () => {
    const first = SqliteTrustedDeviceRoster.open(path)
    expect(await first.installAcceptedProjection(projection)).toBe('installed')
    first.close()
    const restarted = SqliteTrustedDeviceRoster.open(path)
    expect(await restarted.projection(projection.identityId)).toEqual(projection)
    expect(await restarted.deliveryFloor(projection.identityId, 'device-b')).toBe('4')
    expect(await restarted.isTrustedDevice(projection.identityId, 'device-c')).toBe(false)
    restarted.close()
  })
})
