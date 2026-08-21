import { describe, expect, test } from 'bun:test'
import {
  rosterBackedIngressAckAuthorizer,
  rosterBackedRestoreControlAuthorizer,
  rosterBackedVaultDeliveryAuthorizer,
} from '../../src/core/identity/authorizers.ts'
import { MemoryTrustedDeviceRoster } from '../../src/core/identity/device-roster.ts'

const identityId = 'did:web:alice.example'

async function roster(): Promise<MemoryTrustedDeviceRoster> {
  const value = new MemoryTrustedDeviceRoster()
  await value.installAcceptedProjection({
    version: 1,
    identityId,
    selfGroupId: 'self-group-alice',
    epoch: '4',
    devices: [{ deviceId: 'device-a', deliveryFloor: '9', signingKeyId: 'did:web:alice.example#device-a-sign' }],
    acceptedAt: '2026-08-21T00:00:00.000Z',
  })
  return value
}

describe('roster-backed mediation authorizers', () => {
  test('uses the current accepted roster rather than caller-supplied device lists', async () => {
    const value = await roster()
    const ingress = rosterBackedIngressAckAuthorizer(value, { async verifyIngressAck() { return true } })
    const delivery = rosterBackedVaultDeliveryAuthorizer(value, { async verifyVaultDeliveryAck() { return true } })
    expect(await ingress.isTrustedDevice(identityId, 'device-a')).toBe(true)
    expect(await ingress.isTrustedDevice(identityId, 'device-b')).toBe(false)
    expect(await ingress.verify({ recipientDeviceId: 'device-b' } as never, { recipientIdentityId: identityId } as never)).toBe(false)
    expect(await delivery.deliveryFloor(identityId, 'device-a')).toBe('9')
    expect(await delivery.verifyRecipients(identityId, ['device-a'])).toBe(true)
    expect(await delivery.verifyRecipients(identityId, ['device-b'])).toBe(false)
    expect(await delivery.verifyAck({ identityId, recipientDeviceId: 'device-b' } as never, {} as never)).toBe(false)
  })

  test('passes public key identity only for a currently trusted restore signer', async () => {
    const value = await roster()
    const control = rosterBackedRestoreControlAuthorizer(value, {
      async verifyRestoreRequest(_request, device) { return device.signingKeyId.endsWith('#device-a-sign') },
      async verifyRestoreOffer() { return true },
      async verifyRestoreCancel() { return true },
    })
    expect(await control.verifyRequest({ identityId, requesterDeviceId: 'device-a' } as never)).toBe(true)
    expect(await control.verifyRequest({ identityId, requesterDeviceId: 'device-b' } as never)).toBe(false)
  })
})
