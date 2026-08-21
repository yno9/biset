import type { AdapterIngressOfferV1, IngressEnvelopeV1 } from '../../protocol/ingress.ts'
import { assertAdapterIngressOffer, ProtocolValidationError } from '../../protocol/validate.ts'
import type { TrustedDeviceRoster } from '../identity/device-roster.ts'
import type { IngressStore } from '../mediation/ingress-store.ts'

/**
 * The only ingress surface intended for first-party adapters. A transport
 * adapter cannot choose which devices receive a body; the core freezes the
 * current accepted self-group roster itself.
 */
export class CoreIngressAdapter {
  constructor(private readonly roster: TrustedDeviceRoster, private readonly store: IngressStore) {}

  async offer(input: AdapterIngressOfferV1): Promise<void> {
    assertAdapterIngressOffer(input)
    const recipientDeviceSnapshot = (await this.roster.trustedDevices(input.recipientIdentityId)).map(device => device.deviceId)
    if (recipientDeviceSnapshot.length === 0) throw new ProtocolValidationError('recipient identity has no trusted devices')
    const envelope: IngressEnvelopeV1 = { ...input, recipientDeviceSnapshot }
    await this.store.offer(envelope)
  }
}
