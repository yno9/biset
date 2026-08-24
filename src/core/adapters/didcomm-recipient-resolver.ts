// resolveRecipient (protocol/transport.ts's TransportAdapterHost) for
// DIDComm: turns a JWE's outer recipient kid into a local identity.
//
// Simpler than mail-recipient-resolver.ts's own job: mail has to GUESS an
// identity from an address (`alice@mail.<apex>` -> try `alice.<apex>`, then
// resolve to confirm), because SMTP addressing carries no DID. DIDComm's
// addressing already IS a DID URL -- the JWE recipient header's `kid` is
// `did:webvh:...#k_<hash>`, the exact same string this rewrite's DeviceId
// already is (protocol/ids.ts's didOfKid, MLS leaf credential kids;
// didcomm/devicekid.ts derives DIDComm keyAgreement kids the same way, one
// device -> one kid shared by both key types). No live DID/routing.json
// resolution is needed here at all: the kid directly names an identity, and
// whether that identity currently trusts this specific device is exactly
// what the roster (populated by an authenticated self-group roster install,
// not by anything a transport adapter or its packets can influence) already
// answers -- the same ground-truth check CoreIngressAdapter itself relies on
// for `recipientDeviceSnapshot`.
import { didOfKid } from '../../protocol/ids.ts'
import type { RecipientReference, RecipientResolution } from '../../protocol/transport.ts'
import type { TrustedDeviceRoster } from '../identity/device-roster.ts'

export interface DidCommRecipientResolverOptions {
  roster: TrustedDeviceRoster
}

/** `reference.did` carries the JWE's outer recipient kid (a full DID URL,
 * `did:webvh:...#k_<hash>`), not a bare DID -- the field is reused rather
 * than adding a dedicated one since a device kid already IS a DID URL. */
export function createDidCommRecipientResolver(
  options: DidCommRecipientResolverOptions,
): (reference: RecipientReference) => Promise<RecipientResolution | undefined> {
  const roster = options.roster
  return async (reference: RecipientReference): Promise<RecipientResolution | undefined> => {
    if (!reference.did) return undefined
    const kid = reference.did
    if (kid.indexOf('#') < 0) return undefined // not a device kid, just a bare DID
    const identityId = didOfKid(kid)
    if (!identityId.startsWith('did:webvh:')) return undefined

    const devices = await roster.trustedDevices(identityId)
    if (!devices.some(device => device.deviceId === kid)) return undefined
    return { identityId, deviceIds: devices.map(device => device.deviceId) }
  }
}
