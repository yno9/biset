// resolveRecipient (protocol/transport.ts's TransportAdapterHost) for
// DIDComm: turns a JWE's outer recipient kid into a local identity.
//
// Simpler than mail-recipient-resolver.ts's own job: mail has to GUESS an
// identity from an address (`alice@mail.<apex>` -> try `alice.<apex>`, then
// resolve to confirm), because SMTP addressing carries no DID. DIDComm's
// addressing already IS a DID URL -- the JWE recipient header's `kid` is
// `did:webvh:...#<fragment>`, so `didOfKid` (protocol/ids.ts) reads the
// identity straight off it, no live resolution needed.
//
// Deliberately does NOT require the exact kid to already equal one of the
// identity's current MLS-device roster ids -- unlike `didOfKid`, nothing in
// this rewrite yet guarantees a device's DIDComm keyAgreement kid and its
// MLS leaf credential kid are the same string (that unification is
// `identity/bootstrap.ts` device-provisioning work, still pending; see
// PLAN.md §6.1's last checkbox). `CoreIngressAdapter.offer()` doesn't even
// read this resolver's own `deviceIds` back -- it re-derives
// `recipientDeviceSnapshot` from the roster itself -- so this resolver's
// real job, same as mail-recipient-resolver.ts's own `devices.length === 0`
// check, is only "does this identity exist and currently trust ANY device":
// exactly matching an existing device kid isn't what gates safety here --
// a JWE addressed to a kid nobody actually holds the private key for
// simply fails to decrypt on every device that pulls it (already covered:
// the ingress projector's own multidevice-ingress test).
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
    if (devices.length === 0) return undefined
    return { identityId, deviceIds: devices.map(device => device.deviceId) }
  }
}
