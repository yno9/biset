// Endpoint-side producer: turns an accepted MLS self-group commit into the
// AcceptedSelfGroupProjectionV1 core's roster expects, and signs it as a
// RosterInstallV1. Core-independent — it never talks to core's stores
// directly, only builds and signs the control message a transport hands to
// core's `installRosterProjection` (PLAN.md §4.1).
import { mlsEpoch, type DeliverySeq, type IdentityId } from '../protocol/ids.ts'
import type { AcceptedSelfGroupProjectionV1, TrustedDeviceV1 } from '../core/identity/device-roster.ts'
import { rosterInstallSigningBytes, type RosterInstallV1 } from '../core/identity/roster-install.ts'
import { epochOf, memberList } from './group.ts'
import type { ClientState } from './vendor/index.ts'

export interface RosterProjectionDeviceSource {
  /**
   * Maps an MLS leaf's credential kid (`did#kN`) to the DID-URL signing key
   * id the roster's Ed25519 verifier resolves. The MLS credential and the
   * roster's `signingKeyId` are not guaranteed to be the same string in
   * general (`PLANMLSDIDCRED.md` §4's open items — the device-credential
   * design is not finalized); this seam is what lets the caller own that
   * mapping instead of this module guessing at it.
   */
  signingKeyIdForKid(kid: string): string
  /**
   * `deliveryFloor` for a device the roster has not seen before: the
   * vault-delivery seq it starts pulling from. Must be the CURRENT
   * `latestSeq`, never a past one — PLAN.md §2.3 requires that a new device
   * is never retroactively added as a pending recipient of history it never
   * should have received.
   */
  deliveryFloorForNewDevice(): Promise<DeliverySeq>
}

/**
 * Builds the next `AcceptedSelfGroupProjectionV1` for `did` from its current
 * MLS self-group state. `previous` is the roster's own last-installed
 * projection (or undefined for a brand-new identity) — devices already in it
 * keep their existing `deliveryFloor`; only a genuinely new kid gets a fresh
 * one from `source`.
 */
export async function buildAcceptedSelfGroupProjection(
  identityId: IdentityId,
  selfGroupId: string,
  did: string,
  state: ClientState,
  previous: AcceptedSelfGroupProjectionV1 | undefined,
  source: RosterProjectionDeviceSource,
  now: () => Date = () => new Date(),
): Promise<AcceptedSelfGroupProjectionV1> {
  const kids = memberList(state).filter(member => member.did === did).map(member => member.kid)
  if (kids.length === 0) throw new Error('buildAcceptedSelfGroupProjection: identity has no active device in this self group')
  const previousByDeviceId = new Map((previous?.devices ?? []).map(device => [device.deviceId, device]))
  const devices: TrustedDeviceV1[] = []
  for (const kid of kids) {
    const existing = previousByDeviceId.get(kid)
    devices.push({
      deviceId: kid,
      deliveryFloor: existing ? existing.deliveryFloor : await source.deliveryFloorForNewDevice(),
      signingKeyId: source.signingKeyIdForKid(kid),
    })
  }
  return {
    version: 1,
    identityId,
    selfGroupId,
    epoch: mlsEpoch(epochOf(state)),
    devices,
    acceptedAt: now().toISOString(),
  }
}

/** Signs a built projection as the `RosterInstallV1` control message core's
 * `installRosterProjection` verifies (`src/core/identity/authorizers.ts`). */
export async function signRosterInstall(
  projection: AcceptedSelfGroupProjectionV1,
  installerDeviceId: string,
  sign: (bytes: Uint8Array) => Promise<Uint8Array> | Uint8Array,
  now: () => Date = () => new Date(),
): Promise<RosterInstallV1> {
  const unsigned = { version: 1 as const, projection, installerDeviceId, installedAt: now().toISOString() }
  return { ...unsigned, signature: await sign(rosterInstallSigningBytes(unsigned)) }
}
