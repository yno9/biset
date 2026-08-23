import { canonicalBytes } from '../../protocol/canonical.ts'
import type { DeviceId } from '../../protocol/ids.ts'
import type { AcceptedSelfGroupProjectionV1 } from './device-roster.ts'

/**
 * A signed control message installing an `AcceptedSelfGroupProjectionV1` into
 * core's roster. `PLANMLSARCH.md` §4 is the authority for what core may check
 * before accepting one: epoch monotonicity and same-epoch tie-break happen
 * inside `TrustedDeviceRoster.installAcceptedProjection`; `installerDeviceId`
 * authorization (this file) is the piece that was missing — without it any
 * caller could write an arbitrary roster into core.
 */
export interface RosterInstallV1 {
  version: 1
  projection: AcceptedSelfGroupProjectionV1
  installerDeviceId: DeviceId
  installedAt: string
  signature: Uint8Array
}

export function rosterInstallSigningBytes(install: Omit<RosterInstallV1, 'signature'>): Uint8Array {
  const projection = install.projection
  return canonicalBytes({
    label: 'biset/roster-install/v1',
    version: install.version,
    installerDeviceId: install.installerDeviceId,
    installedAt: install.installedAt,
    projection: {
      version: projection.version,
      identityId: projection.identityId,
      selfGroupId: projection.selfGroupId,
      epoch: projection.epoch,
      acceptedAt: projection.acceptedAt,
      devices: projection.devices.map(device => ({
        deviceId: device.deviceId,
        deliveryFloor: device.deliveryFloor,
        signingKeyId: device.signingKeyId,
      })),
    },
  })
}

export type RosterInstallOutcome = 'installed' | 'already-current' | 'rejected'
