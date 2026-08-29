import { base64urlToBytes, bytesToBase64url, canonicalBytes } from '../../protocol/canonical.ts'
import type { DeviceId } from '../../protocol/ids.ts'
import { assertAcceptedSelfGroupProjection, type AcceptedSelfGroupProjectionV1 } from './device-roster.ts'

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
        signingPublicKey: bytesToBase64url(device.signingPublicKey),
        deviceCredential: bytesToBase64url(device.deviceCredential),
      })),
    },
  })
}

export type RosterInstallOutcome = 'installed' | 'already-current' | 'rejected'

export function assertRosterInstall(value: unknown): asserts value is RosterInstallV1 {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('RosterInstallV1 must be an object')
  const input = value as Record<string, unknown>
  const allowed = ['version', 'projection', 'installerDeviceId', 'installedAt', 'signature']
  for (const key of Object.keys(input)) {
    if (!allowed.includes(key)) throw new TypeError(`RosterInstallV1 has unknown field ${key}`)
  }
  if (input.version !== 1) throw new TypeError('RosterInstallV1.version must be 1')
  if (typeof input.installerDeviceId !== 'string' || input.installerDeviceId.length === 0) {
    throw new TypeError('RosterInstallV1.installerDeviceId must be a non-empty string')
  }
  if (typeof input.installedAt !== 'string' || Number.isNaN(Date.parse(input.installedAt))) {
    throw new TypeError('RosterInstallV1.installedAt must be an ISO date string')
  }
  if (!(input.signature instanceof Uint8Array) || input.signature.length === 0) {
    throw new TypeError('RosterInstallV1.signature must be a non-empty Uint8Array')
  }
  assertAcceptedSelfGroupProjection(input.projection as AcceptedSelfGroupProjectionV1)
}

/** Strict JSON boundary for the narrow roster-install HTTP endpoint. */
export function encodeRosterInstallWire(value: RosterInstallV1): string {
  assertRosterInstall(value)
  return JSON.stringify({
    ...value,
    projection: {
      ...value.projection,
      devices: value.projection.devices.map(device => ({
        ...device,
        signingPublicKey: bytesToBase64url(device.signingPublicKey),
        deviceCredential: bytesToBase64url(device.deviceCredential),
      })),
    },
    signature: bytesToBase64url(value.signature),
  })
}

export function decodeRosterInstallWire(text: string): RosterInstallV1 {
  let parsed: unknown
  try { parsed = JSON.parse(text) } catch { throw new TypeError('roster install HTTP body is not JSON') }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) throw new TypeError('roster install HTTP body must be an object')
  const input = parsed as Record<string, unknown>
  const projectionInput = input.projection as Record<string, unknown> | undefined
  const devicesInput = projectionInput?.devices
  const projection = projectionInput && Array.isArray(devicesInput) ? {
    ...projectionInput,
    devices: devicesInput.map(device => {
      if (device === null || typeof device !== 'object' || Array.isArray(device)) return device
      const entry = device as Record<string, unknown>
      return {
        ...entry,
        signingPublicKey: typeof entry.signingPublicKey === 'string' ? base64urlToBytes(entry.signingPublicKey) : entry.signingPublicKey,
        deviceCredential: typeof entry.deviceCredential === 'string' ? base64urlToBytes(entry.deviceCredential) : entry.deviceCredential,
      }
    }),
  } : input.projection
  const value = { ...input, projection, signature: typeof input.signature === 'string' ? base64urlToBytes(input.signature) : input.signature }
  assertRosterInstall(value)
  return value
}
