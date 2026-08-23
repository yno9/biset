import { assertDeliverySeq, assertMlsEpoch, type DeliverySeq, type DeviceId, type IdentityId, type MlsEpoch } from '../../protocol/ids.ts'

export interface TrustedDeviceV1 {
  deviceId: DeviceId
  /** First vault-delivery sequence this device may obtain by ordinary pull. */
  deliveryFloor: DeliverySeq
  /** Public only; private signing/transport/MLS keys never enter core. */
  signingKeyId: string
}

/**
 * A projection produced only after an MLS self-group commit has been accepted.
 * The identity module may persist this public metadata; it has no access to
 * the MLS state encoding, exporter secret, or vault content.
 */
export interface AcceptedSelfGroupProjectionV1 {
  version: 1
  identityId: IdentityId
  selfGroupId: string
  epoch: MlsEpoch
  devices: TrustedDeviceV1[]
  acceptedAt: string
}

export interface TrustedDeviceRoster {
  installAcceptedProjection(projection: AcceptedSelfGroupProjectionV1): Promise<'installed' | 'already-current'>
  projection(identityId: IdentityId): Promise<AcceptedSelfGroupProjectionV1 | undefined>
  isTrustedDevice(identityId: IdentityId, deviceId: DeviceId): Promise<boolean>
  deliveryFloor(identityId: IdentityId, deviceId: DeviceId): Promise<DeliverySeq | undefined>
  trustedDevices(identityId: IdentityId): Promise<TrustedDeviceV1[]>
}

/**
 * Reference identity control-plane store. It does not infer membership from
 * DID publication or device activity: only an accepted self-group projection
 * can add or remove a device. In particular TTL never changes this roster.
 */
export class MemoryTrustedDeviceRoster implements TrustedDeviceRoster {
  private readonly projections = new Map<IdentityId, AcceptedSelfGroupProjectionV1>()

  async installAcceptedProjection(projection: AcceptedSelfGroupProjectionV1): Promise<'installed' | 'already-current'> {
    assertAcceptedSelfGroupProjection(projection)
    const existing = this.projections.get(projection.identityId)
    if (existing) {
      if (existing.selfGroupId !== projection.selfGroupId) throw new TypeError('self group ID cannot change for an identity')
      const ordering = compareMlsEpoch(projection.epoch, existing.epoch)
      if (ordering < 0) throw new TypeError('cannot install a stale MLS projection')
      if (ordering === 0) {
        if (!sameAcceptedSelfGroupProjection(existing, projection)) throw new TypeError('same MLS epoch has conflicting device roster')
        return 'already-current'
      }
    }
    this.projections.set(projection.identityId, copyProjection(projection))
    return 'installed'
  }

  async projection(identityId: IdentityId): Promise<AcceptedSelfGroupProjectionV1 | undefined> {
    const value = this.projections.get(identityId)
    return value && copyProjection(value)
  }

  async isTrustedDevice(identityId: IdentityId, deviceId: DeviceId): Promise<boolean> {
    return this.projections.get(identityId)?.devices.some(device => device.deviceId === deviceId) ?? false
  }

  async deliveryFloor(identityId: IdentityId, deviceId: DeviceId): Promise<DeliverySeq | undefined> {
    return this.projections.get(identityId)?.devices.find(device => device.deviceId === deviceId)?.deliveryFloor
  }

  async trustedDevices(identityId: IdentityId): Promise<TrustedDeviceV1[]> {
    return this.projections.get(identityId)?.devices.map(copyDevice) ?? []
  }
}

export function assertAcceptedSelfGroupProjection(value: AcceptedSelfGroupProjectionV1): void {
  if (value.version !== 1 || !value.identityId || !value.selfGroupId) throw new TypeError('self-group projection has empty required fields')
  assertMlsEpoch(value.epoch)
  if (Number.isNaN(Date.parse(value.acceptedAt))) throw new TypeError('projection acceptedAt must be an ISO date string')
  if (value.devices.length === 0) throw new TypeError('self-group projection must contain at least one device')
  const ids = new Set<string>()
  for (const device of value.devices) {
    if (!device.deviceId || !device.signingKeyId) throw new TypeError('trusted device has empty required fields')
    assertDeliverySeq(device.deliveryFloor)
    if (ids.has(device.deviceId)) throw new TypeError('self-group projection has a duplicate device')
    ids.add(device.deviceId)
  }
}

/**
 * Strict JSON boundary for reading a roster projection back over HTTP
 * (`GET /v1/roster/:identityId`, `roster-http.ts`). No signature: a
 * projection names only public device ids and signing key ids (the same
 * information a resolved DID document already exposes), so reading it back
 * needs no authorization beyond knowing the identityId — unlike every
 * write/pull that touches ciphertext or delivery state.
 */
export function encodeAcceptedSelfGroupProjectionWire(value: AcceptedSelfGroupProjectionV1): string {
  assertAcceptedSelfGroupProjection(value)
  return JSON.stringify(value)
}

export function decodeAcceptedSelfGroupProjectionWire(text: string): AcceptedSelfGroupProjectionV1 {
  let parsed: unknown
  try { parsed = JSON.parse(text) } catch { throw new TypeError('roster projection body is not JSON') }
  const value = parsed as AcceptedSelfGroupProjectionV1
  assertAcceptedSelfGroupProjection(value)
  return value
}

export function compareMlsEpoch(left: MlsEpoch, right: MlsEpoch): number {
  const a = BigInt(left)
  const b = BigInt(right)
  return a < b ? -1 : a > b ? 1 : 0
}

export function sameAcceptedSelfGroupProjection(left: AcceptedSelfGroupProjectionV1, right: AcceptedSelfGroupProjectionV1): boolean {
  return left.identityId === right.identityId
    && left.selfGroupId === right.selfGroupId
    && left.epoch === right.epoch
    && left.acceptedAt === right.acceptedAt
    && left.devices.length === right.devices.length
    && left.devices.every((device, index) => {
      const other = right.devices[index]
      return device.deviceId === other.deviceId
        && device.deliveryFloor === other.deliveryFloor
        && device.signingKeyId === other.signingKeyId
    })
}

function copyProjection(value: AcceptedSelfGroupProjectionV1): AcceptedSelfGroupProjectionV1 {
  return { ...value, devices: value.devices.map(copyDevice) }
}

function copyDevice(value: TrustedDeviceV1): TrustedDeviceV1 {
  return { ...value }
}
