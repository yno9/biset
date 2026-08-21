/**
 * Protocol identifiers are opaque at module boundaries.  Parsing and
 * canonical encoding will be added before the first wire implementation.
 */
export type IdentityId = string
export type DeviceId = string
export type IngressId = string
export type VaultEventId = string
export type VaultObjectId = string
export type SegmentId = string
export type CheckpointId = string
/** Decimal unsigned-64 representation. Strings keep the wire format JSON-safe. */
export type DeliverySeq = string
/** MLS epoch as a decimal unsigned-64 string. MLS epochs must not pass through JS Number. */
export type MlsEpoch = string

const DELIVERY_SEQ = /^(0|[1-9][0-9]{0,19})$/
const MAX_U64 = 18_446_744_073_709_551_615n

export function assertDeliverySeq(value: unknown): asserts value is DeliverySeq {
  assertUnsigned64(value, 'delivery sequence')
}

export function deliverySeq(value: bigint): DeliverySeq {
  if (value < 0n || value > MAX_U64) throw new RangeError('delivery sequence is outside uint64 range')
  return value.toString()
}

export function compareDeliverySeq(left: DeliverySeq, right: DeliverySeq): number {
  const a = BigInt(left)
  const b = BigInt(right)
  return a < b ? -1 : a > b ? 1 : 0
}

export function assertMlsEpoch(value: unknown): asserts value is MlsEpoch {
  assertUnsigned64(value, 'MLS epoch')
}

export function mlsEpoch(value: bigint): MlsEpoch {
  if (value < 0n || value > MAX_U64) throw new RangeError('MLS epoch is outside uint64 range')
  return value.toString()
}

function assertUnsigned64(value: unknown, name: string): asserts value is string {
  if (typeof value !== 'string' || !DELIVERY_SEQ.test(value) || BigInt(value) > MAX_U64) {
    throw new TypeError(`${name} must be an unsigned 64-bit decimal string`)
  }
}
