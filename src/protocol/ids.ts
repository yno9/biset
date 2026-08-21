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

const DELIVERY_SEQ = /^(0|[1-9][0-9]{0,19})$/
const MAX_U64 = 18_446_744_073_709_551_615n

export function assertDeliverySeq(value: unknown): asserts value is DeliverySeq {
  if (typeof value !== 'string' || !DELIVERY_SEQ.test(value) || BigInt(value) > MAX_U64) {
    throw new TypeError('delivery sequence must be an unsigned 64-bit decimal string')
  }
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
