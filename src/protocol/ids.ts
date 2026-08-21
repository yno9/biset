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
export type DeliverySeq = bigint

