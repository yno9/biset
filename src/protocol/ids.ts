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
/** Random 256-bit identifier for a Vault partition. It is never derived from
 * a DID, SCID, domain, mail address, or OIDC subject. */
export type VaultId = `vlt_${string}`
/** Opaque, Vault-local member identifier. */
export type VaultMemberId = string
/** Decimal unsigned-64 representation. Strings keep the wire format JSON-safe. */
export type DeliverySeq = string
/** MLS epoch as a decimal unsigned-64 string. MLS epochs must not pass through JS Number. */
export type MlsEpoch = string

const DELIVERY_SEQ = /^(0|[1-9][0-9]{0,19})$/
const MAX_U64 = 18_446_744_073_709_551_615n

/**
 * The general bound every free-form opaque ID (`IdentityId`/`DeviceId`/
 * `IngressId`/`CheckpointId`, and any other field these types alias) must
 * satisfy, regardless of which system minted it (a DID, a UUID, a
 * device-chosen token). These IDs end up as IndexedDB/SQLite keys and
 * embedded JSON strings, so the bound exists to keep them well-behaved
 * there — it deliberately does NOT attempt to encode DID or UUID grammar
 * itself (that stays with whatever module actually parses one), only to
 * reject the empty string, unbounded length, and whitespace/control
 * characters no legitimate opaque ID should ever contain.
 */
const MAX_OPAQUE_ID_LENGTH = 512
const OPAQUE_ID = /^[\x21-\x7e]+$/

export function assertOpaqueId(value: unknown, name: string, maxLength = MAX_OPAQUE_ID_LENGTH): asserts value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > maxLength || !OPAQUE_ID.test(value)) {
    throw new TypeError(`${name} must be a non-empty printable ASCII string of at most ${maxLength} characters`)
  }
}

/**
 * `VaultEventId`/`VaultObjectId` are never chosen by a caller — `eventId()`
 * (vault/events.ts) and `objectId()` (vault/objects.ts) both derive them via
 * `domainHash`, which always produces this exact shape (`sha256:` + 32
 * base64url-encoded bytes, unpadded). Strict on purpose: unlike the other
 * opaque IDs, nothing legitimate can ever produce a value outside this
 * grammar, so accepting one is itself a sign of a forged or corrupted record.
 */
const HASH_DERIVED_ID = /^sha256:[A-Za-z0-9_-]{43}$/

export function assertVaultEventId(value: unknown): asserts value is VaultEventId {
  if (typeof value !== 'string' || !HASH_DERIVED_ID.test(value)) throw new TypeError('vault event id must be a sha256: domain hash')
}

export function assertVaultObjectId(value: unknown): asserts value is VaultObjectId {
  if (typeof value !== 'string' || !HASH_DERIVED_ID.test(value)) throw new TypeError('vault object id must be a sha256: domain hash')
}

/** `SegmentId` is always minted by `ActiveVaultSegmentManager` via `crypto.randomUUID()` (vault/active-segment.ts). */
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const VAULT_ID = /^vlt_[A-Za-z0-9_-]{43}$/

function assertVaultId(value: unknown): asserts value is VaultId {
  if (typeof value !== 'string' || !VAULT_ID.test(value)) throw new TypeError('vaultId must be vlt_ followed by 256-bit base64url')
}

function assertVaultMemberId(value: unknown): asserts value is VaultMemberId {
  assertOpaqueId(value, 'vault member id', 128)
}

export function assertSegmentId(value: unknown): asserts value is SegmentId {
  if (typeof value !== 'string' || !UUID.test(value)) throw new TypeError('segment id must be a UUID')
}

export function assertDeliverySeq(value: unknown): asserts value is DeliverySeq {
  assertUnsigned64(value, 'delivery sequence')
}

export function deliverySeq(value: bigint): DeliverySeq {
  if (value < 0n || value > MAX_U64) throw new RangeError('delivery sequence is outside uint64 range')
  return value.toString()
}

function compareDeliverySeq(left: DeliverySeq, right: DeliverySeq): number {
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

/**
 * The identity behind a device key id — `did:webvh:x#k1` → `did:webvh:x`.
 * Lives here (not src/client/mimi/identity.ts, which owns the MLS credential shape)
 * so that code with no business touching MLS state — core's DS authorizer,
 * in particular — never has to import src/vendor/mls/ just to parse a DID
 * URL fragment off a string it already has.
 */
export function didOfKid(kid: DeviceId): IdentityId {
  const hash = kid.indexOf('#')
  return hash < 0 ? kid : kid.slice(0, hash)
}
