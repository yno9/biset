// MimiContent (draft-ietf-mimi-content-09): the plaintext content format
// carried inside an MLS application message (mls-ds-1.0.md's message-submit
// `privateMessage`, once decrypted). CBOR-encoded via `cborg`'s RFC 8949
// deterministic mode -- PLAN-mimi.md's decision to depend on an existing
// pure-JS library rather than hand-roll CBOR (biset already depends on
// non-wasm libraries like openpgp/bittorrent-dht; the constraint that ruled
// out didcomm-node was runtime wasm loading, not dependencies as such).
//
// Scope: only NullPart and SinglePart are implemented -- plain text,
// replies (inReplyTo), edits/deletes/reaction-changes (replaces), and
// reactions (SinglePart with disposition=reaction) all reduce to these two
// variants (PLAN-mimi.md §4). ExternalPart/MultiPart (attachments,
// multi-part bodies) are out of scope; decodeMimiContent throws on them
// rather than silently dropping content it can't represent.
import { decode, encode, rfc8949EncodeOptions } from 'cborg'

/** 32-byte content-addressed message identifier (draft-ietf-mimi-content-09
 * §MessageId). Computing one FROM a message (rather than just carrying an
 * already-computed id) is out of scope here -- PLAN-mimi.md §10 leaves the
 * exact hash construction as unconfirmed pending a second reading of the
 * spec; this module only encodes/decodes the id as an opaque 32-byte value
 * wherever the wire format carries one. */
export type MessageId = Uint8Array

export interface Expiration {
  relative: boolean
  time: number // uint32
}

export interface NullPart {
  kind: 'null'
}

export interface SinglePart {
  kind: 'single'
  contentType: string
  content: Uint8Array
}

export type PartBody = NullPart | SinglePart

export interface NestedPart {
  disposition: number
  language: string
  part: PartBody
}

/** Only the two extension keys the spec itself defines (senderUri=1,
 * roomUri=2, draft-ietf-mimi-content-09 §Extensions Map). Unknown extension
 * entries are dropped on decode rather than preserved round-trip -- nothing
 * in PLAN-mimi.md reads them yet (§4.7 leaves the sender/room URI mapping
 * itself unresolved). */
export interface MimiContentExtensions {
  senderUri?: string
  roomUri?: string
}

export interface MimiContent {
  salt: Uint8Array // 16 bytes, per-message random
  replaces: MessageId | null
  topicId: Uint8Array
  expires: Expiration | null
  inReplyTo: MessageId | null
  extensions: MimiContentExtensions
  nestedPart: NestedPart
}

const CARDINALITY_NULL = 0
const CARDINALITY_SINGLE = 1
const CARDINALITY_EXTERNAL = 2
const CARDINALITY_MULTI = 3

export class MimiContentError extends TypeError {}

export function encodeMimiContent(value: MimiContent): Uint8Array {
  if (value.salt.length !== 16) throw new MimiContentError('MimiContent salt must be 16 bytes')
  if (value.replaces !== null && value.replaces.length !== 32) throw new MimiContentError('MimiContent replaces must be a 32-byte MessageId')
  if (value.inReplyTo !== null && value.inReplyTo.length !== 32) throw new MimiContentError('MimiContent inReplyTo must be a 32-byte MessageId')
  const array = [
    value.salt,
    value.replaces,
    value.topicId,
    value.expires ? [value.expires.relative, value.expires.time] : null,
    value.inReplyTo,
    encodeExtensions(value.extensions),
    encodeNestedPart(value.nestedPart),
  ]
  return encode(array, rfc8949EncodeOptions)
}

export function decodeMimiContent(bytes: Uint8Array): MimiContent {
  let array: unknown
  try {
    array = decode(bytes, { strict: true, allowIndefinite: false, rejectDuplicateMapKeys: true, useMaps: true })
  } catch (err) {
    throw new MimiContentError(`MimiContent is not valid CBOR: ${err instanceof Error ? err.message : String(err)}`)
  }
  if (!Array.isArray(array) || array.length !== 7) throw new MimiContentError('MimiContent must be a 7-element CBOR array')
  const [salt, replaces, topicId, expires, inReplyTo, extensions, nestedPart] = array
  if (!(salt instanceof Uint8Array) || salt.length !== 16) throw new MimiContentError('MimiContent salt must be a 16-byte binary string')
  return {
    salt,
    replaces: decodeMessageId(replaces, 'replaces'),
    topicId: decodeBstr(topicId, 'topicId'),
    expires: decodeExpiration(expires),
    inReplyTo: decodeMessageId(inReplyTo, 'inReplyTo'),
    extensions: decodeExtensions(extensions),
    nestedPart: decodeNestedPart(nestedPart),
  }
}

function decodeMessageId(value: unknown, field: string): MessageId | null {
  if (value === null || value === undefined) return null
  if (!(value instanceof Uint8Array) || value.length !== 32) throw new MimiContentError(`MimiContent ${field} must be null or a 32-byte MessageId`)
  return value
}

function decodeBstr(value: unknown, field: string): Uint8Array {
  if (!(value instanceof Uint8Array)) throw new MimiContentError(`MimiContent ${field} must be a binary string`)
  return value
}

function decodeExpiration(value: unknown): Expiration | null {
  if (value === null || value === undefined) return null
  if (!Array.isArray(value) || value.length !== 2 || typeof value[0] !== 'boolean' || typeof value[1] !== 'number') {
    throw new MimiContentError('MimiContent expires must be null or [relative: bool, time: uint32]')
  }
  return { relative: value[0], time: value[1] }
}

function encodeExtensions(extensions: MimiContentExtensions): Map<number, string> {
  const map = new Map<number, string>()
  if (extensions.senderUri !== undefined) map.set(1, extensions.senderUri)
  if (extensions.roomUri !== undefined) map.set(2, extensions.roomUri)
  return map
}

function decodeExtensions(value: unknown): MimiContentExtensions {
  if (!(value instanceof Map)) throw new MimiContentError('MimiContent mimiExtensions must be a CBOR map')
  const senderUri = value.get(1)
  const roomUri = value.get(2)
  return {
    ...(typeof senderUri === 'string' ? { senderUri } : {}),
    ...(typeof roomUri === 'string' ? { roomUri } : {}),
  }
}

function encodeNestedPart(part: NestedPart): unknown[] {
  const body = part.part
  if (body.kind === 'null') return [part.disposition, part.language, CARDINALITY_NULL]
  return [part.disposition, part.language, CARDINALITY_SINGLE, body.contentType, body.content]
}

function decodeNestedPart(value: unknown): NestedPart {
  if (!Array.isArray(value) || value.length < 3) throw new MimiContentError('NestedPart must be a CBOR array of at least 3 elements')
  const [disposition, language, cardinality, ...rest] = value
  if (typeof disposition !== 'number') throw new MimiContentError('NestedPart disposition must be an integer')
  if (typeof language !== 'string') throw new MimiContentError('NestedPart language must be a string')
  if (typeof cardinality !== 'number') throw new MimiContentError('NestedPart cardinality must be an integer')
  if (cardinality === CARDINALITY_NULL) {
    if (rest.length !== 0) throw new MimiContentError('NestedPart NullPart must have no trailing fields')
    return { disposition, language, part: { kind: 'null' } }
  }
  if (cardinality === CARDINALITY_SINGLE) {
    const [contentType, content] = rest
    if (typeof contentType !== 'string' || !(content instanceof Uint8Array)) {
      throw new MimiContentError('NestedPart SinglePart must be [contentType: string, content: bstr]')
    }
    return { disposition, language, part: { kind: 'single', contentType, content } }
  }
  if (cardinality === CARDINALITY_EXTERNAL || cardinality === CARDINALITY_MULTI) {
    throw new MimiContentError(`NestedPart cardinality ${cardinality} (ExternalPart/MultiPart) is not yet supported`)
  }
  throw new MimiContentError(`NestedPart has unknown cardinality ${cardinality}`)
}

/** Disposition values this module's callers use (draft-ietf-mimi-content-09
 * §Disposition Values) -- not exhaustive, just the ones PLAN-mimi.md's
 * Vault projection (§4) branches on. */
export const DISPOSITION_RENDER = 1
export const DISPOSITION_REACTION = 2
