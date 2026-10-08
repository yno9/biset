// The identity's address book, as JMAP for Contacts (RFC 9610) serves it:
// AddressBook and ContactCard, a ContactCard being a JSContact Card (RFC
// 9553) plus `id` and `addressBookIds` (PLAN-refactor.md §12).
//
// Kept in the Vault as `contact.set` events, each a PatchObject (RFC 8620
// §5.3) on one card. The reducer applies them in the projection's
// deterministic event order, so every device folds the same cards and the
// outcome is "last writer wins" per patched path: two devices changing
// different properties at once both keep theirs.
//
// - A card's `id` is derived from its `uid`, so there is never more than one
//   card with the same `uid` (RFC 9610) and two devices creating the same
//   card at once create one card. A card created for a public DID takes a
//   name-based `uid` from that DID (`didContactUid`), the same on every device.
// - A patch that names `@type`, `version` and `uid` (a "creating" patch) makes
//   the card when it does not exist; any other patch to a missing card --
//   after a destroy, say -- is ignored.
// - The vendor property `biset.md:didcomm` (DIDComm routing state: where a
//   counterparty rotated to, and which of this identity's own rotations are
//   confirmed) is written only by DIDComm ingress. A JMAP client may not
//   touch it (ContactCard/set refuses the patch), and an imported file's copy
//   is dropped: anyone could have edited the file to claim "this did:peer is
//   Bob".
import { sha256 } from '@noble/hashes/sha2.js'
import { sha1 } from '@noble/hashes/legacy.js'
import { bytesToBase64url, type CanonicalValue } from '../../../protocol/canonical.ts'
import type { VaultMutationIntent } from './mutations.ts'

export const JMAP_CONTACTS_CAPABILITY = 'urn:ietf:params:jmap:contacts'
/** JSContact vendor property holding DIDComm routing state (§12.2). */
export const DIDCOMM_CONTACT_PROPERTY = 'biset.md:didcomm'
/** The one address book (§12.2: more than one is for later). */
const DEFAULT_ADDRESS_BOOK_ID = 'default'

export interface LocalJmapAddressBook {
  id: string
  name: string
  description: string | null
  sortOrder: number
  isDefault: boolean
  isSubscribed: boolean
  shareWith: null
  myRights: { mayRead: boolean; mayWrite: boolean; mayShare: boolean; mayDelete: boolean }
}

export const DEFAULT_ADDRESS_BOOK: LocalJmapAddressBook = {
  id: DEFAULT_ADDRESS_BOOK_ID, name: 'Contacts', description: null, sortOrder: 0, isDefault: true, isSubscribed: true, shareWith: null,
  myRights: { mayRead: true, mayWrite: true, mayShare: false, mayDelete: false },
}

/** A JSContact Card with RFC 9610's `id` and `addressBookIds`. Every other
 * property, known or not, is kept as it was written (RFC 9553 requires
 * implementations to preserve properties they do not know). */
export type LocalJmapContactCard = { [key: string]: CanonicalValue } & {
  id: string
  '@type': 'Card'
  version: string
  uid: string
  addressBookIds: Record<string, true>
}

/** DIDComm routing state for one contact (§12.2). Every entry is written
 * leaf by leaf, by ingress only. */
export interface DidCommContactState {
  /** Where the counterparty rotated to, keyed by its new DID: the DID it
   * rotated from and the verified `from_prior`'s `iat`. */
  rotations?: Record<string, { prior: string; iat: number }>
  /** This identity's own rotation DIDs for this counterparty: when the
   * rotation started, and when the counterparty first wrote to it (from then
   * on `from_prior` is no longer sent, DIDComm v2.1). */
  own?: Record<string, { startedAt?: string; confirmedAt?: string }>
}

// ---- ids ----

/** The card id for `uid`. */
export function contactCardId(uid: string): string {
  if (!uid) throw new TypeError('contact uid is required')
  return 'c' + bytesToBase64url(sha256(new TextEncoder().encode(`biset/contact-card-id/v1\n${uid}`))).slice(0, 22)
}

/** The Vault event target for a card (kept apart from email ids). */
export function contactTargetId(cardId: string): string { return `contact:${cardId}` }

/** The card id of a `contact.set` event's target, or undefined for any other target. */
export function contactCardIdOfTarget(targetId: string): string | undefined {
  return targetId.startsWith('contact:') ? targetId.slice('contact:'.length) : undefined
}

const URL_NAMESPACE = '6ba7b8119dad11d180b400c04fd430c8' // RFC 9562's NameSpace_URL

/** `urn:uuid:` name-based (version 5, RFC 9562) on a DID: the uid of the card
 * made for a public DID, identical on every device. */
export function didContactUid(did: string): string {
  const namespace = Uint8Array.from(URL_NAMESPACE.match(/../g)!.map(byte => parseInt(byte, 16)))
  const name = new TextEncoder().encode(did)
  const hash = sha1(new Uint8Array([...namespace, ...name])).slice(0, 16)
  hash[6] = (hash[6]! & 0x0f) | 0x50
  hash[8] = (hash[8]! & 0x3f) | 0x80
  const hex = [...hash].map(byte => byte.toString(16).padStart(2, '0')).join('')
  return `urn:uuid:${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
}

// ---- validation ----

const ID_PATTERN = /^[A-Za-z0-9_-]{1,255}$/

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function assertIdMap(value: unknown, name: string, entry: (value: unknown, key: string) => void): void {
  if (!isObject(value)) throw new TypeError(`contact card ${name} must be an object`)
  for (const [key, item] of Object.entries(value)) {
    if (!ID_PATTERN.test(key)) throw new TypeError(`contact card ${name} key is not an Id`)
    entry(item, key)
  }
}

function assertDidCommState(value: unknown): void {
  if (!isObject(value)) throw new TypeError(`contact card ${DIDCOMM_CONTACT_PROPERTY} must be an object`)
  for (const key of Object.keys(value)) if (key !== 'rotations' && key !== 'own') throw new TypeError(`contact card ${DIDCOMM_CONTACT_PROPERTY} has an unknown property`)
  if (value.rotations !== undefined) {
    if (!isObject(value.rotations)) throw new TypeError('contact card rotations must be an object')
    for (const [did, rotation] of Object.entries(value.rotations)) {
      if (!did.startsWith('did:') || !isObject(rotation) || typeof rotation.prior !== 'string' || !rotation.prior.startsWith('did:')
        || typeof rotation.iat !== 'number' || !Number.isSafeInteger(rotation.iat) || Object.keys(rotation).length !== 2) {
        throw new TypeError('contact card rotation is invalid')
      }
    }
  }
  if (value.own !== undefined) {
    if (!isObject(value.own)) throw new TypeError('contact card own rotations must be an object')
    for (const [did, own] of Object.entries(value.own)) {
      const times = isObject(own) ? Object.entries(own) : []
      if (!did.startsWith('did:') || times.length === 0 || times.some(([key, time]) => (key !== 'startedAt' && key !== 'confirmedAt') || typeof time !== 'string' || Number.isNaN(Date.parse(time)))) {
        throw new TypeError('contact card own rotation is invalid')
      }
    }
  }
}

/** Checks a whole card: RFC 9553's required properties, RFC 9610's
 * `addressBookIds`, the Id-typed maps biset reads, and the DIDComm state. */
export function assertContactCard(value: unknown): LocalJmapContactCard {
  if (!isObject(value)) throw new TypeError('contact card must be an object')
  if (value['@type'] !== 'Card' || value.version !== '1.0') throw new TypeError('contact card must be a JSContact 1.0 Card')
  if (typeof value.uid !== 'string' || !value.uid) throw new TypeError('contact card uid is required')
  if (value.id !== contactCardId(value.uid)) throw new TypeError('contact card id does not match its uid')
  assertIdMap(value.addressBookIds, 'addressBookIds', flag => { if (flag !== true) throw new TypeError('contact card addressBookIds values must be true') })
  if (Object.keys(value.addressBookIds as object).length === 0) throw new TypeError('contact card must belong to an address book')
  if (value.name !== undefined && !isObject(value.name)) throw new TypeError('contact card name must be an object')
  if (value.emails !== undefined) assertIdMap(value.emails, 'emails', email => { if (!isObject(email) || typeof email.address !== 'string' || !email.address) throw new TypeError('contact card email needs an address') })
  if (value.onlineServices !== undefined) assertIdMap(value.onlineServices, 'onlineServices', service => {
    if (!isObject(service) || (typeof service.uri !== 'string' && typeof service.user !== 'string')) throw new TypeError('contact card online service needs a uri or user')
  })
  if (value[DIDCOMM_CONTACT_PROPERTY] !== undefined) assertDidCommState(value[DIDCOMM_CONTACT_PROPERTY])
  return value as LocalJmapContactCard
}

// ---- patches ----

/** RFC 8620 §5.3 PatchObject: JSON pointer (without the leading `/`) to
 * value, `null` removing the property. */
export type ContactPatch = Record<string, CanonicalValue>

/** The payload of one `contact.set` event. */
export type ContactSetPayload = { cardId: string; patch: ContactPatch } | { cardId: string; destroy: true }

const CREATING = ['@type', 'version', 'uid'] as const

function pointer(path: string): string[] {
  if (!path) throw new TypeError('contact patch path is empty')
  return path.split('/').map(token => {
    if (!token || /~[^01]|~$/.test(token)) throw new TypeError('contact patch path is invalid')
    return token.replace(/~1/g, '/').replace(/~0/g, '~')
  })
}

/** Escapes one property name as a JSON pointer token. */
export function pointerToken(name: string): string { return name.replace(/~/g, '~0').replace(/\//g, '~1') }

function assertPatchShape(patch: unknown): ContactPatch {
  if (!isObject(patch) || Object.keys(patch).length === 0) throw new TypeError('contact patch must be a non-empty object')
  const paths = Object.keys(patch)
  for (const path of paths) {
    pointer(path)
    // RFC 8620: no patch may set a path and something inside it.
    if (paths.some(other => other !== path && other.startsWith(`${path}/`))) throw new TypeError('contact patch sets a path and a path inside it')
  }
  return patch as ContactPatch
}

function clone<T>(value: T): T { return JSON.parse(JSON.stringify(value)) as T }

/** One `contact.set` applied to `card` (undefined: no such card yet). Missing
 * parents of a patched path are created: the log's patches are written
 * leaf by leaf (a creating patch never sets the DIDComm state as a whole),
 * so a later patch never wipes what another device wrote beside it. */
export function applyContactSet(card: LocalJmapContactCard | undefined, payload: ContactSetPayload): LocalJmapContactCard | undefined {
  if ('destroy' in payload) return undefined
  const creating = CREATING.every(key => key in payload.patch)
  if (!card && !creating) return undefined
  const next: Record<string, CanonicalValue> = card ? clone(card) : { id: payload.cardId, addressBookIds: { [DEFAULT_ADDRESS_BOOK_ID]: true } }
  for (const [path, value] of Object.entries(payload.patch)) {
    const tokens = pointer(path)
    let target = next
    for (const token of tokens.slice(0, -1)) {
      if (!isObject(target[token])) target[token] = {}
      target = target[token] as Record<string, CanonicalValue>
    }
    const last = tokens[tokens.length - 1]!
    if (value === null) delete target[last]
    else target[last] = clone(value)
  }
  return assertContactCard(next)
}

/** Checks a `contact.set` payload against its event's target. */
export function assertContactSetPayload(payload: unknown, targetId: string): ContactSetPayload {
  if (!isObject(payload) || typeof payload.cardId !== 'string' || contactTargetId(payload.cardId) !== targetId) throw new TypeError('contact.set payload does not match its target')
  if (payload.destroy === true && Object.keys(payload).length === 2) return { cardId: payload.cardId, destroy: true }
  if (Object.keys(payload).length !== 2) throw new TypeError('contact.set payload is invalid')
  const patch = assertPatchShape(payload.patch)
  for (const path of Object.keys(patch)) {
    const head = pointer(path)[0]
    // A card's id is its uid's (contactCardId): neither can change.
    if (head === 'id' || (head === 'uid' && (path !== 'uid' || typeof patch.uid !== 'string' || contactCardId(patch.uid) !== payload.cardId))) {
      throw new TypeError('contact.set may not change a card id or uid')
    }
  }
  return { cardId: payload.cardId, patch }
}

/** The intent for one patch on a card. */
export function contactSetIntent(payload: ContactSetPayload): VaultMutationIntent {
  return { kind: 'contact.set', targetIds: [contactTargetId(payload.cardId)], payload: payload as unknown as CanonicalValue }
}

/** A whole card as a creating patch, leaf by leaf: every top-level property,
 * and the DIDComm state's entries one by one (so creating the same card
 * twice never drops a rotation another device recorded in between). */
export function creatingPatch(card: Omit<LocalJmapContactCard, 'id' | 'addressBookIds'> & { addressBookIds?: Record<string, true> }): ContactPatch {
  const patch: ContactPatch = {}
  for (const [key, value] of Object.entries(card)) {
    if (key === 'id' || value === undefined) continue
    if (key === DIDCOMM_CONTACT_PROPERTY && isObject(value)) {
      for (const [section, entries] of Object.entries(value)) {
        for (const [entry, item] of Object.entries(entries as Record<string, CanonicalValue>)) patch[`${pointerToken(key)}/${section}/${pointerToken(entry)}`] = item
      }
      continue
    }
    if (key === 'addressBookIds') {
      for (const book of Object.keys(value as object)) patch[`addressBookIds/${book}`] = true
      continue
    }
    patch[pointerToken(key)] = value as CanonicalValue
  }
  return patch
}

// ---- DIDComm routing state (C3) ----

/** The DIDComm state of a card, as written. */
export function didCommStateOf(card: LocalJmapContactCard): DidCommContactState {
  return (card[DIDCOMM_CONTACT_PROPERTY] ?? {}) as DidCommContactState
}

/** The card of a public DID: the one made for it (`didContactUid`), else any
 * card listing it among its online services. */
export function contactCardForDid(cards: readonly LocalJmapContactCard[], did: string): LocalJmapContactCard | undefined {
  const own = contactCardId(didContactUid(did))
  return cards.find(card => card.id === own) ?? cards.find(card => isObject(card.onlineServices)
    && Object.values(card.onlineServices).some(service => isObject(service) && service.uri === did))
}

/** The counterparty's current DID: the latest rotation (by `iat`, then DID
 * for a tie), or undefined when it has not rotated. */
export function currentRotation(card: LocalJmapContactCard): { did: string; prior: string; iat: number } | undefined {
  const rotations = Object.entries(didCommStateOf(card).rotations ?? {})
  rotations.sort(([a, x], [b, y]) => x.iat - y.iat || a.localeCompare(b))
  const latest = rotations.at(-1)
  return latest ? { did: latest[0], ...latest[1] } : undefined
}

/** The public DID behind a counterparty's rotated DID, and whether that DID
 * is still its current one; undefined when no card names it. */
export function counterpartyOfRotatedDid(cards: readonly LocalJmapContactCard[], did: string): { publicDid: string; card: LocalJmapContactCard; current: boolean } | undefined {
  for (const card of cards) {
    const rotation = didCommStateOf(card).rotations?.[did]
    if (!rotation) continue
    const publicDid = publicDidOf(card) ?? rotation.prior
    return { publicDid, card, current: currentRotation(card)?.did === did }
  }
  return undefined
}

/** The public DID a card was made for (its DIDComm online service). */
export function publicDidOf(card: LocalJmapContactCard): string | undefined {
  const service = isObject(card.onlineServices) ? card.onlineServices.didcomm : undefined
  return isObject(service) && typeof service.uri === 'string' ? service.uri : undefined
}

const state = (path: string) => `${pointerToken(DIDCOMM_CONTACT_PROPERTY)}/${path}`

/** The patch making sure `did` has a card: written leaf by leaf, so writing
 * it again (another device, a later message) never undoes anything. */
export function didContactPatch(did: string): ContactSetPayload {
  const uid = didContactUid(did)
  return { cardId: contactCardId(uid), patch: { '@type': 'Card', version: '1.0', uid, [`addressBookIds/${DEFAULT_ADDRESS_BOOK_ID}`]: true, 'onlineServices/didcomm': { service: 'DIDComm', uri: did } } }
}

/** Records that the counterparty of `cardId` rotated to `did`. */
export function rotationPatch(cardId: string, rotation: { did: string; prior: string; iat: number }): ContactSetPayload {
  return { cardId, patch: { [state(`rotations/${pointerToken(rotation.did)}`)]: { prior: rotation.prior, iat: rotation.iat } } }
}

/** Records this identity's own rotation `ownDid` for the counterparty of
 * `cardId`: started, or confirmed (the counterparty wrote to it). */
export function ownRotationPatch(cardId: string, ownDid: string, field: 'startedAt' | 'confirmedAt', at: string): ContactSetPayload {
  return { cardId, patch: { [state(`own/${pointerToken(ownDid)}/${field}`)]: at } }
}

// ---- ContactCard/set (RFC 9610 §3.4, RFC 8620 §5.3) ----

interface ContactCardSetResult {
  intents: VaultMutationIntent[]
  created: Record<string, { id: string; uid: string; addressBookIds: Record<string, true> }>
  updated: Record<string, null>
  destroyed: string[]
  notCreated: Record<string, { type: string; description: string }>
  notUpdated: Record<string, { type: string; description: string }>
  notDestroyed: Record<string, { type: string; description: string }>
}

const SERVER_SET = new Set(['id'])

function touchesDidComm(path: string): boolean { return pointer(path)[0] === DIDCOMM_CONTACT_PROPERTY }

/** Parses a ContactCard/set request against `cards` into the patches to
 * commit, and the per-item results a JMAP response reports. */
export function contactCardSet(arguments_: Record<string, unknown>, cards: readonly LocalJmapContactCard[], newUid: () => string = () => `urn:uuid:${crypto.randomUUID()}`): ContactCardSetResult {
  for (const key of Object.keys(arguments_)) if (!['accountId', 'ifInState', 'create', 'update', 'destroy'].includes(key)) throw new TypeError(`unsupported ContactCard/set argument: ${key}`)
  const byId = new Map(cards.map(card => [card.id, card]))
  const result: ContactCardSetResult = { intents: [], created: {}, updated: {}, destroyed: [], notCreated: {}, notUpdated: {}, notDestroyed: {} }
  const invalid = (description: string) => ({ type: 'invalidProperties', description })

  if (arguments_.create !== undefined) {
    if (!isObject(arguments_.create)) throw new TypeError('ContactCard/set create must be an object')
    for (const [creationId, value] of Object.entries(arguments_.create)) {
      try {
        if (!isObject(value)) throw new TypeError('a card must be an object')
        if (DIDCOMM_CONTACT_PROPERTY in value) { result.notCreated[creationId] = { type: 'forbidden', description: `${DIDCOMM_CONTACT_PROPERTY} is managed by biset` }; continue }
        if ([...SERVER_SET].some(key => key in value)) throw new TypeError('id is set by the server')
        const uid = typeof value.uid === 'string' && value.uid ? value.uid : newUid()
        const id = contactCardId(uid)
        if (byId.has(id)) { result.notCreated[creationId] = { type: 'alreadyExists', description: 'a card with this uid exists' }; continue }
        const addressBookIds = (value.addressBookIds ?? { [DEFAULT_ADDRESS_BOOK_ID]: true }) as Record<string, true>
        if (!isObject(addressBookIds) || Object.keys(addressBookIds).some(book => book !== DEFAULT_ADDRESS_BOOK_ID)) throw new TypeError('unknown address book')
        const card = assertContactCard({ ...value, '@type': value['@type'] ?? 'Card', version: value.version ?? '1.0', uid, id, addressBookIds })
        result.intents.push(contactSetIntent({ cardId: id, patch: creatingPatch(card) }))
        byId.set(id, card)
        result.created[creationId] = { id, uid, addressBookIds }
      } catch (error) { result.notCreated[creationId] = invalid(error instanceof Error ? error.message : String(error)) }
    }
  }
  if (arguments_.update !== undefined) {
    if (!isObject(arguments_.update)) throw new TypeError('ContactCard/set update must be an object')
    for (const [id, value] of Object.entries(arguments_.update)) {
      const card = byId.get(id)
      if (!card) { result.notUpdated[id] = { type: 'notFound', description: 'no such card' }; continue }
      try {
        const patch = assertPatchShape(value)
        if (Object.keys(patch).some(touchesDidComm)) { result.notUpdated[id] = { type: 'forbidden', description: `${DIDCOMM_CONTACT_PROPERTY} is managed by biset` }; continue }
        for (const path of Object.keys(patch)) {
          const tokens = pointer(path)
          if (tokens[0] === 'id' || tokens[0] === 'uid' || tokens[0] === '@type') throw new TypeError(`${tokens[0]} is immutable`)
          // RFC 8620: every parent of a patched path must already exist.
          let target: unknown = card
          for (const token of tokens.slice(0, -1)) {
            target = isObject(target) ? target[token] : undefined
            if (!isObject(target)) throw new TypeError(`${path}: its parent does not exist`)
          }
        }
        const next = applyContactSet(card, { cardId: id, patch })!
        result.intents.push(contactSetIntent({ cardId: id, patch }))
        byId.set(id, next)
        result.updated[id] = null
      } catch (error) { result.notUpdated[id] = { type: 'invalidPatch', description: error instanceof Error ? error.message : String(error) } }
    }
  }
  if (arguments_.destroy !== undefined) {
    if (!Array.isArray(arguments_.destroy)) throw new TypeError('ContactCard/set destroy must be an array')
    for (const id of arguments_.destroy) {
      if (typeof id !== 'string' || !byId.has(id)) { result.notDestroyed[String(id)] = { type: 'notFound', description: 'no such card' }; continue }
      result.intents.push(contactSetIntent({ cardId: id, destroy: true }))
      byId.delete(id)
      result.destroyed.push(id)
    }
  }
  return result
}

// ---- reads ----

export function contactCardGet(accountId: string, state: string, cards: readonly LocalJmapContactCard[], arguments_: Record<string, unknown>): Record<string, unknown> {
  const ids = arguments_.ids
  if (ids !== undefined && ids !== null && (!Array.isArray(ids) || ids.some(id => typeof id !== 'string'))) throw new TypeError('JMAP ids must be an array of strings')
  const byId = new Map(cards.map(card => [card.id, card]))
  const wanted = (ids as string[] | null | undefined) ?? cards.map(card => card.id)
  const properties = arguments_.properties
  const pick = (card: LocalJmapContactCard) => Array.isArray(properties)
    ? Object.fromEntries(Object.entries(card).filter(([key]) => key === 'id' || properties.includes(key)))
    : clone(card)
  return { accountId, state, list: wanted.flatMap(id => byId.has(id) ? [pick(byId.get(id)!)] : []), notFound: wanted.filter(id => !byId.has(id)) }
}

export function contactCardQuery(accountId: string, state: string, cards: readonly LocalJmapContactCard[], arguments_: Record<string, unknown>): Record<string, unknown> {
  const filter = isObject(arguments_.filter) ? arguments_.filter : {}
  const position = arguments_.position === undefined ? 0 : arguments_.position
  const limit = arguments_.limit === undefined ? 256 : arguments_.limit
  if (!Number.isSafeInteger(position) || (position as number) < 0 || !Number.isSafeInteger(limit) || (limit as number) < 0) throw new TypeError('JMAP position and limit must be non-negative integers')
  const ids = cards
    .filter(card => typeof filter.inAddressBook !== 'string' || card.addressBookIds[filter.inAddressBook] === true)
    .filter(card => typeof filter.uid !== 'string' || card.uid === filter.uid)
    .map(card => card.id)
    .sort()
  return { accountId, queryState: state, canCalculateChanges: false, position, ids: ids.slice(position as number, (position as number) + (limit as number)), total: ids.length }
}

export function addressBookGet(accountId: string, state: string, arguments_: Record<string, unknown>): Record<string, unknown> {
  const ids = arguments_.ids
  const wanted = Array.isArray(ids) ? ids as string[] : [DEFAULT_ADDRESS_BOOK_ID]
  return {
    accountId, state,
    list: wanted.includes(DEFAULT_ADDRESS_BOOK_ID) ? [clone(DEFAULT_ADDRESS_BOOK)] : [],
    notFound: wanted.filter(id => id !== DEFAULT_ADDRESS_BOOK_ID),
  }
}

export function copyContactCard(card: LocalJmapContactCard): LocalJmapContactCard { return clone(card) }
