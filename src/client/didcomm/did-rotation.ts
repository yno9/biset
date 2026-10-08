// DID Rotation between biset identities (PLAN-refactor.md §4.3, §7-3, §12.5):
// a conversation starts on the front door (this device's key in the public
// DID document) and, with a counterparty that says it understands the
// `from_prior` header, moves to a did:peer this identity derives for that
// counterparty alone (Y).
//
// - Whether to move is asked with Discover Features 2.0: a `header` query for
//   `from_prior`. biset answers the same query for itself.
// - Y is derived from the relationship seed and the counterparty's public DID
//   (peer.ts), its service naming this identity's mediator by DID. Every
//   device derives the same Y; the contact card records that this identity
//   started the move (`own.<Y>.startedAt`) and when the counterparty first
//   wrote to Y (`confirmedAt`). Until then every message from Y carries
//   `from_prior` (DIDComm v2.1: until a message to the new DID is received).
// - The counterparty's own move is recorded the same way (`rotations`), by
//   ingress, after verifying its `from_prior`; messages go to its newest DID.
//
// What any message to a counterparty is sent from and to is `chooseRoute`,
// the one place that decides it: 1:1, group (one route per participant,
// §8) and protocol replies alike.
import { createFromPrior } from '../../protocol/didcomm/from-prior.ts'
import { deriveRelationshipPeerIdentity, type PeerIdentity } from '../../protocol/didcomm/peer.ts'
import { DISCOVER_FEATURES, DISCOVER_FEATURES_DISCLOSE, DISCOVER_FEATURES_QUERIES } from '../../protocol/didcomm/mediator-protocol.ts'
import { TRUST_PING } from '../../protocol/didcomm/trust-ping.ts'
import type { DidCommPlaintext } from '../../protocol/didcomm/message.ts'
import { contactCardForDid, currentRotation, didCommStateOf, type LocalJmapContactCard } from '../store/projection/contacts.ts'
import { ROTATION_KEY_FRAGMENT, rotationSigningKey } from './rotation-key.ts'

const FROM_PRIOR_HEADER = 'from_prior'

/** What this identity rotates to for `counterpartyDid`. */
export function ownRotationIdentity(seed: Uint8Array, counterpartyDid: string, mediatorDid: string): PeerIdentity {
  return deriveRelationshipPeerIdentity(seed, counterpartyDid, { uri: mediatorDid })
}

export interface FrontDoorKey { fromKid: string; x25519PrivateKey: Uint8Array }

/** What one message to a counterparty goes from and to. */
export interface DidCommRoute {
  /** The counterparty's current DID: its newest rotation, or its public DID. */
  toDid: string
  fromKid: string
  x25519PrivateKey: Uint8Array
  /** Present while this identity's own rotation is unconfirmed. */
  fromPrior?: string
}

export interface RouteContext {
  /** This identity's public DID. */
  identityDid: string
  frontDoor: FrontDoorKey
  cards: readonly LocalJmapContactCard[]
  /** The usable relationship seed and the mediator Y names; without both, a
   * message goes from the front door. */
  rotation?: { seed: Uint8Array; mediatorDid: string }
  now?: () => number
}

/** The route to the counterparty whose public DID is `publicDid`. */
export function chooseRoute(publicDid: string, context: RouteContext): DidCommRoute {
  const card = contactCardForDid(context.cards, publicDid)
  const toDid = (card && currentRotation(card)?.did) ?? publicDid
  if (card && context.rotation) {
    const own = ownRotationIdentity(context.rotation.seed, publicDid, context.rotation.mediatorDid)
    const entry = didCommStateOf(card).own?.[own.did]
    if (entry?.startedAt) {
      const fromPrior = entry.confirmedAt ? undefined : createFromPrior(
        { iss: context.identityDid, sub: own.did, iat: Math.floor((context.now?.() ?? Date.now()) / 1000) },
        `${context.identityDid}${ROTATION_KEY_FRAGMENT}`, rotationSigningKey(context.rotation.seed).privateKey,
      )
      return { toDid, fromKid: own.xKid, x25519PrivateKey: own.xPriv, ...(fromPrior ? { fromPrior } : {}) }
    }
  }
  return { toDid, fromKid: context.frontDoor.fromKid, x25519PrivateKey: context.frontDoor.x25519PrivateKey }
}

/** This identity's own rotations that are started, one per counterparty
 * card, as derived from the current seed: the inboxes to watch, and the keys
 * a message to them is opened with. A rotation under an older seed (the
 * card names a Y this seed does not derive) is not one of them. */
export function startedOwnRotations(cards: readonly LocalJmapContactCard[], publicDidOf: (card: LocalJmapContactCard) => string | undefined, rotation: { seed: Uint8Array; mediatorDid: string }): Array<{ card: LocalJmapContactCard; publicDid: string; peer: PeerIdentity; confirmed: boolean }> {
  return cards.flatMap(card => {
    const own = didCommStateOf(card).own
    const publicDid = publicDidOf(card)
    if (!own || !publicDid) return []
    const peer = ownRotationIdentity(rotation.seed, publicDid, rotation.mediatorDid)
    const entry = own[peer.did]
    return entry?.startedAt ? [{ card, publicDid, peer, confirmed: entry.confirmedAt !== undefined }] : []
  })
}

// ---- Discover Features 2.0 ----

/** What biset discloses about itself. */
const OWN_FEATURES: Array<{ 'feature-type': string; id: string }> = [
  { 'feature-type': 'protocol', id: 'https://didcomm.org/basicmessage/2.0' },
  { 'feature-type': 'protocol', id: TRUST_PING },
  { 'feature-type': 'protocol', id: DISCOVER_FEATURES },
  { 'feature-type': 'header', id: FROM_PRIOR_HEADER },
]

/** The query asking whether the recipient understands `from_prior`. */
export function fromPriorQuery(): { type: string; body: { queries: Array<{ 'feature-type': string; match: string }> } } {
  return { type: DISCOVER_FEATURES_QUERIES, body: { queries: [{ 'feature-type': 'header', match: FROM_PRIOR_HEADER }] } }
}

function matches(pattern: string, id: string): boolean {
  // Discover Features 2.0: `*` is the only wildcard.
  const expression = new RegExp(`^${pattern.split('*').map(part => part.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*')}$`)
  return expression.test(id)
}

/** The disclosures answering a received `queries` message, or null when it is not one. */
export function disclosuresFor(msg: DidCommPlaintext): Array<{ 'feature-type': string; id: string }> | null {
  if (msg.type !== DISCOVER_FEATURES_QUERIES) return null
  const queries = (msg.body as { queries?: unknown } | undefined)?.queries
  if (!Array.isArray(queries)) return []
  return OWN_FEATURES.filter(feature => queries.some(query => query !== null && typeof query === 'object'
    && (query as Record<string, unknown>)['feature-type'] === feature['feature-type']
    && typeof (query as Record<string, unknown>).match === 'string' && matches((query as { match: string }).match, feature.id)))
}

/** True when `msg` is a disclosure that the sender understands `from_prior`. */
export function disclosesFromPrior(msg: DidCommPlaintext): boolean {
  if (msg.type !== DISCOVER_FEATURES_DISCLOSE) return false
  const disclosures = (msg.body as { disclosures?: unknown } | undefined)?.disclosures
  return Array.isArray(disclosures) && disclosures.some(entry => entry !== null && typeof entry === 'object'
    && (entry as Record<string, unknown>)['feature-type'] === 'header' && (entry as Record<string, unknown>).id === FROM_PRIOR_HEADER)
}

export function isDiscoverFeatures(msg: { type?: string }): boolean {
  return msg.type === DISCOVER_FEATURES_QUERIES || msg.type === DISCOVER_FEATURES_DISCLOSE
}
