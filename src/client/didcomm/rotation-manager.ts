// The device side of DID Rotation (did-rotation.ts): which keys this device
// opens messages with, where each message goes, when to ask a counterparty
// whether it can move, and moving. Everything it decides comes from the
// contact cards (the Vault, shared by every device) and the relationship
// seed (the DID document's authority); what it learns it writes back as
// contact patches. Network and storage are injected (main.ts wires them).
import { didOfKid } from '../../protocol/ids.ts'
import { DISCOVER_FEATURES_DISCLOSE } from '../../protocol/didcomm/mediator-protocol.ts'
import { PING } from '../../protocol/didcomm/trust-ping.ts'
import type { DidCommPlaintext } from '../../protocol/didcomm/message.ts'
import type { PeerIdentity } from '../../protocol/didcomm/peer.ts'
import { contactCardForDid, counterpartyOfRotatedDid, didCommStateOf, didContactPatch, ownRotationPatch, publicDidOf, type ContactSetPayload, type LocalJmapContactCard } from '../store/projection/contacts.ts'
import { chooseRoute, disclosesFromPrior, disclosuresFor, fromPriorQuery, isDiscoverFeatures, ownRotationIdentity, startedOwnRotations, type DidCommRoute, type FrontDoorKey } from './did-rotation.ts'
import type { DidCommSendResult } from './front-door-send.ts'

export interface RotationManagerOptions {
  identityDid: string
  frontDoor: FrontDoorKey
  cards(): Promise<readonly LocalJmapContactCard[]>
  /** The usable seed and the mediator Y names, or undefined when this device
   * cannot move conversations now (no seed yet, no mediator published). */
  rotation(): Promise<{ seed: Uint8Array; mediatorDid: string } | undefined>
  /** Commits contact patches to the Vault (and so to every device). */
  commit(writes: ContactSetPayload[]): Promise<void>
  send(toDid: string, type: string, body: unknown, options: { fromKid: string; x25519PrivateKey: Uint8Array; fromPrior?: string; thid?: string }): Promise<DidCommSendResult>
  /** Registers `peer`'s inbox with the mediator and watches it; idempotent. */
  watch(peer: PeerIdentity): Promise<void>
  now?: () => Date
  onError?(error: unknown): void
}

export interface RotationManager {
  route(publicDid: string): Promise<DidCommRoute>
  /** This device's key for a recipient kid: the front door, or a started rotation. */
  ownKey(kid: string): { kid: string; x25519PrivateKey: Uint8Array } | null
  /** Re-reads the cards: watches every started rotation's inbox. */
  sync(): Promise<void>
  /** The counterparty's public DID behind an authenticated sender. */
  counterpartyOf(senderKid: string): Promise<string | undefined>
  /** Asks the counterparty, once per session, whether it can move. */
  offer(publicDid: string): Promise<void>
  /** Moves the conversation with `publicDid` to this identity's Y. */
  start(publicDid: string): Promise<void>
  /** Handles a Discover Features message; false for any other. */
  handleDiscoverFeatures(msg: DidCommPlaintext, senderKid: string, recipientKid: string): Promise<boolean>
}

export function createRotationManager(options: RotationManagerOptions): RotationManager {
  const ownKeys = new Map<string, Uint8Array>()
  const watched = new Set<string>()
  const offered = new Set<string>()
  const starting = new Map<string, Promise<void>>()
  const now = options.now ?? (() => new Date())
  const report = (error: unknown) => options.onError?.(error)

  async function context() {
    const rotation = await options.rotation().catch(() => undefined)
    return { identityDid: options.identityDid, frontDoor: options.frontDoor, cards: await options.cards(), ...(rotation ? { rotation } : {}) }
  }

  const manager: RotationManager = {
    async route(publicDid) { return chooseRoute(publicDid, await context()) },

    ownKey(kid) {
      if (kid === options.frontDoor.fromKid) return { kid, x25519PrivateKey: options.frontDoor.x25519PrivateKey }
      const key = ownKeys.get(kid)
      return key ? { kid, x25519PrivateKey: key } : null
    },

    async sync() {
      const rotation = await options.rotation().catch(() => undefined)
      if (!rotation) return
      for (const { peer } of startedOwnRotations(await options.cards(), publicDidOf, rotation)) {
        ownKeys.set(peer.xKid, peer.xPriv)
        if (watched.has(peer.did)) continue
        watched.add(peer.did)
        await options.watch(peer).catch(error => { watched.delete(peer.did); report(error) })
      }
    },

    async counterpartyOf(senderKid) {
      const did = didOfKid(senderKid)
      if (!did.startsWith('did:peer:')) return did
      return counterpartyOfRotatedDid(await options.cards(), did)?.publicDid
    },

    async offer(publicDid) {
      if (offered.has(publicDid) || publicDid === options.identityDid || publicDid.startsWith('did:peer:')) return
      const current = await context()
      if (!current.rotation) return
      const card = contactCardForDid(current.cards, publicDid)
      const own = ownRotationIdentity(current.rotation.seed, publicDid, current.rotation.mediatorDid)
      if (card && didCommStateOf(card).own?.[own.did]?.startedAt) return
      offered.add(publicDid)
      const route = chooseRoute(publicDid, current)
      const query = fromPriorQuery()
      const sent = await options.send(route.toDid, query.type, query.body, { fromKid: route.fromKid, x25519PrivateKey: route.x25519PrivateKey })
      if (!sent.ok) { offered.delete(publicDid); report(new Error(sent.error)) }
    },

    start(publicDid) {
      const running = starting.get(publicDid)
      if (running) return running
      const attempt = (async () => {
        const current = await context()
        if (!current.rotation) return
        const peer = ownRotationIdentity(current.rotation.seed, publicDid, current.rotation.mediatorDid)
        const card = contactCardForDid(current.cards, publicDid)
        // Already moving: nothing to announce. Until the counterparty writes
        // to Y, every message from Y carries from_prior anyway.
        if (card && didCommStateOf(card).own?.[peer.did]?.startedAt) return
        // The inbox first: Y is announced only once it can be written to.
        await options.watch(peer)
        watched.add(peer.did)
        ownKeys.set(peer.xKid, peer.xPriv)
        const cardId = card?.id ?? didContactPatch(publicDid).cardId
        await options.commit([...(card ? [] : [didContactPatch(publicDid)]), ownRotationPatch(cardId, peer.did, 'startedAt', now().toISOString())])
        // A ping from Y, carrying from_prior: the counterparty learns Y, and
        // its answer to Y confirms the move (ingress-projector.ts).
        const route = await manager.route(publicDid)
        const sent = await options.send(route.toDid, PING, { response_requested: true }, { fromKid: route.fromKid, x25519PrivateKey: route.x25519PrivateKey, ...(route.fromPrior ? { fromPrior: route.fromPrior } : {}) })
        if (!sent.ok) throw new Error(sent.error)
      })().finally(() => starting.delete(publicDid))
      starting.set(publicDid, attempt)
      return attempt
    },

    async handleDiscoverFeatures(msg, senderKid, recipientKid) {
      if (!isDiscoverFeatures(msg)) return false
      const disclosures = disclosuresFor(msg)
      if (disclosures) {
        // Answered from the key it reached, to whoever asked.
        const key = manager.ownKey(recipientKid)
        if (key && typeof msg.from === 'string') {
          const sent = await options.send(msg.from, DISCOVER_FEATURES_DISCLOSE, { disclosures }, { fromKid: key.kid, x25519PrivateKey: key.x25519PrivateKey, thid: msg.id })
          if (!sent.ok) report(new Error(sent.error))
        }
        return true
      }
      if (disclosesFromPrior(msg)) {
        const publicDid = await manager.counterpartyOf(senderKid)
        if (publicDid && !publicDid.startsWith('did:peer:')) await manager.start(publicDid).catch(report)
      }
      return true
    },
  }
  return manager
}
