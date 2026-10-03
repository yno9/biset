import type { DidCommPlaintext } from '../../../protocol/didcomm/message.ts'
import type { DeliveredMessage } from '../../../protocol/didcomm/mediator-pickup.ts'
import { registerWithMediator } from '../../didcomm/mediator-sync.ts'
import { mediatorInbox } from '../../../protocol/didcomm/mediator-device.ts'
import type { RelationshipSeedAuthority } from '../../didcomm/relationship-seed-bootstrap.ts'
import { PermanentDeliveryError } from '../../../protocol/didcomm/mediator-pickup.ts'
import { sameMediatorUrl } from '../../didcomm/mediator-endpoints.ts'
import { deriveRelationshipPeerIdentity } from '../../../protocol/didcomm/peer.ts'
import {
  RELATIONSHIP_ACCEPT,
  RELATIONSHIP_INIT,
  relationshipBodyOf,
  relationshipMediatorService,
} from '../../didcomm/relationship.ts'
import {
  initiateRelationship,
  sendRelationshipAccept,
  type RelationshipInitiationResult,
} from '../../didcomm/send-message.ts'
import { didOfKid } from '../../../protocol/ids.ts'
import type { ContactKeyV1 } from '../../store/vault/contact-key.ts'

export type RelationshipWatchStarter = (xKid: string, xPriv: Uint8Array, did: string, mediatorUrl: string) => void

interface RelationshipContactReader {
  currentFor(counterpartyDid: string): Promise<ContactKeyV1 | null>
}

interface RelationshipContactSink {
  store(contact: ContactKeyV1): Promise<unknown>
}

interface PendingWalletRelationship {
  result: Extract<RelationshipInitiationResult, { ok: true }>
  /** The seed the initiating did:peer was derived from. */
  seedId: string
  promise: Promise<ContactKeyV1>
  resolve: (contact: ContactKeyV1) => void
  /** A caller may stop waiting without abandoning the registered private
   * receiver. An ACCEPT can legitimately arrive after a temporary live
   * connection drop, so keep this pending state until the authenticated ACCEPT
   * consumes it (or a future contact attempt supersedes it). */
  startedAt: number
}

export interface WalletRelationshipManagerOptions {
  identityId: string
  frontDoor: { xKid: string; x25519PrivateKey: Uint8Array }
  /** The Vault's relationship seed, as the DID log allows this device to
   * use it (relationship-seed-bootstrap.ts): without a usable one it can
   * neither start, accept, nor send on a relationship -- the error is
   * retried later (or, once this device was removed, final). */
  relationshipSeed: RelationshipSeedAuthority
  /** Handles everything already queued in this device's inbox for one of
   * its own relationship kids (mediator-live.ts's drain), before a
   * counterparty's move to a new did:peer makes its old kid unacceptable. */
  drainInbox?: (ownRelationshipKid: string) => Promise<void>
  /** Keys this device's mediator inbox labels (mediator-device.ts). */
  mediatorDeviceSecret: Uint8Array
  reader: RelationshipContactReader
  sink: RelationshipContactSink
  startWatch: RelationshipWatchStarter
  /** Every URI naming this device's configured mediator (PLAN-tor.md D-4:
   * clearnet + onion, canonical first) -- feeds `sameMediatorUrl`'s
   * `aliases` so a relationship message that arrived over one entrance
   * still matches a route.url minted against the other (3-6). Empty/unset
   * keeps the exact pre-Tor single-URL comparison (I-5). */
  mediatorAliases?: readonly string[]
  /** Persist newly stored contact keys to the Wallet's MIMI Vault before a Pickup ACK. */
  afterContactStored?: () => Promise<unknown>
  initiate?: (toDid: string, relationshipSeed: Uint8Array, options: { fromKid: string; x25519PrivateKey: Uint8Array; mediatorDeviceSecret: Uint8Array }) => Promise<RelationshipInitiationResult>
  now?: () => Date
  timeoutMs?: number
}

export interface WalletRelationshipManager {
  ensureContact(counterpartyDid: string): Promise<ContactKeyV1>
  handleMessage(message: DeliveredMessage, recipientKid: string, mediatorUrl: string): Promise<void>
}

/**
 * Owns the Wallet side of a first-contact DIDComm relationship. Its only
 * long-lived private material is the generated did:peer key, which becomes
 * a Vault-encrypted ContactKeyV1 once ACCEPT proves the remote peer route.
 */
export function createWalletRelationshipManager(options: WalletRelationshipManagerOptions): WalletRelationshipManager {
  const pendingByCounterparty = new Map<string, PendingWalletRelationship>()
  // Serializes concurrent ensureContact() calls for the SAME counterparty.
  // Without this, two callers racing (e.g. two outbox items to the same
  // recipient, now flushed in parallel -- didcomm-outbox.ts's own
  // 2026-09-15 fix) both see no stored contact and no pending reservation
  // between their `currentFor` await and their `pendingByCounterparty.get`
  // check, so both call initiate() and each stores an independent
  // ContactKeyV1 that supersedes nothing -- readAll()'s selectUnsuperseded
  // then throws "current contact key is ambiguous" forever afterward.
  const ensuring = new Map<string, Promise<ContactKeyV1>>()
  const initiate = options.initiate ?? ((toDid, relationshipSeed, input) => initiateRelationship(toDid, relationshipSeed, input))
  const now = options.now ?? (() => new Date())
  const timeoutMs = options.timeoutMs ?? 60_000
  const afterContactStored = options.afterContactStored ?? (async () => {})

  /** The relationship to send on. One derived from an older seed has not
   * moved since a device removal: it is moved first (a front-door INIT,
   * which only a device still in the DID document can send), and nothing is
   * sent on it until the counterparty's ACCEPT confirms the move -- the
   * counterparty will not accept the old did:peer once it has seen it. */
  async function ensureContactOnce(counterpartyDid: string): Promise<ContactKeyV1> {
    const usable = await options.relationshipSeed.require()
    const stored = await options.reader.currentFor(counterpartyDid)
    if (stored && stored.seedId === usable.seedId) return stored

    let pending = pendingByCounterparty.get(counterpartyDid)
    if (pending && pending.seedId !== usable.seedId) pending = undefined
    // An INIT unanswered for longer than a send waits was lost or answered
    // in a way this side had to drop (say, by a counterparty still running
    // an older version): send it again. The did:peer derives the same, so a
    // repeat is harmless; the waiters of the first attempt keep waiting.
    if (pending && Date.now() - pending.startedAt > timeoutMs) {
      const again = await initiate(counterpartyDid, usable.seed, {
        fromKid: options.frontDoor.xKid,
        x25519PrivateKey: options.frontDoor.x25519PrivateKey,
        mediatorDeviceSecret: options.mediatorDeviceSecret,
      })
      if (!again.ok) throw new Error(again.error)
      pending.result = again
      pending.startedAt = Date.now()
      options.startWatch(again.pending.peer.xKid, again.pending.peer.xPriv, again.pending.peer.did, again.pending.mediatorUrl)
    }
    if (!pending) {
      const initiated = await initiate(counterpartyDid, usable.seed, {
        fromKid: options.frontDoor.xKid,
        x25519PrivateKey: options.frontDoor.x25519PrivateKey,
        mediatorDeviceSecret: options.mediatorDeviceSecret,
      })
      if (!initiated.ok) throw new Error(initiated.error)
      let resolve!: (contact: ContactKeyV1) => void
      const promise = new Promise<ContactKeyV1>(done => { resolve = done })
      pending = { result: initiated, seedId: usable.seedId, promise, resolve, startedAt: Date.now() }
      pendingByCounterparty.set(counterpartyDid, pending)
      options.startWatch(
        initiated.pending.peer.xKid,
        initiated.pending.peer.xPriv,
        initiated.pending.peer.did,
        initiated.pending.mediatorUrl,
      )
    }

    let timer: ReturnType<typeof setTimeout> | undefined
    const timeout = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => reject(new Error(`relationship handshake with ${counterpartyDid} timed out`)), timeoutMs)
    })
    // The timeout is only this caller's UI/network wait budget. Removing
    // the maps here used to discard the only private key capable of
    // opening an ACCEPT that arrived late, producing "relationship accept
    // has no pending initiation" and leaving that queued ACCEPT wedged at
    // the mediator forever. handleMessage() clears these maps once the
    // authenticated ACCEPT is durably stored.
    return Promise.race([pending.promise, timeout]).finally(() => {
      if (timer !== undefined) clearTimeout(timer)
    })
  }

  return {
    async ensureContact(counterpartyDid): Promise<ContactKeyV1> {
      const inflight = ensuring.get(counterpartyDid)
      if (inflight) return inflight
      const promise = ensureContactOnce(counterpartyDid).finally(() => {
        if (ensuring.get(counterpartyDid) === promise) ensuring.delete(counterpartyDid)
      })
      ensuring.set(counterpartyDid, promise)
      return promise
    },

    async handleMessage(message, _recipientKid, mediatorUrl): Promise<void> {
      const plaintext = message.plaintext as DidCommPlaintext
      if (plaintext.type === RELATIONSHIP_INIT) {
        await handleRelationshipInit(message, mediatorUrl, options.identityId, options.relationshipSeed, options.mediatorDeviceSecret, options.frontDoor, options.reader, options.sink, options.startWatch, afterContactStored, options.mediatorAliases ?? [], options.drainInbox)
        return
      }
      if (plaintext.type !== RELATIONSHIP_ACCEPT) return

      // Over the front door, like the INIT: from a key in the
      // counterparty's DID document, so only one of its current devices --
      // not whoever learned the INIT's did:peer -- can answer it.
      const body = relationshipBodyOf(plaintext)
      if (!body) throw new PermanentDeliveryError('relationship message body is invalid')
      if (message.senderKid.startsWith('did:peer:2.')) throw new PermanentDeliveryError('relationship accept must be authenticated by a public front-door kid')
      try { relationshipMediatorService(body.relationshipKid) } catch { throw new PermanentDeliveryError('relationship accept names an invalid did:peer') }
      const counterpartyDid = didOfKid(message.senderKid)

      const pending = pendingByCounterparty.get(counterpartyDid)
      if (!pending) {
        const existing = await options.reader.currentFor(counterpartyDid)
        if (existing?.counterpartyRelationshipKid === body.relationshipKid) return
        // Its initiation was lost (a reload before the ACCEPT): the next
        // send initiates again and gets a fresh ACCEPT.
        throw new PermanentDeliveryError('relationship accept has no pending initiation')
      }
      // Both members of a newly-created group receive the same roster and
      // may initiate to each other at the same time. In that crossing-INIT
      // case, handling the remote INIT has already stored the exact contact
      // this ACCEPT confirms. Writing it again creates two unsuperseded
      // ContactKey records with the same kid; the next group send then fails
      // closed as an ambiguous/duplicate credential. Reuse the authenticated
      // record and only resolve the pending waiter.
      const existing = await options.reader.currentFor(pending.result.pending.counterpartyDid)
      if (
        existing?.ownRelationshipKid === pending.result.pending.peer.xKid &&
        existing.counterpartyRelationshipKid === body.relationshipKid
      ) {
        pendingByCounterparty.delete(pending.result.pending.counterpartyDid)
        pending.resolve(existing)
        return
      }
      // A move: the counterparty answered from a did:peer it had not used
      // with us before, so its old kid stops being accepted -- take what
      // it already sent from there first.
      if (existing && existing.counterpartyRelationshipKid !== body.relationshipKid) await options.drainInbox?.(existing.ownRelationshipKid)
      const contact: ContactKeyV1 = {
        version: 1,
        kind: 'contact-key',
        identityId: options.identityId,
        counterpartyDid: pending.result.pending.counterpartyDid,
        ownRelationshipKid: pending.result.pending.peer.xKid,
        ownX25519PrivateKey: pending.result.pending.peer.xPriv,
        ownEd25519PrivateKey: pending.result.pending.peer.edPriv,
        counterpartyRelationshipKid: body.relationshipKid,
        counterpartyPublicKey: body.publicKey,
        createdAt: now().toISOString(),
        seedId: pending.seedId,
        ...(existing ? { supersedes: { ownRelationshipKid: existing.ownRelationshipKid, counterpartyRelationshipKid: existing.counterpartyRelationshipKid } } : {}),
      }
      await options.sink.store(contact)
      await afterContactStored()
      pendingByCounterparty.delete(pending.result.pending.counterpartyDid)
      pending.resolve(contact)
    },
  }
}

/** A counterparty's front-door INIT: the one way a relationship begins,
 * and the one way it moves to new did:peers (after either side removed a
 * device). Only a key in the sender's DID document can send it, which is
 * what a removed device -- holding every old relationship key -- lacks. */
async function handleRelationshipInit(
  message: DeliveredMessage, mediatorUrl: string, identityId: string, relationshipSeed: RelationshipSeedAuthority, mediatorDeviceSecret: Uint8Array,
  frontDoor: { xKid: string; x25519PrivateKey: Uint8Array },
  reader: RelationshipContactReader, sink: RelationshipContactSink,
  startWatch: RelationshipWatchStarter, afterContactStored: () => Promise<unknown> = async () => {},
  mediatorAliases: readonly string[] = [],
  drainInbox?: (ownRelationshipKid: string) => Promise<void>,
): Promise<void> {
  const plaintext = message.plaintext as DidCommPlaintext
  if (plaintext.type !== RELATIONSHIP_INIT) return
  const body = relationshipBodyOf(plaintext)
  if (!body) throw new PermanentDeliveryError('relationship message body is invalid')
  const route = relationshipMediatorService(body.relationshipKid)
  if (!sameMediatorUrl(route.url, mediatorUrl, mediatorAliases)) throw new PermanentDeliveryError('relationship mediator does not match the delivery route')
  if (message.senderKid.startsWith('did:peer:2.')) throw new PermanentDeliveryError('relationship init must be authenticated by a public front-door kid')
  const counterpartyDid = didOfKid(message.senderKid)
  const usable = await relationshipSeed.require()
  let contact = await reader.currentFor(counterpartyDid)
  if (!contact || contact.counterpartyRelationshipKid !== body.relationshipKid || contact.seedId !== usable.seedId) {
    // The counterparty moved: what it already sent from its old kid is
    // handled while that kid is still its own, before the move makes it
    // unacceptable (a removed device of the counterparty still holds it).
    if (contact && contact.counterpartyRelationshipKid !== body.relationshipKid) await drainInbox?.(contact.ownRelationshipKid)
    // Deriving from the identity-wide relationship seed (not minting a
    // random identity, and not the device-local front-door key) means
    // re-receiving the same counterparty's INIT after this device's own
    // reload, OR a DIFFERENT device of this same Wallet identity receiving
    // it first, reconstructs the identical did:peer
    // (peer.ts's `deriveRelationshipPeerIdentity`).
    const peer = deriveRelationshipPeerIdentity(usable.seed, counterpartyDid, route.routingKid)
    await registerWithMediator(route.url, mediatorInbox({ did: peer.did, xKid: peer.xKid, xPriv: peer.xPriv }, mediatorDeviceSecret))
    const next: ContactKeyV1 = {
      version: 1, kind: 'contact-key', identityId, counterpartyDid,
      ownRelationshipKid: peer.xKid, ownX25519PrivateKey: peer.xPriv, ownEd25519PrivateKey: peer.edPriv,
      counterpartyRelationshipKid: body.relationshipKid, counterpartyPublicKey: body.publicKey,
      createdAt: new Date().toISOString(), seedId: usable.seedId,
      ...(contact ? { supersedes: { ownRelationshipKid: contact.ownRelationshipKid, counterpartyRelationshipKid: contact.counterpartyRelationshipKid } } : {}),
    }
    if (!contact || next.ownRelationshipKid !== contact.ownRelationshipKid || next.counterpartyRelationshipKid !== contact.counterpartyRelationshipKid) {
      await sink.store(next)
      contact = next
      await afterContactStored()
    }
    startWatch(peer.xKid, peer.xPriv, peer.did, route.url)
  }
  const accepted = await sendRelationshipAccept(contact, { fromKid: frontDoor.xKid, x25519PrivateKey: frontDoor.x25519PrivateKey })
  if (!accepted.ok) throw new Error(accepted.error)
}
