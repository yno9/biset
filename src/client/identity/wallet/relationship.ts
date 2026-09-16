import type { DidCommPlaintext } from '../../../protocol/didcomm/message.ts'
import type { DeliveredMessage } from '../../../protocol/didcomm/mediator-pickup.ts'
import { registerWithMediator } from '../../didcomm/mediator-sync.ts'
import { sameMediatorUrl } from '../../didcomm/mediator-watch.ts'
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
  forOwnKid(ownRelationshipKid: string): Promise<ContactKeyV1 | null>
}

interface RelationshipContactSink {
  store(contact: ContactKeyV1): Promise<unknown>
}

interface PendingWalletRelationship {
  result: Extract<RelationshipInitiationResult, { ok: true }>
  promise: Promise<ContactKeyV1>
  resolve: (contact: ContactKeyV1) => void
  /** A caller may stop waiting without abandoning the registered private
   * receiver. An ACCEPT can legitimately arrive after a temporary SSE
   * disconnect, so keep this pending state until the authenticated ACCEPT
   * consumes it (or a future contact attempt supersedes it). */
  startedAt: number
}

export interface WalletRelationshipManagerOptions {
  identityId: string
  frontDoor: { xKid: string; x25519PrivateKey: Uint8Array }
  /** Identity-wide secret, identical across every device of this same
   * Wallet identity (did-md-oauth.ts derives it from the Wallet's permanent
   * Root key, the same way VCK is derived, under its own fixed purpose) --
   * NOT `frontDoor`'s per-device key. Feeds `deriveRelationshipPeerIdentity`
   * so two different devices of this identity, each contacting the same
   * external counterparty for the first time, converge on the identical
   * relationship peer instead of racing to two non-superseding ContactKeyV1
   * records (peer.ts's own note; found live, 2026-09-15). */
  relationshipSecret: Uint8Array
  reader: RelationshipContactReader
  sink: RelationshipContactSink
  startWatch: RelationshipWatchStarter
  /** Persist newly stored contact keys to the Wallet's MIMI Vault before a Pickup ACK. */
  afterContactStored?: () => Promise<unknown>
  initiate?: (toDid: string, relationshipSecret: Uint8Array, options: { fromKid: string; x25519PrivateKey: Uint8Array }) => Promise<RelationshipInitiationResult>
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
  const pendingByOwnKid = new Map<string, PendingWalletRelationship>()
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
  const initiate = options.initiate ?? ((toDid, relationshipSecret, input) => initiateRelationship(toDid, relationshipSecret, input))
  const now = options.now ?? (() => new Date())
  const timeoutMs = options.timeoutMs ?? 60_000
  const afterContactStored = options.afterContactStored ?? (async () => {})

  async function ensureContactOnce(counterpartyDid: string): Promise<ContactKeyV1> {
    const stored = await options.reader.currentFor(counterpartyDid)
    if (stored) return stored

    let pending = pendingByCounterparty.get(counterpartyDid)
    if (!pending) {
      const initiated = await initiate(counterpartyDid, options.relationshipSecret, {
        fromKid: options.frontDoor.xKid,
        x25519PrivateKey: options.frontDoor.x25519PrivateKey,
      })
      if (!initiated.ok) throw new Error(initiated.error)
      let resolve!: (contact: ContactKeyV1) => void
      const promise = new Promise<ContactKeyV1>(done => { resolve = done })
      pending = { result: initiated, promise, resolve, startedAt: Date.now() }
      pendingByOwnKid.set(initiated.pending.peer.xKid, pending)
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

    async handleMessage(message, recipientKid, mediatorUrl): Promise<void> {
      const plaintext = message.plaintext as DidCommPlaintext
      if (plaintext.type === RELATIONSHIP_INIT) {
        await handleRelationshipInit(message, mediatorUrl, options.identityId, options.relationshipSecret, options.reader, options.sink, options.startWatch, afterContactStored)
        return
      }
      if (plaintext.type !== RELATIONSHIP_ACCEPT) return

      const body = relationshipBodyOf(plaintext)
      if (!body) throw new TypeError('relationship message body is invalid')
      const route = relationshipMediatorService(body.relationshipKid)
      if (!sameMediatorUrl(route.url, mediatorUrl)) throw new TypeError('relationship mediator does not match the delivery route')
      if (body.relationshipKid !== message.senderKid) throw new TypeError('relationship accept sender does not match its relationship kid')

      const pending = pendingByOwnKid.get(recipientKid)
      if (!pending) {
        const existing = await options.reader.forOwnKid(recipientKid)
        if (existing?.counterpartyRelationshipKid === body.relationshipKid) return
        throw new TypeError('relationship accept has no pending initiation')
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
        pendingByOwnKid.delete(recipientKid)
        pendingByCounterparty.delete(pending.result.pending.counterpartyDid)
        pending.resolve(existing)
        return
      }
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
      }
      await options.sink.store(contact)
      await afterContactStored()
      pendingByOwnKid.delete(recipientKid)
      pendingByCounterparty.delete(pending.result.pending.counterpartyDid)
      pending.resolve(contact)
    },
  }
}

async function handleRelationshipInit(
  message: DeliveredMessage, mediatorUrl: string, identityId: string, relationshipSecret: Uint8Array,
  reader: RelationshipContactReader, sink: RelationshipContactSink,
  startWatch: RelationshipWatchStarter, afterContactStored: () => Promise<unknown> = async () => {},
): Promise<void> {
  const plaintext = message.plaintext as DidCommPlaintext
  if (plaintext.type !== RELATIONSHIP_INIT) return
  const body = relationshipBodyOf(plaintext)
  if (!body) throw new TypeError('relationship message body is invalid')
  const route = relationshipMediatorService(body.relationshipKid)
  if (!sameMediatorUrl(route.url, mediatorUrl)) throw new TypeError('relationship mediator does not match the delivery route')
  if (message.senderKid.startsWith('did:peer:2.')) throw new TypeError('relationship init must be authenticated by a public front-door kid')
  const counterpartyDid = didOfKid(message.senderKid)
  let contact = await reader.currentFor(counterpartyDid)
  if (!contact || contact.counterpartyRelationshipKid !== body.relationshipKid) {
    // Deriving from the identity-wide relationshipSecret (not minting a
    // random identity, and not the device-local front-door key) means
    // re-receiving the same counterparty's INIT after this device's own
    // reload, OR a DIFFERENT device of this same Wallet identity receiving
    // it first, reconstructs the identical did:peer rather than leaving a
    // stale one enrolled at the mediator forever, or the two devices
    // converging on two different, non-superseding ContactKeyV1 records
    // (peer.ts's `deriveRelationshipPeerIdentity`).
    const peer = deriveRelationshipPeerIdentity(relationshipSecret, counterpartyDid, { uri: route.url, routingKeys: [route.routingKid] })
    await registerWithMediator(route.url, { did: peer.did, xKid: peer.xKid, xPriv: peer.xPriv })
    const next: ContactKeyV1 = {
      version: 1, kind: 'contact-key', identityId, counterpartyDid,
      ownRelationshipKid: peer.xKid, ownX25519PrivateKey: peer.xPriv, ownEd25519PrivateKey: peer.edPriv,
      counterpartyRelationshipKid: body.relationshipKid, counterpartyPublicKey: body.publicKey,
      createdAt: new Date().toISOString(), ...(contact ? { supersedesKid: contact.ownRelationshipKid } : {}),
    }
    await sink.store(next)
    contact = next
    await afterContactStored()
    startWatch(peer.xKid, peer.xPriv, peer.did, route.url)
  }
  const accepted = await sendRelationshipAccept(contact)
  if (!accepted.ok) throw new Error(accepted.error)
}
