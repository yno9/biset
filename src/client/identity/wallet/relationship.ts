import type { DidCommPlaintext } from '../../../shared/didcomm/message.ts'
import type { DeliveredMessage } from '../../../shared/didcomm/mediator-pickup.ts'
import { registerWithMediator } from '../../../shared/didcomm/mediator-sync.ts'
import { sameMediatorUrl } from '../../../shared/didcomm/mediator-watch.ts'
import { generatePeerIdentity } from '../../../shared/didcomm/peer.ts'
import {
  RELATIONSHIP_ACCEPT,
  RELATIONSHIP_INIT,
  relationshipBodyOf,
  relationshipMediatorService,
} from '../../../shared/didcomm/relationship.ts'
import {
  initiateRelationship,
  sendRelationshipAccept,
  type RelationshipInitiationResult,
} from '../../../shared/didcomm/send-message.ts'
import { didOfKid } from '../../../shared/protocol/ids.ts'
import type { ContactKeyV1 } from '../../store/vault/contact-key.ts'

export type RelationshipWatchStarter = (xKid: string, xPriv: Uint8Array, did: string, mediatorUrl: string) => void

export interface RelationshipContactReader {
  currentFor(counterpartyDid: string): Promise<ContactKeyV1 | null>
  forOwnKid(ownRelationshipKid: string): Promise<ContactKeyV1 | null>
}

export interface RelationshipContactSink {
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
  reader: RelationshipContactReader
  sink: RelationshipContactSink
  startWatch: RelationshipWatchStarter
  /** Persist newly stored contact keys to the Wallet's MIMI Vault before a Pickup ACK. */
  afterContactStored?: () => Promise<unknown>
  initiate?: (toDid: string, options: { fromKid: string; x25519PrivateKey: Uint8Array }) => Promise<RelationshipInitiationResult>
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
  const initiate = options.initiate ?? ((toDid, input) => initiateRelationship(toDid, input))
  const now = options.now ?? (() => new Date())
  const timeoutMs = options.timeoutMs ?? 60_000
  const afterContactStored = options.afterContactStored ?? (async () => {})

  return {
    async ensureContact(counterpartyDid): Promise<ContactKeyV1> {
      const stored = await options.reader.currentFor(counterpartyDid)
      if (stored) return stored

      let pending = pendingByCounterparty.get(counterpartyDid)
      if (!pending) {
        const initiated = await initiate(counterpartyDid, {
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
    },

    async handleMessage(message, recipientKid, mediatorUrl): Promise<void> {
      const plaintext = message.plaintext as DidCommPlaintext
      if (plaintext.type === RELATIONSHIP_INIT) {
        await handleRelationshipInit(message, mediatorUrl, options.identityId, options.reader, options.sink, options.startWatch, afterContactStored)
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

export async function handleRelationshipInit(
  message: DeliveredMessage, mediatorUrl: string, identityId: string,
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
    const peer = generatePeerIdentity({ uri: route.url, routingKeys: [route.routingKid] })
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
