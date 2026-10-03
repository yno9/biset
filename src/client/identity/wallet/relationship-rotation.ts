// Moving relationships to new pairwise did:peers (DIDComm v2.1 DID Rotation,
// protocol/didcomm/from-prior.ts), in both directions.
//
// OWN rotation follows a device removal: the relationship seed was replaced
// (store/vault/relationship-seed.ts), so every relationship moves to the
// did:peer the NEW seed derives for its counterparty -- one the removed
// devices cannot compute. Each new ContactKeyV1 supersedes the old one and
// carries the `from_prior` JWT that every message from it then includes.
// Deterministic like the seed itself, so every remaining device derives the
// same new DIDs and a rerun after a crash finds the work already done.
//
// COUNTERPARTY rotation is the other side doing the same: a message from an
// unknown did:peer whose `from_prior` names a counterparty this side knows.
import type { DidCommPlaintext } from '../../../protocol/didcomm/message.ts'
import type { DeliveredMessage } from '../../../protocol/didcomm/mediator-pickup.ts'
import { decodePeerDid2, deriveRelationshipPeerIdentity, publicKeyOf } from '../../../protocol/didcomm/peer.ts'
import { mediatorInbox } from '../../../protocol/didcomm/mediator-device.ts'
import { signFromPrior, verifyFromPrior } from '../../../protocol/didcomm/from-prior.ts'
import { registerWithMediator } from '../../didcomm/mediator-sync.ts'
import { relationshipMediatorService } from '../../didcomm/relationship.ts'
import { sendRelationshipRotationNotice } from '../../didcomm/send-message.ts'
import type { ContactKeyV1 } from '../../store/vault/contact-key.ts'
import type { RelationshipWatchStarter } from './relationship.ts'

interface ContactReader {
  readAll(): Promise<ContactKeyV1[]>
  currentFor(counterpartyDid: string): Promise<ContactKeyV1 | null>
  forCounterpartyKid(counterpartyRelationshipKid: string): Promise<ContactKeyV1 | null>
}

interface ContactSink { store(contact: ContactKeyV1): Promise<unknown> }

/** Every counterparty's current relationship. */
async function currentContacts(reader: Pick<ContactReader, 'readAll' | 'currentFor'>): Promise<ContactKeyV1[]> {
  const counterparties = [...new Set((await reader.readAll()).map(contact => contact.counterpartyDid))]
  const current: ContactKeyV1[] = []
  for (const counterpartyDid of counterparties) {
    const contact = await reader.currentFor(counterpartyDid)
    if (contact) current.push(contact)
  }
  return current
}

const ref = (contact: ContactKeyV1) => ({ ownRelationshipKid: contact.ownRelationshipKid, counterpartyRelationshipKid: contact.counterpartyRelationshipKid })
const didOf = (kid: string) => kid.split('#', 1)[0]!

export interface OwnRotationResult { rotated: string[]; unchanged: string[]; failed: Array<{ counterpartyDid: string; error: string }> }

/** Moves every current relationship to the did:peer `seed` derives for it.
 * Per relationship: open the new mediator inbox, store the superseding
 * ContactKeyV1 (with `from_prior`), watch it, and send the counterparty a
 * notice. A relationship already on its derived DID is left alone; one that
 * fails is reported and retried by the caller on a later run. */
export async function rotateOwnRelationships(input: {
  identityId: string
  seed: Uint8Array
  mediatorDeviceSecret: Uint8Array
  reader: Pick<ContactReader, 'readAll' | 'currentFor'>
  sink: ContactSink
  startWatch: RelationshipWatchStarter
  afterContactStored?: () => Promise<unknown>
  notify?: (contact: ContactKeyV1) => Promise<{ ok: boolean; error?: string }>
  now?: () => Date
}): Promise<OwnRotationResult> {
  const result: OwnRotationResult = { rotated: [], unchanged: [], failed: [] }
  const notify = input.notify ?? (contact => sendRelationshipRotationNotice(contact))
  for (const contact of await currentContacts(input.reader)) {
    try {
      const route = relationshipMediatorService(contact.ownRelationshipKid)
      const peer = deriveRelationshipPeerIdentity(input.seed, contact.counterpartyDid, route.routingKid)
      if (peer.xKid === contact.ownRelationshipKid) { result.unchanged.push(contact.counterpartyDid); continue }
      await registerWithMediator(route.url, mediatorInbox({ did: peer.did, xKid: peer.xKid, xPriv: peer.xPriv }, input.mediatorDeviceSecret))
      const priorDid = didOf(contact.ownRelationshipKid)
      const priorEdKid = decodePeerDid2(priorDid).authentication[0]
      if (!priorEdKid) throw new Error('the prior relationship DID has no authentication key')
      const next: ContactKeyV1 = {
        version: 1, kind: 'contact-key', identityId: input.identityId, counterpartyDid: contact.counterpartyDid,
        ownRelationshipKid: peer.xKid, ownX25519PrivateKey: peer.xPriv, ownEd25519PrivateKey: peer.edPriv,
        counterpartyRelationshipKid: contact.counterpartyRelationshipKid, counterpartyPublicKey: contact.counterpartyPublicKey,
        createdAt: (input.now?.() ?? new Date()).toISOString(),
        supersedes: ref(contact),
        fromPrior: signFromPrior({ did: priorDid, edKid: priorEdKid, edPrivateKey: contact.ownEd25519PrivateKey }, peer.did),
      }
      await input.sink.store(next)
      await input.afterContactStored?.()
      input.startWatch(peer.xKid, peer.xPriv, peer.did, route.url)
      // The notice is a courtesy: every later message carries `from_prior`
      // too, so a failure here is not a failed rotation.
      const sent = await notify(next).catch(error => ({ ok: false, error: error instanceof Error ? error.message : String(error) }))
      if (!sent.ok) console.warn(`[relationship rotation] notice to ${contact.counterpartyDid} failed: ${sent.error}`)
      result.rotated.push(contact.counterpartyDid)
    } catch (error) {
      result.failed.push({ counterpartyDid: contact.counterpartyDid, error: error instanceof Error ? error.message : String(error) })
    }
  }
  return result
}

/** Handles a delivered relationship message's `from_prior`, if any: when it
 * proves that a counterparty this side knows moved to the sender's DID, the
 * relationship is moved over (a superseding ContactKeyV1) before the message
 * itself is processed. Returns whether it did. Throws on a `from_prior` that
 * does not verify -- the message must not be trusted then. */
export async function acceptCounterpartyRotation(input: {
  message: DeliveredMessage
  reader: ContactReader
  sink: ContactSink
  afterContactStored?: () => Promise<unknown>
  now?: () => Date
}): Promise<boolean> {
  const plaintext = input.message.plaintext as DidCommPlaintext
  if (typeof plaintext.from_prior !== 'string' || typeof plaintext.from !== 'string') return false
  if (!input.message.senderKid.startsWith(`${plaintext.from}#`)) return false
  if (await input.reader.forCounterpartyKid(input.message.senderKid)) return false
  const claims = verifyFromPrior(plaintext.from_prior, plaintext.from)
  const priorKid = decodePeerDid2(claims.iss).keyAgreement[0]
  const prior = priorKid ? await input.reader.forCounterpartyKid(priorKid) : null
  if (!prior) return false
  const current = await input.reader.currentFor(prior.counterpartyDid)
  // Only the relationship as it stands now moves; a stale announcement for
  // a DID the counterparty already left again changes nothing.
  if (!current || current.counterpartyRelationshipKid !== priorKid) return false
  const next: ContactKeyV1 = {
    ...current,
    counterpartyRelationshipKid: input.message.senderKid,
    counterpartyPublicKey: publicKeyOf(decodePeerDid2(plaintext.from), input.message.senderKid),
    createdAt: (input.now?.() ?? new Date()).toISOString(),
    supersedes: ref(current),
  }
  await input.sink.store(next)
  await input.afterContactStored?.()
  return true
}
