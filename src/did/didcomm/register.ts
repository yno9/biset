// Links a device's DIDComm keyAgreement key to a live mediator registration
// and republishes the resulting did:dht document — the "did:dht direct" path
// from PLAN.md's "DIDComm transport identity" (coexists with the per-contact
// did:peer path; this file is the did:dht half).
//
// Multi-device (document.ts's DidKeyAgreement note): `existingDoc` must
// already carry EVERY device's keyAgreement entry, including this one's — the
// caller (create-standalone.ts) resolves siblings and merges before calling
// in, since only it knows which entry is "this device" (`ownN`). This file
// stays a plain two/three-phase publish orchestrator with no merge logic of
// its own.
//
// Two-phase publish, not one (found live, against a real mediator +
// ~/didmediator's did:dht resolver — see PLAN.md): the mediator must be able
// to resolve OUR key to encrypt mediate-grant back to us, which means it has
// to already be resolvable on the DHT *before* mediate-request is sent —
// publishing it together with the mediator's own service (which we only
// learn about *from* that same mediate-request) is a chicken-and-egg
// ordering bug. So: publish the keys alone first, then register, then
// republish with the DIDCommMessaging service added.
import type { DidDocument } from '../document.ts'
import { publishDocument } from '../resolver.ts'
import { fetchMediatorInfo, requestMediation, updateKeylist, type MediatorInfo } from './coordinate.ts'
import type { DidCommSender } from './message.ts'

export interface DidCommDhtRegistration {
  doc: DidDocument // existingDoc + a DIDCommMessaging service
  publishedTo: number // how many gateways accepted the final republish
  mediator: MediatorInfo // for callers that go on to pickup from the same mediator
  own: DidCommSender // this device's identity, ready to pass to send.ts/pickup.ts
}

/** Publishes `existingDoc` (already carrying this device's key at slot `ownN`,
 * merged with any known siblings by the caller), registers with `mediatorUrl`
 * (mediate-request + keylist-update, same protocol as the did:peer path), then
 * republishes with the DIDCommMessaging service added. */
export async function registerDidCommViaDht(
  didCommPrivateKey: Uint8Array,
  ownN: number,
  rootPrivateKey: Uint8Array,
  existingDoc: DidDocument,
  mediatorUrl: string,
  gatewayUrls: string[],
): Promise<DidCommDhtRegistration> {
  const ownKid = `${existingDoc.id}#k${ownN}`
  const own: DidCommSender = { did: existingDoc.id, xKid: ownKid, xPriv: didCommPrivateKey }

  // Phase 1: publish (existingDoc already carries this device's key) so it's
  // resolvable before the mediator is ever asked to encrypt to it.
  const publishedK1To = await publishDocument(rootPrivateKey, existingDoc, gatewayUrls)
  if (publishedK1To === 0) throw new Error('registerDidCommViaDht: no gateway accepted the key publish')

  // Phase 2: now the mediator can resolve us — register.
  const mediator = await fetchMediatorInfo(mediatorUrl)
  await requestMediation(mediator, own)
  await updateKeylist(mediator, own, ownKid, 'add')

  const mediatorXKid = mediator.doc.keyAgreement[0]
  if (!mediatorXKid) throw new Error('registerDidCommViaDht: mediator DID doc has no keyAgreement')

  // Phase 3: republish with the DIDCommMessaging service added — REPLACING
  // any existing one rather than appending. Registering twice (a retry, a
  // second device, a different mediator) must not stack duplicates: a
  // did:dht document is a BEP44 value capped at 1000 bytes, and each of
  // these services costs ~330 bytes (the mediator's did:peer routing kid
  // alone is 236 chars), so appending blindly overflows the cap within a
  // couple of registrations — found live on a real account, which had
  // accumulated two identical entries and could no longer publish at all.
  const doc: DidDocument = {
    ...existingDoc,
    service: [
      ...existingDoc.service.filter(s => s.type !== 'DIDCommMessaging'),
      { id: 'didcomm', type: 'DIDCommMessaging', serviceEndpoint: [mediator.url], accept: ['didcomm/v2'], routingKeys: [mediatorXKid] },
    ],
  }

  const publishedTo = await publishDocument(rootPrivateKey, doc, gatewayUrls)
  return { doc, publishedTo, mediator, own }
}
