// Links _k1 (the DIDComm keyAgreement key, keys.ts's deriveDidCommKey) to a
// live mediator registration and republishes the resulting did:dht document
// — the "did:dht direct" path from PLAN.md's "DIDComm transport identity"
// (coexists with the per-contact did:peer path; this file is the did:dht
// half).
//
// Two-phase publish, not one (found live, against a real mediator +
// ~/didmediator's did:dht resolver — see PLAN.md): the mediator must be able
// to resolve OUR _k1 to encrypt mediate-grant back to us, which means _k1
// has to already be resolvable on the DHT *before* mediate-request is sent —
// publishing it together with the mediator's own service (which we only
// learn about *from* that same mediate-request) is a chicken-and-egg
// ordering bug. So: publish _k1 alone first, then register, then republish
// with the DIDCommMessaging service added.
import { x25519 } from '@noble/curves/ed25519.js'
import type { DidDocument } from '../document.ts'
import { publishDocument } from '../resolver.ts'
import { fetchMediatorInfo, requestMediation, updateKeylist, type MediatorInfo } from './coordinate.ts'
import type { DidCommSender } from './message.ts'

export interface DidCommDhtRegistration {
  doc: DidDocument // existingDoc + keyAgreementKey + a DIDCommMessaging service
  publishedTo: number // how many gateways accepted the final republish
  mediator: MediatorInfo // for callers that go on to pickup from the same mediator
  own: DidCommSender // the _k1 identity, ready to pass to send.ts/pickup.ts
}

/** Publishes _k1 (already-derived — keys.ts's deriveDidCommKey, or a
 * DidRecord's stored didCommPrivateKey; the master seed itself deliberately
 * doesn't travel this far into the codebase, same hygiene as store.ts never
 * persisting it), registers with `mediatorUrl` (mediate-request +
 * keylist-update, same protocol as the did:peer path), then republishes
 * `existingDoc` with the keyAgreement key and a DIDCommMessaging service
 * (routingKeys = the mediator's own kid) added. */
export async function registerDidCommViaDht(
  didCommPrivateKey: Uint8Array,
  rootPrivateKey: Uint8Array,
  existingDoc: DidDocument,
  mediatorUrl: string,
  gatewayUrls: string[],
): Promise<DidCommDhtRegistration> {
  const didCommPublicKey = x25519.getPublicKey(didCommPrivateKey)
  const k1Kid = `${existingDoc.id}#k1`
  const own: DidCommSender = { did: existingDoc.id, xKid: k1Kid, xPriv: didCommPrivateKey }

  // Phase 1: publish _k1 alone so it's resolvable before we ever use it.
  const withK1: DidDocument = { ...existingDoc, keyAgreementKey: didCommPublicKey }
  const publishedK1To = await publishDocument(rootPrivateKey, withK1, gatewayUrls)
  if (publishedK1To === 0) throw new Error('registerDidCommViaDht: no gateway accepted the _k1 publish')

  // Phase 2: now the mediator can resolve us — register.
  const mediator = await fetchMediatorInfo(mediatorUrl)
  await requestMediation(mediator, own)
  await updateKeylist(mediator, own, k1Kid, 'add')

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
    ...withK1,
    service: [
      ...withK1.service.filter(s => s.type !== 'DIDCommMessaging'),
      { id: 'didcomm', type: 'DIDCommMessaging', serviceEndpoint: [mediator.url], accept: ['didcomm/v2'], routingKeys: [mediatorXKid] },
    ],
  }

  const publishedTo = await publishDocument(rootPrivateKey, doc, gatewayUrls)
  return { doc, publishedTo, mediator, own }
}
