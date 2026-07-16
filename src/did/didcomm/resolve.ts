// Unified DIDComm recipient resolution: given any DID (did:peer or did:dht),
// returns a PeerDidDoc-shaped document — send.ts/message.ts's publicKeyOf
// only ever need {keyAgreement, service, verificationMethod}, so both
// methods can share one recipient shape once resolved. did:peer self-decodes
// (no network); did:dht resolves over Pkarr gateways and gets converted —
// same conversion ~/didmediator's resolver.ts does server-side for
// didcomm-node, mirrored here for biset's own client-side send path.
import { decodePeerDid2, b64url, type PeerDidDoc } from '../peer.ts'
import { resolve as resolveDidDht, PUBLIC_PKARR_FALLBACKS, type DidDocument } from '../resolver.ts'
import { b64urlToBytes } from './crypto.ts'

function didDhtToPeerDidDocShape(doc: DidDocument): PeerDidDoc {
  const verificationMethod: PeerDidDoc['verificationMethod'] = [
    { id: `${doc.id}#k0`, type: 'JsonWebKey2020', controller: doc.id, publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: b64url(doc.identityKey) } },
  ]
  const keyAgreement: string[] = []
  if (doc.keyAgreementKey) {
    verificationMethod.push({ id: `${doc.id}#k1`, type: 'JsonWebKey2020', controller: doc.id, publicKeyJwk: { kty: 'OKP', crv: 'X25519', x: b64url(doc.keyAgreementKey) } })
    keyAgreement.push(`${doc.id}#k1`)
  }
  return {
    id: doc.id,
    keyAgreement,
    authentication: [`${doc.id}#k0`],
    verificationMethod,
    // Only DIDCommMessaging services belong in a DIDComm-resolved document —
    // a did:dht identity's other services (JMAPRelay etc.) aren't DIDComm
    // endpoints. Matters more than it looks: didcomm-node's Rust ServiceKind
    // is internally tagged on the literal `type` string "DIDCommMessaging"
    // or "Other" (verified against its did_doc.rs) — passing through e.g.
    // "JMAPRelay" as-is throws "unknown variant" wherever this shape ends up
    // feeding a real didcomm-node resolver (found live, via ~/didmediator).
    service: doc.service
      .filter(s => s.type === 'DIDCommMessaging')
      .map(s => ({
        id: `${doc.id}#${s.id}`,
        type: s.type,
        serviceEndpoint: { uri: s.serviceEndpoint[0] ?? '', accept: s.accept ?? [], routing_keys: s.routingKeys ?? [] },
      })),
  }
}

/** Resolves any DIDComm recipient DID to a PeerDidDoc-shaped document,
 * dispatching on method. did:dht resolution defaults to the public Pkarr
 * fallback gateways (no "own relay" concept for a bare resolve call here). */
export async function resolveDidCommDoc(did: string, gatewayUrls: string[] = PUBLIC_PKARR_FALLBACKS): Promise<PeerDidDoc | null> {
  if (did.startsWith('did:peer:2.')) {
    try {
      return decodePeerDid2(did)
    } catch {
      return null
    }
  }
  if (did.startsWith('did:dht:')) {
    const doc = await resolveDidDht(did, gatewayUrls)
    return doc ? didDhtToPeerDidDocShape(doc) : null
  }
  return null
}

/** pickup.ts's resolveSenderKey shape, method-agnostic: resolves the sender's
 * own DID (either method) and looks up the specific kid's public key. */
export async function resolveSenderPublicKey(senderKid: string, gatewayUrls: string[] = PUBLIC_PKARR_FALLBACKS): Promise<Uint8Array> {
  const senderDid = senderKid.split('#')[0]!
  const doc = await resolveDidCommDoc(senderDid, gatewayUrls)
  if (!doc) throw new Error(`resolveSenderPublicKey: could not resolve ${senderDid}`)
  const vm = doc.verificationMethod.find(v => v.id === senderKid)
  if (!vm) throw new Error(`resolveSenderPublicKey: kid ${senderKid} not found in its own DID`)
  return b64urlToBytes(vm.publicKeyJwk.x)
}
