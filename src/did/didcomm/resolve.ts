// Unified DIDComm recipient resolution: given any DID (did:peer or
// did:webvh), returns a PeerDidDoc-shaped document — send.ts/message.ts's
// publicKeyOf only ever need {keyAgreement, service, verificationMethod}, so
// every method can share one recipient shape once resolved. did:peer
// self-decodes (no network); did:webvh resolves over its own domain's
// did.jsonl (webvh/resolver.ts) — the same conversion ~/didmediator's
// resolver.ts does server-side for didcomm-node, mirrored here for biset's
// own client-side send path.
import { decodePeerDid2, b64url, type PeerDidDoc } from '../peer/peer.ts'
import { resolve as resolveDidWebvh } from '../webvh/resolver.ts'
import { decodeMultikey, decodeX25519Multikey, decodeMlkem768Multikey } from '../webvh/multikey.ts'
import type { WebvhDidDocument } from '../webvh/document.ts'
import { b64urlToBytes } from './crypto.ts'
import { isMlkemKid } from '../devicekid.ts'

// did:webvh's state is already W3C DID Core shaped, so this conversion is
// mostly a field-rename — the one real transform is multikey (base58btc) ->
// the JsonWebKey2020 (base64url-x) shape send.ts/message.ts's publicKeyOf
// expects.
function webvhToPeerDidDocShape(doc: WebvhDidDocument): PeerDidDoc {
  const kaIds = new Set(doc.keyAgreement ?? [])
  const identityKeyId = `${doc.id}#key-1`
  const verificationMethod: PeerDidDoc['verificationMethod'] = []
  for (const vm of doc.verificationMethod) {
    if (vm.id === identityKeyId) {
      verificationMethod.push({ id: vm.id, type: 'JsonWebKey2020', controller: doc.id, publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: b64url(decodeMultikey(vm.publicKeyMultibase)) } })
    } else if (isMlkemKid(vm.id)) {
      // ML-KEM-768 hybrid entry. Recognized by its id alone, NOT by being
      // listed in `keyAgreement` — it deliberately is not (webvh/document.ts):
      // that relationship means X25519-shaped ECDH to every other
      // implementation. (PLAN.md "did:webvh
      // PQハイブリッド化" Phase 2) — kty/crv aren't real JWK registry values
      // (no standard OKP-style JWK shape exists for ML-KEM yet), self-
      // descriptive tags for send.ts's mlkemPublicKeyOf to read back, never
      // interpreted as an actual JWK `crv` elsewhere.
      verificationMethod.push({ id: vm.id, type: 'JsonWebKey2020', controller: doc.id, publicKeyJwk: { kty: 'AKP', crv: 'ML-KEM-768', x: b64url(decodeMlkem768Multikey(vm.publicKeyMultibase)) } })
    } else if (kaIds.has(vm.id)) {
      verificationMethod.push({ id: vm.id, type: 'JsonWebKey2020', controller: doc.id, publicKeyJwk: { kty: 'OKP', crv: 'X25519', x: b64url(decodeX25519Multikey(vm.publicKeyMultibase)) } })
    }
  }
  return {
    id: doc.id,
    // Fan-out list (send.ts's sendDidComm loop) — X25519 kids only. `#kk<n>`
    // entries stay in verificationMethod (mlkemPublicKeyOf reads them from
    // there, keyed off the X25519 kid) but must NOT appear here too, or the
    // loop would try to fan out to them as if they were a second device.
    // Matched by PREFIX, not by a `#kk<digits>` pattern. A device kid is
    // derived from its key now (did/devicekid.ts) — `#k_<hash>` with `#kk_…`
    // for its ML-KEM counterpart — so a digit-based test silently stopped
    // recognizing them: the ML-KEM entries would have been left in the
    // fan-out list AND run through the X25519 decoder below, which throws on
    // a 1184-byte key and would have made the whole identity unresolvable.
    keyAgreement: (doc.keyAgreement ?? []).filter(id => !isMlkemKid(id)),
    authentication: doc.authentication,
    verificationMethod,
    name: doc.name,
    // Only DIDCommMessaging services belong in a DIDComm-resolved document.
    // Matters more than it looks: didcomm-node's Rust ServiceKind is
    // internally tagged on the literal `type` string "DIDCommMessaging" or
    // "Other" (verified against its did_doc.rs) — passing through e.g.
    // "JMAPRelay" as-is throws "unknown variant" wherever this shape ends up
    // feeding a real didcomm-node resolver (found live, via ~/didmediator).
    service: doc.service
      .filter(s => s.type === 'DIDCommMessaging')
      .map(s => {
        // Two shapes, because documents published before the fix carry the
        // pre-DIDComm-v2 one: uri/accept/routingKeys nested inside
        // `serviceEndpoint` (current), or a bare string/array with `accept`
        // and `routingKeys` as siblings (legacy). Reading both is what lets an
        // identity that has not republished yet still be reached.
        const nested = typeof s.serviceEndpoint === 'object' && !Array.isArray(s.serviceEndpoint) ? s.serviceEndpoint : null
        const flat = Array.isArray(s.serviceEndpoint) ? s.serviceEndpoint[0] : typeof s.serviceEndpoint === 'string' ? s.serviceEndpoint : undefined
        const uri = nested ? nested.uri : flat ?? ''
        return {
          id: s.id, type: s.type,
          serviceEndpoint: {
            uri,
            accept: nested?.accept ?? s.accept ?? [],
            routing_keys: nested?.routingKeys ?? s.routingKeys ?? [],
          },
        }
      }),
  }
}

/** Resolves any DIDComm recipient DID to a PeerDidDoc-shaped document,
 * dispatching on method. `gatewayUrls`/`opts` are accepted for call-site
 * compatibility and unused — did:webvh derives its own URL from the DID
 * string itself (same as resolver.ts's resolveAny). */
export async function resolveDidCommDoc(
  did: string, _gatewayUrls: string[] = [], opts?: { skipCache?: boolean },
): Promise<PeerDidDoc | null> {
  if (did.startsWith('did:peer:2.')) {
    try {
      return decodePeerDid2(did)
    } catch {
      return null
    }
  }
  if (did.startsWith('did:webvh:')) {
    // The MLS authentication path calls this immediately after publishing a
    // new device key. A normal browser fetch is allowed to reuse its prior
    // routing.json response there, which makes the authenticator reject the
    // very credential it just published. Honor skipCache for BOTH the log and
    // routing resource, not merely an in-memory caller cache.
    const doc = await resolveDidWebvh(did, opts?.skipCache ? { cache: 'no-store' } : undefined).catch(() => null)
    return doc ? webvhToPeerDidDocShape(doc) : null
  }
  return null
}

/** pickup.ts's resolveSenderKey shape, method-agnostic: resolves the sender's
 * own DID (either method) and looks up the specific kid's public key. */
export async function resolveSenderPublicKey(senderKid: string, gatewayUrls: string[] = []): Promise<Uint8Array> {
  const senderDid = senderKid.split('#')[0]!
  const doc = await resolveDidCommDoc(senderDid, gatewayUrls)
  if (!doc) throw new Error(`resolveSenderPublicKey: could not resolve ${senderDid}`)
  let vm = doc.verificationMethod.find(v => v.id === senderKid)
  // Moved-identity fallback (did:webvh portability, webvh/publish.ts's
  // moveDidToNewDomain): after a domain move, resolving the OLD DID returns
  // the NEW document — same log, same SCID, verified chain — whose
  // verificationMethod ids are all scoped to the NEW DID string. So an
  // old-DID-scoped kid like `{oldDid}#key-1` is legitimately absent, and
  // matching on the full id alone would reject a key that demonstrably
  // belongs to this very identity. This is exactly the case from_prior
  // verification hits (rotation.ts resolves the PRIOR DID by design), which
  // is precisely when the sender is telling us they moved.
  //
  // Narrow on purpose: only when the resolved document's own `id` differs
  // from the DID we asked for — which for did:webvh can only happen through
  // a location change the resolver already validated (SCID match, unbroken
  // entryHash/proof chain, `portable` set at genesis — resolver.ts). Same-id
  // documents keep strict full-id matching, so two unrelated DIDs sharing a
  // fragment name can never satisfy each other's kids.
  if (!vm && doc.id && doc.id !== senderDid) {
    const fragment = senderKid.slice(senderDid.length) // "#key-1"
    vm = doc.verificationMethod.find(v => v.id === `${doc.id}${fragment}`)
  }
  if (!vm) throw new Error(`resolveSenderPublicKey: kid ${senderKid} not found in its own DID`)
  return b64urlToBytes(vm.publicKeyJwk.x)
}
