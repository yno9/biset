// did:webvh implementation of didcomm-devices.ts's MethodOps — the one
// method-specific piece (build + publish a document) that file's shared
// multi-device logic calls through. Thin: wraps webvh/publish.ts's
// updateDocument + webvh/resolver.ts's resolve, no new business logic.
import { hexToBytes, firstServiceEndpoint } from '../../utils.ts'
import { resolve } from './resolver.ts'
import { updateDocument, type BisetRelay } from './publish.ts'
import { keyAgreementKeysFromWebvhState, mlkemKeyAgreementKeysFromWebvhState, type WebvhDidDocument } from './document.ts'
import type { MethodOps } from '../didcomm-devices.ts'
import { requireRootPrivateKey, storeDidRecord } from '../store.ts'

/** did:webvh has no gateway list — a DID's own domain segment names exactly
 * one URL (identifier.ts's didToHttpsUrl). Kept as an empty array rather
 * than removed from the interface so didcomm-devices.ts's shared code
 * doesn't need a method-conditional branch just to skip passing gateways. */
function noGateways(): string[] {
  return []
}

/** The read-side counterpart of MethodOps.publishFull's relayInput: pulls
 * relays/addresses back out of a resolved document, for the "no live
 * session — carry forward" branch (mirrors dht/method-ops.ts's equivalent,
 * which does the same by reading a resolved DidDocument's `service`/
 * `alsoKnownAs`). */
function relaysAndAddressesFromState(doc: WebvhDidDocument): { relays: BisetRelay[]; addresses: string[] } {
  const relays: BisetRelay[] = doc.service
    .filter(s => s.type === 'JMAPRelay')
    .map(s => ({
      id: s.id.split('#')[1] ?? s.id,
      serverUrl: firstServiceEndpoint(s.serviceEndpoint),
      protocol: s.protocol, address: s.address,
    }))
  const addresses = doc.alsoKnownAs.filter(a => a.startsWith('mailto:')).map(a => a.slice('mailto:'.length))
  return { relays, addresses }
}

export const webvhMethodOps: MethodOps = {
  async resolveKeyAgreement(did, _gatewayUrls) {
    const doc = await resolve(did).catch(() => null)
    return doc
      ? {
        keyAgreementKeys: keyAgreementKeysFromWebvhState(doc),
        mlkemKeyAgreementKeys: mlkemKeyAgreementKeysFromWebvhState(doc),
      }
      : null
  },

  async resolveConfirmedAbsent(did, _gatewayUrls) {
    // A single URL, not a gateway list — a clean 404 (resolve() returning
    // null) IS confirmed absence, no quorum needed. A resolution error
    // (network/CORS/verification failure) is "couldn't check", same
    // fail-closed stance as the dht path's 429/CORS case — never read as
    // absence.
    try {
      return (await resolve(did)) === null
    } catch {
      return false
    }
  },

  gatewayUrls: noGateways,

  async publishFull(rec, relayInput, opts) {
    // Three-tier fallback for whichever key currently holds updateKeys
    // authority: an explicit override (a caller that just resolved it some
    // other way, e.g. left-pane.ts's Sync after a fresh prompt) beats the
    // record's own cached Sign Key (did/store.ts's signingPrivateKey/
    // signingPublicKey — set once ui/prerotation.ts's revealCurrentSigner or
    // any rotate/deactivate/revoke has verified one), which beats the root
    // key as the last resort. Root alone is only ever right when updateKeys
    // has never diverged from #key-1.
    //
    // The cache tier is what makes this useful for AUTOMATIC callers
    // (boot-time avatar publish, mediator re-registration) that cannot
    // prompt at all: before this, only a caller that explicitly threaded an
    // override through ever benefited from a cached Sign Key, so every
    // automatic publish kept failing with "local signing key is not
    // authorized" forever, even on a device that had already cached the
    // right key via an earlier Sync (found live, 2026-08-17, y@biset.md).
    const cachedSigningPriv = rec.signingPrivateKey ? hexToBytes(rec.signingPrivateKey) : null
    const cachedSigningPub = rec.signingPublicKey ? hexToBytes(rec.signingPublicKey) : null
    const rootSigningPriv = hexToBytes(requireRootPrivateKey(rec))
    const rootSigningPub = hexToBytes(rec.rootPublicKey)
    const signingPriv = opts.signingKeyOverride?.privateKey ?? cachedSigningPriv ?? rootSigningPriv
    const signingPub = opts.signingKeyOverride?.publicKey ?? cachedSigningPub ?? rootSigningPub
    const identityPub = hexToBytes(rec.rootPublicKey)

    let relays: BisetRelay[]
    let addresses: string[]
    if (relayInput) {
      relays = relayInput.services
      addresses = relayInput.addresses
    } else {
      // No live session for this identity on this device: resolve whatever
      // is currently published and carry its services/addresses forward,
      // rather than guessing "no relays anywhere" — same reasoning as
      // dht/method-ops.ts's equivalent branch.
      const resolved = await resolve(rec.did).catch(() => null)
      const carried = resolved ? relaysAndAddressesFromState(resolved) : { relays: [], addresses: [] }
      relays = carried.relays
      addresses = carried.addresses
    }

    const publish = async (privateKey: Uint8Array, publicKey: Uint8Array): Promise<void> => {
      await updateDocument({
        did: rec.did, signingPrivateKey: privateKey, signingPublicKey: publicKey, identityPublicKey: identityPub, relays, addresses,
        // routing.ts, not the signed document (document.ts's own header):
        // an absent didCommService/keyAgreementKeys here already IS the
        // removal (updateDocument rewrites routing.json from scratch every
        // call) — which is also what registerWithMediator's Phase 1 relies
        // on. No `removeDidCommService` handling needed (unlike
        // dht/method-ops.ts, whose document.service is carried forward
        // wholesale rather than rebuilt).
        didCommService: opts.didCommService,
        keyAgreementKeys: opts.keyAgreementKeys,
        mlkemKeyAgreementKeys: opts.mlkemKeyAgreementKeys,
        // The self-asserted display name, exactly as dht/method-ops.ts
        // passes relayInput.name to buildBisetDocument. This was missing
        // entirely at first, so NO did:webvh document ever carried a name:
        // every peer's displayLabelFor fell through to the shortened DID,
        // and channel.ts's post-arrival name resolve (which reads doc.name
        // and patches both the stored Email and the contact Card) had
        // nothing to find (found live, 2026-08-02). Undefined when this
        // device has no live relay session — updateDocument carries the
        // previously published name forward in that case rather than
        // erasing it.
        name: relayInput?.name,
      })
    }

    try {
      await publish(signingPriv, signingPub)
      // did:webvh has exactly one publish target (the anchor serving this
      // DID's domain segment) — accepted count is boolean-shaped, matching
      // the dht path's "number of gateways that accepted it" convention
      // closely enough for every caller's `accepted === 0` check to work
      // the same way.
      return 1
    } catch (e) {
      // A device that was offline when pre-rotation was turned OFF can still
      // carry the formerly-valid Sign Key. It must not be preferred forever:
      // the current document is authoritative, and after OFF it names Root
      // Key alone. Retry exactly this stale-cache case with Root Key, then
      // erase the obsolete cache so the next automatic DIDComm registration
      // follows the same authority without another failed round trip.
      const usedCachedSignKey = !opts.signingKeyOverride && !!cachedSigningPriv && !!cachedSigningPub
      const staleCachedSigner = e instanceof Error && e.message.includes('not authorized by the document\'s current updateKeys')
      if (usedCachedSignKey && staleCachedSigner) {
        try {
          await publish(rootSigningPriv, rootSigningPub)
          delete rec.signingPrivateKey
          delete rec.signingPublicKey
          await storeDidRecord(rec)
          console.info(`[webvh] dropped stale Sign Key cache for ${rec.did}; Root Key is current again`)
          return 1
        } catch (rootError) {
          console.warn('[webvh] Root Key retry after stale Sign Key failed:', rootError instanceof Error ? rootError.message : rootError)
        }
      }
      // Swallowed into a bare 0 for the caller (its own contract — see the
      // interface note above), but the actual reason (e.g. "local key not
      // authorized by the current updateKeys" — publish.ts's updateDocument)
      // is otherwise invisible: it never reaches the eventual
      // "no gateway/endpoint accepted the key publish" the caller throws.
      console.warn('[webvh] publishFull failed:', e instanceof Error ? e.message : e)
      return 0
    }
  },
}
