// did:webvh implementation of didcomm-devices.ts's MethodOps — the one
// method-specific piece (build + publish a document) that file's shared
// multi-device logic calls through. Thin: wraps webvh/publish.ts's
// updateDocument + webvh/resolver.ts's resolve, no new business logic.
import { hexToBytes, firstServiceEndpoint } from '../../utils.ts'
import { resolve } from './resolver.ts'
import { updateDocument, type BisetRelay } from './publish.ts'
import { keyAgreementKeysFromWebvhState, mlkemKeyAgreementKeysFromWebvhState, type WebvhDidDocument } from './document.ts'
import type { MethodOps } from '../didcomm-devices.ts'
import { requireRootPrivateKey } from '../store.ts'

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
    // Signing needs the root key, which is sealed at rest on a device with
    // passkey protection (store.ts) — requireRootPrivateKey turns "locked"
    // into a message instead of a signature over undefined. Overridden when
    // the caller already resolved the CURRENT updateKeys-holding key some
    // other way (opts.signingKeyOverride's own note) — #key-1 always stays
    // rec.rootPublicKey regardless, passed separately below.
    const signingPriv = opts.signingKeyOverride?.privateKey ?? hexToBytes(requireRootPrivateKey(rec))
    const signingPub = opts.signingKeyOverride?.publicKey ?? hexToBytes(rec.rootPublicKey)
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

    try {
      await updateDocument({
        did: rec.did, signingPrivateKey: signingPriv, signingPublicKey: signingPub, identityPublicKey: identityPub, relays, addresses,
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
      // did:webvh has exactly one publish target (the anchor serving this
      // DID's domain segment) — accepted count is boolean-shaped, matching
      // the dht path's "number of gateways that accepted it" convention
      // closely enough for every caller's `accepted === 0` check to work
      // the same way.
      return 1
    } catch (e) {
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
