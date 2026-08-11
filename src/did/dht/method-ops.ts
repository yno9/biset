// did:dht implementation of didcomm-devices.ts's MethodOps — the one
// method-specific piece (build + publish a document) that file's shared
// multi-device logic calls through. Thin: wraps existing document.ts/
// resolver.ts primitives, no new business logic (dht/publish.ts's own
// buildOwnDocument/publishOwnDids/publishOneVisible are untouched and keep
// serving the routine-republish path they always have — this is a second,
// narrower builder for didcomm-devices.ts's explicit register/revoke calls,
// which take relayInput/keyAgreement/removed/service as plain arguments
// instead of resolving them from live app state itself).
import { hexToBytes } from '../../utils.ts'
import { buildBisetDocument, type DidDocument } from './document.ts'
import { resolve, resolveConfirmedAbsent, publishDocument } from './resolver.ts'
import { didCommGateways } from './publish.ts'
import type { MethodOps } from '../didcomm-devices.ts'

export const dhtMethodOps: MethodOps = {
  async resolveKeyAgreement(did, gatewayUrls) {
    const doc = await resolve(did, gatewayUrls, { skipCache: true }).catch(() => null)
    return doc ? { keyAgreementKeys: doc.keyAgreementKeys ?? [], removedKeyNs: doc.removedKeyNs } : null
  },

  resolveConfirmedAbsent,

  gatewayUrls: didCommGateways,

  async publishFull(rec, relayInput, opts) {
    const rootPriv = hexToBytes(rec.rootPrivateKey)
    const rootPub = hexToBytes(rec.rootPublicKey)
    let doc: DidDocument
    let gateways: string[]

    if (relayInput) {
      gateways = didCommGateways(relayInput.services.map(s => ({ account: { serverUrl: s.serverUrl } })), rec.didCommMediatorUrl)
      doc = buildBisetDocument(rec.did, rootPub, relayInput.services, relayInput.addresses, relayInput.name)
    } else {
      // No live session for this identity on this device: resolve whatever
      // is currently published and carry its services/addresses/name
      // forward, rather than guessing "no relays anywhere" (dht/publish.ts's
      // buildOwnDocument documents the same reasoning for the same bug this
      // avoids).
      gateways = didCommGateways([], rec.didCommMediatorUrl)
      const resolved = await resolve(rec.did, gateways, { skipCache: true }).catch(() => null)
      doc = resolved
        ? { ...resolved, ext: undefined, keyAgreementKeys: undefined, removedKeyNs: undefined }
        : buildBisetDocument(rec.did, rootPub, [], [])
    }

    if (opts.keyAgreementKeys.length) doc.keyAgreementKeys = opts.keyAgreementKeys
    if (opts.removedKeyNs?.length) doc.removedKeyNs = opts.removedKeyNs
    if (opts.didCommService) {
      doc.service = [
        ...doc.service.filter(s => s.type !== 'DIDCommMessaging'),
        {
          id: 'didcomm', type: 'DIDCommMessaging', serviceEndpoint: [opts.didCommService.mediatorUrl],
          accept: ['didcomm/v2'], routingKeys: [opts.didCommService.routingKey],
        },
      ]
    } else if (opts.removeDidCommService) {
      // Explicit removal, not just "don't write one": the carry-forward branch
      // above re-publishes a resolved document's whole `service` array, so an
      // absent didCommService alone leaves the old entry standing — which is
      // what left identities advertising DIDComm with no keyAgreement key
      // behind it (didcomm-devices.ts's publishCurrentState invariant note).
      doc.service = doc.service.filter(s => s.type !== 'DIDCommMessaging')
    }

    return publishDocument(rootPriv, doc, gateways)
  },
}
