// Publishes the one-time signed pointer to routing.json (this identity's
// `#routing` service entry) — the one piece of DIDComm/routing metadata that
// DOES belong in the signed did:webvh log rather than routing.json itself.
//
// Without it, nothing in did.jsonl signals routing.json exists at all — a
// resolver would have to already know biset's private filename convention to
// find it, unfriendly to exactly the kind of third party did:webvh's own
// "override the implicit DID URL resolution with an explicit service"
// mechanism exists to help (spec's DID URL Handling section). This entry
// never changes after it's first written (routing.json's own URL is a pure
// function of the DID), so it costs one one-time log entry, never a
// recurring one.
//
// Same log-update shape as identity/webvh/add-device-verification-method.ts
// (fetch current log -> append one new signed entry) — kept as its own
// function here, in the DIDComm package, rather than added to that file:
// Vault Core's base identity generation does not publish this pointer (only
// an identity that provisions a DIDComm-capable device does), so it stays
// opt-in rather than folded into the generic device-registration path.
import { encodeMultikey } from '../identity/webvh/multikey.ts'
import { fetchCurrentLog, nowVersionTime, putLog } from '../identity/webvh/log-io.ts'
import { entryVersionNumber, generateEntryHash, parametersToWrite, resolveParameters, type LogEntry } from '../identity/webvh/log.ts'
import { buildProof } from '../identity/webvh/proof.ts'
import type { SignedWebvhState } from '../identity/webvh/document.ts'
import { defaultFetch } from '../net-fetch.ts'
import { didToRoutingUrl } from './webvh-routing.ts'

export interface PublishRoutingPointerOptions {
  did: string
  /** Whichever key currently holds updateKeys authority (the root key, in the common no-pre-rotation case). */
  signingPrivateKey: Uint8Array
  signingPublicKey: Uint8Array
  fetch?: typeof fetch
}

/** Idempotent: a `#routing` entry already present in the document's service
 * array is a no-op, not an error. */
export async function publishRoutingPointer(opts: PublishRoutingPointerOptions): Promise<void> {
  const fetchImpl = opts.fetch ?? defaultFetch()
  const { url, entries, last } = await fetchCurrentLog(opts.did, fetchImpl)
  const updateKey = encodeMultikey(opts.signingPublicKey)
  if (!(last.parameters.updateKeys ?? []).includes(updateKey)) {
    throw new Error('publishRoutingPointer: local signing key is not authorized by the document\'s current updateKeys')
  }

  const previousState = last.state as SignedWebvhState
  const pointerId = `${opts.did}#routing`
  if (previousState.service.some(s => s.id === pointerId)) return

  const state: SignedWebvhState = {
    ...previousState,
    service: [...previousState.service, { id: pointerId, type: 'BisetRoutingDocument', serviceEndpoint: didToRoutingUrl(opts.did) }],
  }

  const versionTime = nowVersionTime()
  const parameters = parametersToWrite(last.parameters, resolveParameters(last.parameters, {}))
  const entryHash = generateEntryHash(last.versionId, versionTime, parameters, state)
  const versionId = `${entryVersionNumber(last.versionId) + 1}-${entryHash}`
  const unsigned = { versionId, versionTime, parameters, state }
  const proof = buildProof(unsigned, { verificationMethod: `did:key:${updateKey}#${updateKey}`, privateKey: opts.signingPrivateKey, created: versionTime })
  const entry: LogEntry = { ...unsigned, proof: [proof] }

  await putLog(url, [...entries, entry], [entry], fetchImpl)
}
