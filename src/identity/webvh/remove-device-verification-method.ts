// Removes a revoked device's verificationMethod entry from the identity's
// DID document -- the counterpart add-device-verification-method.ts's own
// header named as deliberately out of scope when that file was written
// ("revoking a device's verification method is a real operation... that
// deserves its own reviewed change"). Built 2026-08-26 alongside
// mls/self-group.ts's removeDeviceFromSelfGroup, which is the OTHER half of
// a revoke: that function cuts the device out of MLS membership (so it
// cannot read anything committed afterwards); this one cuts it out of the
// DID document (so nothing resolving this identity's document still lists
// the revoked device's leaf key as valid, e.g. for MLS Authentication
// Service checks -- mls/webvh-authentication-service.ts resolves a
// device's signing key straight off this document).
import { encodeMultikey } from './multikey.ts'
import { parseWebvhDid } from './identifier.ts'
import { fetchCurrentLog, nowVersionTime, putLog } from './log-io.ts'
import { entryVersionNumber, generateEntryHash, parametersToWrite, resolveParameters, type LogEntry } from './log.ts'
import { buildProof } from './proof.ts'
import type { SignedWebvhState } from './document.ts'
import { syncDidWebMirror } from '../web/mirror.ts'
import { defaultFetch } from '../../net-fetch.ts'

export interface RemoveDeviceVerificationMethodOptions {
  did: string
  /** The verificationMethod id to remove -- the full `${did}#${fragment}` form (the revoked device's own kid). */
  deviceKeyId: string
  signingPrivateKey: Uint8Array
  signingPublicKey: Uint8Array
  didWebMirror?: boolean
  fetch?: typeof fetch
}

/** Idempotent: a fragment already absent from the document's verificationMethod is a no-op, not an error. */
export async function removeDeviceVerificationMethod(opts: RemoveDeviceVerificationMethodOptions): Promise<void> {
  const fetchImpl = opts.fetch ?? defaultFetch()
  const { url, entries, last } = await fetchCurrentLog(opts.did, fetchImpl)
  const updateKey = encodeMultikey(opts.signingPublicKey)
  if (!(last.parameters.updateKeys ?? []).includes(updateKey)) {
    throw new Error('removeDeviceVerificationMethod: local signing key is not authorized by the document\'s current updateKeys')
  }

  const previousState = last.state as SignedWebvhState
  if (!previousState.verificationMethod.some(vm => vm.id === opts.deviceKeyId)) return

  const state: SignedWebvhState = {
    ...previousState,
    verificationMethod: previousState.verificationMethod.filter(vm => vm.id !== opts.deviceKeyId),
  }

  const versionTime = nowVersionTime()
  const parameters = parametersToWrite(last.parameters, resolveParameters(last.parameters, {}))
  const entryHash = generateEntryHash(last.versionId, versionTime, parameters, state)
  const versionId = `${entryVersionNumber(last.versionId) + 1}-${entryHash}`
  const unsigned = { versionId, versionTime, parameters, state }
  const proof = buildProof(unsigned, { verificationMethod: `did:key:${updateKey}#${updateKey}`, privateKey: opts.signingPrivateKey, created: versionTime })
  const entry: LogEntry = { ...unsigned, proof: [proof] }

  await putLog(url, [...entries, entry], [entry], fetchImpl)

  if (opts.didWebMirror) await syncDidWebMirror(opts.did, state, { domain: parseWebvhDid(opts.did).domain, fetch: fetchImpl })
}
