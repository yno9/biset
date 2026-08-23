// Registers a device's MLS leaf signature key into the identity's DID
// document as a new verificationMethod entry — the missing piece
// Ed25519MlsDsSignatureVerifier / WebvhSigningKeyResolver need to actually
// resolve a real device's kid (PLANMLSDIDCRED.md §2.3's "no new key type"
// stance: this IS the MLS leaf key, not a separate device credential).
//
// No routing.json write (Vault Core's identity generation doesn't publish
// that resource — create-genesis.ts's own header), and no removal path:
// revoking a device's verification method is a real operation (it also has
// to interact with MLS Remove — see PLAN.md §4.4's "Remove must be followed
// by a rekey" invariant) that deserves its own reviewed change rather than
// riding in with the add-only case this bootstraps.
import { encodeMultikey } from './multikey.ts'
import { parseWebvhDid } from './identifier.ts'
import { fetchCurrentLog, nowVersionTime, putLog } from './log-io.ts'
import { entryVersionNumber, generateEntryHash, parametersToWrite, resolveParameters, type LogEntry } from './log.ts'
import { buildProof } from './proof.ts'
import type { SignedWebvhState } from './document.ts'
import { syncDidWebMirror } from '../web/mirror.ts'

export interface AddDeviceVerificationMethodOptions {
  did: string
  /** The verificationMethod id becomes `${did}#${fragment}` — the same string this device's MLS credential kid must equal. */
  fragment: string
  /** This device's MLS leaf signature key (KeyPackage.publicPackage.leafNode.signaturePublicKey). */
  devicePublicKey: Uint8Array
  /** Whichever key currently holds updateKeys authority (the root key, in the common no-pre-rotation case). */
  signingPrivateKey: Uint8Array
  signingPublicKey: Uint8Array
  /** Keep the did:web mirror (`mirror.ts`) at this DID's domain in sync —
   * must match whatever `createGenesis` was called with for this identity. */
  didWebMirror?: boolean
  fetch?: typeof fetch
}

/** Idempotent: a fragment already present in the document's verificationMethod is a no-op, not an error. */
export async function addDeviceVerificationMethod(opts: AddDeviceVerificationMethodOptions): Promise<void> {
  const fetchImpl = opts.fetch ?? fetch
  const { url, entries, last } = await fetchCurrentLog(opts.did, fetchImpl)
  const updateKey = encodeMultikey(opts.signingPublicKey)
  if (!(last.parameters.updateKeys ?? []).includes(updateKey)) {
    throw new Error('addDeviceVerificationMethod: local signing key is not authorized by the document\'s current updateKeys')
  }

  const previousState = last.state as SignedWebvhState
  const deviceKeyId = `${opts.did}#${opts.fragment}`
  if (previousState.verificationMethod.some(vm => vm.id === deviceKeyId)) return

  const state: SignedWebvhState = {
    ...previousState,
    verificationMethod: [
      ...previousState.verificationMethod,
      { id: deviceKeyId, type: 'Multikey', controller: opts.did, publicKeyMultibase: encodeMultikey(opts.devicePublicKey) },
    ],
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
