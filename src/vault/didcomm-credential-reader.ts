import type { IdentityId, SegmentId } from '../protocol/ids.ts'
import { decryptVaultObject } from './objects.ts'
import { assertDidCommCredentialRecord, type DidCommPrivateCredentialV1 } from './didcomm-credential.ts'
import type { SegmentKeyResolver } from './segment-key-resolver.ts'
import type { VaultCredentialEventReader, VaultObjectReader } from './store.ts'
import { verifyVaultEvent, type VaultEventVerifier } from './events.ts'

export interface DidCommCredentialReaderOptions {
  identityId: IdentityId
  objects: VaultObjectReader
  events: VaultCredentialEventReader
  segmentKeys: SegmentKeyResolver
  verifier: VaultEventVerifier
}

/**
 * Endpoint-only reader for the identity-shared DIDComm keyAgreement
 * credential held in the encrypted vault -- same shape and same reasoning
 * as vault/openpgp-credential-reader.ts.
 */
export class DidCommCredentialReader {
  constructor(private readonly options: DidCommCredentialReaderOptions) {
    if (!options.identityId) throw new TypeError('DIDComm credential reader identity is required')
  }

  /** Returns every verified credential, including historical keys superseded by a rotation. */
  async readAll(): Promise<DidCommPrivateCredentialV1[]> {
    const events = await this.options.events.readCredentialEvents(this.options.identityId)
    const keys = new Map<SegmentId, Uint8Array>()
    try {
      const credentials: DidCommPrivateCredentialV1[] = []
      for (const event of events) {
        if (event.kind !== 'credential.didcomm.set') continue
        if (!(await verifyVaultEvent(event, this.options.verifier))) throw new TypeError('DIDComm credential event signature is invalid')
        if (event.objectRefs.length !== 1) throw new TypeError('DIDComm credential event must reference exactly one object')
        const object = await this.options.objects.readObject(this.options.identityId, event.objectRefs[0])
        if (!object) throw new Error('DIDComm credential object is unavailable; restore is required')
        let segmentKey = keys.get(object.segmentId)
        if (!segmentKey) {
          segmentKey = await this.options.segmentKeys.resolveSegmentKey(this.options.identityId, object.segmentId)
          keys.set(object.segmentId, segmentKey)
        }
        credentials.push(assertDidCommCredentialRecord(event, object, await decryptVaultObject(segmentKey, object)))
      }
      return credentials
    } finally {
      for (const key of keys.values()) key.fill(0)
    }
  }

  /**
   * Selects the unique unsuperseded key for this identity's DIDComm
   * keyAgreement kid. If two keys are independently introduced (e.g. two
   * devices raced to mint one before either had synced the other's), fail
   * closed and require an explicit rotation decision instead of silently
   * picking one by local clock order.
   */
  async readCurrent(): Promise<DidCommPrivateCredentialV1> {
    const credentials = await this.readAll()
    if (credentials.length === 0) throw new Error('no DIDComm credential is available')
    const byKid = new Map<string, DidCommPrivateCredentialV1>()
    const superseded = new Set<string>()
    for (const credential of credentials) {
      if (byKid.has(credential.didCommKid)) throw new TypeError('duplicate DIDComm credential kid')
      byKid.set(credential.didCommKid, credential)
      if (credential.supersedesKid) superseded.add(credential.supersedesKid)
    }
    const current = credentials.filter(credential => !superseded.has(credential.didCommKid))
    if (current.length !== 1) throw new Error('DIDComm current credential is ambiguous; explicit rotation is required')
    return copyCredential(current[0]!)
  }
}

function copyCredential(value: DidCommPrivateCredentialV1): DidCommPrivateCredentialV1 {
  return { ...value, privateKey: value.privateKey.slice() }
}
