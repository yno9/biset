import type { IdentityId, SegmentId } from '../protocol/ids.ts'
import { decryptVaultObject } from './objects.ts'
import { assertOpenPgpCredentialRecord, type OpenPgpPrivateCredentialV1 } from './openpgp-credential.ts'
import type { SegmentKeyResolver } from './segment-key-resolver.ts'
import type { VaultCredentialEventReader, VaultObjectReader } from './store.ts'
import { verifyVaultEvent, type VaultEventVerifier } from './events.ts'

export interface OpenPgpCredentialReaderOptions {
  identityId: IdentityId
  objects: VaultObjectReader
  events: VaultCredentialEventReader
  segmentKeys: SegmentKeyResolver
  verifier: VaultEventVerifier
}

/**
 * Endpoint-only reader for the mail key held in the encrypted vault. It does
 * not add credentials to the JMAP projection and it never exposes a VEK.
 */
export class OpenPgpCredentialReader {
  constructor(private readonly options: OpenPgpCredentialReaderOptions) {
    if (!options.identityId) throw new TypeError('OpenPGP credential reader identity is required')
  }

  /** Returns every verified credential, including historical keys needed to read old mail. */
  async readAll(): Promise<OpenPgpPrivateCredentialV1[]> {
    const events = await this.options.events.readCredentialEvents(this.options.identityId)
    const keys = new Map<SegmentId, Uint8Array>()
    try {
      const credentials: OpenPgpPrivateCredentialV1[] = []
      for (const event of events) {
        if (event.kind !== 'credential.openpgp.set') continue
        if (!(await verifyVaultEvent(event, this.options.verifier))) throw new TypeError('OpenPGP credential event signature is invalid')
        if (event.objectRefs.length !== 1) throw new TypeError('OpenPGP credential event must reference exactly one object')
        const object = await this.options.objects.readObject(this.options.identityId, event.objectRefs[0])
        if (!object) throw new Error('OpenPGP credential object is unavailable; restore is required')
        let segmentKey = keys.get(object.segmentId)
        if (!segmentKey) {
          segmentKey = await this.options.segmentKeys.resolveSegmentKey(this.options.identityId, object.segmentId)
          keys.set(object.segmentId, segmentKey)
        }
        credentials.push(assertOpenPgpCredentialRecord(event, object, await decryptVaultObject(segmentKey, object)))
      }
      return credentials
    } finally {
      for (const key of keys.values()) key.fill(0)
    }
  }

  /**
   * Selects the unique unsuperseded key for new outbound mail. If two keys are
   * independently introduced, fail closed and require an explicit rotation
   * decision instead of silently selecting by local clock order.
   */
  async readCurrent(): Promise<OpenPgpPrivateCredentialV1> {
    const credentials = await this.readAll()
    if (credentials.length === 0) throw new Error('no OpenPGP credential is available')
    const byFingerprint = new Map<string, OpenPgpPrivateCredentialV1>()
    const superseded = new Set<string>()
    for (const credential of credentials) {
      if (byFingerprint.has(credential.fingerprint)) throw new TypeError('duplicate OpenPGP credential fingerprint')
      byFingerprint.set(credential.fingerprint, credential)
      if (credential.supersedesFingerprint) superseded.add(credential.supersedesFingerprint)
    }
    const current = credentials.filter(credential => !superseded.has(credential.fingerprint))
    if (current.length !== 1) throw new Error('OpenPGP current credential is ambiguous; explicit rotation is required')
    return copyCredential(current[0]!)
  }
}

function copyCredential(value: OpenPgpPrivateCredentialV1): OpenPgpPrivateCredentialV1 {
  return { ...value, privateKey: value.privateKey.slice() }
}
