import type { IdentityId, SegmentId } from '../protocol/ids.ts'
import { decryptVaultObject } from './objects.ts'
import { assertMailRelationshipCredentialRecord, type MailRelationshipCredentialV1 } from './mail-relationship-credential.ts'
import type { SegmentKeyResolver } from './segment-key-resolver.ts'
import type { VaultCredentialEventReader, VaultObjectReader } from './store.ts'
import { verifyVaultEvent, type VaultEventVerifier } from './events.ts'

export interface MailRelationshipCredentialReaderOptions {
  identityId: IdentityId
  objects: VaultObjectReader
  events: VaultCredentialEventReader
  segmentKeys: SegmentKeyResolver
  verifier: VaultEventVerifier
}

/**
 * Endpoint-only reader for this identity's private per-mail-mediator
 * relationship credentials -- same shape as
 * vault/didcomm-credential-reader.ts, except selecting the current
 * credential is scoped BY mediatorUrl (there can be several, one per
 * mediator this identity has bound a route with), not identity-wide.
 */
export class MailRelationshipCredentialReader {
  constructor(private readonly options: MailRelationshipCredentialReaderOptions) {
    if (!options.identityId) throw new TypeError('mail relationship credential reader identity is required')
  }

  /** Returns every verified credential across every mediator, including
   * historical keys superseded by a rotation. */
  async readAll(): Promise<MailRelationshipCredentialV1[]> {
    const events = await this.options.events.readCredentialEvents(this.options.identityId)
    const keys = new Map<SegmentId, Uint8Array>()
    try {
      const credentials: MailRelationshipCredentialV1[] = []
      for (const event of events) {
        if (event.kind !== 'credential.mail-relationship.set') continue
        if (!(await verifyVaultEvent(event, this.options.verifier))) throw new TypeError('mail relationship credential event signature is invalid')
        if (event.objectRefs.length !== 1) throw new TypeError('mail relationship credential event must reference exactly one object')
        const object = await this.options.objects.readObject(this.options.identityId, event.objectRefs[0])
        if (!object) throw new Error('mail relationship credential object is unavailable; restore is required')
        let segmentKey = keys.get(object.segmentId)
        if (!segmentKey) {
          segmentKey = await this.options.segmentKeys.resolveSegmentKey(this.options.identityId, object.segmentId)
          keys.set(object.segmentId, segmentKey)
        }
        credentials.push(assertMailRelationshipCredentialRecord(event, object, await decryptVaultObject(segmentKey, object)))
      }
      return credentials
    } finally {
      for (const key of keys.values()) key.fill(0)
    }
  }

  /**
   * Selects the unique unsuperseded relationship credential for ONE
   * mediator. Undefined means no route has ever been bound with this
   * mediator yet -- the caller should mint a fresh one (route-bind).
   * Fails closed (same as didcomm-credential-reader.ts's readCurrent) if
   * two devices raced to mint one before either had synced the other's.
   */
  async readCurrentFor(mediatorUrl: string): Promise<MailRelationshipCredentialV1 | undefined> {
    const all = (await this.readAll()).filter(c => c.mediatorUrl === mediatorUrl)
    if (all.length === 0) return undefined
    const byDid = new Map<string, MailRelationshipCredentialV1>()
    const superseded = new Set<string>()
    for (const credential of all) {
      if (byDid.has(credential.relationshipDid)) throw new TypeError('duplicate mail relationship credential')
      byDid.set(credential.relationshipDid, credential)
      if (credential.supersedesRelationshipDid) superseded.add(credential.supersedesRelationshipDid)
    }
    const current = all.filter(credential => !superseded.has(credential.relationshipDid))
    if (current.length !== 1) throw new Error('mail relationship current credential is ambiguous; explicit rotation is required')
    return copyCredential(current[0]!)
  }
}

function copyCredential(value: MailRelationshipCredentialV1): MailRelationshipCredentialV1 {
  return { ...value, privateKey: value.privateKey.slice(), edPrivateKey: value.edPrivateKey.slice() }
}
