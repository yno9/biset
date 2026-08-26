import type { IdentityId, SegmentId } from '../protocol/ids.ts'
import { decryptVaultObject } from './objects.ts'
import { assertContactKeyRecord, type ContactKeyV1 } from './contact-key.ts'
import type { SegmentKeyResolver } from './segment-key-resolver.ts'
import type { VaultCredentialEventReader, VaultObjectReader } from './store.ts'
import { verifyVaultEvent, type VaultEventVerifier } from './events.ts'

export interface ContactKeyReaderOptions {
  identityId: IdentityId
  objects: VaultObjectReader
  events: VaultCredentialEventReader
  segmentKeys: SegmentKeyResolver
  verifier: VaultEventVerifier
}

export class ContactKeyReader {
  constructor(private readonly options: ContactKeyReaderOptions) {
    if (!options.identityId) throw new TypeError('contact key reader identity is required')
  }

  async readAll(): Promise<ContactKeyV1[]> {
    const events = await this.options.events.readCredentialEvents(this.options.identityId)
    const keys = new Map<SegmentId, Uint8Array>()
    try {
      const contactKeys: ContactKeyV1[] = []
      for (const event of events) {
        if (event.kind !== 'contact-key.set') continue
        if (!(await verifyVaultEvent(event, this.options.verifier))) throw new TypeError('contact key event signature is invalid')
        if (event.objectRefs.length !== 1) throw new TypeError('contact key event must reference exactly one object')
        const object = await this.options.objects.readObject(this.options.identityId, event.objectRefs[0])
        if (!object) throw new Error('contact key object is unavailable; restore is required')
        let segmentKey = keys.get(object.segmentId)
        if (!segmentKey) {
          segmentKey = await this.options.segmentKeys.resolveSegmentKey(this.options.identityId, object.segmentId)
          keys.set(object.segmentId, segmentKey)
        }
        contactKeys.push(assertContactKeyRecord(event, object, await decryptVaultObject(segmentKey, object)))
      }
      return contactKeys
    } finally {
      for (const key of keys.values()) key.fill(0)
    }
  }

  async forCounterparty(counterpartyDid: string): Promise<ContactKeyV1[]> {
    return (await this.readAll()).filter(value => value.counterpartyDid === counterpartyDid).map(copyContactKey)
  }

  async currentFor(counterpartyDid: string): Promise<ContactKeyV1 | null> {
    const contactKeys = await this.forCounterparty(counterpartyDid)
    if (contactKeys.length === 0) return null
    const byKid = new Map<string, ContactKeyV1>()
    const superseded = new Set<string>()
    for (const contactKey of contactKeys) {
      if (byKid.has(contactKey.ownRelationshipKid)) throw new TypeError('duplicate contact key kid')
      byKid.set(contactKey.ownRelationshipKid, contactKey)
      if (contactKey.supersedesKid) superseded.add(contactKey.supersedesKid)
    }
    const current = contactKeys.filter(value => !superseded.has(value.ownRelationshipKid))
    if (current.length !== 1) throw new Error('current contact key is ambiguous; explicit rotation is required')
    return copyContactKey(current[0]!)
  }

  async forOwnKid(ownRelationshipKid: string): Promise<ContactKeyV1 | null> {
    const matches = (await this.readAll()).filter(value => value.ownRelationshipKid === ownRelationshipKid)
    if (matches.length > 1) throw new TypeError('duplicate contact key kid')
    return matches[0] ? copyContactKey(matches[0]) : null
  }

  async forCounterpartyKid(counterpartyRelationshipKid: string): Promise<ContactKeyV1 | null> {
    const matches = (await this.readAll()).filter(value => value.counterpartyRelationshipKid === counterpartyRelationshipKid)
    if (matches.length > 1) throw new TypeError('duplicate counterparty contact key kid')
    return matches[0] ? copyContactKey(matches[0]) : null
  }
}

function copyContactKey(value: ContactKeyV1): ContactKeyV1 {
  return {
    ...value,
    ownX25519PrivateKey: value.ownX25519PrivateKey.slice(),
    ownEd25519PrivateKey: value.ownEd25519PrivateKey.slice(),
    counterpartyPublicKey: value.counterpartyPublicKey.slice(),
  }
}
