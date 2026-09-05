import { contactKeyCredentialKind, type ContactKeyV1 } from './contact-key.ts'
import { selectUnsuperseded, VaultCredentialReader, type VaultCredentialReaderOptions } from './credential-store.ts'
import type { VaultCredentialEventReader } from './store.ts'

/** Unchanged shape, now defined once in credential-store.ts. */
export type ContactKeyReaderOptions = VaultCredentialReaderOptions<VaultCredentialEventReader>

export class ContactKeyReader {
  private readonly reader: VaultCredentialReader<ContactKeyV1, VaultCredentialEventReader>

  constructor(options: ContactKeyReaderOptions) {
    this.reader = new VaultCredentialReader(contactKeyCredentialKind, options)
  }

  async readAll(): Promise<ContactKeyV1[]> {
    return this.reader.readAll()
  }

  async forCounterparty(counterpartyDid: string): Promise<ContactKeyV1[]> {
    return (await this.readAll()).filter(value => value.counterpartyDid === counterpartyDid).map(copyContactKey)
  }

  /**
   * Selects the unique unsuperseded relationship key for one counterparty.
   * Fails closed when two generations were introduced independently -- see
   * `selectUnsuperseded`.
   */
  async currentFor(counterpartyDid: string): Promise<ContactKeyV1 | null> {
    const contactKeys = await this.forCounterparty(counterpartyDid)
    if (contactKeys.length === 0) return null
    return copyContactKey(selectUnsuperseded(contactKeys, {
      kidOf: value => value.ownRelationshipKid,
      supersededKidOf: value => value.supersedesKid,
      duplicateMessage: 'duplicate contact key kid',
      ambiguousMessage: 'current contact key is ambiguous; explicit rotation is required',
    }))
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
  return contactKeyCredentialKind.copy(value)
}
