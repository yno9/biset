import { contactKeyCredentialKind, type ContactKeyV1 } from './contact-key.ts'
import { selectUnsuperseded, VaultCredentialReader, type VaultCredentialReaderOptions } from './credential-store.ts'
import type { VaultCredentialEventReader } from './store.ts'
import { equalBytes } from '../../../protocol/canonical.ts'

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
    const contactKeys = equivalentDuplicatesRemoved(await this.forCounterparty(counterpartyDid), 'duplicate contact key kid')
    if (contactKeys.length === 0) return null
    return copyContactKey(selectUnsuperseded(contactKeys, {
      kidOf: value => value.ownRelationshipKid,
      supersededKidOf: value => value.supersedesKid,
      duplicateMessage: 'duplicate contact key kid',
      ambiguousMessage: 'current contact key is ambiguous; explicit rotation is required',
    }))
  }

  async forOwnKid(ownRelationshipKid: string): Promise<ContactKeyV1 | null> {
    const matches = equivalentDuplicatesRemoved(
      (await this.readAll()).filter(value => value.ownRelationshipKid === ownRelationshipKid),
      'duplicate contact key kid',
    )
    return matches[0] ? copyContactKey(matches[0]) : null
  }

  async forCounterpartyKid(counterpartyRelationshipKid: string): Promise<ContactKeyV1 | null> {
    const matches = equivalentDuplicatesRemoved(
      (await this.readAll()).filter(value => value.counterpartyRelationshipKid === counterpartyRelationshipKid),
      'duplicate counterparty contact key kid',
    )
    return matches[0] ? copyContactKey(matches[0]) : null
  }
}

/** A crossing relationship INIT/ACCEPT race in older clients could commit
 * the same cryptographic relationship twice with different timestamps. It
 * is safe to collapse only those byte-for-byte equivalent credentials;
 * genuinely different relationships retain the existing fail-closed path. */
function equivalentDuplicatesRemoved(values: ContactKeyV1[], error: string): ContactKeyV1[] {
  const unique: ContactKeyV1[] = []
  for (const value of values) {
    const sameKid = unique.find(candidate => candidate.ownRelationshipKid === value.ownRelationshipKid)
    if (!sameKid) { unique.push(value); continue }
    if (!equivalentContactKey(sameKid, value)) throw new TypeError(error)
  }
  return unique
}

function equivalentContactKey(left: ContactKeyV1, right: ContactKeyV1): boolean {
  return left.identityId === right.identityId &&
    left.counterpartyDid === right.counterpartyDid &&
    left.ownRelationshipKid === right.ownRelationshipKid &&
    equalBytes(left.ownX25519PrivateKey, right.ownX25519PrivateKey) &&
    equalBytes(left.ownEd25519PrivateKey, right.ownEd25519PrivateKey) &&
    left.counterpartyRelationshipKid === right.counterpartyRelationshipKid &&
    equalBytes(left.counterpartyPublicKey, right.counterpartyPublicKey) &&
    left.supersedesKid === right.supersedesKid
}

function copyContactKey(value: ContactKeyV1): ContactKeyV1 {
  return contactKeyCredentialKind.copy(value)
}
