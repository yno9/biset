import { contactKeyCredentialKind, contactKeyRef, type ContactKeyV1 } from './contact-key.ts'
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
   * Fails closed when two were introduced independently -- see
   * `selectUnsuperseded`.
   */
  async currentFor(counterpartyDid: string): Promise<ContactKeyV1 | null> {
    const contactKeys = equivalentDuplicatesRemoved(await this.forCounterparty(counterpartyDid), 'duplicate contact key kid')
    if (contactKeys.length === 0) return null
    return copyContactKey(selectUnsuperseded(contactKeys, {
      kidOf: (value: ContactKeyV1) => contactKeyRef(value),
      supersededKidOf: (value: ContactKeyV1) => value.supersedes ? contactKeyRef(value.supersedes) : undefined,
      duplicateMessage: 'duplicate contact key kid',
      ambiguousMessage: 'current contact key is ambiguous; explicit rotation is required',
    }))
  }

  /** The newest record using this own kid -- current or superseded, since
   * mail can still arrive at a kid this side has rotated away from. Every
   * record sharing an own kid shares its private key. */
  async forOwnKid(ownRelationshipKid: string): Promise<ContactKeyV1 | null> {
    return newestAgreeing((await this.readAll()).filter(value => value.ownRelationshipKid === ownRelationshipKid), 'own contact key kid is ambiguous')
  }

  /** The newest record naming this counterparty kid, current or superseded. */
  async forCounterpartyKid(counterpartyRelationshipKid: string): Promise<ContactKeyV1 | null> {
    return newestAgreeing((await this.readAll()).filter(value => value.counterpartyRelationshipKid === counterpartyRelationshipKid), 'counterparty contact key kid is ambiguous')
  }

  /** The relationship whose CURRENT counterparty kid this is -- the only
   * one a message from that kid may be attributed to. Once a counterparty
   * moved to a new did:peer (a front-door INIT, after it removed a device),
   * its old kid is no longer that counterparty: a removed device still holds
   * the old key and could keep using it. */
  async currentForCounterpartyKid(counterpartyRelationshipKid: string): Promise<ContactKeyV1 | null> {
    const named = await this.forCounterpartyKid(counterpartyRelationshipKid)
    if (!named) return null
    const current = await this.currentFor(named.counterpartyDid)
    return current?.counterpartyRelationshipKid === counterpartyRelationshipKid ? current : null
  }
}

/** A crossing relationship INIT/ACCEPT race in older clients could commit
 * the same cryptographic relationship twice with different timestamps. It
 * is safe to collapse only those byte-for-byte equivalent credentials;
 * genuinely different relationships retain the existing fail-closed path. */
function equivalentDuplicatesRemoved(values: ContactKeyV1[], error: string): ContactKeyV1[] {
  const unique: ContactKeyV1[] = []
  for (const value of values) {
    const sameKid = unique.find(candidate => contactKeyRef(candidate) === contactKeyRef(value))
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
    (left.supersedes ? contactKeyRef(left.supersedes) : '') === (right.supersedes ? contactKeyRef(right.supersedes) : '') &&
    left.seedId === right.seedId
}

/** Records sharing one kid must agree on who the counterparty is and on
 * this side's private keys; past that, the newest one is the answer. */
function newestAgreeing(values: ContactKeyV1[], error: string): ContactKeyV1 | null {
  if (values.length === 0) return null
  const [first] = values
  if (values.some(value => value.counterpartyDid !== first!.counterpartyDid)) throw new TypeError(error)
  const newest = [...values].sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt))[0]!
  return copyContactKey(newest)
}

function copyContactKey(value: ContactKeyV1): ContactKeyV1 {
  return contactKeyCredentialKind.copy(value)
}
