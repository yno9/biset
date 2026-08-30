import { describe, expect, test } from 'bun:test'
import { mailFromForIdentity, identityDomainForMailAddress } from '../../src/identity/webvh/identifier.ts'

describe('mail address <-> did:webvh domain (identifier.ts)', () => {
  test('mailFromForIdentity derives {username}@mail.{apexDomain} from a subdomain-per-identity DID', () => {
    expect(mailFromForIdentity('did:webvh:{SCID}:y.biset.md', 'biset.md')).toBe('y@mail.biset.md')
  })

  test('identityDomainForMailAddress is the exact inverse', () => {
    expect(identityDomainForMailAddress('y@mail.biset.md', 'biset.md')).toBe('y.biset.md')
  })

  test('round-trips for an arbitrary username', () => {
    const did = 'did:webvh:{SCID}:someone.biset.md'
    const address = mailFromForIdentity(did, 'biset.md')
    const { domain } = { domain: identityDomainForMailAddress(address, 'biset.md') }
    expect(`did:webvh:{SCID}:${domain}`).toBe(did)
  })

  test('rejects an address at the wrong apex domain', () => {
    expect(() => identityDomainForMailAddress('y@mail.other.example', 'biset.md')).toThrow(/is not a mail\.biset\.md address/)
  })

  test('rejects a malformed address', () => {
    expect(() => identityDomainForMailAddress('not-an-address', 'biset.md')).toThrow(/is not a valid mail address/)
    expect(() => identityDomainForMailAddress('@mail.biset.md', 'biset.md')).toThrow(/is not a valid mail address/)
  })
})
