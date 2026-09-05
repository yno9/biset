import { describe, expect, test } from 'bun:test'
import { mailFromForIdentity, identityDomainForMailAddress } from '../../src/client/identity/webvh/identifier.ts'

describe('mail address <-> did:webvh domain (identifier.ts)', () => {
  test('mailFromForIdentity derives {username}@{apexDomain} from a subdomain-per-identity DID', () => {
    expect(mailFromForIdentity('did:webvh:{SCID}:y.biset.md', 'biset.md')).toBe('y@biset.md')
  })

  test('identityDomainForMailAddress is the exact inverse for the canonical bare-apex address', () => {
    expect(identityDomainForMailAddress('y@biset.md', 'biset.md')).toBe('y.biset.md')
  })

  test('identityDomainForMailAddress rejects the old mail.{apexDomain} form -- no back-compat fallback', () => {
    // Bare apex became canonical 2026-09-04 (found live: an external
    // sender's message to user@apexDomain -- what a sender naturally
    // types, and what MX for the bare apex already resolves to -- bounced
    // 550 "no such user" because only the mail.-prefixed form was ever
    // accepted). The old form is just a wrong host now, same as any other.
    expect(() => identityDomainForMailAddress('y@mail.biset.md', 'biset.md')).toThrow(/is not a biset\.md address/)
  })

  test('round-trips for an arbitrary username', () => {
    const did = 'did:webvh:{SCID}:someone.biset.md'
    const address = mailFromForIdentity(did, 'biset.md')
    const { domain } = { domain: identityDomainForMailAddress(address, 'biset.md') }
    expect(`did:webvh:{SCID}:${domain}`).toBe(did)
  })

  test('rejects an address at the wrong apex domain', () => {
    expect(() => identityDomainForMailAddress('y@other.example', 'biset.md')).toThrow(/is not a biset\.md address/)
    expect(() => identityDomainForMailAddress('y@mail.other.example', 'biset.md')).toThrow(/is not a biset\.md address/)
  })

  test('rejects a malformed address', () => {
    expect(() => identityDomainForMailAddress('not-an-address', 'biset.md')).toThrow(/is not a valid mail address/)
    expect(() => identityDomainForMailAddress('@biset.md', 'biset.md')).toThrow(/is not a valid mail address/)
  })
})
