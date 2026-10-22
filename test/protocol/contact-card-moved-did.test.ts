import { expect, test } from 'vitest'
import { contactCardForDid, didContactUid } from '../../src/client/store/projection/contacts.ts'

const scid = 'QmfJMASJbk8m6aQr1Xobx8BFTBXQ6SThWz3RvFwMpvzh4E'

test('a person who changes their address stays the same contact card', () => {
  const before = `did:webvh:${scid}:kfl.did.md`
  const after = `did:webvh:${scid}:kfl2.did.md`
  expect(didContactUid(before)).toBe(didContactUid(after))
  expect(contactCardForDid([], after)).toBeUndefined()
})
