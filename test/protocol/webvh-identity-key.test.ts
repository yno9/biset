import { expect, test } from 'vitest'
import { identityKey, sameIdentity, scidOf } from '../../src/protocol/webvh/identifier.ts'

const scid = 'QmfJMASJbk8m6aQr1Xobx8BFTBXQ6SThWz3RvFwMpvzh4E'
const old = `did:webvh:${scid}:kfl.did.md`
const moved = `did:webvh:${scid}:kfl2.did.md`

test('the SCID is the part that survives a move to another host', () => {
  expect(scidOf(old)).toBe(scid)
  expect(sameIdentity(old, moved)).toBe(true)
  expect(identityKey(old)).toBe(identityKey(moved))
  expect(identityKey(old)).toBe(`did:webvh:${scid}`)
})

test('another SCID, or another DID method, is another identity', () => {
  expect(sameIdentity(old, `did:webvh:Qm${'x'.repeat(44)}:kfl.did.md`)).toBe(false)
  expect(scidOf('did:web:example.com')).toBeUndefined()
  expect(identityKey('did:web:example.com')).toBe('did:web:example.com')
  expect(sameIdentity('did:web:example.com', 'did:web:example.com')).toBe(true)
})
