// A did:vh DID is its own identity key: nothing in it moves.
import { expect, test } from 'vitest'
import { identityKey, sameIdentity, vhScidOf } from '../../src/protocol/vh/identifier.ts'
import { sameIdentity as sameClientIdentity } from '../../src/client/identity/idkey.ts'
import { isScid, isVhDid, parseVhDid } from '../../src/protocol/vh/identifier.ts'

const scid = 'QmfJMASJbk8m6aQr1Xobx8BFTBXQ6SThWz3RvFwMpvzh4E'
const vh = `did:vh:${scid}`

test('did:vh syntax: the whole identifier is a 46-character base58btc SCID', () => {
  expect(isVhDid(vh)).toBe(true)
  expect(parseVhDid(vh).scid).toBe(scid)
  expect(isScid(scid)).toBe(true)
  for (const bad of ['did:vh:', 'did:vh:short', `${vh}#k`, `${vh}?src=https://a.example`, `${vh}:x`, `did:vh:${'0'.repeat(46)}`]) {
    expect(isVhDid(bad), bad).toBe(false)
  }
  expect(() => parseVhDid('did:vh:nope')).toThrow()
})

test('a did:vh is its own identity key, and the same identity only as itself', () => {
  expect(identityKey(vh)).toBe(vh)
  expect(vhScidOf(vh)).toBe(scid)
  expect(sameIdentity(vh, vh)).toBe(true)
  expect(sameClientIdentity(vh, vh)).toBe(true)
  expect(sameIdentity(vh, `did:vh:${'Q'.repeat(46)}`)).toBe(false)
  expect(sameClientIdentity(vh, `did:vh:${'Q'.repeat(46)}`)).toBe(false)
})
