import { expect, test } from 'vitest'
import { labelForDid } from '../../src/client/app/ui/did-display.ts'

test('a mail bridge DID is shown as the mail address it stands for', () => {
  expect(labelForDid('did:web:did.md:nine.testrun.org:hrdcv7qkr')).toBe('hrdcv7qkr@nine.testrun.org')
  expect(labelForDid('did:web:did.md:gmail.com:bob%2Bnews')).toBe('bob+news@gmail.com')
})

test('a did:webvh of this system is its address, anything else stays as it is', () => {
  expect(labelForDid('did:webvh:QmafKp1jjhnP1vjDYZs6rpQ7bk3mQBS2hQvwGbqc2UAEYi:alice.did.md')).toBe('alice@did.md')
  expect(labelForDid('bob@x.test')).toBe('bob@x.test')
})

// What a screen shows for an identity key (`did:webvh:<SCID>`, no host): the name, else the address, never the key.
import { setContactDids, setContactNames, displayName, avatarOf, setContactAvatars } from '../../src/client/app/ui/did-display.ts'
import { setOwnDid } from '../../src/client/app/ui/did-display.ts'
import { identityKey } from '../../src/protocol/webvh/identifier.ts'

const SCID = 'QmafKp1jjhnP1vjDYZs6rpQ7bk3mQBS2hQvwGbqc2UAEYi'
const ALICE = `did:webvh:${SCID}:alice.did.md`

test('an identity key shows the contact\'s name, else the address the contact\'s DID stands for', () => {
  const key = identityKey(ALICE)
  setContactNames(new Map())
  setContactDids(new Map([[key, ALICE]]))
  expect(displayName(key)).toBe('alice@did.md')
  setContactNames(new Map([[key, 'Alice']]))
  expect(displayName(key)).toBe('Alice')
  expect(displayName(ALICE)).toBe('Alice') // the same person under her full DID: the name is found by key too
  setContactNames(new Map())
  setContactDids(new Map())
})

test('a card that names its person by the key itself (this identity\'s own card) does not hide the address', () => {
  const key = identityKey(ALICE)
  setOwnDid(ALICE)
  setContactNames(new Map())
  setContactDids(new Map([[key, key]])) // the own card's public DID is the key: no host, no help
  expect(displayName(key)).toBe(defaultDisplayName(SCID))
  setOwnDid(undefined)
  expect(displayName(key)).toBe(key)
  setContactDids(new Map())
})

test('this identity\'s own key shows its default name even with no contact card', () => {
  setOwnDid(ALICE)
  expect(displayName(identityKey(ALICE))).toBe(defaultDisplayName(SCID))
  setOwnDid(undefined)
  expect(displayName(identityKey(ALICE))).toBe(identityKey(ALICE)) // nobody knows it: the raw string, as before
})

test('a mail bridge DID shows its mail address, and a picture is found by key', () => {
  expect(displayName('did:web:did.md:gmail.com:n')).toBe('n@gmail.com')
  setContactAvatars(new Map([[identityKey(ALICE), 'data:image/png;base64,AA']]))
  expect(avatarOf(ALICE)).toBe('data:image/png;base64,AA')
  expect(avatarOf(identityKey(ALICE))).toBe('data:image/png;base64,AA')
  setContactAvatars(new Map())
})

import { defaultDisplayName } from '../../src/client/app/ui/account/default-name.ts'
import { ownDefaultName } from '../../src/client/app/ui/did-display.ts'

test('a default display name is two English words, the same for the same SCID, and differs across SCIDs', () => {
  const name = defaultDisplayName(SCID)
  expect(name).toMatch(/^[A-Z][a-z]+ [A-Z][a-z]+$/)
  expect(defaultDisplayName(SCID)).toBe(name)
  const names = new Set(Array.from({ length: 200 }, (_, index) => defaultDisplayName(`Qm${index}x`)))
  expect(names.size).toBeGreaterThan(150)
})

test('this identity without a chosen name is shown by its default name, wherever its key or DID is shown', () => {
  setOwnDid(ALICE)
  setContactNames(new Map())
  setContactDids(new Map())
  const name = defaultDisplayName(SCID)
  expect(ownDefaultName()).toBe(name)
  expect(displayName(identityKey(ALICE))).toBe(name)
  expect(displayName(ALICE)).toBe(name)
  setContactNames(new Map([[identityKey(ALICE), 'Alice']]))
  expect(displayName(ALICE)).toBe('Alice') // a name the identity chose wins
  setContactNames(new Map())
  setOwnDid(undefined)
})
