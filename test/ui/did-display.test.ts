import { afterEach, expect, test } from 'vitest'
import { avatarOf, displayName, labelForDid, setContactAvatars, setContactNames, setOwnDid, setVerifiedAddresses } from '../../src/client/app/ui/did-display.ts'
import { randomDisplayName } from '../../src/client/app/ui/account/default-name.ts'
import { identityKey } from '../../src/protocol/vh/identifier.ts'

const SCID = 'QmafKp1jjhnP1vjDYZs6rpQ7bk3mQBS2hQvwGbqc2UAEYi'
const ALICE = `did:vh:${SCID}`

afterEach(() => { setVerifiedAddresses(new Map()); setContactNames(new Map()); setContactAvatars(new Map()); setOwnDid(undefined) })

test('a mail bridge DID is shown as the mail address it stands for', () => {
  expect(labelForDid('did:web:did.md:nine.testrun.org:hrdcv7qkr')).toBe('hrdcv7qkr@nine.testrun.org')
  expect(labelForDid('did:web:did.md:gmail.com:bob%2Bnews')).toBe('bob+news@gmail.com')
})

test('a did:vh is its address once one was verified for it; anything else stays as it is', () => {
  expect(labelForDid(ALICE)).toBe(ALICE)
  setVerifiedAddresses(new Map([[ALICE, 'alice@did.md']]))
  expect(labelForDid(ALICE)).toBe('alice@did.md')
  expect(labelForDid(`${ALICE}#key-1`)).toBe('alice@did.md')
  expect(labelForDid('bob@x.test')).toBe('bob@x.test')
})

// What a screen shows for an identity: the name, else the verified address, never an invented one.
test('a contact shows its name, else its verified address', () => {
  setVerifiedAddresses(new Map([[ALICE, 'alice@did.md']]))
  expect(displayName(ALICE)).toBe('alice@did.md')
  setContactNames(new Map([[ALICE, 'Alice']]))
  expect(displayName(ALICE)).toBe('Alice')
  expect(displayName(`${ALICE}#key-1`)).toBe('Alice') // the same person under a fragment: the name is found by key too
})

test('this identity\'s own DID shows its verified address, and its card name once it has one', () => {
  setOwnDid(ALICE)
  expect(displayName(identityKey(ALICE))).toBe(ALICE) // nobody verified an address: the raw string
  setVerifiedAddresses(new Map([[ALICE, 'alice@did.md']]))
  expect(displayName(identityKey(ALICE))).toBe('alice@did.md')
  setContactNames(new Map([[ALICE, 'Quiet Heron']]))
  expect(displayName(ALICE)).toBe('Quiet Heron')
})

test('a mail bridge DID shows its mail address, and a picture is found by key', () => {
  expect(displayName('did:web:did.md:gmail.com:n')).toBe('n@gmail.com')
  setContactAvatars(new Map([[ALICE, 'data:image/png;base64,AA']]))
  expect(avatarOf(ALICE)).toBe('data:image/png;base64,AA')
  expect(avatarOf(`${ALICE}#key-1`)).toBe('data:image/png;base64,AA')
})

test('a random display name is two capitalised English words, and it varies', () => {
  const names = Array.from({ length: 300 }, () => randomDisplayName())
  for (const name of names) expect(name).toMatch(/^[A-Z][a-z]+ [A-Z][a-z]+$/)
  expect(new Set(names).size).toBeGreaterThan(200)
})
