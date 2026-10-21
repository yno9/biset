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
