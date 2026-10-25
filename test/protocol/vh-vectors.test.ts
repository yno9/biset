// did:vh vectors shared with dito's packages/vh (copied from packages/vh/vectors/vectors.json there): two independent
// implementations must give every log the same verdict and the same error code.
import { expect, test } from 'vitest'
import vectors from '../fixtures/did-vh-vectors.json'
import { resolveVhEntries } from '../../src/protocol/vh/resolver.ts'
import type { LogEntry } from '../../src/protocol/webvh/log.ts'

type Expectation = { ok: true; versionNumber: number; deactivated: boolean; documentNull?: boolean } | { ok: false; code: string; reason: string }
const file = vectors as unknown as { now: string; vectors: Array<{ name: string; note: string; did: string; log: unknown[]; options?: Record<string, unknown>; expect: Expectation }> }

test('the vectors are the ones dito generated, and cover both verdicts', () => {
  expect(file.vectors.length).toBeGreaterThanOrEqual(30)
  expect(file.vectors.filter(vector => vector.expect.ok).length).toBeGreaterThanOrEqual(6)
  expect(file.vectors.filter(vector => !vector.expect.ok).length).toBeGreaterThanOrEqual(25)
})

for (const vector of file.vectors) {
  test(`vector ${vector.name}: ${vector.note}`, () => {
    const run = () => resolveVhEntries(vector.did, vector.log as LogEntry[], { ...(vector.options as object | undefined), now: Date.parse(file.now) })
    if (vector.expect.ok) {
      const resolved = run()
      expect(resolved.versionNumber).toBe(vector.expect.versionNumber)
      expect(resolved.deactivated).toBe(vector.expect.deactivated)
      expect(resolved.doc === null).toBe(vector.expect.documentNull === true)
    } else {
      expect(run).toThrow(expect.objectContaining({ name: 'VhResolutionError', code: vector.expect.code }))
    }
  })
}

// ---- the did:web shadow ----------------------------------------------------------------------------------------------

import { checkDidWebShadow, didWebCandidates, didWebDocumentUrl, verifiedAddress } from '../../src/protocol/vh/didweb.ts'

const shadows = (vectors as unknown as { shadows: Array<{ name: string; note: string; vhDocument: Record<string, unknown>; didWeb: string; webDocument: unknown; ok: boolean }> }).shadows

test('the shadow vectors are there', () => {
  expect(shadows.filter(vector => vector.ok).length).toBeGreaterThanOrEqual(1)
  expect(shadows.filter(vector => !vector.ok).length).toBeGreaterThanOrEqual(10)
})

for (const vector of shadows) {
  test(`shadow ${vector.name}: ${vector.note}`, () => {
    expect(checkDidWebShadow(vector.vhDocument, vector.didWeb, vector.webDocument).ok).toBe(vector.ok)
  })
}

test('a verified did:vh identity goes by the address of its did:web DID; an unverified one by none', () => {
  const valid = shadows.find(vector => vector.name === 'valid/derived')!
  expect(verifiedAddress(valid.vhDocument, valid.didWeb, valid.webDocument)).toBe('alice@did.md')
  const forged = shadows.find(vector => vector.name === 'invalid/extra-service')!
  expect(verifiedAddress(forged.vhDocument, forged.didWeb, forged.webDocument)).toBeUndefined()
  expect(didWebCandidates(valid.vhDocument)).toEqual(['did:web:alice.did.md'])
  expect(didWebCandidates({ alsoKnownAs: ['did:web:example.com:dids:x', 'did:web:localhost%3A3000', 'did:web:alice.did.md', 'https://x'] })).toEqual(['did:web:alice.did.md'])
  expect(didWebDocumentUrl('did:web:alice.did.md')).toBe('https://alice.did.md/.well-known/did.json')
  expect(() => didWebDocumentUrl('did:web:example.com:dids:x')).toThrow()
  // A host of two labels has no name in it: no address is invented.
  expect(verifiedAddress({ id: `did:vh:${'Q'.repeat(46)}`, alsoKnownAs: ['did:web:example.com'] }, 'did:web:example.com', { id: 'did:web:example.com', alsoKnownAs: [`did:vh:${'Q'.repeat(46)}`] })).toBeUndefined()
})
