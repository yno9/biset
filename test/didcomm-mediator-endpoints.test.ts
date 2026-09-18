// PLAN-tor.md Phase 0-3: the single place that knows a mediator's clearnet
// and (optional) Tor entrances. Pins the alias/onion-detection/selection
// contracts other modules (sameMediatorUrl's aliases, D-5's transport
// choice) will be wired to in later phases.
import { describe, expect, test } from 'bun:test'
import { mediatorAliases, isOnionUrl, preferredMediatorUrl, type MediatorEndpoints } from '../src/client/didcomm/mediator-endpoints.ts'

const canonical = 'https://mediator.biset.md'
const onion = `http://${'a'.repeat(56)}.onion`

describe('mediatorAliases', () => {
  test('clearnet-only mediator has a single alias', () => {
    expect(mediatorAliases({ canonicalUrl: canonical })).toEqual([canonical])
  })

  test('a mediator with an onion entrance lists canonical first', () => {
    expect(mediatorAliases({ canonicalUrl: canonical, onionUrl: onion })).toEqual([canonical, onion])
  })
})

describe('isOnionUrl', () => {
  test('recognizes a .onion host', () => {
    expect(isOnionUrl(onion)).toBe(true)
    expect(isOnionUrl(`${onion}/pickup`)).toBe(true)
  })

  test('rejects clearnet hosts and unparseable input', () => {
    expect(isOnionUrl(canonical)).toBe(false)
    expect(isOnionUrl('https://onion.example')).toBe(false)
    expect(isOnionUrl('not a url')).toBe(false)
    expect(isOnionUrl('')).toBe(false)
  })
})

describe('preferredMediatorUrl', () => {
  const both: MediatorEndpoints = { canonicalUrl: canonical, onionUrl: onion }
  const clearnetOnly: MediatorEndpoints = { canonicalUrl: canonical }

  test('a non-Tor environment always gets canonical, even if onion is published', () => {
    expect(preferredMediatorUrl(both, false)).toBe(canonical)
  })

  test('a Tor environment prefers the onion entrance when one exists', () => {
    expect(preferredMediatorUrl(both, true)).toBe(onion)
  })

  test('a Tor environment falls back to canonical when no onion is published', () => {
    expect(preferredMediatorUrl(clearnetOnly, true)).toBe(canonical)
  })
})
