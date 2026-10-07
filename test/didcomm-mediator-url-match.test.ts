// sameMediatorUrl: whether two spellings name the same mediator endpoint.
// The two strings come from different places (a deployment's `mediatorUrls`
// config, a URL a DID document or the Wallet canonicalized), so a raw `!==`
// rejects a match over nothing but punctuation.
import { describe, expect, test } from 'bun:test'
import { sameMediatorUrl } from '../src/client/didcomm/mediator-endpoints.ts'

describe('sameMediatorUrl', () => {
  test('the same mediator spelled with and without a trailing slash matches', () => {
    // The exact pair a raw `!==` gets wrong.
    expect(sameMediatorUrl('https://mediator.test.example', 'https://mediator.test.example/')).toBe(true)
    expect(sameMediatorUrl('https://mediator.test.example', 'https://mediator.test.example')).toBe(true)
  })

  test('other spellings of one endpoint match', () => {
    expect(sameMediatorUrl('https://mediator.test.example:443/', 'https://mediator.test.example')).toBe(true)
    expect(sameMediatorUrl('https://mediator.test.example/pickup', 'https://mediator.test.example/pickup')).toBe(true)
  })

  test('a genuinely different endpoint never matches', () => {
    expect(sameMediatorUrl('https://mediator.test.example', 'https://other.test.example')).toBe(false)
    expect(sameMediatorUrl('https://mediator.test.example', 'http://mediator.test.example')).toBe(false)
    expect(sameMediatorUrl('https://mediator.test.example', 'https://mediator.test.example:8443')).toBe(false)
    expect(sameMediatorUrl('https://mediator.test.example/pickup', 'https://mediator.test.example/other')).toBe(false)
    // Case sensitivity survives where it must (path), and not where it must
    // not (host) -- the URL parser's job, pinned here so a future
    // hand-rolled normalisation cannot quietly change either answer.
    expect(sameMediatorUrl('https://MEDIATOR.test.example', 'https://mediator.test.example')).toBe(true)
    expect(sameMediatorUrl('https://mediator.test.example/Pickup', 'https://mediator.test.example/pickup')).toBe(false)
  })

  test('matches two entrances only inside one explicitly trusted alias set', () => {
    const canonical = 'https://mediator.test.example'
    const onion = `http://${'a'.repeat(56)}.onion`
    const aliases = [canonical, onion]
    expect(sameMediatorUrl(canonical, onion)).toBe(false)
    expect(sameMediatorUrl(canonical, `${onion}/`, aliases)).toBe(true)
    expect(sameMediatorUrl(onion, `${canonical}:443/`, aliases)).toBe(true)
    expect(sameMediatorUrl(canonical, 'https://other.test.example', aliases)).toBe(false)
    expect(sameMediatorUrl(canonical, `${onion}/other`, aliases)).toBe(false)
    expect(sameMediatorUrl(canonical, onion, [onion])).toBe(false)
    expect(sameMediatorUrl('', '', aliases)).toBe(false)
    expect(sameMediatorUrl(canonical, onion, ['not a url', ...aliases])).toBe(false)
  })

  test('an unparseable spelling is not a match, and does not throw', () => {
    expect(sameMediatorUrl('not a url', 'https://mediator.test.example')).toBe(false)
    expect(sameMediatorUrl('https://mediator.test.example', '')).toBe(false)
    expect(sameMediatorUrl('', '')).toBe(false)
  })
})
