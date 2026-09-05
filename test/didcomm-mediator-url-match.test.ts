// Regression coverage for the relationship handler's "did this message
// really arrive from the mediator its did:peer names?" check
// (main.ts's handleRelationshipMessage / handleWalletRelationshipMessage).
//
// The two strings being compared reach that check from different places:
// route.url is whatever the peer minted into its did:peer:2 service
// endpoint, mediatorUrl is whatever this device's own `mediatorUrls` config
// spells. The local-identity path used to compare them raw (`route.url !==
// mediatorUrl`), so a config entry that differed only in a trailing slash
// rejected every relationship INIT/ACCEPT from that mediator -- a handshake
// that can never complete, on nothing but punctuation. Both paths now go
// through sameMediatorUrl.
import { describe, expect, test } from 'bun:test'
import { generatePeerIdentity } from '../src/shared/didcomm/peer.ts'
import { relationshipMediatorService } from '../src/shared/didcomm/relationship.ts'
import { sameMediatorUrl } from '../src/shared/didcomm/mediator-watch.ts'

describe('sameMediatorUrl', () => {
  test('a did:peer service endpoint matches the same mediator spelled with a trailing slash', () => {
    const routing = generatePeerIdentity()
    const peer = generatePeerIdentity({ uri: 'https://mediator.test.example', routingKeys: [routing.xKid] })
    const route = relationshipMediatorService(peer.xKid)
    expect(route.url).toBe('https://mediator.test.example')

    // The exact pair a raw `!==` gets wrong.
    expect(sameMediatorUrl(route.url, 'https://mediator.test.example/')).toBe(true)
    expect(sameMediatorUrl(route.url, 'https://mediator.test.example')).toBe(true)
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

  test('an unparseable spelling is not a match, and does not throw', () => {
    expect(sameMediatorUrl('not a url', 'https://mediator.test.example')).toBe(false)
    expect(sameMediatorUrl('https://mediator.test.example', '')).toBe(false)
    expect(sameMediatorUrl('', '')).toBe(false)
  })
})
