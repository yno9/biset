// Route selection out of a resolved did:webvh document -- what replaced
// buildRoutingDoc's mediator branches when routing.json was retired
// (2026-09-16). biset no longer BUILDS this document: did.md Wallet writes
// the `#didcomm` service and the device keys through
// `urn:did-core:document-edit:v1`, so the only thing left to pin down on
// this side is how a sender reads it back. Shapes match a live
// `cb81.did.md/.well-known/did.jsonl`.
import { describe, expect, test } from 'bun:test'
import { x25519 } from '@noble/curves/ed25519.js'
import { didCommRouteFromDocument, keyAgreementRecipients } from '../../src/protocol/didcomm/webvh-route.ts'
import { encodeX25519Multikey } from '../../src/protocol/didcomm/multikey.ts'
import type { WebvhDidDocument } from '../../src/protocol/webvh/document.ts'

const DID = 'did:webvh:QmScid:alice.example'

const KEYS = new Map<string, Uint8Array>()
function keyOf(fragment: string): Uint8Array {
  if (!KEYS.has(fragment)) KEYS.set(fragment, x25519.getPublicKey(x25519.utils.randomSecretKey()))
  return KEYS.get(fragment)!
}
function vm(fragment: string) {
  return { id: `${DID}#${fragment}`, type: 'Multikey' as const, controller: DID, publicKeyMultibase: encodeX25519Multikey(keyOf(fragment)) }
}
const kids = (route: { recipients: Array<{ kid: string }> }) => route.recipients.map(r => r.kid)

function service(id: string, uri: string, routingKeys: string[] = []) {
  return { id: `${DID}${id}`, type: 'DIDCommMessaging', serviceEndpoint: { uri, accept: ['didcomm/v2'], routingKeys } }
}

function doc(parts: Partial<WebvhDidDocument>): WebvhDidDocument {
  return { '@context': [], id: DID, verificationMethod: [], authentication: [], service: [], alsoKnownAs: [], ...parts }
}

describe('didCommRouteFromDocument', () => {
  test('a mediator-registered identity: routingKeys names the mediator to Forward through', () => {
    const route = didCommRouteFromDocument(doc({
      verificationMethod: [vm('k_one')],
      keyAgreement: [`${DID}#k_one`],
      service: [service('#didcomm', 'https://mediator.example', ['did:peer:2.Ez6Mk...#key-1'])],
    }))
    expect(route.endpoint).toEqual({ uri: 'https://mediator.example', accept: ['didcomm/v2'], routingKeys: ['did:peer:2.Ez6Mk...#key-1'] })
    expect(kids(route)).toEqual([`${DID}#k_one`])
    expect(route.recipients[0]!.publicKey).toEqual(keyOf('k_one'))
  })

  test('no DIDCommMessaging service at all: no endpoint (this identity never enabled DIDComm)', () => {
    const route = didCommRouteFromDocument(doc({ verificationMethod: [vm('k_one')], keyAgreement: [`${DID}#k_one`] }))
    expect(route.endpoint).toBeUndefined()
  })

  test('a verificationMethod NOT referenced from keyAgreement is not a DIDComm key', () => {
    const route = didCommRouteFromDocument(doc({
      verificationMethod: [vm('key-1'), vm('k_one')],
      service: [service('#didcomm', 'https://mediator.example')],
    }))
    expect(route.recipients).toEqual([])
  })

  test('a keyAgreement reference with no matching verificationMethod resolves to nothing', () => {
    const route = didCommRouteFromDocument(doc({
      verificationMethod: [vm('key-1')],
      keyAgreement: [`${DID}#k_missing`],
      service: [service('#didcomm', 'https://mediator.example')],
    }))
    expect(route.recipients).toEqual([])
  })

  test('every device key is a recipient: one message reaches all of them', () => {
    const route = didCommRouteFromDocument(doc({
      verificationMethod: [vm('k_old'), vm('k_newest')],
      keyAgreement: [`${DID}#k_old`, `${DID}#k_newest`],
      service: [service('#didcomm', 'https://mediator.example')],
    }))
    expect(kids(route)).toEqual([`${DID}#k_old`, `${DID}#k_newest`])
  })

  test('a keyAgreement entry that is not X25519 is skipped, not fatal', () => {
    expect(keyAgreementRecipients({
      id: DID,
      keyAgreement: [`${DID}#k_one`, `${DID}#bad`],
      verificationMethod: [vm('k_one'), { id: `${DID}#bad`, publicKeyMultibase: 'z6MkNotX25519' }],
    }).map(r => r.kid)).toEqual([`${DID}#k_one`])
  })

  test('keyAgreement may reference a bare #fragment instead of an absolute DID URL', () => {
    const route = didCommRouteFromDocument(doc({
      verificationMethod: [vm('k_one')],
      keyAgreement: ['#k_one'],
      service: [service('#didcomm', 'https://mediator.example')],
    }))
    expect(kids(route)).toEqual([`${DID}#k_one`])
  })
})

describe('didCommRouteFromDocument -- a mediator with a Tor entrance (PLAN-tor.md D-4/D-5)', () => {
  const ROUTING = ['did:peer:2.Ez6Mk...#key-1']
  const ONION = 'http://4rh3nzidm2dhed4chzyd5je4obqctf5vtocjjnwdmzprqnxmmy55qrid.onion'
  const entry = (uri: string, routingKeys = ROUTING) => ({ uri, accept: ['didcomm/v2'], routingKeys })
  const withSet = (entries: unknown[]) => doc({
    verificationMethod: [vm('k_one')],
    keyAgreement: [`${DID}#k_one`],
    service: [{ id: `${DID}#didcomm`, type: 'DIDCommMessaging', serviceEndpoint: entries as never }],
  })

  test('a non-Tor sender gets the canonical entry, whatever the order', () => {
    expect(didCommRouteFromDocument(withSet([entry('https://mediator.example'), entry(ONION)])).endpoint?.uri).toBe('https://mediator.example')
    expect(didCommRouteFromDocument(withSet([entry(ONION), entry('https://mediator.example')])).endpoint?.uri).toBe('https://mediator.example')
  })

  test('a Tor sender gets the onion entry when it names the same mediator', () => {
    const route = didCommRouteFromDocument(withSet([entry('https://mediator.example'), entry(ONION)]), { preferOnion: true })
    expect(route.endpoint).toEqual(entry(ONION))
  })

  test('a Tor sender falls back to canonical when no onion entry is published', () => {
    expect(didCommRouteFromDocument(withSet([entry('https://mediator.example')]), { preferOnion: true }).endpoint?.uri).toBe('https://mediator.example')
  })

  test('an onion entry with different routingKeys is another mediator and is never used', () => {
    const route = didCommRouteFromDocument(withSet([entry('https://mediator.example'), entry(ONION, ['did:peer:2.Eother#key-1'])]), { preferOnion: true })
    expect(route.endpoint?.uri).toBe('https://mediator.example')
  })

  test('an onion-only set, an empty set or a malformed element yields no route', () => {
    expect(didCommRouteFromDocument(withSet([entry(ONION)]), { preferOnion: true }).endpoint).toBeUndefined()
    expect(didCommRouteFromDocument(withSet([])).endpoint).toBeUndefined()
    expect(didCommRouteFromDocument(withSet([entry('https://mediator.example'), 'https://x'])).endpoint).toBeUndefined()
  })

  test('a single map is unchanged (I-5)', () => {
    expect(didCommRouteFromDocument(doc({ verificationMethod: [vm('k_one')], keyAgreement: [`${DID}#k_one`], service: [service('#didcomm', 'https://mediator.example', ROUTING)] }), { preferOnion: true }).endpoint?.uri).toBe('https://mediator.example')
  })
})
