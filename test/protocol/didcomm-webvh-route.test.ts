// Route selection out of a resolved did:webvh document -- what replaced
// buildRoutingDoc's mediator branches when routing.json was retired
// (2026-09-16). biset no longer BUILDS this document: did.md Wallet writes
// the `#didcomm` service and the device keys through
// `urn:did-core:document-edit:v1`, so the only thing left to pin down on
// this side is how a sender reads it back. Shapes match a live
// `cb81.did.md/.well-known/did.jsonl`.
import { describe, expect, test } from 'bun:test'
import { didCommRouteFromDocument, absoluteKid } from '../../src/protocol/didcomm/webvh-route.ts'
import type { WebvhDidDocument } from '../../src/protocol/webvh/document.ts'

const DID = 'did:webvh:QmScid:alice.example'

function vm(fragment: string) {
  return { id: `${DID}#${fragment}`, type: 'Multikey' as const, controller: DID, publicKeyMultibase: `z6LS${fragment}` }
}

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
    expect(route.keyAgreement?.id).toBe(`${DID}#k_one`)
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
    expect(route.keyAgreement).toBeUndefined()
  })

  test('a keyAgreement reference with no matching verificationMethod resolves to nothing', () => {
    const route = didCommRouteFromDocument(doc({
      verificationMethod: [vm('key-1')],
      keyAgreement: [`${DID}#k_missing`],
      service: [service('#didcomm', 'https://mediator.example')],
    }))
    expect(route.keyAgreement).toBeUndefined()
  })

  test('the newest device wins: Wallet appends rather than rewriting older (offline) devices', () => {
    const route = didCommRouteFromDocument(doc({
      verificationMethod: [vm('k_old'), vm('k_newest')],
      keyAgreement: [`${DID}#k_old`, `${DID}#k_newest`],
      service: [service('#didcomm', 'https://mediator.example')],
    }))
    expect(route.keyAgreement?.id).toBe(`${DID}#k_newest`)
  })

  test('the legacy `#didcomm-biset-<suffix>` form binds one service to one device key', () => {
    const route = didCommRouteFromDocument(doc({
      verificationMethod: [vm('k_old'), vm('k_newest')],
      keyAgreement: [`${DID}#k_old`, `${DID}#k_newest`],
      service: [service('#didcomm-biset-newest', 'https://new.example'), service('#didcomm-biset-old', 'https://old.example')],
    }))
    // Newest SERVICE wins, and it names `k_old` -- so the bound key is used
    // even though a later keyAgreement entry exists.
    expect(route.endpoint?.uri).toBe('https://old.example')
    expect(route.keyAgreement?.id).toBe(`${DID}#k_old`)
  })

  test('keyAgreement may reference a bare #fragment instead of an absolute DID URL', () => {
    const route = didCommRouteFromDocument(doc({
      verificationMethod: [vm('k_one')],
      keyAgreement: ['#k_one'],
      service: [service('#didcomm', 'https://mediator.example')],
    }))
    expect(route.keyAgreement?.id).toBe(`${DID}#k_one`)
  })
})

describe('absoluteKid', () => {
  test('a JWE header needs the absolute DID URL, whichever form the document used', () => {
    const document = doc({})
    expect(absoluteKid(document, '#k_one')).toBe(`${DID}#k_one`)
    expect(absoluteKid(document, `${DID}#k_one`)).toBe(`${DID}#k_one`)
  })
})
