import { describe, expect, test } from 'vitest'
import { assertMatchesSchema, type JSONSchema } from '../../src/client/identity/wallet/json-schema.ts'
import capabilitySchema from '../../src/client/identity/wallet/schemas/biset-messenger-capability.schema.json' with { type: 'json' }

// PLAN3 (~/did.md/PLAN3-oid4vp-transport.md): the capability is a VC-DM 2.0
// credential with an embedded proof -- RP-owned content (audience/scope/
// deviceJkt/issuedAt/expiresAt/authorizationDetails) lives under
// credentialSubject, not at the top level.
function validCapabilityCredential(overrides: { type?: string; topLevel?: Record<string, unknown>; subject?: Record<string, unknown> } = {}) {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: 'urn:uuid:11111111-1111-4111-8111-111111111111',
    type: ['VerifiableCredential', overrides.type ?? 'biset.md/MessengerCapability'],
    issuer: 'did:vh:abc',
    credentialSubject: {
      audience: 'redirect_uri:https://biset.example/wallet/callback',
      deviceJkt: 'A'.repeat(43),
      scope: ['biset:device', 'biset:vault'],
      issuedAt: '2026-09-05T00:00:00.000Z',
      expiresAt: '2030-01-01T00:00:00.000Z',
      authorizationDetails: [
        { type: 'urn:did-core:document-edit:v1', services: [], verificationMethods: [], remove: [] },
      ],
      ...overrides.subject,
    },
    proof: {
      type: 'DataIntegrityProof', cryptosuite: 'eddsa-jcs-2022', proofPurpose: 'authentication',
      verificationMethod: 'did:vh:abc#pass-1', proofValue: 'zStubProofValue',
    },
    ...overrides.topLevel,
  }
}

describe('json-schema.ts (interpretive validator, used against biset-messenger-capability.schema.json)', () => {
  test('a well-formed capability credential is accepted', () => {
    expect(() => assertMatchesSchema(capabilitySchema as JSONSchema, validCapabilityCredential(), 'credential')).not.toThrow()
  })

  test('an unrecognized type is rejected', () => {
    expect(() => assertMatchesSchema(capabilitySchema as JSONSchema, validCapabilityCredential({ type: 'acme.example/SomethingElse' }), 'credential')).toThrow(/expected one of/)
  })

  test('a Tor hidden service callback is an audience, over http', () => {
    const onion = `${'a'.repeat(56)}.onion`
    expect(() => assertMatchesSchema(capabilitySchema as JSONSchema, validCapabilityCredential({ subject: { audience: `redirect_uri:http://${onion}/wallet/callback` } }), 'credential')).not.toThrow()
    expect(() => assertMatchesSchema(capabilitySchema as JSONSchema, validCapabilityCredential({ subject: { audience: 'redirect_uri:http://evil.example/wallet/callback' } }), 'credential')).toThrow()
  })

  test('only a redirect_uri Client Identifier is an audience', () => {
    for (const audience of ['client_abcdefghijklmnopqrstuvwxyzABCDEF', 'did:vh:QmaQdf3VFoXtk7WjfP2rhmKAvMNinLh4qU1bjZ4mPDzVr6', 'redirect_uri:http://biset.example/wallet/callback']) {
      expect(() => assertMatchesSchema(capabilitySchema as JSONSchema, validCapabilityCredential({ subject: { audience } }), 'credential')).toThrow()
    }
  })

  test('a missing required subject field is rejected', () => {
    const credential = validCapabilityCredential()
    delete (credential.credentialSubject as Record<string, unknown>).deviceJkt
    expect(() => assertMatchesSchema(capabilitySchema as JSONSchema, credential, 'credential')).toThrow(/required property is missing/)
  })

  test('an unexpected extra subject field is rejected (additionalProperties: false)', () => {
    expect(() => assertMatchesSchema(capabilitySchema as JSONSchema, validCapabilityCredential({ subject: { extra: 'nope' } }), 'credential')).toThrow(/unexpected property/)
  })

  test('a malformed deviceJkt (wrong pattern) is rejected', () => {
    expect(() => assertMatchesSchema(capabilitySchema as JSONSchema, validCapabilityCredential({ subject: { deviceJkt: 'not-a-thumbprint' } }), 'credential')).toThrow(/does not match pattern/)
  })

  test('a capability with no authorizationDetails (nothing was requested) is accepted', () => {
    const credential = validCapabilityCredential()
    delete (credential.credentialSubject as Record<string, unknown>).authorizationDetails
    expect(() => assertMatchesSchema(capabilitySchema as JSONSchema, credential, 'credential')).not.toThrow()
  })

  test('an authorizationDetails item matching none of the known detail types is rejected', () => {
    expect(() => assertMatchesSchema(capabilitySchema as JSONSchema, validCapabilityCredential({ subject: { authorizationDetails: [{ type: 'urn:unknown:v1' }] } }), 'credential')).toThrow(/oneOf branch/)
  })

  test('every error is reported, not just the first', () => {
    const credential = validCapabilityCredential({ topLevel: { type: ['NotVerifiableCredential', 'biset.md/MessengerCapability'] } })
    delete (credential.credentialSubject as Record<string, unknown>).deviceJkt
    try {
      assertMatchesSchema(capabilitySchema as JSONSchema, credential, 'credential')
      throw new Error('expected assertMatchesSchema to throw')
    } catch (error) {
      const message = (error as Error).message
      expect(message).toContain('required property is missing')
      expect(message).toContain('expected the constant')
    }
  })

  test('$ref/$defs resolution: a valid didDocumentEditDetail item is accepted', () => {
    const credential = validCapabilityCredential({
      subject: {
        authorizationDetails: [
          { type: 'urn:did-core:document-edit:v1', services: [], verificationMethods: [], remove: [] },
        ],
      },
    })
    expect(() => assertMatchesSchema(capabilitySchema as JSONSchema, credential, 'credential')).not.toThrow()
  })

  test('prefixItems tuple validation: a 3-element type array is rejected (maxItems)', () => {
    expect(() => assertMatchesSchema(capabilitySchema as JSONSchema, validCapabilityCredential({ topLevel: { type: ['VerifiableCredential', 'biset.md/MessengerCapability', 'extra'] } }), 'credential')).toThrow(/expected at most 2 items/)
  })
})
