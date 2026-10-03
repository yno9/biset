import { describe, expect, test } from 'bun:test'
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
    issuer: 'did:webvh:abc:alice.did.md',
    credentialSubject: {
      audience: 'client_abcdefghijklmnopqrstuvwxyzABCDEF',
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
      verificationMethod: 'did:webvh:abc:alice.did.md#pass-1', proofValue: 'zStubProofValue',
    },
    ...overrides.topLevel,
  }
}

describe('json-schema.ts (interpretive validator, used against biset-messenger-capability.schema.json)', () => {
  test('a well-formed capability credential is accepted', () => {
    expect(() => assertMatchesSchema(capabilitySchema as JSONSchema, validCapabilityCredential(), 'credential')).not.toThrow()
  })

  test('the legacy did.md/DeviceCapability type is still accepted (transition compatibility)', () => {
    expect(() => assertMatchesSchema(capabilitySchema as JSONSchema, validCapabilityCredential({ type: 'did.md/DeviceCapability' }), 'credential')).not.toThrow()
  })

  test('an unrecognized type is rejected', () => {
    expect(() => assertMatchesSchema(capabilitySchema as JSONSchema, validCapabilityCredential({ type: 'acme.example/SomethingElse' }), 'credential')).toThrow(/expected one of/)
  })

  // PLAN6 (~/did.md/PLAN6-rp-did-authentication.md): found live -- a
  // did:webvh-authenticated audience (JAR/client_id_scheme=did, biset's own
  // RP DID) was rejected here even after did.md's server-side checks all
  // passed, because this schema's audience pattern only ever allowed a DCR
  // client_XXXX id.
  test('a did:webvh audience (JAR/client_id_scheme=did) is accepted alongside a DCR client_id', () => {
    expect(() => assertMatchesSchema(capabilitySchema as JSONSchema, validCapabilityCredential({ subject: { audience: 'did:webvh:QmaQdf3VFoXtk7WjfP2rhmKAvMNinLh4qU1bjZ4mPDzVr6:t.biset.md' } }), 'credential')).not.toThrow()
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
          { type: 'urn:biset:mail-relay:v1', relayOrigin: 'https://api.did.md' },
        ],
      },
    })
    expect(() => assertMatchesSchema(capabilitySchema as JSONSchema, credential, 'credential')).not.toThrow()
  })

  test('prefixItems tuple validation: a 3-element type array is rejected (maxItems)', () => {
    expect(() => assertMatchesSchema(capabilitySchema as JSONSchema, validCapabilityCredential({ topLevel: { type: ['VerifiableCredential', 'biset.md/MessengerCapability', 'extra'] } }), 'credential')).toThrow(/expected at most 2 items/)
  })
})
