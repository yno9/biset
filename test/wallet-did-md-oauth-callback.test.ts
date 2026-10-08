import 'fake-indexeddb/auto'
import { afterEach, describe, expect, test } from 'bun:test'
import { ed25519 } from '@noble/curves/ed25519.js'
import { bytesToBase64url, canonicalBytes } from '../src/protocol/canonical.ts'
import { encodeMultikey } from '../src/protocol/webvh/multikey.ts'
import { buildProof } from '../src/protocol/webvh/proof.ts'
import { didToHttpsUrl } from '../src/protocol/webvh/identifier.ts'
import { buildGenesisLog } from './protocol/support/webvh-log-fixture.ts'
import {
  clearDidMdPendingAuthorization,
  readDidMdDeviceSession,
  readDidMdPendingAuthorization,
  saveDidMdPendingAuthorization,
  saveDidMdRegistration,
  type DidMdPendingAuthorization,
  type DidMdRegistration,
} from '../src/client/identity/wallet/did-md-store.ts'
import { completeDidMdWalletCallback } from '../src/client/identity/wallet/did-md-oauth.ts'

const DATABASE_NAME = 'biset-did-md-wallet'
const ORIGIN = 'https://biset.example'
const ISSUER = 'https://api.did.md'
const CALLBACK_PATH = '/wallet/callback'
const FILE_CALLBACK_URL = 'file:///Users/n/biset/dist/index.html'
const CODE = `code_${'c'.repeat(32)}`
const bytes = (start: number) => Uint8Array.from({ length: 32 }, (_, index) => start + index)

const originalFetch = globalThis.fetch
const originalLocation = globalThis.location
const originalHistory = globalThis.history

afterEach(async () => {
  globalThis.fetch = originalFetch
  if (originalLocation === undefined) delete (globalThis as { location?: Location }).location
  else Object.defineProperty(globalThis, 'location', { configurable: true, value: originalLocation })
  if (originalHistory === undefined) delete (globalThis as { history?: History }).history
  else Object.defineProperty(globalThis, 'history', { configurable: true, value: originalHistory })
  await new Promise<void>((resolve, reject) => {
    const request = indexedDB.deleteDatabase(DATABASE_NAME)
    request.onsuccess = () => resolve()
    request.onerror = () => reject(request.error)
    request.onblocked = () => resolve()
  })
})

function callbackLocation(params: Record<string, string>, callbackUrl = `${ORIGIN}${CALLBACK_PATH}`): void {
  const url = new URL(callbackUrl)
  for (const [name, value] of Object.entries(params)) url.searchParams.set(name, value)
  Object.defineProperty(globalThis, 'location', {
    configurable: true,
    value: { href: url.toString(), origin: url.origin, pathname: url.pathname, protocol: url.protocol, replace() {} },
  })
  Object.defineProperty(globalThis, 'history', { configurable: true, value: { replaceState() {} } })
}

function registrationFixture(redirectUri = `${ORIGIN}${CALLBACK_PATH}`): DidMdRegistration {
  return {
    v: 2,
    issuer: ISSUER,
    authorizationEndpoint: `${ISSUER}/v1/oauth/authorize`,
    tokenEndpoint: `${ISSUER}/v1/oauth/token`,
    refreshEndpoint: `${ISSUER}/v1/oauth/device-refresh`,
    registrationEndpoint: `${ISSUER}/v1/oauth/register`,
    clientId: `client_${'a'.repeat(32)}`,
    registrationAccessToken: 'r'.repeat(32),
    redirectUri,
  }
}

async function pendingFixture(overrides: Partial<DidMdPendingAuthorization> = {}): Promise<DidMdPendingAuthorization> {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']) as CryptoKeyPair
  return {
    v: 2,
    issuer: ISSUER,
    clientId: registrationFixture().clientId,
    state: 'expected-state',
    codeVerifier: 'expected-code-verifier',
    did: 'did:webvh:111111111111111111111111111111111111111111111111:test.example',
    handle: 'alice.did.md',
    verificationMethod: 'did:webvh:111111111111111111111111111111111111111111111111:test.example#key-1',
    rootPublicKey: bytes(1),
    deviceJkt: 'A'.repeat(43),
    privateKey: pair.privateKey,
    publicJwk: await crypto.subtle.exportKey('jwk', pair.publicKey),
    vaultDeviceId: 'urn:uuid:11111111-1111-4111-8111-111111111111',
    documentEdit: { type: 'urn:did-core:document-edit:v1', services: [], verificationMethods: [], remove: [] },
    createdAt: '2026-09-05T00:00:00.000Z',
    ...overrides,
  }
}

async function expectCallbackRejection(params: Record<string, string>, message: string): Promise<void> {
  callbackLocation(params)
  await expect(completeDidMdWalletCallback()).rejects.toThrow(message)
  expect(await readDidMdPendingAuthorization()).toBeUndefined()
}

describe('did.md OAuth callback validation', () => {
  test('rejects a callback with no pending authorization', async () => {
    callbackLocation({ state: 'anything', iss: ISSUER, code: CODE })
    await expect(completeDidMdWalletCallback()).rejects.toThrow('No matching did.md Wallet authorization is pending')
  })

  test('rejects and consumes a callback whose state differs from pending authorization', async () => {
    const pending = await pendingFixture()
    await saveDidMdPendingAuthorization(pending)
    await expectCallbackRejection({ state: 'wrong-state', iss: ISSUER, code: CODE }, 'state or issuer did not match')
  })

  test('rejects and consumes a callback whose issuer differs from pending authorization', async () => {
    const pending = await pendingFixture()
    await saveDidMdPendingAuthorization(pending)
    await expectCallbackRejection({ state: pending.state, iss: 'https://attacker.example', code: CODE }, 'state or issuer did not match')
  })

  test('consumes a successful file:// callback and rejects replay of its authorization code', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const { did, log } = buildGenesisLog(rootPrivateKey, rootPublicKey, [])
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']) as CryptoKeyPair
    const registration = registrationFixture(FILE_CALLBACK_URL)
    const pending: DidMdPendingAuthorization = {
      v: 2,
      issuer: ISSUER,
      clientId: registration.clientId,
      state: 'success-state',
      codeVerifier: 'success-code-verifier',
      did,
      handle: 'alice.did.md',
      verificationMethod: `${did}#key-1`,
      rootPublicKey,
      deviceJkt: 'A'.repeat(43),
      privateKey: pair.privateKey,
      publicJwk: await crypto.subtle.exportKey('jwk', pair.publicKey),
      vaultDeviceId: 'urn:uuid:22222222-2222-4222-8222-222222222222',
      documentEdit: { type: 'urn:did-core:document-edit:v1', services: [], verificationMethods: [], remove: [] },
      createdAt: '2026-09-05T00:00:00.000Z',
    }
    // PLAN3 (~/did.md/PLAN3-oid4vp-transport.md): the capability is a
    // VC-DM 2.0 credential with an embedded proof, not a {document, proof}
    // pair -- RP-owned content lives under credentialSubject.
    const unsignedVc = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: 'urn:uuid:11111111-1111-4111-8111-111111111111',
      type: ['VerifiableCredential', 'biset.md/MessengerCapability'],
      issuer: did,
      credentialSubject: {
        audience: registration.clientId,
        authorizationDetails: [pending.documentEdit],
        deviceJkt: pending.deviceJkt,
        expiresAt: '2030-01-01T00:00:00.000Z',
        issuedAt: '2026-09-05T00:00:00.000Z',
        scope: ['biset:login', 'biset:device', 'biset:vault'],
      },
    }
    const vc = { ...unsignedVc, proof: buildProof(unsignedVc, { verificationMethod: pending.verificationMethod, proofPurpose: 'authentication', privateKey: rootPrivateKey }) }
    // PLAN7: did.md delivers the DCQL-wrapped vp_token straight to this RP
    // (fragment on https, query string on file://) -- there is no token
    // endpoint round trip to mock any more.
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = input.toString()
      if (url === `${ISSUER}/.well-known/oauth-authorization-server`) {
        return Response.json({ issuer: ISSUER, authorization_endpoint: registration.authorizationEndpoint, token_endpoint: registration.tokenEndpoint, registration_endpoint: registration.registrationEndpoint })
      }
      if (url === `${ISSUER}/v1/oauth/register/${encodeURIComponent(registration.clientId)}`) {
        return Response.json({ client_id: registration.clientId, redirect_uris: [registration.redirectUri], scope: 'openid profile biset:login biset:device biset:routing biset:messaging biset:vault', token_endpoint_auth_method: 'none' })
      }
      // The log is read with a unique query string (log-io.ts's freshFetch: a CDN must not answer for a just-published edit).
      if (url.split('?')[0] === didToHttpsUrl(did)) return new Response(log.map(entry => JSON.stringify(entry)).join('\n') + '\n')
      return new Response('unexpected request', { status: 500 })
    }) as typeof fetch
    await saveDidMdRegistration(registration)
    await saveDidMdPendingAuthorization(pending)
    callbackLocation({ state: pending.state, iss: ISSUER, vp_token: JSON.stringify({ capability: [vc] }) }, FILE_CALLBACK_URL)

    await expect(completeDidMdWalletCallback()).resolves.toMatchObject({ did, clientId: registration.clientId, scope: ['biset:login', 'biset:device', 'biset:vault'] })
    expect(await readDidMdPendingAuthorization()).toBeUndefined()
    expect(await readDidMdDeviceSession()).toMatchObject({ did, clientId: registration.clientId, vaultDeviceId: pending.vaultDeviceId })

    await expect(completeDidMdWalletCallback()).rejects.toThrow('No matching did.md Wallet authorization is pending')
    await clearDidMdPendingAuthorization()
  })
})

// PLAN-refactor.md §7-1: a sign-in offers a candidate relationship seed by its
// rotation key (`ifAbsent`); the session keeps the seed only if the Wallet
// published that key. A key already there (another device's) is not a failure.
import { sealDidMdSecret } from '../src/client/identity/wallet/did-md-store.ts'
import { approvedRotationSeed, ROTATION_SEED_CANDIDATE } from '../src/client/identity/wallet/did-md-oauth.ts'
import { rotationKeyEditMethod, rotationSigningKey, ROTATION_KEY_FRAGMENT } from '../src/client/didcomm/rotation-key.ts'

describe('the rotation key a sign-in offers', () => {
  async function approve(options: { candidate: Uint8Array; mode: 'ifAbsent' | 'replace'; published?: Uint8Array; referenced?: boolean }) {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const published = options.published ? rotationSigningKey(options.published) : undefined
    const { did, log } = buildGenesisLog(rootPrivateKey, rootPublicKey, [], 'test.example', published ? {
      rawVerificationMethods: [{ fragment: ROTATION_KEY_FRAGMENT.slice(1), publicKeyMultibase: published.publicKeyMultibase }],
      authenticationFragments: options.referenced === false ? [] : [ROTATION_KEY_FRAGMENT.slice(1)],
    } : {})
    const registration = registrationFixture(FILE_CALLBACK_URL)
    const documentEdit = { type: 'urn:did-core:document-edit:v1' as const, services: [], verificationMethods: [{ ...rotationKeyEditMethod(options.candidate, options.mode), controller: did }], remove: [] }
    const pending = await pendingFixture({
      clientId: registration.clientId, state: `rotation-${options.mode}`, did, verificationMethod: `${did}#key-1`, rootPublicKey, documentEdit,
      rotationSeedCandidate: await sealDidMdSecret(ROTATION_SEED_CANDIDATE, options.candidate),
    })
    const unsignedVc = {
      '@context': ['https://www.w3.org/ns/credentials/v2'], id: 'urn:uuid:33333333-3333-4333-8333-333333333333',
      type: ['VerifiableCredential', 'biset.md/MessengerCapability'], issuer: did,
      credentialSubject: { audience: registration.clientId, authorizationDetails: [documentEdit], deviceJkt: pending.deviceJkt, expiresAt: '2030-01-01T00:00:00.000Z', issuedAt: '2026-10-08T00:00:00.000Z', scope: ['biset:login', 'biset:device', 'biset:vault'] },
    }
    const vc = { ...unsignedVc, proof: buildProof(unsignedVc, { verificationMethod: `${did}#key-1`, proofPurpose: 'authentication', privateKey: rootPrivateKey }) }
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = input.toString()
      if (url === `${ISSUER}/.well-known/oauth-authorization-server`) return Response.json({ issuer: ISSUER, authorization_endpoint: registration.authorizationEndpoint, token_endpoint: registration.tokenEndpoint, registration_endpoint: registration.registrationEndpoint })
      if (url === `${ISSUER}/v1/oauth/register/${encodeURIComponent(registration.clientId)}`) return Response.json({ client_id: registration.clientId, redirect_uris: [registration.redirectUri], scope: 'openid profile biset:login biset:device biset:routing biset:messaging biset:vault', token_endpoint_auth_method: 'none' })
      if (url.split('?')[0] === didToHttpsUrl(did)) return new Response(log.map(entry => JSON.stringify(entry)).join('\n') + '\n')
      return new Response('unexpected request', { status: 500 })
    }) as typeof fetch
    await saveDidMdRegistration(registration)
    await saveDidMdPendingAuthorization(pending)
    callbackLocation({ state: pending.state, iss: ISSUER, vp_token: JSON.stringify({ capability: [vc] }) }, FILE_CALLBACK_URL)
    return completeDidMdWalletCallback()
  }

  test('its key published: the session keeps the seed until the Vault stores it', async () => {
    const candidate = crypto.getRandomValues(new Uint8Array(32))
    await approve({ candidate, mode: 'ifAbsent', published: candidate })
    const approved = await approvedRotationSeed()
    expect([...approved!.seed]).toEqual([...candidate])
    await approved!.forget()
    expect(await approvedRotationSeed()).toBeUndefined()
  })

  test('another device\'s key already there (ifAbsent): the sign-in succeeds, and keeps no seed', async () => {
    await expect(approve({ candidate: crypto.getRandomValues(new Uint8Array(32)), mode: 'ifAbsent', published: crypto.getRandomValues(new Uint8Array(32)) })).resolves.toBeDefined()
    expect(await approvedRotationSeed()).toBeUndefined()
  })

  test('a replacement the Wallet did not publish fails', async () => {
    await expect(approve({ candidate: crypto.getRandomValues(new Uint8Array(32)), mode: 'replace', published: crypto.getRandomValues(new Uint8Array(32)) })).rejects.toThrow(`did not publish requested verification method ${ROTATION_KEY_FRAGMENT}`)
  })

  test('published but not referenced from authentication fails', async () => {
    const candidate = crypto.getRandomValues(new Uint8Array(32))
    await expect(approve({ candidate, mode: 'replace', published: candidate, referenced: false })).rejects.toThrow(`did not reference ${ROTATION_KEY_FRAGMENT} from authentication`)
  })

})

describe('the endpoint update ("Edit server" with the URL already in use)', () => {
  const MEDIATOR_DID = 'did:web:mediator.example'
  const LEGACY = { uri: 'https://mediator.example/', routingKeys: [`${MEDIATOR_DID}#key-1`] }
  const ONION = { uri: 'http://abc.onion/', routingKeys: ['did:peer:2.Ez6L.Vz6M#key-1'] }

  async function approve(published: Array<{ uri: string; routingKeys?: string[] | null }>) {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const { did, log } = buildGenesisLog(rootPrivateKey, rootPublicKey, [], 'test.example', { services: [{ id: '#didcomm', serviceEndpoints: published }] })
    const registration = registrationFixture(FILE_CALLBACK_URL)
    const documentEdit = {
      type: 'urn:did-core:document-edit:v1' as const,
      services: [{ id: '#didcomm', type: 'DIDCommMessaging', serviceEndpoint: { uri: MEDIATOR_DID, accept: ['didcomm/v2'] }, endpointMode: 'merge' as const }],
      verificationMethods: [], remove: [],
      removeEndpoints: [{ serviceId: '#didcomm', match: { uri: 'https://mediator.example' } }, { serviceId: '#didcomm', match: { uri: 'https://mediator.example/' } }],
    }
    const pending = await pendingFixture({ clientId: registration.clientId, state: 'endpoint-update', did, verificationMethod: `${did}#key-1`, rootPublicKey, documentEdit })
    const unsignedVc = {
      '@context': ['https://www.w3.org/ns/credentials/v2'], id: 'urn:uuid:33333333-3333-4333-8333-333333333333',
      type: ['VerifiableCredential', 'biset.md/MessengerCapability'], issuer: did,
      credentialSubject: { audience: registration.clientId, authorizationDetails: [documentEdit], deviceJkt: pending.deviceJkt, expiresAt: '2030-01-01T00:00:00.000Z', issuedAt: '2026-10-08T00:00:00.000Z', scope: ['biset:login', 'biset:device', 'biset:vault'] },
    }
    const vc = { ...unsignedVc, proof: buildProof(unsignedVc, { verificationMethod: `${did}#key-1`, proofPurpose: 'authentication', privateKey: rootPrivateKey }) }
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = input.toString()
      if (url === `${ISSUER}/.well-known/oauth-authorization-server`) return Response.json({ issuer: ISSUER, authorization_endpoint: registration.authorizationEndpoint, token_endpoint: registration.tokenEndpoint, registration_endpoint: registration.registrationEndpoint })
      if (url === `${ISSUER}/v1/oauth/register/${encodeURIComponent(registration.clientId)}`) return Response.json({ client_id: registration.clientId, redirect_uris: [registration.redirectUri], scope: 'openid profile biset:login biset:device biset:routing biset:messaging biset:vault', token_endpoint_auth_method: 'none' })
      if (url.split('?')[0] === didToHttpsUrl(did)) return new Response(log.map(entry => JSON.stringify(entry)).join('\n') + '\n')
      return new Response('unexpected request', { status: 500 })
    }) as typeof fetch
    await saveDidMdRegistration(registration)
    await saveDidMdPendingAuthorization(pending)
    callbackLocation({ state: pending.state, iss: ISSUER, vp_token: JSON.stringify({ capability: [vc] }) }, FILE_CALLBACK_URL)
    return completeDidMdWalletCallback()
  }

  test('the document with the mediator\'s DID beside the onion entry, and the URL form gone, is what the check accepts', async () => {
    await approve([ONION, { uri: MEDIATOR_DID, routingKeys: null }])
  })

  test('the URL form still there after the approval fails the check', async () => {
    await expect(approve([LEGACY, ONION, { uri: MEDIATOR_DID, routingKeys: null }])).rejects.toThrow('did not remove the requested endpoints')
  })

  test('the mediator\'s DID missing after the approval fails the check', async () => {
    await expect(approve([ONION])).rejects.toThrow('did not publish requested service')
  })
})
