import 'fake-indexeddb/auto'
import { afterEach, describe, expect, test } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519.js'
import { bytesToBase64url, canonicalBytes } from '../src/protocol/canonical.ts'
import { encodeMultikey } from '../src/protocol/vh/multikey.ts'
import { buildProof } from '../src/protocol/vh/proof.ts'
import { didToHttpsUrl } from '../src/protocol/webvh/identifier.ts'
import { buildGenesisLog } from './protocol/support/did-log-fixture.ts'
import {
  clearDidMdPendingAuthorization,
  readDidMdDeviceSession,
  readDidMdPendingAuthorization,
  saveDidMdPendingAuthorization,
  type DidMdPendingAuthorization,
} from '../src/client/identity/wallet/did-md-store.ts'
import { completeDidMdWalletCallback } from '../src/client/identity/wallet/did-md-oauth.ts'

const DATABASE_NAME = 'biset-did-md-wallet'
const ORIGIN = 'https://biset.example'
const WALLET = 'https://app.did.md/authorize'
const CALLBACK_PATH = '/wallet/callback'
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
  url.hash = new URLSearchParams(params).toString()
  Object.defineProperty(globalThis, 'location', {
    configurable: true,
    value: { href: url.toString(), origin: url.origin, pathname: url.pathname, hash: url.hash, protocol: url.protocol, replace() {} },
  })
  Object.defineProperty(globalThis, 'history', { configurable: true, value: { replaceState() {} } })
}

const CLIENT_ID = `redirect_uri:${ORIGIN}${CALLBACK_PATH}`
const NONCE = 'n'.repeat(32)

async function pendingFixture(overrides: Partial<DidMdPendingAuthorization> = {}): Promise<DidMdPendingAuthorization> {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']) as CryptoKeyPair
  return {
    v: 3,
    wallet: WALLET,
    clientId: CLIENT_ID,
    state: 'expected-state',
    nonce: NONCE,
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

/** What the wallet answers with: the capability in a presentation bound to the request (challenge = nonce, domain = Client
 * Identifier) and a self-issued id_token for the same request. `tamper` breaks one thing. */
function walletResponse(did: string, vc: object, rootPrivateKey: Uint8Array, tamper: { nonce?: string; domain?: string; aud?: string; iss?: string } = {}): Record<string, string> {
  const unsignedVp = { '@context': ['https://www.w3.org/ns/credentials/v2'], type: ['VerifiablePresentation'], holder: did, verifiableCredential: [vc] }
  const presentation = { ...unsignedVp, proof: buildProof(unsignedVp, { verificationMethod: `${did}#key-1`, proofPurpose: 'authentication', challenge: tamper.nonce ?? NONCE, domain: tamper.domain ?? CLIENT_ID, privateKey: rootPrivateKey }) }
  const part = (value: unknown) => bytesToBase64url(new TextEncoder().encode(JSON.stringify(value)))
  const now = Math.floor(Date.now() / 1000)
  const input = `${part({ alg: 'EdDSA', typ: 'JWT', kid: `${did}#key-1` })}.${part({ iss: tamper.iss ?? did, sub: did, aud: tamper.aud ?? CLIENT_ID, nonce: tamper.nonce ?? NONCE, iat: now, exp: now + 3600 })}`
  return { vp_token: JSON.stringify({ capability: [presentation] }), id_token: `${input}.${bytesToBase64url(ed25519.sign(new TextEncoder().encode(input), rootPrivateKey))}` }
}

async function expectCallbackRejection(params: Record<string, string>, message: string): Promise<void> {
  callbackLocation(params)
  await expect(completeDidMdWalletCallback()).rejects.toThrow(message)
  expect(await readDidMdPendingAuthorization()).toBeUndefined()
}

function serveLog(did: string, log: unknown[]): void {
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const url = input.toString()
    // The log is read with a unique query string (log-io.ts's freshFetch: a CDN must not answer for a just-published edit).
    if (url.split('?')[0] === didToHttpsUrl(did)) return new Response(log.map(entry => JSON.stringify(entry)).join('\n') + '\n')
    return new Response('unexpected request', { status: 500 })
  }) as typeof fetch
}

const SCOPE = ['openid', 'biset:login', 'biset:device', 'biset:vault']
function capability(did: string, pending: DidMdPendingAuthorization, rootPrivateKey: Uint8Array, id = '11111111-1111-4111-8111-111111111111') {
  const unsignedVc = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: `urn:uuid:${id}`,
    type: ['VerifiableCredential', 'biset.md/MessengerCapability'],
    issuer: did,
    credentialSubject: {
      audience: CLIENT_ID,
      authorizationDetails: [pending.documentEdit],
      deviceJkt: pending.deviceJkt,
      expiresAt: '2030-01-01T00:00:00.000Z',
      issuedAt: '2026-09-05T00:00:00.000Z',
      scope: SCOPE,
    },
  }
  return { ...unsignedVc, proof: buildProof(unsignedVc, { verificationMethod: `${did}#key-1`, proofPurpose: 'authentication', privateKey: rootPrivateKey }) }
}

describe('did.md SIOPv2 callback validation', () => {
  test('rejects a callback with no pending authorization', async () => {
    callbackLocation({ state: 'anything' })
    await expect(completeDidMdWalletCallback()).rejects.toThrow('No matching did.md Wallet authorization is pending')
  })

  test('rejects and consumes a callback whose state differs from pending authorization', async () => {
    await saveDidMdPendingAuthorization(await pendingFixture())
    await expectCallbackRejection({ state: 'wrong-state', vp_token: '{}', id_token: 'a.b.c' }, 'state did not match')
  })

  test('rejects and consumes an error response', async () => {
    const pending = await pendingFixture()
    await saveDidMdPendingAuthorization(pending)
    await expectCallbackRejection({ state: pending.state, error: 'access_denied', error_description: 'The authorization was cancelled.' }, 'The authorization was cancelled.')
  })

  async function deliver(tamper: Parameters<typeof walletResponse>[3] = {}) {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const { did, log } = buildGenesisLog(rootPrivateKey, rootPublicKey, [])
    const pending = await pendingFixture({ state: 'success-state', did, verificationMethod: `${did}#key-1`, rootPublicKey, vaultDeviceId: 'urn:uuid:22222222-2222-4222-8222-222222222222' })
    serveLog(did, log)
    await saveDidMdPendingAuthorization(pending)
    callbackLocation({ state: pending.state, ...walletResponse(did, capability(did, pending, rootPrivateKey), rootPrivateKey, tamper) })
    return { did, pending }
  }

  test('consumes a successful callback and rejects its replay', async () => {
    const { did, pending } = await deliver()
    await expect(completeDidMdWalletCallback()).resolves.toMatchObject({ did, clientId: CLIENT_ID, scope: SCOPE })
    expect(await readDidMdPendingAuthorization()).toBeUndefined()
    expect(await readDidMdDeviceSession()).toMatchObject({ did, clientId: CLIENT_ID, vaultDeviceId: pending.vaultDeviceId })
    await expect(completeDidMdWalletCallback()).rejects.toThrow('No matching did.md Wallet authorization is pending')
  })

  test.each([
    ['a presentation bound to another nonce', { nonce: 'x'.repeat(32) }, 'presentation proof is invalid'],
    ['a presentation bound to another verifier', { domain: 'redirect_uri:https://evil.example/wallet/callback' }, 'presentation proof is invalid'],
    ['an id_token for another audience', { aud: 'redirect_uri:https://evil.example/wallet/callback' }, 'id_token is invalid'],
    ['an id_token whose issuer is not the holder', { iss: 'did:webvh:222222222222222222222222222222222222222222222222:other.example' }, 'id_token is invalid'],
  ] as const)('rejects %s', async (_label, tamper, message) => {
    await deliver(tamper)
    await expect(completeDidMdWalletCallback()).rejects.toThrow(message)
    expect(await readDidMdDeviceSession()).toBeUndefined()
    expect(await readDidMdPendingAuthorization()).toBeUndefined()
  })
})

// PLAN-refactor.md §7-1: a sign-in offers a candidate generation seed by its
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
    const documentEdit = { type: 'urn:did-core:document-edit:v1' as const, services: [], verificationMethods: [{ ...rotationKeyEditMethod(options.candidate, options.mode), controller: did }], remove: [] }
    const pending = await pendingFixture({
      state: `rotation-${options.mode}`, did, verificationMethod: `${did}#key-1`, rootPublicKey, documentEdit,
      rotationSeedCandidate: await sealDidMdSecret(ROTATION_SEED_CANDIDATE, options.candidate),
    })
    serveLog(did, log)
    await saveDidMdPendingAuthorization(pending)
    callbackLocation({ state: pending.state, ...walletResponse(did, capability(did, pending, rootPrivateKey, '33333333-3333-4333-8333-333333333333'), rootPrivateKey) })
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
    const documentEdit = {
      type: 'urn:did-core:document-edit:v1' as const,
      services: [{ id: '#didcomm', type: 'DIDCommMessaging', serviceEndpoint: { uri: MEDIATOR_DID, accept: ['didcomm/v2'] }, endpointMode: 'merge' as const }],
      verificationMethods: [], remove: [],
      removeEndpoints: [{ serviceId: '#didcomm', match: { uri: 'https://mediator.example' } }, { serviceId: '#didcomm', match: { uri: 'https://mediator.example/' } }],
    }
    const pending = await pendingFixture({ state: 'endpoint-update', did, verificationMethod: `${did}#key-1`, rootPublicKey, documentEdit })
    serveLog(did, log)
    await saveDidMdPendingAuthorization(pending)
    callbackLocation({ state: pending.state, ...walletResponse(did, capability(did, pending, rootPrivateKey, '33333333-3333-4333-8333-333333333333'), rootPrivateKey) })
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
