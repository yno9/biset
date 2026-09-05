import 'fake-indexeddb/auto'
import { afterEach, describe, expect, test } from 'bun:test'
import { ed25519 } from '@noble/curves/ed25519.js'
import { bytesToBase64url } from '../src/shared/protocol/canonical.ts'
import { buildProof } from '../src/identity/webvh/proof.ts'
import { didToHttpsUrl } from '../src/identity/webvh/identifier.ts'
import { createMlsDeviceCredential, encodeMlsDeviceCredential } from '../src/mls/device-credential.ts'
import { buildGenesisLog } from './protocol/support/webvh-log-fixture.ts'
import {
  clearDidMdPendingAuthorization,
  readDidMdDeviceSession,
  readDidMdPendingAuthorization,
  saveDidMdPendingAuthorization,
  saveDidMdRegistration,
  sealDidMdBisetDeviceMaterial,
  type DidMdPendingAuthorization,
  type DidMdRegistration,
} from '../src/wallet/did-md-store.ts'
import { completeDidMdWalletCallback } from '../src/wallet/did-md-oauth.ts'

const DATABASE_NAME = 'biset-did-md-wallet'
const ORIGIN = 'https://biset.example'
const ISSUER = 'https://api.did.md'
const CALLBACK_PATH = '/wallet/callback'
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

function callbackLocation(params: Record<string, string>): void {
  const url = new URL(`${ORIGIN}${CALLBACK_PATH}`)
  for (const [name, value] of Object.entries(params)) url.searchParams.set(name, value)
  Object.defineProperty(globalThis, 'location', {
    configurable: true,
    value: { href: url.toString(), origin: url.origin, pathname: url.pathname },
  })
  Object.defineProperty(globalThis, 'history', { configurable: true, value: { replaceState() {} } })
}

function registrationFixture(): DidMdRegistration {
  return {
    v: 2,
    issuer: ISSUER,
    authorizationEndpoint: `${ISSUER}/v1/oauth/authorize`,
    tokenEndpoint: `${ISSUER}/v1/oauth/token`,
    refreshEndpoint: `${ISSUER}/v1/oauth/device-refresh`,
    registrationEndpoint: `${ISSUER}/v1/oauth/register`,
    clientId: `client_${'a'.repeat(32)}`,
    registrationAccessToken: 'r'.repeat(32),
    redirectUri: `${ORIGIN}${CALLBACK_PATH}`,
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
    deviceJkt: 'dpop-thumbprint',
    privateKey: pair.privateKey,
    publicJwk: await crypto.subtle.exportKey('jwk', pair.publicKey),
    bisetDevice: await sealDidMdBisetDeviceMaterial(bytes(33), { signaturePrivateKey: bytes(65), vaultSecret: bytes(97) }),
    bisetMimiVaultRoom: { providerUrl: 'https://mimi.example/', roomId: 'mimi://mimi.example/r/vault-test' },
    bisetMimiVaultRoomCreated: true,
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

  test('consumes a successful callback and rejects replay of its authorization code', async () => {
    const rootPrivateKey = ed25519.utils.randomSecretKey()
    const rootPublicKey = ed25519.getPublicKey(rootPrivateKey)
    const leafPrivateKey = ed25519.utils.randomSecretKey()
    const leafPublicKey = ed25519.getPublicKey(leafPrivateKey)
    const { did, log } = buildGenesisLog(rootPrivateKey, rootPublicKey, [])
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']) as CryptoKeyPair
    const registration = registrationFixture()
    const room = { providerUrl: 'https://mimi.example/', roomId: 'mimi://mimi.example/r/vault-test' }
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
      deviceJkt: 'dpop-thumbprint',
      privateKey: pair.privateKey,
      publicJwk: await crypto.subtle.exportKey('jwk', pair.publicKey),
      bisetDevice: await sealDidMdBisetDeviceMaterial(leafPublicKey, { signaturePrivateKey: leafPrivateKey, vaultSecret: bytes(97) }),
      bisetMimiVaultRoom: room,
      bisetMimiVaultRoomCreated: true,
      createdAt: '2026-09-05T00:00:00.000Z',
    }
    const credential = createMlsDeviceCredential(did, log[0]!.versionId, leafPublicKey, rootPrivateKey, rootPrivateKey)
    const document = {
      audience: registration.clientId,
      authorizationDetails: [{ type: 'urn:biset:device-enrollment:v1', mlsCredential: bytesToBase64url(encodeMlsDeviceCredential(credential)), mimiVaultRoom: room }],
      deviceJkt: pending.deviceJkt,
      expiresAt: '2030-01-01T00:00:00.000Z',
      id: 'capability-1',
      issuedAt: '2026-09-05T00:00:00.000Z',
      issuer: did,
      scope: ['biset:login', 'biset:device', 'biset:vault'],
      type: 'did.md/DeviceCapability',
      version: 1,
    }
    const token = {
      access_token: 'access-token',
      token_type: 'DPoP',
      sub: did,
      expires_in: 3600,
      device_capability: {
        document,
        proof: buildProof(document, { verificationMethod: pending.verificationMethod, proofPurpose: 'authentication', privateKey: rootPrivateKey }),
      },
    }
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = input.toString()
      if (url === `${ISSUER}/.well-known/oauth-authorization-server`) {
        return Response.json({ issuer: ISSUER, authorization_endpoint: registration.authorizationEndpoint, token_endpoint: registration.tokenEndpoint, registration_endpoint: registration.registrationEndpoint })
      }
      if (url === `${ISSUER}/v1/oauth/register/${encodeURIComponent(registration.clientId)}`) {
        return Response.json({ client_id: registration.clientId, redirect_uris: [registration.redirectUri], scope: 'biset:login biset:device biset:routing biset:messaging biset:vault', token_endpoint_auth_method: 'none' })
      }
      if (url === registration.tokenEndpoint) return new Response(JSON.stringify(token), { headers: { 'content-type': 'application/json', 'dpop-nonce': 'nonce-value' } })
      if (url === didToHttpsUrl(did)) return new Response(log.map(entry => JSON.stringify(entry)).join('\n') + '\n')
      return new Response('unexpected request', { status: 500 })
    }) as typeof fetch
    await saveDidMdRegistration(registration)
    await saveDidMdPendingAuthorization(pending)
    callbackLocation({ state: pending.state, iss: ISSUER, code: CODE })

    await expect(completeDidMdWalletCallback()).resolves.toMatchObject({ did, accessToken: 'access-token', nonce: 'nonce-value' })
    expect(await readDidMdPendingAuthorization()).toBeUndefined()
    expect(await readDidMdDeviceSession()).toMatchObject({ did, clientId: registration.clientId })

    await expect(completeDidMdWalletCallback()).rejects.toThrow('No matching did.md Wallet authorization is pending')
    leafPrivateKey.fill(0)
    await clearDidMdPendingAuthorization()
  })
})
