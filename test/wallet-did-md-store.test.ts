import 'fake-indexeddb/auto'
import { afterEach, describe, expect, test } from 'vitest'
import {
  clearDidMdDeviceSession,
  clearDidMdPendingAuthorization,
  openDidMdBisetDidCommDeviceMaterial,
  readDidMdDeviceSession,
  readDidMdPendingAuthorization,
  saveDidMdDeviceSession,
  saveDidMdPendingAuthorization,
  sealDidMdBisetDidCommDeviceMaterial,
  type DidMdDeviceSession,
  type DidMdPendingAuthorization,
} from '../src/client/identity/wallet/did-md-store.ts'

const DATABASE_NAME = 'biset-did-md-wallet'
const bytes = (start: number) => Uint8Array.from({ length: 32 }, (_, index) => start + index)

afterEach(async () => {
  await new Promise<void>((resolve, reject) => {
    const request = indexedDB.deleteDatabase(DATABASE_NAME)
    request.onsuccess = () => resolve()
    request.onerror = () => reject(request.error)
    request.onblocked = () => resolve()
  })
})

function changed(value: Uint8Array): Uint8Array {
  const copy = value.slice()
  copy[0] = copy[0]! ^ 1
  return copy
}

async function expectNoSecretInError(action: () => Promise<unknown>, secret: Uint8Array): Promise<void> {
  try {
    await action()
    throw new Error('expected opening tampered material to fail')
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    expect(message).not.toContain([...secret].join(','))
  }
}

async function pendingFixture(): Promise<DidMdPendingAuthorization> {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']) as CryptoKeyPair
  return {
    v: 3,
    wallet: 'https://app.did.md/authorize',
    clientId: 'redirect_uri:https://biset.example/wallet/callback',
    state: 'state-value',
    nonce: 'nonce-value',
    did: 'did:web:alice.did.md',
    handle: 'alice.did.md',
    verificationMethod: 'did:web:alice.did.md#key-1',
    rootPublicKey: bytes(33),
    deviceJkt: 'device-thumbprint',
    privateKey: pair.privateKey,
    publicJwk: await crypto.subtle.exportKey('jwk', pair.publicKey),
    vaultDeviceId: 'urn:uuid:11111111-1111-4111-8111-111111111111',
    documentEdit: { type: 'urn:did-core:document-edit:v1', services: [], verificationMethods: [], remove: [] },
    createdAt: '2026-09-05T00:00:00.000Z',
  }
}

describe('did.md Biset DIDComm device material sealing', () => {
  test('round-trips a context-bound DIDComm private key', async () => {
    const x25519PublicKey = bytes(129)
    const privateMaterial = { x25519PrivateKey: bytes(161), mediatorDeviceSecret: bytes(33) }

    const sealed = await sealDidMdBisetDidCommDeviceMaterial(x25519PublicKey, privateMaterial)

    expect(sealed.x25519PublicKey).toEqual(x25519PublicKey)
    expect(sealed.sealed.ciphertext).not.toEqual(privateMaterial.x25519PrivateKey)
    expect(await openDidMdBisetDidCommDeviceMaterial(sealed)).toEqual(privateMaterial)
  })

  test('rejects separately tampered DIDComm ciphertext and nonce without leaking private material', async () => {
    const secret = bytes(161)
    const sealed = await sealDidMdBisetDidCommDeviceMaterial(bytes(129), { x25519PrivateKey: secret, mediatorDeviceSecret: bytes(33) })

    await expectNoSecretInError(
      () => openDidMdBisetDidCommDeviceMaterial({ ...sealed, sealed: { ...sealed.sealed, ciphertext: changed(sealed.sealed.ciphertext) } }),
      secret,
    )
    await expectNoSecretInError(
      () => openDidMdBisetDidCommDeviceMaterial({ ...sealed, sealed: { ...sealed.sealed, iv: changed(sealed.sealed.iv) } }),
      secret,
    )
    await expectNoSecretInError(
      () => openDidMdBisetDidCommDeviceMaterial({ ...sealed, x25519PublicKey: changed(sealed.x25519PublicKey) }),
      secret,
    )
  })

})

describe('did.md Wallet IndexedDB storage', () => {
  test('reads, saves, and clears pending authorization and session records', async () => {
    const pending = await pendingFixture()
    const session: DidMdDeviceSession = {
      v: 3,
      wallet: pending.wallet,
      clientId: pending.clientId,
      did: pending.did,
      handle: pending.handle,
      verificationMethod: pending.verificationMethod,
      rootPublicKey: pending.rootPublicKey,
      deviceJkt: pending.deviceJkt,
      privateKey: pending.privateKey,
      publicJwk: pending.publicJwk,
      capability: { document: { id: 'capability-1' }, proof: { type: 'DataIntegrityProof' } },
      capabilityExpiresAt: '2026-10-05T00:00:00.000Z',
      vaultDeviceId: pending.vaultDeviceId,
    }

    await saveDidMdPendingAuthorization(pending)
    await saveDidMdDeviceSession(session)
    expect(await readDidMdPendingAuthorization()).toEqual(pending)
    expect(await readDidMdDeviceSession()).toEqual(session)

    await clearDidMdPendingAuthorization()
    await clearDidMdDeviceSession()
    expect(await readDidMdPendingAuthorization()).toBeUndefined()
    expect(await readDidMdDeviceSession()).toBeUndefined()
  })
})
