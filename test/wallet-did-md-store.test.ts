import 'fake-indexeddb/auto'
import { afterEach, describe, expect, test } from 'bun:test'
import {
  clearDidMdDeviceSession,
  clearDidMdPendingAuthorization,
  clearDidMdRegistration,
  openDidMdBisetDeviceMaterial,
  openDidMdBisetDidCommDeviceMaterial,
  readDidMdDeviceSession,
  readDidMdPendingAuthorization,
  readDidMdRegistration,
  saveDidMdDeviceSession,
  saveDidMdPendingAuthorization,
  saveDidMdRegistration,
  sealDidMdBisetDeviceMaterial,
  sealDidMdBisetDidCommDeviceMaterial,
  type DidMdDeviceSession,
  type DidMdPendingAuthorization,
  type DidMdRegistration,
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
  const signaturePublicKey = bytes(1)
  return {
    v: 2,
    issuer: 'https://api.did.md',
    clientId: `client_${'a'.repeat(32)}`,
    state: 'state-value',
    codeVerifier: 'verifier-value',
    did: 'did:web:alice.did.md',
    handle: 'alice.did.md',
    verificationMethod: 'did:web:alice.did.md#key-1',
    rootPublicKey: bytes(33),
    deviceJkt: 'device-thumbprint',
    privateKey: pair.privateKey,
    publicJwk: await crypto.subtle.exportKey('jwk', pair.publicKey),
    bisetDevice: await sealDidMdBisetDeviceMaterial(signaturePublicKey, { signaturePrivateKey: bytes(65), vaultSecret: bytes(97) }),
    bisetMimiVaultRoom: { providerUrl: 'https://mimi.example/', roomId: 'mimi://mimi.example/r/vault-test' },
    bisetMimiVaultRoomCreated: true,
    createdAt: '2026-09-05T00:00:00.000Z',
  }
}

function registrationFixture(): DidMdRegistration {
  return {
    v: 2,
    issuer: 'https://api.did.md',
    authorizationEndpoint: 'https://api.did.md/v1/oauth/authorize',
    tokenEndpoint: 'https://api.did.md/v1/oauth/token',
    refreshEndpoint: 'https://api.did.md/v1/oauth/device-refresh',
    registrationEndpoint: 'https://api.did.md/v1/oauth/register',
    clientId: `client_${'a'.repeat(32)}`,
    registrationAccessToken: 'r'.repeat(32),
    redirectUri: 'https://biset.example/wallet/callback',
  }
}

describe('did.md Biset device material sealing', () => {
  // Reproduced: changing this field currently still permits decryption. The
  // caller later derives and checks the matching public key, but the sealed
  // envelope itself does not authenticate this metadata yet.
  test.todo('binds MLS public metadata to the sealed envelope')

  test('round-trips Biset MLS device material', async () => {
    const signaturePublicKey = bytes(1)
    const privateMaterial = { signaturePrivateKey: bytes(65), vaultSecret: bytes(97) }

    const sealed = await sealDidMdBisetDeviceMaterial(signaturePublicKey, privateMaterial)

    expect(sealed.signaturePublicKey).toEqual(signaturePublicKey)
    expect(sealed.sealed.ciphertext).not.toEqual(privateMaterial.signaturePrivateKey)
    expect(await openDidMdBisetDeviceMaterial(sealed)).toEqual(privateMaterial)
  })

  test('rejects separately tampered MLS ciphertext and nonce without leaking secrets', async () => {
    const secret = bytes(65)
    const sealed = await sealDidMdBisetDeviceMaterial(bytes(1), { signaturePrivateKey: secret, vaultSecret: bytes(97) })

    await expectNoSecretInError(
      () => openDidMdBisetDeviceMaterial({ ...sealed, sealed: { ...sealed.sealed, ciphertext: changed(sealed.sealed.ciphertext) } }),
      secret,
    )
    await expectNoSecretInError(
      () => openDidMdBisetDeviceMaterial({ ...sealed, sealed: { ...sealed.sealed, iv: changed(sealed.sealed.iv) } }),
      secret,
    )
  })

  test('cannot open material after its browser wrapping key is replaced', async () => {
    const sealed = await sealDidMdBisetDeviceMaterial(bytes(1), { signaturePrivateKey: bytes(65), vaultSecret: bytes(97) })
    await new Promise<void>((resolve, reject) => {
      const request = indexedDB.deleteDatabase(DATABASE_NAME)
      request.onsuccess = () => resolve()
      request.onerror = () => reject(request.error)
    })

    await expect(openDidMdBisetDeviceMaterial(sealed)).rejects.toThrow('could not be decrypted')
  })
})

describe('did.md Biset DIDComm device material sealing', () => {
  // Reproduced: x25519PublicKey is also outside AES-GCM authenticated data.
  test.todo('binds DIDComm public metadata to the sealed envelope')

  test('round-trips a context-bound DIDComm private key', async () => {
    const x25519PublicKey = bytes(129)
    const privateMaterial = { x25519PrivateKey: bytes(161) }

    const sealed = await sealDidMdBisetDidCommDeviceMaterial(x25519PublicKey, privateMaterial)

    expect(sealed.x25519PublicKey).toEqual(x25519PublicKey)
    expect(sealed.sealed.ciphertext).not.toEqual(privateMaterial.x25519PrivateKey)
    expect(await openDidMdBisetDidCommDeviceMaterial(sealed)).toEqual(privateMaterial)
  })

  test('rejects separately tampered DIDComm ciphertext and nonce without leaking private material', async () => {
    const secret = bytes(161)
    const sealed = await sealDidMdBisetDidCommDeviceMaterial(bytes(129), { x25519PrivateKey: secret })

    await expectNoSecretInError(
      () => openDidMdBisetDidCommDeviceMaterial({ ...sealed, sealed: { ...sealed.sealed, ciphertext: changed(sealed.sealed.ciphertext) } }),
      secret,
    )
    await expectNoSecretInError(
      () => openDidMdBisetDidCommDeviceMaterial({ ...sealed, sealed: { ...sealed.sealed, iv: changed(sealed.sealed.iv) } }),
      secret,
    )
  })

})

describe('did.md Wallet IndexedDB storage', () => {
  test('reads, saves, and clears registration, pending authorization, and session records', async () => {
    const registration = registrationFixture()
    const pending = await pendingFixture()
    const session: DidMdDeviceSession = {
      v: 2,
      issuer: pending.issuer,
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
      bisetDevice: { ...pending.bisetDevice, credentialWire: 'credential-wire', mimiVaultRoom: pending.bisetMimiVaultRoom, mimiVaultRoomCreated: true },
    }

    await saveDidMdRegistration(registration)
    await saveDidMdPendingAuthorization(pending)
    await saveDidMdDeviceSession(session)
    expect(await readDidMdRegistration()).toEqual(registration)
    expect(await readDidMdPendingAuthorization()).toEqual(pending)
    expect(await readDidMdDeviceSession()).toEqual(session)

    await clearDidMdRegistration()
    await clearDidMdPendingAuthorization()
    await clearDidMdDeviceSession()
    expect(await readDidMdRegistration()).toBeUndefined()
    expect(await readDidMdPendingAuthorization()).toBeUndefined()
    expect(await readDidMdDeviceSession()).toBeUndefined()
  })

  test('persists only the sealed Biset material, never its plaintext fields', async () => {
    const pending = await pendingFixture()
    await saveDidMdPendingAuthorization(pending)
    const stored = await new Promise<unknown>((resolve, reject) => {
      const request = indexedDB.open(DATABASE_NAME)
      request.onsuccess = () => {
        const db = request.result
        const get = db.transaction('pending', 'readonly').objectStore('pending').get('current')
        get.onsuccess = () => { db.close(); resolve(get.result) }
        get.onerror = () => { db.close(); reject(get.error) }
      }
      request.onerror = () => reject(request.error)
    })
    const serialized = JSON.stringify(stored)

    expect(serialized).not.toContain('signaturePrivateKey')
    expect(serialized).not.toContain('vaultSecret')
    expect(serialized).toContain('ciphertext')
  })
})
