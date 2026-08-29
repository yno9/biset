// End-to-end: ensureKeyPackagePool against a real DS (SqliteMlsDeliveryService)
// behind its real HTTP handler -- confirms the pool is topped up to target,
// left alone once full, and only mints the shortfall after some packages
// were consumed (mirroring src.bak/did/didcomm-devices.ts's own refill step).
import { afterEach, describe, expect, test } from 'bun:test'
import { rmSync } from 'node:fs'
import { ed25519 } from '@noble/curves/ed25519.js'
import { SqliteMlsDeliveryService } from '../../src/coordinator/mls-delivery-store.ts'
import { Ed25519MlsDsSignatureVerifier } from '../../src/coordinator/mls-delivery-authorizer.ts'
import { createMlsDeliveryHttpHandler } from '../../src/coordinator/mls-delivery-http.ts'
import { CoordinatorMlsDeliveryTransport } from '../../src/mls/coordinator-mls-delivery-transport.ts'
import { generateOwnKeyPackage, keyPackageRefOf } from '../../src/mls/group.ts'
import { ensureKeyPackagePool } from '../../src/mls/key-package-pool.ts'
import { mlsKeyPackageCountPullSigningBytes, mlsKeyPackageTakeSigningBytes } from '../../src/protocol/signing.ts'
import type { MlsKeyPackageStore } from '../../src/mls/keypackage-store.ts'
import type { OwnKeyPackage } from '../../src/mls/group.ts'
import { encodeMlsDeviceCredential } from '../../src/mls/device-credential.ts'
import { mlsDeviceFixture } from './support/mls-device-fixture.ts'

const dsPath = `/tmp/biset-key-package-pool-${process.pid}-${Date.now()}.sqlite`
const identityId = 'did:web:alice.example'
const device = await mlsDeviceFixture(identityId)
const deviceKid = device.kid

afterEach(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { rmSync(`${dsPath}${suffix}`) } catch {}
  }
})

/** In-memory stand-in for IndexedDbMlsKeyPackageStore -- same contract
 * (mint keeps every private half), no IndexedDB required. */
function memoryKeyPackageStore(): MlsKeyPackageStore & { size(): number } {
  const byRef = new Map<string, OwnKeyPackage>()
  return {
    async mint(kid, credential, signaturePrivateKey, count) {
      const minted: OwnKeyPackage[] = []
      for (let i = 0; i < count; i++) {
        const own = await generateOwnKeyPackage(credential, signaturePrivateKey)
        byRef.set(await keyPackageRefOf(own.publicPackage), own)
        minted.push(own)
      }
      return minted
    },
    async takeForWelcome() {
      throw new Error('not used by this test')
    },
    size() { return byRef.size },
  }
}

function signerFor(kp: OwnKeyPackage) {
  return (bytes: Uint8Array) => ed25519.sign(bytes, kp.privatePackage.signaturePrivateKey)
}

function setup(kids: Record<string, OwnKeyPackage>) {
  const ds = SqliteMlsDeliveryService.open(dsPath)
  const verifier = new Ed25519MlsDsSignatureVerifier({
    async resolveEd25519PublicKey(kid) { return kids[kid]?.publicPackage.leafNode.signaturePublicKey },
  })
  const handle = createMlsDeliveryHttpHandler(ds, verifier, async () => true)
  const transport = new CoordinatorMlsDeliveryTransport({ baseUrl: 'https://core.example', deviceCredential: encodeMlsDeviceCredential(device.credential), fetch: (input, init) => handle(new Request(input, init)) })
  return { ds, handle, transport }
}

async function freshCount(transport: CoordinatorMlsDeliveryTransport, deviceKid: string, sign: (bytes: Uint8Array) => Uint8Array | Promise<Uint8Array>): Promise<number> {
  const pull = { version: 1 as const, identityId, kid: deviceKid, requestedAt: new Date().toISOString() }
  return transport.keyPackageCount({ ...pull, signature: await sign(mlsKeyPackageCountPullSigningBytes(pull)) })
}

describe('ensureKeyPackagePool', () => {
  test('mints and publishes up to target when the DS pool is empty', async () => {
    const kp = await generateOwnKeyPackage(device.credential, device.signaturePrivateKey)
    const { ds, transport } = setup({ [deviceKid]: kp })
    const keyStore = memoryKeyPackageStore()

    await ensureKeyPackagePool(transport, keyStore, identityId, deviceKid, device.credential, device.signaturePrivateKey, signerFor(kp), 5)

    expect(keyStore.size()).toBe(5)
    expect(await freshCount(transport, deviceKid, signerFor(kp))).toBe(5)

    ds.close()
  })

  test('is a no-op once the DS pool already meets target', async () => {
    const kp = await generateOwnKeyPackage(device.credential, device.signaturePrivateKey)
    const { ds, handle, transport } = setup({ [deviceKid]: kp })
    const keyStore = memoryKeyPackageStore()

    await ensureKeyPackagePool(transport, keyStore, identityId, deviceKid, device.credential, device.signaturePrivateKey, signerFor(kp), 5)
    expect(keyStore.size()).toBe(5)

    const guardedTransport = new CoordinatorMlsDeliveryTransport({
      baseUrl: 'https://core.example',
      deviceCredential: encodeMlsDeviceCredential(device.credential),
      fetch: (input, init) => {
        const request = new Request(input, init)
        if (new URL(request.url).pathname === '/v1/mls/keypackage/publish') throw new Error('publish must not be called when the pool is already full')
        return handle(request)
      },
    })
    await ensureKeyPackagePool(guardedTransport, keyStore, identityId, deviceKid, device.credential, device.signaturePrivateKey, signerFor(kp), 5)
    expect(keyStore.size()).toBe(5)

    ds.close()
  })

  test('tops up only the shortfall after some packages were consumed', async () => {
    const kp = await generateOwnKeyPackage(device.credential, device.signaturePrivateKey)
    const { ds, transport } = setup({ [deviceKid]: kp })
    const keyStore = memoryKeyPackageStore()

    await ensureKeyPackagePool(transport, keyStore, identityId, deviceKid, device.credential, device.signaturePrivateKey, signerFor(kp), 5)
    expect(await freshCount(transport, deviceKid, signerFor(kp))).toBe(5)

    // Simulate the DS handing packages out for another device's Welcome.
    const take = { version: 1 as const, identityId, requesterKid: deviceKid, requestedAt: new Date().toISOString() }
    const taken = await transport.takeKeyPackages({ ...take, signature: await signerFor(kp)(mlsKeyPackageTakeSigningBytes(take)) })
    expect(taken.length).toBeGreaterThan(0)
    expect(await freshCount(transport, deviceKid, signerFor(kp))).toBeLessThan(5)

    await ensureKeyPackagePool(transport, keyStore, identityId, deviceKid, device.credential, device.signaturePrivateKey, signerFor(kp), 5)
    expect(await freshCount(transport, deviceKid, signerFor(kp))).toBe(5)

    ds.close()
  })
})
