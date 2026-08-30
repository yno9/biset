// Keeps this device's published KeyPackage pool topped up at the DS
// (coordinator-mls-delivery-transport.ts), so another of this identity's devices
// can external-join the self group without this device needing to be online
// at that moment.
//
// Ported at the algorithm level from src.bak/did/didcomm-devices.ts's own
// key-package refill step: only the DS's stored count is authoritative (a
// key package is consumed there, and this device keeps every private half
// until a Welcome uses one — see keypackage-store.ts), so this always asks
// first and mints only the shortfall, never assumes anything about how many
// remain from local state.
import { encodeKeyPackage, type OwnKeyPackage } from './group.ts'
import type { CoordinatorMlsDeliveryTransport } from './coordinator-mls-delivery-transport.ts'
import { KEY_PACKAGE_POOL_TARGET, type MlsKeyPackageStore } from './keypackage-store.ts'
import { mlsKeyPackageCountPullSigningBytes, mlsKeyPackagePublishSigningBytes } from '../protocol/signing.ts'
import type { MlsKeyPackageCountPullV1, MlsKeyPackagePublishV1 } from '../protocol/mls-ds.ts'
import type { SelfGroupSigner } from './self-group.ts'
import type { MlsDeviceCredentialV2 } from './device-credential.ts'

/**
 * Tops up this device's published KeyPackage pool at the DS to `target`,
 * minting and publishing only the shortfall. A no-op (never touches the
 * transport's publish endpoint) when the DS already holds `target` or more.
 */
export async function ensureKeyPackagePool(
  transport: CoordinatorMlsDeliveryTransport,
  keyStore: MlsKeyPackageStore,
  identityId: string,
  deviceKid: string,
  deviceCredential: MlsDeviceCredentialV2,
  signaturePrivateKey: Uint8Array,
  sign: SelfGroupSigner,
  target: number = KEY_PACKAGE_POOL_TARGET,
  now: () => Date = () => new Date(),
): Promise<void> {
  const countPull: Omit<MlsKeyPackageCountPullV1, 'signature'> = { version: 1, identityId, kid: deviceKid, requestedAt: now().toISOString() }
  const remaining = await transport.keyPackageCount({ ...countPull, signature: await sign(mlsKeyPackageCountPullSigningBytes(countPull)) })
  const short = target - remaining
  if (short <= 0) return

  const minted: OwnKeyPackage[] = await keyStore.mint(deviceKid, deviceCredential, signaturePrivateKey, short)
  const publish: Omit<MlsKeyPackagePublishV1, 'signature'> = {
    version: 1, identityId, kid: deviceKid, packages: minted.map(kp => encodeKeyPackage(kp.publicPackage)), publishedAt: now().toISOString(),
  }
  await transport.publishKeyPackages({ ...publish, signature: await sign(mlsKeyPackagePublishSigningBytes(publish)) })
}
