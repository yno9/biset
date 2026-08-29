import { ed25519 } from '@noble/curves/ed25519.js'
import { createMlsDeviceCredential } from '../../../src/mls/device-credential.ts'
import { generateOwnKeyPackage } from '../../../src/mls/group.ts'

/** Test-only constructor for a Root-authorized MLS device. */
export async function mlsDeviceFixture(identityId: string, rootPrivateKey = ed25519.utils.randomSecretKey()) {
  const signaturePrivateKey = ed25519.utils.randomSecretKey()
  const credential = createMlsDeviceCredential(identityId, ed25519.getPublicKey(signaturePrivateKey), rootPrivateKey)
  return {
    kid: credential.deviceKid,
    credential,
    rootPrivateKey,
    signaturePrivateKey,
    own: await generateOwnKeyPackage(credential, signaturePrivateKey),
  }
}
