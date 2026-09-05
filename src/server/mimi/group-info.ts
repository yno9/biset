/**
 * draft §5.6 external join: HPKE-seals the room's stored GroupInfo/
 * ratchet_tree to the requester's `groupInfoPublicKey`, signed with the
 * room's own franking key as the `hub_sender` (protocol-types.ts's
 * GroupInfoResponse doc comment explains why that key is reused).
 */
import { ed25519 } from '@noble/curves/ed25519.js'
import { encryptWithLabel } from '../../vendor/mls/crypto/hpke.js'
import { mlsSuite } from '../../vendor/mls/suite.ts'
import { groupInfoResponseSigningBytes } from './authorizer.ts'
import { encodeGroupInfoRatchetTreeBundle } from './wire.ts'
import type { FrankingKeyMaterial } from './franking.ts'
import type { GroupInfoResponse } from './protocol-types.ts'

const GROUP_INFO_HPKE_LABEL = 'GroupInfo and ratchet_tree encryption'

export async function sealGroupInfoResponse(
  roomId: string, groupInfo: Uint8Array, ratchetTree: Uint8Array | undefined,
  requesterGroupInfoPublicKey: Uint8Array, hubSenderCredential: Uint8Array, keys: FrankingKeyMaterial,
): Promise<GroupInfoResponse> {
  const suite = await mlsSuite()
  const publicKey = await suite.hpke.importPublicKey(requesterGroupInfoPublicKey)
  const plaintext = encodeGroupInfoRatchetTreeBundle(groupInfo, ratchetTree)
  const { ct, enc } = await encryptWithLabel(publicKey, GROUP_INFO_HPKE_LABEL, new TextEncoder().encode(roomId), plaintext, suite.hpke)
  const unsigned: Omit<GroupInfoResponse, 'signature'> = {
    version: 1, roomId, status: 'success', cipherSuite: 1,
    hubSenderSignatureKey: keys.signingPublicKey, hubSenderCredential,
    encryptedGroupInfoAndTree: { kemOutput: enc, ciphertext: ct },
  }
  return { ...unsigned, signature: ed25519.sign(groupInfoResponseSigningBytes(unsigned), keys.signingPrivateKey) }
}
