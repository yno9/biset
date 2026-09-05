/** Hub-side MIMI message franking (draft §5.4.1). */
import { ed25519 } from '@noble/curves/ed25519.js'
import { hmac } from '@noble/hashes/hmac.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { concatBytes } from '@noble/hashes/utils.js'
import { canonicalBytes } from '../../shared/protocol/canonical.ts'
import type { Frank, FrankAAD, MimiRoomId, MimiUserUri, ServerFrankingContext } from './protocol-types.ts'

export interface FrankingKeyMaterial {
  hubKey: Uint8Array
  signingPrivateKey: Uint8Array
  signingPublicKey: Uint8Array
}

export interface FrankingInput {
  aad: FrankAAD
  senderUri: MimiUserUri
  roomUri: MimiRoomId
  acceptedTimestamp: string
  ciphersuite: number
}

export function createFrankingKeyMaterial(): FrankingKeyMaterial {
  const signingPrivateKey = ed25519.utils.randomSecretKey()
  return { hubKey: crypto.getRandomValues(new Uint8Array(32)), signingPrivateKey, signingPublicKey: ed25519.getPublicKey(signingPrivateKey) }
}

export function frankMessage(keys: FrankingKeyMaterial, input: FrankingInput): Frank {
  if (keys.hubKey.length !== 32 || input.aad.frankingTag.length !== 32) throw new TypeError('MIMI franking keys and tag must be 32 bytes')
  const context: ServerFrankingContext = { senderUri: input.senderUri, roomUri: input.roomUri, acceptedTimestamp: input.acceptedTimestamp }
  const serverFrank = hmac(sha256, keys.hubKey, concatBytes(input.aad.frankingTag, frankingContextBytes(context)))
  const unsigned = { serverFrank, frankingSignatureCiphersuite: input.ciphersuite, context }
  return { ...unsigned, frankingIntegritySignature: ed25519.sign(frankingIntegrityBytes(unsigned), keys.signingPrivateKey) }
}

/** Receiver-side integrity verification after it has decrypted the content. */
export function verifyFrank(publicKey: Uint8Array, frank: Frank): boolean {
  return publicKey.length === 32 && frank.serverFrank.length === 32 && ed25519.verify(frank.frankingIntegritySignature, frankingIntegrityBytes(frank), publicKey)
}

function frankingContextBytes(context: ServerFrankingContext): Uint8Array {
  return canonicalBytes({ label: 'biset/mimi-server-franking-context/v1', senderUri: context.senderUri, roomUri: context.roomUri, acceptedTimestamp: context.acceptedTimestamp })
}

function frankingIntegrityBytes(value: Pick<Frank, 'serverFrank' | 'frankingSignatureCiphersuite' | 'context'>): Uint8Array {
  return canonicalBytes({ label: 'FrankingIntegrityTBS', serverFrank: Array.from(value.serverFrank), frankingSignatureCiphersuite: value.frankingSignatureCiphersuite, context: { senderUri: value.context.senderUri, roomUri: value.context.roomUri, acceptedTimestamp: value.context.acceptedTimestamp } })
}
