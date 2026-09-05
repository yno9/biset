/** MIMI's registered application components, encoded with MLS TLS
 * Presentation Language primitives (draft-ietf-mimi-protocol-06 §7/§10). */
import { decodeUint32, uint32Encoder } from '../vendor/mls/codec/number.ts'
import { Decoder, mapDecoder, mapDecoders } from '../vendor/mls/codec/tlsDecoder.ts'
import { BufferEncoder, contramapBufferEncoders, encode, Encoder } from '../vendor/mls/codec/tlsEncoder.ts'
import { decodeVarLenData, decodeVarLenType, varLenDataEncoder, varLenTypeEncoder } from '../vendor/mls/codec/variableLength.ts'
import type { FrankAAD, FrankingAgentData, ParticipantListData, RoomMetadata, UserRolePair } from './protocol-types.ts'

const MIMI_FRANK_AAD_COMPONENT = 0x0020
export const MIMI_FRANKING_SIGNATURE_KEY_COMPONENT = 0x0021
export const MIMI_PARTICIPANT_LIST_COMPONENT = 0x0022
export const MIMI_ROOM_METADATA_COMPONENT = 0x0023

const text = new TextEncoder()
const decodeText = new TextDecoder('utf-8', { fatal: true })
const textEncoder: BufferEncoder<string> = value => varLenDataEncoder(text.encode(value))
const decodeTextValue: Decoder<string> = mapDecoder(decodeVarLenData, bytes => decodeText.decode(bytes))

const userRolePairEncoder: BufferEncoder<UserRolePair> = contramapBufferEncoders(
  [textEncoder, uint32Encoder], value => [value.user, value.roleIndex] as const,
)
const decodeUserRolePair: Decoder<UserRolePair> = mapDecoders(
  [decodeTextValue, decodeUint32], (user, roleIndex) => ({ user, roleIndex }),
)

const participantListEncoder: BufferEncoder<ParticipantListData> = contramapBufferEncoders(
  [varLenTypeEncoder(userRolePairEncoder)], value => [value.participants] as const,
)
const encodeMimiParticipantList: Encoder<ParticipantListData> = encode(participantListEncoder)
const decodeMimiParticipantList: Decoder<ParticipantListData> = mapDecoder(
  decodeVarLenType(decodeUserRolePair), participants => ({ participants }),
)

export interface ParticipantListUpdate {
  changedRoleParticipants: { userIndex: number; roleIndex: number }[]
  removedIndices: number[]
  addedParticipants: UserRolePair[]
}
const userIndexRoleEncoder: BufferEncoder<{ userIndex: number; roleIndex: number }> = contramapBufferEncoders(
  [uint32Encoder, uint32Encoder], value => [value.userIndex, value.roleIndex] as const,
)
const decodeUserIndexRole: Decoder<{ userIndex: number; roleIndex: number }> = mapDecoders(
  [decodeUint32, decodeUint32], (userIndex, roleIndex) => ({ userIndex, roleIndex }),
)
const participantListUpdateEncoder: BufferEncoder<ParticipantListUpdate> = contramapBufferEncoders(
  [varLenTypeEncoder(userIndexRoleEncoder), varLenTypeEncoder(uint32Encoder), varLenTypeEncoder(userRolePairEncoder)],
  value => [value.changedRoleParticipants, value.removedIndices, value.addedParticipants] as const,
)
export const encodeMimiParticipantListUpdate: Encoder<ParticipantListUpdate> = encode(participantListUpdateEncoder)
export const decodeMimiParticipantListUpdate: Decoder<ParticipantListUpdate> = mapDecoders(
  [decodeVarLenType(decodeUserIndexRole), decodeVarLenType(decodeUint32), decodeVarLenType(decodeUserRolePair)],
  (changedRoleParticipants, removedIndices, addedParticipants) => ({ changedRoleParticipants, removedIndices, addedParticipants }),
)

export function applyMimiParticipantListUpdate(current: ParticipantListData, update: ParticipantListUpdate): ParticipantListData {
  const next = current.participants.map(value => ({ ...value }))
  const changed = new Set<number>()
  for (const value of update.changedRoleParticipants) {
    if (!Number.isInteger(value.userIndex) || value.userIndex < 0 || value.userIndex >= next.length || changed.has(value.userIndex)) throw new TypeError('invalid or duplicate participant role index')
    changed.add(value.userIndex)
    next[value.userIndex]!.roleIndex = value.roleIndex
  }
  const removed = new Set<number>()
  for (const index of update.removedIndices) {
    // draft §7.5 (line 3090-3092): a commit is invalid if it operates on the
    // same user more than once across changedRoleParticipants and
    // removedIndices combined, not just within one list.
    if (!Number.isInteger(index) || index < 0 || index >= next.length || removed.has(index) || changed.has(index)) throw new TypeError('invalid or duplicate participant removal index')
    removed.add(index)
  }
  return { participants: [...next.filter((_value, index) => !removed.has(index)), ...update.addedParticipants.map(value => ({ ...value }))] }
}

const richDescriptionEncoder: BufferEncoder<{ mediaType: string; languageTag: string; content: string }> = contramapBufferEncoders(
  [textEncoder, textEncoder, textEncoder], value => [value.mediaType, value.languageTag, value.content] as const,
)
const decodeRichDescription: Decoder<{ mediaType: string; languageTag: string; content: string }> = mapDecoders(
  [decodeTextValue, decodeTextValue, decodeTextValue], (mediaType, languageTag, content) => ({ mediaType, languageTag, content }),
)
const roomMetadataEncoder: BufferEncoder<RoomMetadata> = contramapBufferEncoders(
  [textEncoder, textEncoder, varLenTypeEncoder(richDescriptionEncoder), textEncoder, textEncoder, textEncoder],
  value => [value.roomUri, value.roomName, value.descriptions ?? [], value.roomAvatar ?? '', value.roomSubject ?? '', value.roomMood ?? ''] as const,
)
export const encodeMimiRoomMetadata: Encoder<RoomMetadata> = encode(roomMetadataEncoder)
export const decodeMimiRoomMetadata: Decoder<RoomMetadata> = mapDecoders(
  [decodeTextValue, decodeTextValue, decodeVarLenType(decodeRichDescription), decodeTextValue, decodeTextValue, decodeTextValue],
  (roomUri, roomName, descriptions, roomAvatar, roomSubject, roomMood) => ({ roomUri, roomName, ...(descriptions.length ? { descriptions } : {}), ...(roomAvatar ? { roomAvatar } : {}), ...(roomSubject ? { roomSubject } : {}), ...(roomMood ? { roomMood } : {}) }),
)

const frankingAgentEncoder: BufferEncoder<FrankingAgentData> = contramapBufferEncoders(
  [varLenDataEncoder, varLenDataEncoder], value => [value.frankingSignatureKey, value.credential] as const,
)
export const encodeMimiFrankingAgent: Encoder<FrankingAgentData> = encode(frankingAgentEncoder)
export const decodeMimiFrankingAgent: Decoder<FrankingAgentData> = mapDecoders(
  [decodeVarLenData, decodeVarLenData], (frankingSignatureKey, credential) => ({ frankingSignatureKey, credential }),
)

function encodeMimiFrankAad(value: FrankAAD): Uint8Array {
  if (value.frankingTag.length !== 32) throw new TypeError('FrankAAD franking_tag must be 32 bytes')
  return new Uint8Array(value.frankingTag)
}
function decodeMimiFrankAad(value: Uint8Array): FrankAAD | undefined {
  return value.length === 32 ? { frankingTag: new Uint8Array(value) } : undefined
}

export function decodeExact<T>(decoder: Decoder<T>, bytes: Uint8Array): T | undefined {
  const decoded = decoder(bytes, 0)
  return decoded && decoded[1] === bytes.length ? decoded[0] : undefined
}
