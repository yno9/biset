import { Decoder, flatMapDecoder, mapDecoder, mapDecoders } from "./codec/tlsDecoder.js"
import { contramapBufferEncoders, BufferEncoder, encode, Encoder } from "./codec/tlsEncoder.js"
import { decodeGroupInfo, groupInfoEncoder, GroupInfo } from "./groupInfo.js"
import { decodeKeyPackage, keyPackageEncoder, KeyPackage } from "./keyPackage.js"
import { decodePrivateMessage, privateMessageEncoder, PrivateMessage } from "./privateMessage.js"
import { decodeProtocolVersion, protocolVersionEncoder, ProtocolVersionName } from "./protocolVersion.js"
import { decodePublicMessage, publicMessageEncoder, PublicMessage } from "./publicMessage.js"
import { decodeWelcome, Welcome, welcomeEncoder } from "./welcome.js"
import { decodeWireformat, wireformatEncoder } from "./wireformat.js"

/** @public */
export interface MlsMessageProtocol {
  version: ProtocolVersionName
}

/** @public */
export interface MlsWelcome {
  wireformat: "mls_welcome"
  welcome: Welcome
}

/** @public */
export interface MlsPrivateMessage {
  wireformat: "mls_private_message"
  privateMessage: PrivateMessage
}

/** @public */
export interface MlsGroupInfo {
  wireformat: "mls_group_info"
  groupInfo: GroupInfo
}

/** @public */
export interface MlsKeyPackage {
  wireformat: "mls_key_package"
  keyPackage: KeyPackage
}
/** @public */
export interface MlsPublicMessage {
  wireformat: "mls_public_message"
  publicMessage: PublicMessage
}

/** @public */
export type MlsMessageContent = MlsWelcome | MlsPrivateMessage | MlsGroupInfo | MlsKeyPackage | MlsPublicMessage
/** @public */
export type MLSMessage = MlsMessageProtocol & MlsMessageContent

const mlsPublicMessageEncoder: BufferEncoder<MlsPublicMessage> = contramapBufferEncoders(
  [wireformatEncoder, publicMessageEncoder],
  (msg) => [msg.wireformat, msg.publicMessage] as const,
)

const encodeMlsPublicMessage: Encoder<MlsPublicMessage> = encode(mlsPublicMessageEncoder)

const mlsWelcomeEncoder: BufferEncoder<MlsWelcome> = contramapBufferEncoders(
  [wireformatEncoder, welcomeEncoder],
  (wm) => [wm.wireformat, wm.welcome] as const,
)

const encodeMlsWelcome: Encoder<MlsWelcome> = encode(mlsWelcomeEncoder)

const mlsPrivateMessageEncoder: BufferEncoder<MlsPrivateMessage> = contramapBufferEncoders(
  [wireformatEncoder, privateMessageEncoder],
  (pm) => [pm.wireformat, pm.privateMessage] as const,
)

const encodeMlsPrivateMessage: Encoder<MlsPrivateMessage> = encode(mlsPrivateMessageEncoder)

const mlsGroupInfoEncoder: BufferEncoder<MlsGroupInfo> = contramapBufferEncoders(
  [wireformatEncoder, groupInfoEncoder],
  (gi) => [gi.wireformat, gi.groupInfo] as const,
)

const encodeMlsGroupInfo: Encoder<MlsGroupInfo> = encode(mlsGroupInfoEncoder)

const mlsKeyPackageEncoder: BufferEncoder<MlsKeyPackage> = contramapBufferEncoders(
  [wireformatEncoder, keyPackageEncoder],
  (kp) => [kp.wireformat, kp.keyPackage] as const,
)

const encodeMlsKeyPackage: Encoder<MlsKeyPackage> = encode(mlsKeyPackageEncoder)

const mlsMessageContentEncoder: BufferEncoder<MlsMessageContent> = (mc) => {
  switch (mc.wireformat) {
    case "mls_public_message":
      return mlsPublicMessageEncoder(mc)
    case "mls_welcome":
      return mlsWelcomeEncoder(mc)
    case "mls_private_message":
      return mlsPrivateMessageEncoder(mc)
    case "mls_group_info":
      return mlsGroupInfoEncoder(mc)
    case "mls_key_package":
      return mlsKeyPackageEncoder(mc)
  }
}

const encodeMlsMessageContent: Encoder<MlsMessageContent> = encode(mlsMessageContentEncoder)

const decodeMlsMessageContent: Decoder<MlsMessageContent> = flatMapDecoder(
  decodeWireformat,
  (wireformat): Decoder<MlsMessageContent> => {
    switch (wireformat) {
      case "mls_public_message":
        return mapDecoder(decodePublicMessage, (publicMessage) => ({ wireformat, publicMessage }))
      case "mls_welcome":
        return mapDecoder(decodeWelcome, (welcome) => ({ wireformat, welcome }))
      case "mls_private_message":
        return mapDecoder(decodePrivateMessage, (privateMessage) => ({ wireformat, privateMessage }))
      case "mls_group_info":
        return mapDecoder(decodeGroupInfo, (groupInfo) => ({ wireformat, groupInfo }))
      case "mls_key_package":
        return mapDecoder(decodeKeyPackage, (keyPackage) => ({ wireformat, keyPackage }))
    }
  },
)

const mlsMessageEncoder: BufferEncoder<MLSMessage> = contramapBufferEncoders(
  [protocolVersionEncoder, mlsMessageContentEncoder],
  (w) => [w.version, w] as const,
)

/** @public */
export const encodeMlsMessage: Encoder<MLSMessage> = encode(mlsMessageEncoder)

/** @public */
export const decodeMlsMessage: Decoder<MLSMessage> = mapDecoders(
  [decodeProtocolVersion, decodeMlsMessageContent],
  (version, mc) => ({ ...mc, version }),
)
