import { decodeUint16, decodeUint32, uint16Encoder, uint32Encoder } from "./codec/number.js"
import { Decoder, flatMapDecoder, mapDecoder, mapDecoders, orDecoder } from "./codec/tlsDecoder.js"
import { contramapBufferEncoder, contramapBufferEncoders, BufferEncoder, encode, Encoder } from "./codec/tlsEncoder.js"
import { decodeVarLenData, decodeVarLenType, varLenDataEncoder, varLenTypeEncoder } from "./codec/variableLength.js"
import { CiphersuiteName, ciphersuiteEncoder, decodeCiphersuite } from "./crypto/ciphersuite.js"
import { decodeExtension, extensionEncoder, Extension } from "./extension.js"
import { decodeKeyPackage, keyPackageEncoder, KeyPackage } from "./keyPackage.js"
import { decodePskId, pskIdEncoder, PreSharedKeyID } from "./presharedkey.js"
import { decodeDefaultProposalType, defaultProposalTypeEncoder } from "./defaultProposalType.js"
import { decodeProtocolVersion, protocolVersionEncoder, ProtocolVersionName } from "./protocolVersion.js"
import { decodeLeafNodeUpdate, leafNodeEncoder, LeafNodeUpdate } from "./leafNode.js"
import { AppDataUpdate, appDataUpdateEncoder, decodeAppDataUpdate } from './appData.js'

/** @public */
export interface Add {
  keyPackage: KeyPackage
}

const addEncoder: BufferEncoder<Add> = contramapBufferEncoder(keyPackageEncoder, (a) => a.keyPackage)

const encodeAdd: Encoder<Add> = encode(addEncoder)
const decodeAdd: Decoder<Add> = mapDecoder(decodeKeyPackage, (keyPackage) => ({ keyPackage }))

/** @public */
export interface Update {
  leafNode: LeafNodeUpdate
}

const updateEncoder: BufferEncoder<Update> = contramapBufferEncoder(leafNodeEncoder, (u) => u.leafNode)

const encodeUpdate: Encoder<Update> = encode(updateEncoder)
const decodeUpdate: Decoder<Update> = mapDecoder(decodeLeafNodeUpdate, (leafNode) => ({ leafNode }))

/** @public */
export interface Remove {
  removed: number
}

const removeEncoder: BufferEncoder<Remove> = contramapBufferEncoder(uint32Encoder, (r) => r.removed)

const encodeRemove: Encoder<Remove> = encode(removeEncoder)
const decodeRemove: Decoder<Remove> = mapDecoder(decodeUint32, (removed) => ({ removed }))

/** @public */
export interface PSK {
  preSharedKeyId: PreSharedKeyID
}

const pskEncoder: BufferEncoder<PSK> = contramapBufferEncoder(pskIdEncoder, (p) => p.preSharedKeyId)

const encodePSK: Encoder<PSK> = encode(pskEncoder)
const decodePSK: Decoder<PSK> = mapDecoder(decodePskId, (preSharedKeyId) => ({ preSharedKeyId }))

/** @public */
export interface Reinit {
  groupId: Uint8Array
  version: ProtocolVersionName
  cipherSuite: CiphersuiteName
  extensions: Extension[]
}

export const reinitEncoder: BufferEncoder<Reinit> = contramapBufferEncoders(
  [varLenDataEncoder, protocolVersionEncoder, ciphersuiteEncoder, varLenTypeEncoder(extensionEncoder)],
  (r) => [r.groupId, r.version, r.cipherSuite, r.extensions] as const,
)

const encodeReinit: Encoder<Reinit> = encode(reinitEncoder)

export const decodeReinit: Decoder<Reinit> = mapDecoders(
  [decodeVarLenData, decodeProtocolVersion, decodeCiphersuite, decodeVarLenType(decodeExtension)],
  (groupId, version, cipherSuite, extensions) => ({ groupId, version, cipherSuite, extensions }),
)

/** @public */
export interface ExternalInit {
  kemOutput: Uint8Array
}

const externalInitEncoder: BufferEncoder<ExternalInit> = contramapBufferEncoder(
  varLenDataEncoder,
  (e) => e.kemOutput,
)

const encodeExternalInit: Encoder<ExternalInit> = encode(externalInitEncoder)
const decodeExternalInit: Decoder<ExternalInit> = mapDecoder(decodeVarLenData, (kemOutput) => ({ kemOutput }))

/** @public */
export interface GroupContextExtensions {
  extensions: Extension[]
}

const groupContextExtensionsEncoder: BufferEncoder<GroupContextExtensions> = contramapBufferEncoder(
  varLenTypeEncoder(extensionEncoder),
  (g) => g.extensions,
)

const encodeGroupContextExtensions: Encoder<GroupContextExtensions> = encode(groupContextExtensionsEncoder)

const decodeGroupContextExtensions: Decoder<GroupContextExtensions> = mapDecoder(
  decodeVarLenType(decodeExtension),
  (extensions) => ({ extensions }),
)

/** @public */
export interface ProposalAdd {
  proposalType: "add"
  add: Add
}

/** @public */
export interface ProposalUpdate {
  proposalType: "update"
  update: Update
}

/** @public */
export interface ProposalRemove {
  proposalType: "remove"
  remove: Remove
}

/** @public */
export interface ProposalPSK {
  proposalType: "psk"
  psk: PSK
}

/** @public */
export interface ProposalReinit {
  proposalType: "reinit"
  reinit: Reinit
}

/** @public */
export interface ProposalExternalInit {
  proposalType: "external_init"
  externalInit: ExternalInit
}

/** @public */
export interface ProposalGroupContextExtensions {
  proposalType: "group_context_extensions"
  groupContextExtensions: GroupContextExtensions
}

/** `draft-ietf-mls-extensions`-10 §4.7. */
export interface ProposalAppDataUpdate {
  proposalType: 'app_data_update'
  appDataUpdate: AppDataUpdate
}

/** @public */
export interface ProposalCustom {
  proposalType: number
  proposalData: Uint8Array
}

/** @public */
export type Proposal =
  | ProposalAdd
  | ProposalUpdate
  | ProposalRemove
  | ProposalPSK
  | ProposalReinit
  | ProposalExternalInit
  | ProposalGroupContextExtensions
  | ProposalAppDataUpdate
  | ProposalCustom

const proposalAddEncoder: BufferEncoder<ProposalAdd> = contramapBufferEncoders(
  [defaultProposalTypeEncoder, addEncoder],
  (p) => [p.proposalType, p.add] as const,
)

const encodeProposalAdd: Encoder<ProposalAdd> = encode(proposalAddEncoder)

const proposalUpdateEncoder: BufferEncoder<ProposalUpdate> = contramapBufferEncoders(
  [defaultProposalTypeEncoder, updateEncoder],
  (p) => [p.proposalType, p.update] as const,
)

const encodeProposalUpdate: Encoder<ProposalUpdate> = encode(proposalUpdateEncoder)

const proposalRemoveEncoder: BufferEncoder<ProposalRemove> = contramapBufferEncoders(
  [defaultProposalTypeEncoder, removeEncoder],
  (p) => [p.proposalType, p.remove] as const,
)

const encodeProposalRemove: Encoder<ProposalRemove> = encode(proposalRemoveEncoder)

const proposalPSKEncoder: BufferEncoder<ProposalPSK> = contramapBufferEncoders(
  [defaultProposalTypeEncoder, pskEncoder],
  (p) => [p.proposalType, p.psk] as const,
)

const encodeProposalPSK: Encoder<ProposalPSK> = encode(proposalPSKEncoder)

const proposalReinitEncoder: BufferEncoder<ProposalReinit> = contramapBufferEncoders(
  [defaultProposalTypeEncoder, reinitEncoder],
  (p) => [p.proposalType, p.reinit] as const,
)

const encodeProposalReinit: Encoder<ProposalReinit> = encode(proposalReinitEncoder)

const proposalExternalInitEncoder: BufferEncoder<ProposalExternalInit> = contramapBufferEncoders(
  [defaultProposalTypeEncoder, externalInitEncoder],
  (p) => [p.proposalType, p.externalInit] as const,
)

const encodeProposalExternalInit: Encoder<ProposalExternalInit> = encode(proposalExternalInitEncoder)

const proposalGroupContextExtensionsEncoder: BufferEncoder<ProposalGroupContextExtensions> =
  contramapBufferEncoders(
    [defaultProposalTypeEncoder, groupContextExtensionsEncoder],
    (p) => [p.proposalType, p.groupContextExtensions] as const,
  )

const encodeProposalGroupContextExtensions: Encoder<ProposalGroupContextExtensions> = encode(
  proposalGroupContextExtensionsEncoder,
)

const proposalAppDataUpdateEncoder: BufferEncoder<ProposalAppDataUpdate> = contramapBufferEncoders(
  [defaultProposalTypeEncoder, appDataUpdateEncoder],
  (p) => [p.proposalType, p.appDataUpdate] as const,
)
const encodeProposalAppDataUpdate: Encoder<ProposalAppDataUpdate> = encode(proposalAppDataUpdateEncoder)

const proposalCustomEncoder: BufferEncoder<ProposalCustom> = contramapBufferEncoders(
  [uint16Encoder, varLenDataEncoder],
  (p) => [p.proposalType, p.proposalData] as const,
)

const encodeProposalCustom: Encoder<ProposalCustom> = encode(proposalCustomEncoder)

export const proposalEncoder: BufferEncoder<Proposal> = (p) => {
  switch (p.proposalType) {
    case "add":
      return proposalAddEncoder(p)
    case "update":
      return proposalUpdateEncoder(p)
    case "remove":
      return proposalRemoveEncoder(p)
    case "psk":
      return proposalPSKEncoder(p)
    case "reinit":
      return proposalReinitEncoder(p)
    case "external_init":
      return proposalExternalInitEncoder(p)
    case "group_context_extensions":
      return proposalGroupContextExtensionsEncoder(p)
    case 'app_data_update':
      return proposalAppDataUpdateEncoder(p)
    default:
      return proposalCustomEncoder(p)
  }
}

const encodeProposal: Encoder<Proposal> = encode(proposalEncoder)

const decodeProposalAdd: Decoder<ProposalAdd> = mapDecoder(decodeAdd, (add) => ({ proposalType: "add", add }))

const decodeProposalUpdate: Decoder<ProposalUpdate> = mapDecoder(decodeUpdate, (update) => ({
  proposalType: "update",
  update,
}))

const decodeProposalRemove: Decoder<ProposalRemove> = mapDecoder(decodeRemove, (remove) => ({
  proposalType: "remove",
  remove,
}))

const decodeProposalPSK: Decoder<ProposalPSK> = mapDecoder(decodePSK, (psk) => ({ proposalType: "psk", psk }))

const decodeProposalReinit: Decoder<ProposalReinit> = mapDecoder(decodeReinit, (reinit) => ({
  proposalType: "reinit",
  reinit,
}))

const decodeProposalExternalInit: Decoder<ProposalExternalInit> = mapDecoder(
  decodeExternalInit,
  (externalInit) => ({ proposalType: "external_init", externalInit }),
)

const decodeProposalGroupContextExtensions: Decoder<ProposalGroupContextExtensions> = mapDecoder(
  decodeGroupContextExtensions,
  (groupContextExtensions) => ({ proposalType: "group_context_extensions", groupContextExtensions }),
)

const decodeProposalAppDataUpdate: Decoder<ProposalAppDataUpdate> = mapDecoder(
  decodeAppDataUpdate,
  appDataUpdate => ({ proposalType: 'app_data_update', appDataUpdate }),
)

function decodeProposalCustom(proposalType: number): Decoder<ProposalCustom> {
  return mapDecoder(decodeVarLenData, (proposalData) => ({ proposalType, proposalData }))
}

export const decodeProposal: Decoder<Proposal> = orDecoder(
  flatMapDecoder(decodeDefaultProposalType, (proposalType): Decoder<Proposal> => {
    switch (proposalType) {
      case "add":
        return decodeProposalAdd
      case "update":
        return decodeProposalUpdate
      case "remove":
        return decodeProposalRemove
      case "psk":
        return decodeProposalPSK
      case "reinit":
        return decodeProposalReinit
      case "external_init":
        return decodeProposalExternalInit
      case "group_context_extensions":
        return decodeProposalGroupContextExtensions
      case 'app_data_update':
        return decodeProposalAppDataUpdate
    }
  }),
  flatMapDecoder(decodeUint16, (n) => decodeProposalCustom(n)),
)
