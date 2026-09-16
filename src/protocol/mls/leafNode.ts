import { Capabilities, capabilitiesEncoder, decodeCapabilities } from "./capabilities.js"
import { decodeUint32, uint32Encoder } from "./codec/number.js"
import { Decoder, mapDecoders, flatMapDecoder, mapDecoderOption, mapDecoder } from "./codec/tlsDecoder.js"
import { BufferEncoder, contramapBufferEncoders, encode, Encoder } from "./codec/tlsEncoder.js"
import { varLenDataEncoder, decodeVarLenData, varLenTypeEncoder, decodeVarLenType } from "./codec/variableLength.js"
import { credentialEncoder, decodeCredential, Credential } from "./credential.js"
import { Signature, signWithLabel, verifyWithLabel } from "./crypto/signature.js"
import { Extension, extensionEncoder, decodeExtension } from "./extension.js"
import { leafNodeSourceEncoder, decodeLeafNodeSource } from "./leafNodeSource.js"
import { Lifetime, lifetimeEncoder, decodeLifetime } from "./lifetime.js"

/** @public */
export interface LeafNodeData {
  hpkePublicKey: Uint8Array
  signaturePublicKey: Uint8Array
  credential: Credential
  capabilities: Capabilities
}

const leafNodeDataEncoder: BufferEncoder<LeafNodeData> = contramapBufferEncoders(
  [varLenDataEncoder, varLenDataEncoder, credentialEncoder, capabilitiesEncoder],
  (data) => [data.hpkePublicKey, data.signaturePublicKey, data.credential, data.capabilities] as const,
)

const encodeLeafNodeData: Encoder<LeafNodeData> = encode(leafNodeDataEncoder)

const decodeLeafNodeData: Decoder<LeafNodeData> = mapDecoders(
  [decodeVarLenData, decodeVarLenData, decodeCredential, decodeCapabilities],
  (hpkePublicKey, signaturePublicKey, credential, capabilities) => ({
    hpkePublicKey,
    signaturePublicKey,
    credential,
    capabilities,
  }),
)

/** @public */
export type LeafNodeInfoOmitted = LeafNodeInfoKeyPackage | LeafNodeInfoUpdateOmitted | LeafNodeInfoCommitOmitted

/** @public */
export interface LeafNodeInfoUpdateOmitted {
  leafNodeSource: "update"
  extensions: Extension[]
}

/** @public */
export interface LeafNodeInfoCommitOmitted {
  leafNodeSource: "commit"
  parentHash: Uint8Array
  extensions: Extension[]
}

/** @public */
export interface LeafNodeInfoKeyPackage {
  leafNodeSource: "key_package"
  lifetime: Lifetime
  extensions: Extension[]
}

const leafNodeInfoKeyPackageEncoder: BufferEncoder<LeafNodeInfoKeyPackage> = contramapBufferEncoders(
  [leafNodeSourceEncoder, lifetimeEncoder, varLenTypeEncoder(extensionEncoder)],
  (info) => ["key_package", info.lifetime, info.extensions] as const,
)

const encodeLeafNodeInfoKeyPackage: Encoder<LeafNodeInfoKeyPackage> = encode(leafNodeInfoKeyPackageEncoder)

const leafNodeInfoUpdateOmittedEncoder: BufferEncoder<LeafNodeInfoUpdateOmitted> = contramapBufferEncoders(
  [leafNodeSourceEncoder, varLenTypeEncoder(extensionEncoder)],
  (i) => [i.leafNodeSource, i.extensions] as const,
)

const encodeLeafNodeInfoUpdateOmitted: Encoder<LeafNodeInfoUpdate> = encode(leafNodeInfoUpdateOmittedEncoder)

const leafNodeInfoCommitOmittedEncoder: BufferEncoder<LeafNodeInfoCommitOmitted> = contramapBufferEncoders(
  [leafNodeSourceEncoder, varLenDataEncoder, varLenTypeEncoder(extensionEncoder)],
  (info) => [info.leafNodeSource, info.parentHash, info.extensions] as const,
)

const encodeLeafNodeInfoCommitOmitted: Encoder<LeafNodeInfoCommitOmitted> = encode(
  leafNodeInfoCommitOmittedEncoder,
)

const leafNodeInfoOmittedEncoder: BufferEncoder<LeafNodeInfoOmitted> = (info) => {
  switch (info.leafNodeSource) {
    case "key_package":
      return leafNodeInfoKeyPackageEncoder(info)
    case "update":
      return leafNodeInfoUpdateOmittedEncoder(info)
    case "commit":
      return leafNodeInfoCommitOmittedEncoder(info)
  }
}

const encodeLeafNodeInfoOmitted: Encoder<LeafNodeInfoOmitted> = encode(leafNodeInfoOmittedEncoder)

const decodeLeafNodeInfoKeyPackage: Decoder<LeafNodeInfoKeyPackage> = mapDecoders(
  [decodeLifetime, decodeVarLenType(decodeExtension)],
  (lifetime, extensions) => ({
    leafNodeSource: "key_package",
    lifetime,
    extensions,
  }),
)

const decodeLeafNodeInfoUpdateOmitted: Decoder<LeafNodeInfoUpdateOmitted> = mapDecoder(
  decodeVarLenType(decodeExtension),
  (extensions) => ({
    leafNodeSource: "update",
    extensions,
  }),
)

const decodeLeafNodeInfoCommitOmitted: Decoder<LeafNodeInfoCommitOmitted> = mapDecoders(
  [decodeVarLenData, decodeVarLenType(decodeExtension)],
  (parentHash, extensions) => ({
    leafNodeSource: "commit",
    parentHash,
    extensions,
  }),
)

const decodeLeafNodeInfoOmitted: Decoder<LeafNodeInfoOmitted> = flatMapDecoder(
  decodeLeafNodeSource,
  (leafNodeSource): Decoder<LeafNodeInfoOmitted> => {
    switch (leafNodeSource) {
      case "key_package":
        return decodeLeafNodeInfoKeyPackage
      case "update":
        return decodeLeafNodeInfoUpdateOmitted
      case "commit":
        return decodeLeafNodeInfoCommitOmitted
    }
  },
)

type LeafNodeInfo = LeafNodeInfoKeyPackage | LeafNodeInfoUpdate | LeafNodeInfoCommit

type LeafNodeInfoUpdate = LeafNodeInfoUpdateOmitted & {
  groupId: Uint8Array
  leafIndex: number
}
type LeafNodeInfoCommit = LeafNodeInfoCommitOmitted & {
  groupId: Uint8Array
  leafIndex: number
}

const leafNodeInfoUpdateEncoder: BufferEncoder<LeafNodeInfoUpdate> = contramapBufferEncoders(
  [leafNodeInfoUpdateOmittedEncoder, varLenDataEncoder, uint32Encoder],
  (i) => [i, i.groupId, i.leafIndex] as const,
)

const encodeLeafNodeInfoUpdate: Encoder<LeafNodeInfoUpdate> = encode(leafNodeInfoUpdateEncoder)

const leafNodeInfoCommitEncoder: BufferEncoder<LeafNodeInfoCommit> = contramapBufferEncoders(
  [leafNodeInfoCommitOmittedEncoder, varLenDataEncoder, uint32Encoder],
  (info) => [info, info.groupId, info.leafIndex] as const,
)

const encodeLeafNodeInfoCommit: Encoder<LeafNodeInfoCommit> = encode(leafNodeInfoCommitEncoder)

const leafNodeInfoEncoder: BufferEncoder<LeafNodeInfo> = (info) => {
  switch (info.leafNodeSource) {
    case "key_package":
      return leafNodeInfoKeyPackageEncoder(info)
    case "update":
      return leafNodeInfoUpdateEncoder(info)
    case "commit":
      return leafNodeInfoCommitEncoder(info)
  }
}

const encodeLeafNodeInfo: Encoder<LeafNodeInfo> = encode(leafNodeInfoEncoder)

const decodeLeafNodeInfoUpdate: Decoder<LeafNodeInfoUpdate> = mapDecoders(
  [decodeLeafNodeInfoUpdateOmitted, decodeVarLenData, decodeUint32],
  (ln, groupId, leafIndex) => ({
    ...ln,
    groupId,
    leafIndex,
  }),
)

const decodeLeafNodeInfoCommit: Decoder<LeafNodeInfoCommit> = mapDecoders(
  [decodeLeafNodeInfoCommitOmitted, decodeVarLenData, decodeUint32],
  (ln, groupId, leafIndex) => ({
    ...ln,
    groupId,
    leafIndex,
  }),
)

const decodeLeafNodeInfo: Decoder<LeafNodeInfo> = flatMapDecoder(
  decodeLeafNodeSource,
  (leafNodeSource): Decoder<LeafNodeInfo> => {
    switch (leafNodeSource) {
      case "key_package":
        return decodeLeafNodeInfoKeyPackage
      case "update":
        return decodeLeafNodeInfoUpdate
      case "commit":
        return decodeLeafNodeInfoCommit
    }
  },
)

type LeafNodeTBS = LeafNodeData & LeafNodeInfo

export type LeafNodeTBSCommit = LeafNodeData & LeafNodeInfoCommit

export type LeafNodeTBSKeyPackage = LeafNodeData & LeafNodeInfoKeyPackage

// biset: the third LeafNodeTBS variant upstream never named or exported a
// signer for — signLeafNodeCommit/signLeafNodeKeyPackage below cover the
// other two, but nothing in this file's own createCommit/joinGroup flows
// ever needed to construct a self-issued Update proposal, which is exactly
// what mls/group.ts's updateOwnCredential (a did:webvh domain move's
// credential migration, see self-group.ts's own header) needs: replace an
// EXISTING leaf's credential in place via a plain Update proposal, with no
// tree-shape change at all -- unlike an external-commit resync, which
// removes and re-adds a leaf and, for a single-member group, hits an
// unrelated bug in ratchetTree.ts's extendRatchetTree (found live,
// 2026-08-26, resync approach abandoned for this reason).
type LeafNodeTBSUpdate = LeafNodeData & LeafNodeInfoUpdate

const leafNodeTBSEncoder: BufferEncoder<LeafNodeTBS> = contramapBufferEncoders(
  [leafNodeDataEncoder, leafNodeInfoEncoder],
  (tbs) => [tbs, tbs] as const,
)

const encodeLeafNodeTBS: Encoder<LeafNodeTBS> = encode(leafNodeTBSEncoder)

/** @public */
export type LeafNode = LeafNodeData & LeafNodeInfoOmitted & { signature: Uint8Array }

export const leafNodeEncoder: BufferEncoder<LeafNode> = contramapBufferEncoders(
  [leafNodeDataEncoder, leafNodeInfoOmittedEncoder, varLenDataEncoder],
  (leafNode) => [leafNode, leafNode, leafNode.signature] as const,
)

const encodeLeafNode: Encoder<LeafNode> = encode(leafNodeEncoder)

export const decodeLeafNode: Decoder<LeafNode> = mapDecoders(
  [decodeLeafNodeData, decodeLeafNodeInfoOmitted, decodeVarLenData],
  (data, info, signature) => ({
    ...data,
    ...info,
    signature,
  }),
)

/** @public */
export type LeafNodeKeyPackage = LeafNode & { leafNodeSource: "key_package" }

export const decodeLeafNodeKeyPackage: Decoder<LeafNodeKeyPackage> = mapDecoderOption(decodeLeafNode, (ln) =>
  ln.leafNodeSource === "key_package" ? ln : undefined,
)

/** @public */
export type LeafNodeCommit = LeafNode & { leafNodeSource: "commit" }

export const decodeLeafNodeCommit: Decoder<LeafNodeCommit> = mapDecoderOption(decodeLeafNode, (ln) =>
  ln.leafNodeSource === "commit" ? ln : undefined,
)

/** @public */
export type LeafNodeUpdate = LeafNode & { leafNodeSource: "update" }

export const decodeLeafNodeUpdate: Decoder<LeafNodeUpdate> = mapDecoderOption(decodeLeafNode, (ln) =>
  ln.leafNodeSource === "update" ? ln : undefined,
)

function toTbs(leafNode: LeafNode, groupId: Uint8Array, leafIndex: number): LeafNodeTBS {
  switch (leafNode.leafNodeSource) {
    case "key_package":
      return { ...leafNode, leafNodeSource: leafNode.leafNodeSource }
    case "update":
      return { ...leafNode, leafNodeSource: leafNode.leafNodeSource, groupId, leafIndex }
    case "commit":
      return { ...leafNode, leafNodeSource: leafNode.leafNodeSource, groupId, leafIndex }
  }
}

export async function signLeafNodeCommit(
  tbs: LeafNodeTBSCommit,
  signaturePrivateKey: Uint8Array,
  sig: Signature,
): Promise<LeafNodeCommit> {
  return {
    ...tbs,
    signature: await signWithLabel(signaturePrivateKey, "LeafNodeTBS", encode(leafNodeTBSEncoder)(tbs), sig),
  }
}

export async function signLeafNodeKeyPackage(
  tbs: LeafNodeTBSKeyPackage,
  signaturePrivateKey: Uint8Array,
  sig: Signature,
): Promise<LeafNodeKeyPackage> {
  return {
    ...tbs,
    signature: await signWithLabel(signaturePrivateKey, "LeafNodeTBS", encode(leafNodeTBSEncoder)(tbs), sig),
  }
}

// biset: the missing third variant -- see LeafNodeTBSUpdate's own comment above.
async function signLeafNodeUpdate(
  tbs: LeafNodeTBSUpdate,
  signaturePrivateKey: Uint8Array,
  sig: Signature,
): Promise<LeafNodeUpdate> {
  return {
    ...tbs,
    signature: await signWithLabel(signaturePrivateKey, "LeafNodeTBS", encode(leafNodeTBSEncoder)(tbs), sig),
  }
}

export function verifyLeafNodeSignature(
  leaf: LeafNode,
  groupId: Uint8Array,
  leafIndex: number,
  sig: Signature,
): Promise<boolean> {
  return verifyWithLabel(
    leaf.signaturePublicKey,
    "LeafNodeTBS",
    encode(leafNodeTBSEncoder)(toTbs(leaf, groupId, leafIndex)),
    leaf.signature,
    sig,
  )
}

export function verifyLeafNodeSignatureKeyPackage(leaf: LeafNodeKeyPackage, sig: Signature): Promise<boolean> {
  return verifyWithLabel(leaf.signaturePublicKey, "LeafNodeTBS", encode(leafNodeTBSEncoder)(leaf), leaf.signature, sig)
}
