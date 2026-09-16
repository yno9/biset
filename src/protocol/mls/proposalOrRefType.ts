import { decodeUint8, uint8Encoder } from "./codec/number.js"
import { Decoder, flatMapDecoder, mapDecoder, mapDecoderOption } from "./codec/tlsDecoder.js"
import { contramapBufferEncoder, contramapBufferEncoders, BufferEncoder, encode, Encoder } from "./codec/tlsEncoder.js"
import { decodeVarLenData, varLenDataEncoder } from "./codec/variableLength.js"
import { decodeProposal, Proposal, proposalEncoder } from "./proposal.js"
import { enumNumberToKey } from "./util/enumHelpers.js"

const proposalOrRefTypes = {
  proposal: 1,
  reference: 2,
} as const

type ProposalOrRefTypeName = keyof typeof proposalOrRefTypes
type ProposalOrRefTypeValue = (typeof proposalOrRefTypes)[ProposalOrRefTypeName]

const proposalOrRefTypeEncoder: BufferEncoder<ProposalOrRefTypeName> = contramapBufferEncoder(
  uint8Encoder,
  (t) => proposalOrRefTypes[t],
)

const encodeProposalOrRefType: Encoder<ProposalOrRefTypeName> = encode(proposalOrRefTypeEncoder)

const decodeProposalOrRefType: Decoder<ProposalOrRefTypeName> = mapDecoderOption(
  decodeUint8,
  enumNumberToKey(proposalOrRefTypes),
)

/** @public */
export interface ProposalOrRefProposal {
  proposalOrRefType: "proposal"
  proposal: Proposal
}

/** @public */
export interface ProposalOrRefProposalRef {
  proposalOrRefType: "reference"
  reference: Uint8Array
}

/** @public */
export type ProposalOrRef = ProposalOrRefProposal | ProposalOrRefProposalRef

const proposalOrRefProposalEncoder: BufferEncoder<ProposalOrRefProposal> = contramapBufferEncoders(
  [proposalOrRefTypeEncoder, proposalEncoder],
  (p) => [p.proposalOrRefType, p.proposal] as const,
)

const encodeProposalOrRefProposal: Encoder<ProposalOrRefProposal> = encode(proposalOrRefProposalEncoder)

const proposalOrRefProposalRefEncoder: BufferEncoder<ProposalOrRefProposalRef> = contramapBufferEncoders(
  [proposalOrRefTypeEncoder, varLenDataEncoder],
  (r) => [r.proposalOrRefType, r.reference] as const,
)

const encodeProposalOrRefProposalRef: Encoder<ProposalOrRefProposalRef> = encode(proposalOrRefProposalRefEncoder)

export const proposalOrRefEncoder: BufferEncoder<ProposalOrRef> = (input) => {
  switch (input.proposalOrRefType) {
    case "proposal":
      return proposalOrRefProposalEncoder(input)
    case "reference":
      return proposalOrRefProposalRefEncoder(input)
  }
}

const encodeProposalOrRef: Encoder<ProposalOrRef> = encode(proposalOrRefEncoder)

export const decodeProposalOrRef: Decoder<ProposalOrRef> = flatMapDecoder(
  decodeProposalOrRefType,
  (proposalOrRefType): Decoder<ProposalOrRef> => {
    switch (proposalOrRefType) {
      case "proposal":
        return mapDecoder(decodeProposal, (proposal) => ({ proposalOrRefType, proposal }))
      case "reference":
        return mapDecoder(decodeVarLenData, (reference) => ({ proposalOrRefType, reference }))
    }
  },
)
