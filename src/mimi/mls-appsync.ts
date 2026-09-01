/** Extraction of MIMI application state from authenticated MLS public commits.
 * A hub intentionally has no MLS epoch secrets, so a PrivateMessage cannot be
 * inspected here.  MIMI AppDataUpdate proposals for provider-visible room
 * state therefore have to arrive in an MLS PublicMessage. */
import { decodeMlsMessage, type AppDataUpdate } from '../mls/vendor/index.ts'
import { decodeExact, decodeMimiFrankingAgent, decodeMimiParticipantListUpdate, decodeMimiRoomMetadata, type ParticipantListUpdate } from './app-data.ts'
import {
  MIMI_FRANKING_SIGNATURE_KEY_COMPONENT,
  MIMI_PARTICIPANT_LIST_COMPONENT,
  MIMI_ROOM_METADATA_COMPONENT,
} from './app-data.ts'
import type { FrankingAgentData, RoomMetadata } from './protocol-types.ts'

export interface MimiMlsStateTransition {
  participantListUpdates: ParticipantListUpdate[]
  roomMetadata?: RoomMetadata
  frankingAgent?: FrankingAgentData
}

export class MimiMlsWireError extends TypeError {}

/** Decode only direct AppDataUpdate proposals in a public Commit.  Proposal
 * references are deliberately rejected: accepting a reference without the
 * authenticated proposal it names recreates the old JSON-sidecar trust bug. */
export function extractMimiMlsStateTransition(bytes: Uint8Array): MimiMlsStateTransition {
  const decoded = decodeMlsMessage(bytes, 0)
  if (!decoded || decoded[1] !== bytes.length || decoded[0].wireformat !== 'mls_public_message') {
    throw new MimiMlsWireError('room-state update must be a complete MLS PublicMessage')
  }
  const content = decoded[0].publicMessage.content
  if (content.contentType !== 'commit') throw new MimiMlsWireError('room-state update must be an MLS Commit')

  const transition: MimiMlsStateTransition = { participantListUpdates: [] }
  for (const proposalOrRef of content.commit.proposals) {
    if (proposalOrRef.proposalOrRefType !== 'proposal') throw new MimiMlsWireError('MLS Commit must carry direct AppDataUpdate proposals')
    const proposal = proposalOrRef.proposal
    if (proposal.proposalType !== 'app_data_update') continue
    acceptMimiAppDataUpdate(transition, proposal.appDataUpdate)
  }
  return transition
}

function acceptMimiAppDataUpdate(transition: MimiMlsStateTransition, update: AppDataUpdate): void {
  if (update.operation !== 'update' || update.update === undefined) throw new MimiMlsWireError('MIMI room components may not be removed')
  switch (update.componentId) {
    case MIMI_PARTICIPANT_LIST_COMPONENT: {
      const participantListUpdate = decodeExact(decodeMimiParticipantListUpdate, update.update)
      if (!participantListUpdate) throw new MimiMlsWireError('invalid participant_list AppDataUpdate')
      transition.participantListUpdates.push(participantListUpdate)
      return
    }
    case MIMI_ROOM_METADATA_COMPONENT: {
      if (transition.roomMetadata !== undefined) throw new MimiMlsWireError('only one room_metadata update is valid per Commit')
      const roomMetadata = decodeExact(decodeMimiRoomMetadata, update.update)
      if (!roomMetadata) throw new MimiMlsWireError('invalid room_metadata AppDataUpdate')
      transition.roomMetadata = roomMetadata
      return
    }
    case MIMI_FRANKING_SIGNATURE_KEY_COMPONENT: {
      if (transition.frankingAgent !== undefined) throw new MimiMlsWireError('only one franking_signature_key update is valid per Commit')
      const frankingAgent = decodeExact(decodeMimiFrankingAgent, update.update)
      if (!frankingAgent) throw new MimiMlsWireError('invalid franking_signature_key AppDataUpdate')
      transition.frankingAgent = frankingAgent
      return
    }
  }
}
