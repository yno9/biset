/** Creation of the single-user Self/Vault MIMI room.
 *
 * The room ID is an opaque random provider URI.  It is intentionally separate
 * from the MLS GroupId: MIMI routes by room URI while MLS keeps its GroupId
 * cryptographic and opaque. */
import { ed25519 } from '@noble/curves/ed25519.js'
import { bytesToBase64url } from '../protocol/canonical.ts'
import { createMlsGroup, confirmCommit, generateOwnKeyPackage, groupInfoForExternalJoin } from './group.ts'
import type { MlsDeviceCredentialV2 } from './device-credential.ts'
import { createCommit, encodeMlsMessage } from './vendor/index.ts'
import { encodeCredential } from './vendor/credential.ts'
import { mlsSuite } from './suite.ts'
import { encodeMimiFrankingAgent, encodeMimiParticipantListUpdate, encodeMimiRoomMetadata } from '../mimi/app-data.ts'
import { updateRoomSigningBytes } from '../mimi/authorizer.ts'
import type { MimiClientMode, MimiClientTransport } from './mimi-client-transport.ts'
import type { VisibleCredential } from '../mimi/protocol-types.ts'
import type { MimiVaultSessionStateStore } from './mimi-vault-session.ts'

export interface CreateMimiVaultRoomOptions {
  identityId: string
  /** Full device URI (`did…#kid`), never an account or mail address. */
  deviceId: string
  selfGroupId: string
  credential: MlsDeviceCredentialV2
  signaturePrivateKey: Uint8Array
  transport: MimiClientTransport
  stateStore: MimiVaultSessionStateStore
  mode?: MimiClientMode
  providerHost?: string
  now?: () => Date
}

export interface CreatedMimiVaultRoom { roomId: string; credential: VisibleCredential }

/** Creates and durably records a fresh Self/Vault room.  Nothing is saved
 * locally before the hub has accepted the initial public MLS commit. */
export async function createMimiVaultRoom(options: CreateMimiVaultRoomOptions): Promise<CreatedMimiVaultRoom> {
  const mode = options.mode ?? 'self'
  const now = options.now ?? (() => new Date())
  const providerHost = options.providerHost ?? 'mimi-self.biset.md'
  if (!options.identityId || !options.deviceId || !options.selfGroupId || !/^[A-Za-z0-9.-]+$/.test(providerHost)) throw new TypeError('MIMI Vault room identity is invalid')
  const roomId = `mimi://${providerHost}/r/vault-${bytesToBase64url(crypto.getRandomValues(new Uint8Array(32)))}`
  const own = await generateOwnKeyPackage(options.credential, options.signaturePrivateKey)
  const sender: VisibleCredential = {
    kind: 'visible', user: options.identityId, client: options.deviceId,
    credential: encodeCredential(own.publicPackage.leafNode.credential), signaturePublicKey: own.publicPackage.leafNode.signaturePublicKey,
  }
  const franking = await options.transport.frankingAgent(mode, roomId)
  const state = await createMlsGroup(crypto.getRandomValues(new Uint8Array(32)), own)
  const proposal = (componentId: number, update: Uint8Array) => ({ proposalType: 'app_data_update' as const, appDataUpdate: { componentId, operation: 'update' as const, update } })
  const initial = await createCommit({ state, cipherSuite: await mlsSuite() }, {
    wireAsPublicMessage: true,
    extraProposals: [
      proposal(0x0021, encodeMimiFrankingAgent({ frankingSignatureKey: franking.frankingSignatureKey, credential: franking.credential })),
      proposal(0x0022, encodeMimiParticipantListUpdate({ changedRoleParticipants: [], removedIndices: [], addedParticipants: [{ user: options.identityId, roleIndex: 1 }] })),
      proposal(0x0023, encodeMimiRoomMetadata({ roomUri: roomId, roomName: 'Biset Vault' })),
    ],
  })
  const unsigned = {
    version: 1 as const, protocol: 'mls10' as const, roomId, sender, epoch: '0',
    bundle: { kind: 'commit' as const, proposalOrCommit: encodeMlsMessage(initial.commit), groupInfo: await groupInfoForExternalJoin(initial.newState) },
    initialState: {
      basePolicy: new Uint8Array(), participantList: { participants: [{ user: options.identityId, roleIndex: 1, clientIds: [options.deviceId] }] },
      memberCredentials: [sender], metadata: { roomUri: roomId, roomName: 'Biset Vault' },
    }, submittedAt: now().toISOString(),
  }
  const response = await options.transport.update(mode, { ...unsigned, signature: ed25519.sign(updateRoomSigningBytes(unsigned), options.signaturePrivateKey) })
  if (response.status !== 'success') throw new Error(`MIMI Vault room creation failed: ${response.status}`)
  try {
    await options.stateStore.saveMimiVault(options.identityId, { roomId, selfGroupId: options.selfGroupId, state: initial.newState })
  } catch (error) {
    // The hub accepted the commit, so this process must not retain its
    // optimistic state as usable if persistence failed.  The caller can
    // recover by external joining the known room rather than double-creating.
    throw new Error('MIMI Vault room was accepted but local state could not be saved', { cause: error })
  }
  confirmCommit({ state: initial.newState, commit: encodeMlsMessage(initial.commit), consumed: initial.consumed })
  return { roomId, credential: sender }
}
