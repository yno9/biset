/** Live, destructive-only-to-a-fresh-random-room verification for §19.
 * Run with `bun scripts/verify-mimi-vault-live.ts`; it never uses a real
 * identity or an existing room. */
import { ed25519 } from '@noble/curves/ed25519.js'
import { bytesToBase64url } from '../src/shared/protocol/canonical.ts'
import { createMlsGroup, encryptApplication, generateOwnKeyPackageForCredential } from '../src/mls/group.ts'
import { createCommit, encodeMlsMessage } from '../src/mls/vendor/index.ts'
import { encodeCredential } from '../src/mls/vendor/credential.ts'
import { mlsSuite } from '../src/mls/suite.ts'
import { encodeMimiFrankingAgent, encodeMimiParticipantListUpdate, encodeMimiRoomMetadata } from '../src/mimi/app-data.ts'
import { deliveriesPullSigningBytes, submitMessageSigningBytes, submitVaultCheckpointSigningBytes, updateRoomSigningBytes } from '../src/mimi/authorizer.ts'
import { decodeDeliveriesWire, decodeFrankingAgentDataWire, decodeSubmitMessageResponseWire, decodeSubmitVaultCheckpointResponseWire, decodeUpdateRoomResponseWire, encodeDeliveriesPullRequestWire, encodeSubmitMessageRequestWire, encodeSubmitVaultCheckpointRequestWire, encodeUpdateRoomRequestWire } from '../src/mimi/wire.ts'
import { sendMimiVaultCheckpoint } from '../src/vault/mimi-vault-sync.ts'
import { encodeVaultDeliveryPack } from '../src/vault/delivery-pack.ts'

const baseUrl = (process.env.MIMI_SELF_URL ?? 'https://mimi-self.biset.md').replace(/\/$/, '')
const now = () => new Date().toISOString()
const roomId = `mimi://mimi-self.biset.md/r/vault-${bytesToBase64url(crypto.getRandomValues(new Uint8Array(32)))}`
const user = `did:biset:live-vault-${crypto.randomUUID()}`
const client = `${user}#device`
const marker = `private-target-${crypto.randomUUID()}`

async function request(path: string, body?: string): Promise<string> {
  const response = await fetch(`${baseUrl}${path}`, body === undefined ? undefined : { method: 'POST', headers: { 'content-type': 'application/json' }, body })
  const text = await response.text()
  if (!response.ok) throw new Error(`${path}: HTTP ${response.status}: ${text.slice(0, 300)}`)
  return text
}

const own = await generateOwnKeyPackageForCredential({ credentialType: 'basic', identity: new TextEncoder().encode(client) })
const credential = {
  kind: 'visible' as const, user, client,
  credential: encodeCredential(own.publicPackage.leafNode.credential),
  signaturePublicKey: own.publicPackage.leafNode.signaturePublicKey,
}
const franking = decodeFrankingAgentDataWire(await request(`/v1/mimi/franking-agent/${encodeURIComponent(roomId)}`))
let state = await createMlsGroup(crypto.getRandomValues(new Uint8Array(32)), own)
const suite = await mlsSuite()
const participant = { user, roleIndex: 1, clientIds: [client] }
const proposal = (componentId: number, update: Uint8Array) => ({ proposalType: 'app_data_update' as const, appDataUpdate: { componentId, operation: 'update' as const, update } })
const initial = await createCommit({ state, cipherSuite: suite }, {
  wireAsPublicMessage: true,
  extraProposals: [
    proposal(0x0021, encodeMimiFrankingAgent({ frankingSignatureKey: franking.frankingSignatureKey, credential: new TextEncoder().encode(baseUrl) })),
    proposal(0x0022, encodeMimiParticipantListUpdate({ changedRoleParticipants: [], removedIndices: [], addedParticipants: [{ user, roleIndex: 1 }] })),
    proposal(0x0023, encodeMimiRoomMetadata({ roomUri: roomId, roomName: 'ephemeral vault privacy probe' })),
  ],
})
const initialUnsigned = {
  version: 1 as const, protocol: 'mls10' as const, roomId, sender: credential, epoch: '0',
  bundle: { kind: 'commit' as const, proposalOrCommit: encodeMlsMessage(initial.commit) },
  initialState: { basePolicy: new Uint8Array(), participantList: { participants: [participant] }, memberCredentials: [credential], metadata: { roomUri: roomId, roomName: 'ephemeral vault privacy probe' } },
  submittedAt: now(),
}
const created = decodeUpdateRoomResponseWire(await request(`/update/${encodeURIComponent(roomId)}`, encodeUpdateRoomRequestWire({ ...initialUnsigned, signature: ed25519.sign(updateRoomSigningBytes(initialUnsigned), own.privatePackage.signaturePrivateKey) })))
if (created.status !== 'success') throw new Error(`room creation failed: ${created.status}`)
state = initial.newState

async function sendApplication(plaintext: Uint8Array, deliveryId: string): Promise<void> {
  const encrypted = await encryptApplication(state, plaintext)
  const unsigned = {
    version: 1 as const, protocol: 'mls10' as const, roomId, sender: credential, epoch: '1', appMessage: encrypted.wire, deliveryId,
    frankAAD: { frankingTag: crypto.getRandomValues(new Uint8Array(32)) }, frankingSignatureCiphersuite: 1, submittedAt: now(),
  }
  const response = decodeSubmitMessageResponseWire(await request(`/submitMessage/${encodeURIComponent(roomId)}`, encodeSubmitMessageRequestWire({ ...unsigned, signature: ed25519.sign(submitMessageSigningBytes(unsigned), own.privatePackage.signaturePrivateKey) })))
  if (response.status !== 'accepted') throw new Error(`application submission failed: ${response.status}`)
  state = encrypted.state
}

const vaultPack = encodeVaultDeliveryPack({
  version: 1, identityId: user, objects: [], keyWraps: [],
  events: [{ version: 1, id: `evt-${crypto.randomUUID()}`, identityId: user, actorDeviceId: client, actorSeq: 1, kind: 'message.add', targetIds: [marker], objectRefs: [], parents: [], createdAt: now(), signature: new Uint8Array(64) }],
})
await sendApplication(vaultPack, 'live-application-00000001')
const pullUnsigned = () => ({ version: 1 as const, roomId, requester: credential, afterSeq: 0, requestedAt: now() })
const pull = async () => {
  const unsigned = pullUnsigned()
  return decodeDeliveriesWire(await request('/v1/mimi/deliveries/pull', encodeDeliveriesPullRequestWire({ ...unsigned, signature: ed25519.sign(deliveriesPullSigningBytes(unsigned), own.privatePackage.signaturePrivateKey) })))
}
const before = await pull()
const application = before.find(entry => entry.kind === 'application')
const hubVisible = new TextDecoder().decode(application?.payload)
if (!application || hubVisible.includes('message.add') || hubVisible.includes(marker)) throw new Error('hub-visible application payload contains VaultDeliveryPack plaintext')

const checkpointPayload = new Uint8Array(500 * 1024 + 1).fill(0x5a)
const manifest = await sendMimiVaultCheckpoint(checkpointPayload, application.seq, {
  sendApplication,
  async sendCheckpoint(value) {
    const unsigned = { version: 1 as const, protocol: 'mls10' as const, roomId, sender: credential, epoch: '1', manifest: value, submittedAt: now() }
    const response = decodeSubmitVaultCheckpointResponseWire(await request(`/v1/mimi/vault-checkpoint/${encodeURIComponent(roomId)}`, encodeSubmitVaultCheckpointRequestWire({ ...unsigned, signature: ed25519.sign(submitVaultCheckpointSigningBytes(unsigned), own.privatePackage.signaturePrivateKey) })))
    if (response.status !== 'accepted') throw new Error(`checkpoint submission failed: ${response.status}`)
  },
})
const after = await pull()
const compacted = after.find(entry => entry.seq === application.seq)
const checkpoint = after.find(entry => entry.kind === 'vaultCheckpoint')
const checkpointChunks = after.filter(entry => entry.kind === 'application' && entry.seq > application.seq)
if (!compacted || compacted.payload.length !== 0 || !checkpoint?.vaultCheckpoint || checkpoint.vaultCheckpoint.transferId !== manifest.transferId || manifest.chunkCount !== 2 || checkpointChunks.length !== 2) throw new Error('multi-chunk checkpoint compaction or manifest retrieval failed')
console.log(JSON.stringify({ verified: true, baseUrl, roomId, applicationSeq: application.seq, checkpointSeq: checkpoint.seq, chunkCount: manifest.chunkCount }))
