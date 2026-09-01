import { describe, expect, test } from 'bun:test'
import {
  decodeRoomStateWire,
  decodeDeliveriesWatchTokenWire,
  decodeFrankAADWire,
  decodeFrankWire,
  decodeFrankingAgentDataWire,
  decodeKeyPackagePublishWire,
  decodeMimiErrorWire,
  decodeUpdateRoomRequestWire,
  encodeKeyPackagePublishWire,
  encodeFrankAADWire,
  encodeFrankWire,
  encodeFrankingAgentDataWire,
  encodeRoomStateWire,
  encodeUpdateRoomRequestWire,
  MimiWireError,
} from '../../src/mimi/wire.ts'
import type { RoomState, UpdateRoomRequest, VisibleCredential } from '../../src/mimi/protocol-types.ts'

const alice: VisibleCredential = {
  kind: 'visible', user: 'did:web:alice', client: 'did:web:alice#phone',
  credential: new Uint8Array([1, 2]), signaturePublicKey: new Uint8Array([3, 4]),
}

const roomId = 'mimi://example.test/r/wire'
const state: RoomState = {
  roomId, protocol: 'mls10', epoch: '18446744073709551615', basePolicy: new Uint8Array([5]),
  participantList: { participants: [{ user: alice.user, roleIndex: 3, clientIds: [alice.client] }] },
  memberCredentials: [alice], metadata: { roomUri: roomId, roomName: 'Wire', descriptions: [{ mediaType: '', languageTag: '', content: 'plain text' }] },
  groupInfo: new Uint8Array([6]), ratchetTree: new Uint8Array([7]),
  createdAt: '2026-09-01T00:00:00.000Z', updatedAt: '2026-09-01T00:01:00.000Z',
}

describe('MIMI JSON/base64url wire', () => {
  test('RoomState preserves every binary field and permitted empty metadata text', () => {
    const decoded = decodeRoomStateWire(encodeRoomStateWire(state))
    expect(decoded).toEqual(state)
  })

  test('Update request round-trips its initial and incremental room state', () => {
    const request: UpdateRoomRequest = {
      version: 1, protocol: 'mls10', roomId, sender: alice, epoch: '0',
      bundle: { kind: 'commit', proposalOrCommit: new Uint8Array([8]), welcome: new Uint8Array([9]) },
      initialState: { basePolicy: state.basePolicy, participantList: state.participantList, memberCredentials: state.memberCredentials, metadata: state.metadata },
      stateUpdate: { metadata: { ...state.metadata, roomName: 'Updated' } },
      submittedAt: state.createdAt, signature: new Uint8Array([10]),
    }
    expect(decodeUpdateRoomRequestWire(encodeUpdateRoomRequestWire(request))).toEqual(request)
  })

  test('rejects unsigned-64 epochs above the JSON-safe protocol bound', () => {
    const invalid = JSON.parse(encodeRoomStateWire(state)) as Record<string, unknown>
    invalid.epoch = '18446744073709551616'
    expect(() => decodeRoomStateWire(JSON.stringify(invalid))).toThrow(MimiWireError)
  })

  test('round-trips KeyPackage publication and small response objects', () => {
    const publication = { version: 1 as const, credential: alice, packages: [{ reference: new Uint8Array([11]), user: alice.user, client: alice.client, keyPackage: new Uint8Array([12]), publishedAt: state.createdAt }], publishedAt: state.createdAt, signature: new Uint8Array([13]) }
    expect(decodeKeyPackagePublishWire(encodeKeyPackagePublishWire(publication))).toEqual(publication)
    expect(decodeDeliveriesWatchTokenWire('{"token":"token","expiresAt":"2026-09-01T00:00:00.000Z"}')).toEqual({ token: 'token', expiresAt: '2026-09-01T00:00:00.000Z' })
    expect(decodeMimiErrorWire('{"error":"not-found","message":"missing"}')).toEqual({ error: 'not-found', message: 'missing' })
  })

  test('round-trips fixed-size franking values and rejects a short tag', () => {
    const tag = new Uint8Array(32).fill(1)
    expect(decodeFrankAADWire(encodeFrankAADWire({ frankingTag: tag }))).toEqual({ frankingTag: tag })
    expect(decodeFrankingAgentDataWire(encodeFrankingAgentDataWire({ frankingSignatureKey: new Uint8Array([2]), credential: new Uint8Array([3]) }))).toEqual({ frankingSignatureKey: new Uint8Array([2]), credential: new Uint8Array([3]) })
    const frank = { serverFrank: new Uint8Array(32).fill(4), frankingSignatureCiphersuite: 1, context: { senderUri: alice.user, roomUri: roomId, acceptedTimestamp: '1' }, frankingIntegritySignature: new Uint8Array([5]) }
    expect(decodeFrankWire(encodeFrankWire(frank))).toEqual(frank)
    expect(() => encodeFrankAADWire({ frankingTag: new Uint8Array(31) })).toThrow(MimiWireError)
  })
})
