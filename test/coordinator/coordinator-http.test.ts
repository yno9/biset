import { afterEach, describe, expect, test } from 'bun:test'
import { Database } from 'bun:sqlite'
import { ed25519 } from '@noble/curves/ed25519.js'
import { bytesToBase64url, sha256Bytes } from '../../src/protocol/canonical.ts'
import { vaultCoordinatorAckSigningBytes, vaultCoordinatorAppendSigningBytes, vaultCoordinatorCheckpointSigningBytes, vaultCoordinatorPullSigningBytes } from '../../src/protocol/coordinator.ts'
import { encodeVaultGroupView, vaultGroupViewSigningBytes, type VaultGroupViewV1 } from '../../src/protocol/vault-group-view.ts'
import { createVaultCoordinatorFetchHandler } from '../../src/coordinator/app.ts'
import type { VaultAccessPrincipal, VaultAccessTokenVerifier } from '../../src/coordinator/auth.ts'
import { SqliteVaultCoordinatorStore } from '../../src/coordinator/store.ts'

const vaultId = `vlt_${'A'.repeat(43)}` as const
const groupId = new Uint8Array(32).fill(9)
const databases: Database[] = []
const memberSecrets = {
  'member-a': new Uint8Array(32).fill(1),
  'member-b': new Uint8Array(32).fill(2),
  'member-c': new Uint8Array(32).fill(3),
}

afterEach(() => {
  for (const database of databases.splice(0)) database.close()
})

describe('biset-coordinator HTTP boundary', () => {
  test('creates an OIDC-subject-owned Vault and fans opaque payload out to its members', async () => {
    const { handler } = setup()
    expect((await call(handler, '/v1/vaults', createBody(), 'alice:create')).status).toBe(201)

    const payload = new Uint8Array([7, 8, 9])
    const payloadHash = sha256Bytes(payload)
    const append = await call(handler, '/v1/deliveries/append', appendBody('append-1', '1', payload), 'alice:append')
    expect(append.status).toBe(202)
    expect(await append.json()).toEqual({ seq: '1' })

    const pull = await call(handler, '/v1/deliveries/pull', pullBody('member-b', '0'), 'alice:pull')
    expect(pull.status).toBe(200)
    const result = await pull.json() as { kind: string; items: Array<{ vaultId: string; payload: string }> }
    expect(result.kind).toBe('items')
    expect(result.items).toHaveLength(1)
    expect(result.items[0]).toMatchObject({ vaultId, payload: bytesToBase64url(payload) })

    expect((await call(handler, '/v1/deliveries/ack', ackBody('member-b', '1', payloadHash), 'alice:ack')).status).toBe(202)
    const afterAck = await call(handler, '/v1/deliveries/pull', pullBody('member-b', '0'), 'alice:pull')
    expect(await afterAck.json()).toMatchObject({ kind: 'items', items: [] })
  })

  test('requires the operation scope and hides another subject Vault as not found', async () => {
    const { handler } = setup()
    expect((await call(handler, '/v1/vaults', createBody())).status).toBe(401)
    expect((await call(handler, '/v1/vaults', createBody(), 'alice:pull')).status).toBe(403)
    expect((await call(handler, '/v1/vaults', createBody(), 'alice:create')).status).toBe(201)
    expect((await call(handler, '/v1/deliveries/pull', pullBody('member-a', '0'), 'mallory:pull')).status).toBe(404)
  })

  test('makes an identical create retry idempotent but rejects conflicting genesis state', async () => {
    const { handler } = setup()
    expect((await call(handler, '/v1/vaults', createBody(), 'alice:create')).status).toBe(201)
    expect((await call(handler, '/v1/vaults', createBody(), 'alice:create')).status).toBe(201)
    const conflicting = wireView(signedView({ epoch: '1', previousViewHash: null, memberIds: ['member-c'], installerMemberId: 'member-c', newMemberFloor: '1' }))
    expect((await call(handler, '/v1/vaults', conflicting, 'alice:create')).status).toBe(409)
  })

  test('rejects identity-plane fields at the exact JSON boundary', async () => {
    const { handler } = setup()
    const response = await call(handler, '/v1/vaults', { ...createBody(), identityId: 'did:webvh:secret:example.com' }, 'alice:create')
    expect(response.status).toBe(400)
    expect(await response.text()).toContain('unexpected fields')
  })

  test('retires the view-only group install endpoint so MLS artifacts cannot be bypassed', async () => {
    const { handler } = setup()
    const response = await call(handler, '/v1/group/install', createBody(), 'alice:group.install')
    expect(response.status).toBe(410)
    expect(await response.text()).toContain('/v1/mls/transitions/install')
  })

  test('rejects a forged member operation even with a valid owner access token', async () => {
    const { handler } = setup()
    expect((await call(handler, '/v1/vaults', createBody(), 'alice:create')).status).toBe(201)
    const forged = appendBody('forged-append', '1', new Uint8Array([4])) as Record<string, unknown>
    forged.senderMemberId = 'member-b'
    expect((await call(handler, '/v1/deliveries/append', forged, 'alice:append')).status).toBe(400)
  })

  test('discovers the owner Vault and retains its opaque checkpoint after every recipient ACKs', async () => {
    const { handler, database } = setup()
    expect((await call(handler, '/v1/vaults', createBody(), 'alice:create')).status).toBe(201)
    const payload = new Uint8Array([7, 8, 9])
    const payloadHash = sha256Bytes(payload)
    expect((await call(handler, '/v1/deliveries/append', appendBody('append-1', '1', payload), 'alice:append')).status).toBe(202)

    expect((await call(handler, '/v1/deliveries/ack', ackBody('member-a', '1', payloadHash), 'alice:ack')).status).toBe(202)
    expect((await call(handler, '/v1/deliveries/ack', ackBody('member-b', '1', payloadHash), 'alice:ack')).status).toBe(202)
    expect(database.query<{ bytes: number }, []>('SELECT length(payload) AS bytes FROM entries').get()!.bytes).toBe(payload.length)

    const checkpoint = new Uint8Array([40, 41, 42, 43])
    expect((await call(handler, '/v1/checkpoints/put', checkpointBody('member-a', '1', checkpoint), 'alice:append')).status).toBe(202)
    expect(database.query<{ bytes: number }, []>('SELECT length(payload) AS bytes FROM entries').get()!.bytes).toBe(0)
    expect(await (await call(handler, '/v1/vaults/owned', { version: 1 }, 'alice:pull')).json()).toEqual({ vaults: [{ vaultId, latestSeq: '1', checkpointSeq: '1' }] })
    const restored = await call(handler, '/v1/checkpoints/pull', { version: 1, vaultId }, 'alice:pull')
    expect(restored.status).toBe(200)
    expect(await restored.json()).toMatchObject({ vaultId, coveredSeq: '1', payload: bytesToBase64url(checkpoint) })
  })

  test('SQLite schema contains no DID, SCID, domain, mail, or identity column', () => {
    const database = new Database(':memory:')
    databases.push(database)
    new SqliteVaultCoordinatorStore(database)
    const schema = database.query<{ sql: string }, []>("SELECT sql FROM sqlite_master WHERE type='table'").all().map(row => row.sql.toLowerCase()).join('\n')
    for (const forbidden of ['did', 'scid', 'domain', 'mail', 'identity']) expect(schema).not.toContain(forbidden)
  })
})

function setup(): { handler: ReturnType<typeof createVaultCoordinatorFetchHandler>; database: Database } {
  const database = new Database(':memory:')
  databases.push(database)
  const store = new SqliteVaultCoordinatorStore(database)
  const verifier: VaultAccessTokenVerifier = {
    async verify(token): Promise<VaultAccessPrincipal> {
      const [subject, operation] = token.split(':')
      if (!subject || !operation) throw new Error('invalid test token')
      return { subject, scopes: new Set([`vault.${operation}`]), expiresAt: Number.MAX_SAFE_INTEGER }
    },
  }
  return { handler: createVaultCoordinatorFetchHandler({ store, accessTokens: verifier }), database }
}

function createBody() {
  return wireView(signedView({ epoch: '1', previousViewHash: null, memberIds: ['member-a', 'member-b'], installerMemberId: 'member-a', newMemberFloor: '1' }))
}

function signedView(options: {
  epoch: string
  previousViewHash: string | null
  memberIds: Array<keyof typeof memberSecrets>
  installerMemberId: keyof typeof memberSecrets
  newMemberFloor: string
  signingSecret?: Uint8Array
}): VaultGroupViewV1 {
  const members = options.memberIds.map(memberId => ({
    memberId,
    signaturePublicKey: ed25519.getPublicKey(memberSecrets[memberId]),
    deliveryFloor: memberId === 'member-c' ? options.newMemberFloor : '1',
  }))
  const unsigned = {
    version: 1 as const,
    vaultId,
    groupId,
    groupEpoch: options.epoch,
    confirmedTranscriptHash: new Uint8Array(32).fill(Number(options.epoch) + 20),
    previousViewHash: options.previousViewHash,
    members,
    installerMemberId: options.installerMemberId,
  }
  return { ...unsigned, signature: ed25519.sign(vaultGroupViewSigningBytes(unsigned), options.signingSecret ?? memberSecrets[options.installerMemberId]) }
}

function wireView(view: VaultGroupViewV1): unknown { return JSON.parse(encodeVaultGroupView(view)) }

function appendBody(appendId: string, groupEpoch: string, payload: Uint8Array): unknown {
  return appendBodyFor('member-a', appendId, groupEpoch, payload)
}

function appendBodyFor(memberId: keyof typeof memberSecrets, appendId: string, groupEpoch: string, payload: Uint8Array): unknown {
  const payloadHash = sha256Bytes(payload)
  const unsigned = { version: 1 as const, vaultId, appendId, senderMemberId: memberId, groupEpoch, payloadHash, sentAt: '2026-08-27T00:00:00.000Z' }
  return { ...unsigned, payload: bytesToBase64url(payload), payloadHash: bytesToBase64url(payloadHash), signature: bytesToBase64url(ed25519.sign(vaultCoordinatorAppendSigningBytes(unsigned), memberSecrets[memberId])) }
}

function pullBody(memberId: keyof typeof memberSecrets, after: string): unknown {
  const unsigned = { version: 1 as const, vaultId, recipientMemberId: memberId, after, requestedAt: '2026-08-27T00:00:00.000Z' }
  return { ...unsigned, signature: bytesToBase64url(ed25519.sign(vaultCoordinatorPullSigningBytes(unsigned), memberSecrets[memberId])) }
}

function ackBody(memberId: keyof typeof memberSecrets, seq: string, payloadHash: Uint8Array): unknown {
  const unsigned = { version: 1 as const, vaultId, recipientMemberId: memberId, seq, payloadHash, ackedAt: '2026-08-27T00:00:00.000Z' }
  return { ...unsigned, payloadHash: bytesToBase64url(payloadHash), signature: bytesToBase64url(ed25519.sign(vaultCoordinatorAckSigningBytes(unsigned), memberSecrets[memberId])) }
}

function checkpointBody(memberId: keyof typeof memberSecrets, coveredSeq: string, payload: Uint8Array): unknown {
  const payloadHash = sha256Bytes(payload)
  const unsigned = { version: 1 as const, vaultId, writerMemberId: memberId, coveredSeq, payloadHash, createdAt: '2026-08-27T00:00:01.000Z' }
  return { ...unsigned, payload: bytesToBase64url(payload), payloadHash: bytesToBase64url(payloadHash), signature: bytesToBase64url(ed25519.sign(vaultCoordinatorCheckpointSigningBytes(unsigned), memberSecrets[memberId])) }
}

function call(handler: ReturnType<typeof createVaultCoordinatorFetchHandler>, path: string, body: unknown, token?: string): Promise<Response> {
  const headers = new Headers({ 'content-type': 'application/json' })
  if (token) headers.set('authorization', `Bearer ${token}`)
  return handler(new Request(`https://coordinator.example${path}`, { method: 'POST', headers, body: JSON.stringify(body) }))
}
