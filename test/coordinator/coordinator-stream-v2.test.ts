import { afterEach, describe, expect, test } from 'bun:test'
import { Database } from 'bun:sqlite'
import { bytesToBase64url, sha256Bytes } from '../../src/protocol/canonical.ts'
import type { VaultAccessPrincipal, VaultAccessTokenVerifier } from '../../src/coordinator/auth.ts'
import { createVaultCoordinatorFetchHandler } from '../../src/coordinator/app.ts'
import { SqliteVaultCoordinatorStore } from '../../src/coordinator/store.ts'

const databases: Database[] = []
afterEach(() => { for (const database of databases.splice(0)) database.close() })

describe('owner-scoped Coordinator v2 stream', () => {
  test('creates one default stream and synchronizes opaque ordered entries without members or ACKs', async () => {
    const { handler } = setup()
    const first = await post(handler, '/v2/vaults/default', { version: 2 }, 'alice:create')
    const stream = await first.json() as { version: number; vaultId: string; latestSeq: string }
    expect(stream).toMatchObject({ version: 2, latestSeq: '0' })
    expect((await post(handler, '/v2/vaults/default', { version: 2 }, 'alice:create')).status).toBe(200)

    const payload = new Uint8Array([1, 2, 3])
    const body = { version: 2, vaultId: stream.vaultId, appendId: 'mutation-1', payload: bytesToBase64url(payload), payloadHash: bytesToBase64url(sha256Bytes(payload)) }
    expect(await (await post(handler, '/v2/entries/append', body, 'alice:append')).json()).toEqual({ seq: '1' })
    expect(await (await post(handler, '/v2/entries/append', body, 'alice:append')).json()).toEqual({ seq: '1' })

    const pulled = await (await post(handler, '/v2/entries/pull', { version: 2, vaultId: stream.vaultId, after: '0' }, 'alice:pull')).json() as { items: unknown[]; nextCursor: string }
    expect(pulled.items).toHaveLength(1)
    expect(pulled.nextCursor).toBe('1')
    expect((await post(handler, '/v2/entries/pull', { version: 2, vaultId: stream.vaultId, after: '0' }, 'mallory:pull')).status).toBe(404)
  })

  test('uses a checkpoint as the sole retention boundary', async () => {
    const { handler, database } = setup()
    const stream = await (await post(handler, '/v2/vaults/default', { version: 2 }, 'alice:create')).json() as { vaultId: string }
    const entry = new Uint8Array([7])
    await post(handler, '/v2/entries/append', { version: 2, vaultId: stream.vaultId, appendId: 'a', payload: bytesToBase64url(entry), payloadHash: bytesToBase64url(sha256Bytes(entry)) }, 'alice:append')
    const snapshot = new Uint8Array([8, 9])
    expect((await post(handler, '/v2/checkpoints/put', { version: 2, vaultId: stream.vaultId, coveredSeq: '1', payload: bytesToBase64url(snapshot), payloadHash: bytesToBase64url(sha256Bytes(snapshot)) }, 'alice:append')).status).toBe(202)
    expect(database.query<{ bytes: number }, []>('SELECT length(payload) AS bytes FROM vault_stream_entries').get()!.bytes).toBe(0)
    const checkpoint = await (await post(handler, '/v2/checkpoints/pull', { version: 2, vaultId: stream.vaultId }, 'alice:pull')).json()
    expect(checkpoint).toMatchObject({ version: 2, vaultId: stream.vaultId, coveredSeq: '1', payload: bytesToBase64url(snapshot) })
  })

  test('v2 schema has no device, member, MLS, DID, SCID, domain, mail, or identity field', () => {
    const { database } = setup()
    const schema = database.query<{ sql: string }, []>("SELECT sql FROM sqlite_master WHERE type='table' AND name LIKE 'vault_stream%'").all().map(row => row.sql.toLowerCase()).join('\n')
    for (const forbidden of ['device', 'member', 'mls', 'did', 'scid', 'domain', 'mail', 'identity']) expect(schema).not.toContain(forbidden)
  })
})

function setup(): { handler: ReturnType<typeof createVaultCoordinatorFetchHandler>; database: Database } {
  const database = new Database(':memory:')
  databases.push(database)
  const verifier: VaultAccessTokenVerifier = {
    async verify(token): Promise<VaultAccessPrincipal> {
      const [subject, operation] = token.split(':')
      if (!subject || !operation) throw new Error('bad test token')
      return { subject, scopes: new Set([`vault.${operation}`]), expiresAt: Number.MAX_SAFE_INTEGER }
    },
  }
  return { database, handler: createVaultCoordinatorFetchHandler({ store: new SqliteVaultCoordinatorStore(database), accessTokens: verifier }) }
}

function post(handler: ReturnType<typeof createVaultCoordinatorFetchHandler>, path: string, body: unknown, token: string): Promise<Response> {
  return handler(new Request(`https://coordinator.example${path}`, { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: JSON.stringify(body) }))
}
