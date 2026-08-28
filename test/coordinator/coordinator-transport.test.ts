import { afterEach, describe, expect, test } from 'bun:test'
import { Database } from 'bun:sqlite'
import { ed25519 } from '@noble/curves/ed25519.js'
import { createVaultCoordinatorFetchHandler } from '../../src/coordinator/app.ts'
import type { VaultAccessPrincipal, VaultAccessTokenVerifier } from '../../src/coordinator/auth.ts'
import { SqliteVaultCoordinatorStore } from '../../src/coordinator/store.ts'
import { sha256Bytes } from '../../src/protocol/canonical.ts'
import { vaultCoordinatorAckSigningBytes, vaultCoordinatorAppendSigningBytes, vaultCoordinatorPullSigningBytes } from '../../src/protocol/coordinator.ts'
import { vaultGroupViewSigningBytes, type VaultGroupViewV1 } from '../../src/protocol/vault-group-view.ts'
import { VaultCoordinatorTransport, type VaultCoordinatorScope } from '../../src/vault/coordinator-transport.ts'

const databases: Database[] = []
const vaultId = `vlt_${'C'.repeat(43)}` as const
const memberId = 'browser-member' as const
const secret = new Uint8Array(32).fill(17)

afterEach(() => {
  for (const database of databases.splice(0)) database.close()
})

describe('VaultCoordinatorTransport', () => {
  test('connects the browser transport boundary to create, append, pull, and ACK', async () => {
    const database = new Database(':memory:')
    databases.push(database)
    const accessTokens: VaultAccessTokenVerifier = {
      async verify(token): Promise<VaultAccessPrincipal> {
        return { subject: 'owner', scopes: new Set([`vault.${token}`]), expiresAt: Number.MAX_SAFE_INTEGER }
      },
    }
    const handler = createVaultCoordinatorFetchHandler({ store: new SqliteVaultCoordinatorStore(database), accessTokens })
    const requestedScopes: VaultCoordinatorScope[] = []
    const transport = new VaultCoordinatorTransport({
      baseUrl: 'https://coordinator.example/',
      accessTokens: {
        async getAccessToken(scope) {
          requestedScopes.push(scope)
          return scope.slice('vault.'.length)
        },
      },
      fetch: ((input: RequestInfo | URL, init?: RequestInit) => handler(new Request(input, init))) as typeof fetch,
    })

    const view = genesisView()
    expect(await transport.createVault(view)).toMatch(/^sha256:/)
    const payload = new Uint8Array([8, 6, 7, 5, 3, 0, 9])
    const payloadHash = sha256Bytes(payload)
    const append = { version: 1 as const, vaultId, appendId: 'browser-append', senderMemberId: memberId, groupEpoch: '1' as const, payloadHash, sentAt: '2026-08-28T01:00:00.000Z' }
    expect(await transport.append({ ...append, payload, signature: ed25519.sign(vaultCoordinatorAppendSigningBytes(append), secret) })).toBe('1')

    const pull = { version: 1 as const, vaultId, recipientMemberId: memberId, after: '0' as const, requestedAt: '2026-08-28T01:00:01.000Z' }
    const result = await transport.pull({ ...pull, signature: ed25519.sign(vaultCoordinatorPullSigningBytes(pull), secret) })
    expect(result).toMatchObject({ kind: 'items', latestSeq: '1' })
    if (result.kind !== 'items') throw new Error('expected items')
    expect(result.items[0]?.payload).toEqual(payload)

    const ack = { version: 1 as const, vaultId, recipientMemberId: memberId, seq: '1' as const, payloadHash, ackedAt: '2026-08-28T01:00:02.000Z' }
    await transport.acknowledge({ ...ack, signature: ed25519.sign(vaultCoordinatorAckSigningBytes(ack), secret) })
    expect(requestedScopes).toEqual(['vault.create', 'vault.append', 'vault.pull', 'vault.ack'])
  })
})

function genesisView(): VaultGroupViewV1 {
  const unsigned = {
    version: 1 as const,
    vaultId,
    groupId: new Uint8Array(32).fill(4),
    groupEpoch: '1' as const,
    confirmedTranscriptHash: new Uint8Array(32).fill(5),
    previousViewHash: null,
    members: [{ memberId, signaturePublicKey: ed25519.getPublicKey(secret), deliveryFloor: '1' as const }],
    installerMemberId: memberId,
  }
  return { ...unsigned, signature: ed25519.sign(vaultGroupViewSigningBytes(unsigned), secret) }
}
