import { afterEach, describe, expect, test } from 'bun:test'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { ed25519 } from '@noble/curves/ed25519.js'
import { sha256Bytes } from '../../src/protocol/canonical.ts'
import { vaultCoordinatorAppendSigningBytes, vaultCoordinatorPullSigningBytes } from '../../src/protocol/coordinator.ts'
import { vaultGroupViewHash, vaultGroupViewSigningBytes, type VaultGroupViewV1 } from '../../src/protocol/vault-group-view.ts'
import { SqliteVaultCoordinatorStore, VaultCoordinatorStoreError } from '../../src/coordinator/store.ts'

const vaultId = `vlt_${'B'.repeat(43)}` as const
const groupId = new Uint8Array(32).fill(19)
const directories: string[] = []
const secrets = { a: new Uint8Array(32).fill(11), b: new Uint8Array(32).fill(12), c: new Uint8Array(32).fill(13) }

afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true })
})

describe('SQLite Vault Coordinator group-view durability', () => {
  test('persists the accepted hash chain and removed-member denial across restart', () => {
    const directory = mkdtempSync(join(tmpdir(), 'biset-coordinator-'))
    directories.push(directory)
    const path = join(directory, 'coordinator.sqlite')
    const genesis = view('1', null, [['a', '1'], ['b', '1']], 'a')
    const first = SqliteVaultCoordinatorStore.open(path)
    expect(first.create(genesis, 'owner-subject')).toBe(vaultGroupViewHash(genesis))
    first.close()

    const epochTwo = view('2', vaultGroupViewHash(genesis), [['a', '1'], ['c', '1']], 'a')
    const second = SqliteVaultCoordinatorStore.open(path)
    expect(second.installGroupView(epochTwo, 'owner-subject')).toBe(vaultGroupViewHash(epochTwo))
    const payload = new Uint8Array([4, 5, 6])
    const append = { version: 1 as const, vaultId, appendId: 'after-restart', senderMemberId: 'a', groupEpoch: '2', payloadHash: sha256Bytes(payload), sentAt: '2026-08-28T00:00:00.000Z' }
    second.append({ ...append, payload, signature: ed25519.sign(vaultCoordinatorAppendSigningBytes(append), secrets.a) }, 'owner-subject')
    second.close()

    const third = SqliteVaultCoordinatorStore.open(path)
    const pullC = { version: 1 as const, vaultId, recipientMemberId: 'c', after: '0', requestedAt: '2026-08-28T00:00:01.000Z' }
    expect(third.pull({ ...pullC, signature: ed25519.sign(vaultCoordinatorPullSigningBytes(pullC), secrets.c) }, 'owner-subject')).toMatchObject({ kind: 'items', latestSeq: '1' })
    const pullB = { version: 1 as const, vaultId, recipientMemberId: 'b', after: '0', requestedAt: '2026-08-28T00:00:01.000Z' }
    expect(() => third.pull({ ...pullB, signature: ed25519.sign(vaultCoordinatorPullSigningBytes(pullB), secrets.b) }, 'owner-subject')).toThrow(VaultCoordinatorStoreError)
    third.close()
  })
})

function view(
  groupEpoch: string,
  previousViewHash: string | null,
  memberSpecs: Array<[keyof typeof secrets, string]>,
  installerMemberId: keyof typeof secrets,
): VaultGroupViewV1 {
  const members = memberSpecs.map(([memberId, deliveryFloor]) => ({ memberId, deliveryFloor, signaturePublicKey: ed25519.getPublicKey(secrets[memberId]) }))
  const unsigned = { version: 1 as const, vaultId, groupId, groupEpoch, confirmedTranscriptHash: new Uint8Array(32).fill(Number(groupEpoch) + 30), previousViewHash, members, installerMemberId }
  return { ...unsigned, signature: ed25519.sign(vaultGroupViewSigningBytes(unsigned), secrets[installerMemberId]) }
}
