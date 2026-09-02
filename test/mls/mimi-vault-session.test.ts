import { expect, test } from 'bun:test'
import { createMlsGroup, generateOwnKeyPackageForCredential } from '../../src/mls/group.ts'
import { PersistedMimiVaultSession, type MimiVaultSessionRecord } from '../../src/mls/mimi-vault-session.ts'

test('a lost MIMI response reuses the durable MLS PrivateMessage and delivery ID', async () => {
  const own = await generateOwnKeyPackageForCredential({ credentialType: 'basic', identity: new TextEncoder().encode('client') })
  const initial: MimiVaultSessionRecord = { roomId: 'mimi://self.example/r/vault-test', selfGroupId: 'self', state: await createMlsGroup(new Uint8Array(32).fill(1), own), deliveryCursor: 7 }
  let stored = initial
  const submissions: Uint8Array[] = []
  let fails = true
  const transport = {
    async submitMessage(_mode: string, request: { appMessage: Uint8Array }) { submissions.push(request.appMessage.slice()); if (fails) { fails = false; throw new Error('connection lost') }; return { status: 'accepted' as const } },
    async submitVaultCheckpoint() { return { status: 'accepted' as const } },
  }
  const session = new PersistedMimiVaultSession({
    identityId: 'did:example:me', mode: 'self', credential: { kind: 'visible', user: 'did:example:me', client: 'client', credential: new Uint8Array([1]), signaturePublicKey: own.publicPackage.leafNode.signaturePublicKey },
    sign: () => new Uint8Array(64), transport: transport as never,
    stateStore: { async loadMimiVault() { return stored }, async saveMimiVault(_identity, value) { stored = value } },
  })
  const plaintext = new Uint8Array([1, 2, 3])
  await expect(session.sendApplication(plaintext, 'A'.repeat(24))).rejects.toThrow('connection lost')
  expect(stored.pending?.appMessage).toEqual(submissions[0])
  await session.sendApplication(plaintext, 'A'.repeat(24))
  expect(submissions[1]).toEqual(submissions[0])
  expect(stored.pending).toBeUndefined()
  expect(stored.deliveryCursor).toBe(7)
  await expect(session.receive({ seq: 1, kind: 'application', payload: submissions[0]!, epoch: '0', acceptedAt: '2026-09-02T00:00:00.000Z' })).resolves.toBeUndefined()
})
