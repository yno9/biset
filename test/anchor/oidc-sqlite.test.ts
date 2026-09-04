import { afterEach, describe, expect, test } from 'bun:test'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { SqliteAnchorOidcState } from '../../src/anchor/oidc-sqlite.ts'

const directories: string[] = []
afterEach(() => { for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true }) })

describe('Anchor OIDC SQLite state', () => {
  test('persists signing/pairwise secrets and consumes authorization codes once across restart', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'anchor-oidc-state-'))
    directories.push(directory)
    const path = join(directory, 'oidc.sqlite')
    const first = SqliteAnchorOidcState.open(path)
    const secrets = first.secrets()
    await first.put({ codeHash: 'hash', clientId: 'client', redirectUri: 'https://client.example/cb', rootSubject: 'root', generation: `1-${'a'.repeat(32)}`, sectorIdentifier: 'sector', audience: 'https://coordinator.biset.md', scopes: ['vault.pull'], codeChallenge: 'c'.repeat(43), nonce: 'nonce', authenticatedAt: 1, expiresAt: 2 })
    first.close()

    const second = SqliteAnchorOidcState.open(path)
    expect(second.secrets()).toEqual(secrets)
    expect(await second.take('hash')).toMatchObject({ clientId: 'client', scopes: ['vault.pull'] })
    expect(await second.take('hash')).toBeUndefined()
    second.close()
  })

  test('expires abandoned short-lived codes without touching issuer secrets', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'anchor-oidc-expiry-'))
    directories.push(directory)
    const state = SqliteAnchorOidcState.open(join(directory, 'oidc.sqlite'))
    const secrets = state.secrets()
    await state.put({ codeHash: 'expired', clientId: 'client', redirectUri: 'https://client.example/cb', rootSubject: 'root', generation: `1-${'a'.repeat(32)}`, sectorIdentifier: 'sector', audience: 'https://coordinator.biset.md', scopes: [], codeChallenge: 'c'.repeat(43), nonce: 'nonce', authenticatedAt: 1, expiresAt: 2 })
    expect(state.expire(new Date(3000))).toBe(1)
    expect(await state.take('expired')).toBeUndefined()
    expect(state.secrets()).toEqual(secrets)
    state.close()
  })

  test('persists OID4VP account, credential, transaction, completion, and session state across restart', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'anchor-oid4vp-state-'))
    directories.push(directory)
    const path = join(directory, 'oidc.sqlite')
    const first = SqliteAnchorOidcState.open(path)
    const accountRef = await first.accountRef('root-subject')
    await first.putCredential({ credentialId: 'urn:uuid:11111111-1111-4111-8111-111111111111', credentialHash: 'credential-hash', accountRef, rootSubject: 'root-subject', generation: `1-${'a'.repeat(32)}`, holderKeyId: 'holder-key', issuedAt: 10, expiresAt: 100 })
    await first.putTransaction({ transactionId: 'transaction', state: 'state', nonce: 'nonce', returnUrl: 'https://anchor.biset.md/oauth/authorize', expiresAt: 100 })
    await first.putCompletion({ responseCodeHash: 'completion', rootSubject: 'root-subject', generation: `1-${'a'.repeat(32)}`, authenticatedAt: 10, returnUrl: 'https://anchor.biset.md/oauth/authorize', expiresAt: 100 })
    await first.putSession({ sessionHash: 'session', rootSubject: 'root-subject', generation: `1-${'a'.repeat(32)}`, authenticatedAt: 10, expiresAt: 100 })
    first.close()

    const second = SqliteAnchorOidcState.open(path)
    expect(await second.accountRef('root-subject')).toBe(accountRef)
    expect(await second.credential('urn:uuid:11111111-1111-4111-8111-111111111111')).toMatchObject({ rootSubject: 'root-subject', holderKeyId: 'holder-key' })
    expect(await second.transaction('transaction')).toMatchObject({ state: 'state' })
    expect(await second.takeTransactionByState('state')).toMatchObject({ transactionId: 'transaction' })
    expect(await second.takeTransactionByState('state')).toBeUndefined()
    expect(await second.takeCompletion('completion')).toMatchObject({ rootSubject: 'root-subject' })
    expect(await second.takeCompletion('completion')).toBeUndefined()
    expect(await second.session('session')).toMatchObject({ rootSubject: 'root-subject' })
    second.close()
  })

  test('activating a Sign generation revokes older credentials, sessions, codes, and refresh tokens atomically', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'anchor-oidc-generation-'))
    directories.push(directory)
    const state = SqliteAnchorOidcState.open(join(directory, 'oidc.sqlite'))
    const oldGeneration = `1-${'a'.repeat(32)}`
    const currentGeneration = `2-${'b'.repeat(32)}`
    const accountRef = await state.accountRef('root-subject')
    await state.putCredential({ credentialId: 'urn:uuid:11111111-1111-4111-8111-111111111111', credentialHash: 'old-credential', accountRef, rootSubject: 'root-subject', generation: oldGeneration, holderKeyId: 'old-holder', issuedAt: 10, expiresAt: 1000 })
    await state.putSession({ sessionHash: 'old-session', rootSubject: 'root-subject', generation: oldGeneration, authenticatedAt: 10, expiresAt: 1000 })
    await state.put({ codeHash: 'old-code', clientId: 'client', redirectUri: 'https://client.example/cb', rootSubject: 'root-subject', generation: oldGeneration, sectorIdentifier: 'sector', audience: 'https://coordinator.biset.md', scopes: [], codeChallenge: 'c'.repeat(43), nonce: 'nonce', authenticatedAt: 10, expiresAt: 1000 })
    await state.putRefresh({ tokenHash: 'old-refresh', clientId: 'client', rootSubject: 'root-subject', generation: oldGeneration, sectorIdentifier: 'sector', audience: 'https://coordinator.biset.md', scopes: [], expiresAt: 1000 })

    await state.activateGeneration('root-subject', currentGeneration, 20)

    expect((await state.credential('urn:uuid:11111111-1111-4111-8111-111111111111'))?.revokedAt).toBe(20)
    expect(await state.session('old-session')).toBeUndefined()
    expect(await state.take('old-code')).toBeUndefined()
    expect(await state.takeRefresh('old-refresh')).toBeUndefined()
    state.close()
  })
})
