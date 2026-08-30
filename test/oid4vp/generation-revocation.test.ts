import { afterEach, describe, expect, test } from 'bun:test'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { p256 } from '@noble/curves/nist.js'
import { AnchorOid4vpProvider, MemoryAnchorOid4vpStore } from '../../src/anchor/oid4vp.ts'
import { SqliteAnchorOidcState } from '../../src/anchor/oidc-sqlite.ts'
import { p256PublicJwk } from '../../src/oid4vp/profile.ts'

const directories: string[] = []
afterEach(() => { for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true }) })

describe('Anchor Sign generation activation', () => {
  test('new issuance revokes an older credential and browser session', async () => {
    const now = new Date('2026-08-31T00:00:00.000Z')
    const store = new MemoryAnchorOid4vpStore()
    const provider = new AnchorOid4vpProvider({ issuer: 'https://anchor.biset.md', store, credentialSigningPrivateKey: p256.utils.randomSecretKey(), now: () => now })
    const old = await provider.issueCredential('root-subject', `1-${'a'.repeat(32)}`, p256PublicJwk(p256.utils.randomSecretKey()))
    const oldId = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(old.credential.split('.')[1]!.replace(/-/g, '+').replace(/_/g, '/')), value => value.charCodeAt(0)))).id as string
    await store.putSession({ sessionHash: 'old-session', rootSubject: 'root-subject', generation: `1-${'a'.repeat(32)}`, authenticatedAt: 1, expiresAt: 9999999999 })

    await provider.issueCredential('root-subject', `2-${'b'.repeat(32)}`, p256PublicJwk(p256.utils.randomSecretKey()))

    expect((await store.credential(oldId))?.revokedAt).toBe(Math.floor(now.getTime() / 1000))
    expect(await store.session('old-session')).toBeUndefined()
  })

  test('SQLite activation also removes old authorization codes and refresh tokens', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'anchor-generation-'))
    directories.push(directory)
    const state = SqliteAnchorOidcState.open(join(directory, 'oidc.sqlite'))
    const oldGeneration = `1-${'a'.repeat(32)}`
    await state.put({ codeHash: 'old-code', clientId: 'client', redirectUri: 'https://client.example/cb', rootSubject: 'root-subject', generation: oldGeneration, sectorIdentifier: 'sector', audience: 'https://coordinator.biset.md', scopes: [], codeChallenge: 'c'.repeat(43), nonce: 'nonce', authenticatedAt: 1, expiresAt: 9999999999 })
    await state.putRefresh({ tokenHash: 'old-refresh', clientId: 'client', rootSubject: 'root-subject', generation: oldGeneration, sectorIdentifier: 'sector', audience: 'https://coordinator.biset.md', scopes: [], expiresAt: 9999999999 })

    await state.activateGeneration('root-subject', `2-${'b'.repeat(32)}`, 2)

    expect(await state.take('old-code')).toBeUndefined()
    expect(await state.takeRefresh('old-refresh')).toBeUndefined()
    state.close()
  })
})
