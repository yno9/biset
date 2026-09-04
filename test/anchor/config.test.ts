import { describe, expect, test } from 'bun:test'
import { parseAnchorOidcClients } from '../../src/anchor/config.ts'

describe('Anchor environment config', () => {
  test('parses an exact static OIDC client registration', () => {
    expect(parseAnchorOidcClients(JSON.stringify([{
      clientId: 'biset-client', redirectUris: ['https://biset.md/oauth/callback'], sectorIdentifier: 'biset.md', audience: 'https://coordinator.biset.md', allowedScopes: ['vault.pull'],
    }]))).toEqual([{
      clientId: 'biset-client', redirectUris: ['https://biset.md/oauth/callback'], sectorIdentifier: 'biset.md', audience: 'https://coordinator.biset.md', allowedScopes: ['vault.pull'],
    }])
  })
  test('rejects unknown or missing fields', () => {
    expect(() => parseAnchorOidcClients('[{"clientId":"x"}]')).toThrow('OIDC client 0 is invalid')
    expect(() => parseAnchorOidcClients('[{"clientId":"x","redirectUris":[],"sectorIdentifier":"s","audience":"a","allowedScopes":[],"vaultId":"leak"}]')).toThrow('OIDC client 0 is invalid')
  })
})
