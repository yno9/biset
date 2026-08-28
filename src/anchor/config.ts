import type { AnchorOidcClient } from './oidc.ts'

export function parseAnchorOidcClients(value: string): AnchorOidcClient[] {
  let parsed: unknown
  try { parsed = JSON.parse(value) } catch { throw new TypeError('ANCHOR_OIDC_CLIENTS_JSON must be valid JSON') }
  if (!Array.isArray(parsed) || parsed.length === 0) throw new TypeError('ANCHOR_OIDC_CLIENTS_JSON must be a non-empty array')
  return parsed.map((entry, index) => {
    if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) throw new TypeError(`OIDC client ${index} is invalid`)
    const client = entry as Record<string, unknown>
    const keys = Object.keys(client).sort().join()
    const legacyKeys = ['allowedScopes', 'audience', 'clientId', 'redirectUris', 'sectorIdentifier'].sort().join()
    const currentKeys = ['allowedScopes', 'applicationOrigins', 'audience', 'clientId', 'redirectUris', 'sectorIdentifier'].sort().join()
    if ((keys !== legacyKeys && keys !== currentKeys) || typeof client.clientId !== 'string' || typeof client.sectorIdentifier !== 'string' || typeof client.audience !== 'string' || !stringArray(client.redirectUris) || !stringArray(client.allowedScopes) || (client.applicationOrigins !== undefined && !stringArray(client.applicationOrigins))) throw new TypeError(`OIDC client ${index} is invalid`)
    return { clientId: client.clientId, redirectUris: [...client.redirectUris], ...(client.applicationOrigins ? { applicationOrigins: [...client.applicationOrigins] } : {}), sectorIdentifier: client.sectorIdentifier, audience: client.audience, allowedScopes: [...client.allowedScopes] }
  })
}

function stringArray(value: unknown): value is string[] { return Array.isArray(value) && value.every(item => typeof item === 'string') }
