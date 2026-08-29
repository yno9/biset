import { createBisetAnchorDeployment } from './deployment.ts'
import { createPersistentAnchorOid4vpOidcProvider } from './oidc-deployment.ts'
import { parseAnchorOidcClients } from './config.ts'

const dataDir = Bun.env.ANCHOR_DATA_DIR
if (!dataDir) throw new Error('ANCHOR_DATA_DIR is required')

const port = Number(Bun.env.PORT ?? 8788)
const issuer = Bun.env.ANCHOR_ISSUER
const clientsJson = Bun.env.ANCHOR_OIDC_CLIENTS_JSON
if ((issuer && !clientsJson) || (!issuer && clientsJson)) throw new Error('ANCHOR_ISSUER and ANCHOR_OIDC_CLIENTS_JSON must be configured together')
const authentication = issuer && clientsJson
  ? createPersistentAnchorOid4vpOidcProvider({
      dataDir,
      issuer,
      clients: parseAnchorOidcClients(clientsJson),
      walletAuthorizationEndpoint: Bun.env.ANCHOR_WALLET_AUTHORIZATION_ENDPOINT,
    })
  : undefined
const anchor = createBisetAnchorDeployment({
  dataDir,
  domainHeader: Bun.env.ANCHOR_DOMAIN_HEADER ?? 'x-biset-domain',
  oidc: authentication?.oidc,
  oid4vp: authentication?.oid4vp,
  apexDomain: Bun.env.ANCHOR_APEX_DOMAIN,
})

Bun.serve({ port, fetch: anchor.fetch })
console.info(`biset-anchor listening on :${port} (OIDC/OID4VP ${authentication ? 'enabled' : 'disabled'})`)
